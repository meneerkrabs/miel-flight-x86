#!/usr/bin/env python3
"""Contract for the native media/animation semantics trace and its promotion.

Three clean-room-open UDSP presentation behaviours block 370 web semantic
claims because their native completion timing is untraced:

* audio completion      -- PLAY_CHARACTER_SOUND / PLAY_SOUND / PLAY_RADIO
                           (blocking vs fire-and-forget, and duration source);
* random-frame cadence  -- ANIMATION_RANDOMFRAME rand() sampling period;
* callback interruption -- a second PLAY_CHARACTER_ANIMATION on a busy part.

This module is the single boundary that says what the observer must emit and
what evidence is required before the web engine may promote any of these
opcodes from ``UNPROVEN`` to a proven completion contract.  It never resolves a
behaviour on its own: promotion requires a hash-bound trace receipt produced by
a real native run.  Absent that receipt every behaviour stays fail-closed, so
importing this module can only *enable* a promotion that a trace already earned.

The receipt shape defined here is exactly what
``tools/miel_vliegt/hangover/native_observer_hook.c`` writes on its bounded,
env-gated ``media-semantics`` diagnostic channel; ``validate_trace_receipt``
rejects any receipt that is not byte-consistent with that emission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/native_media_semantics_contract.json"
PROTOCOL = "miel-vliegt-native-media-semantics-contract"
TRACE_PROTOCOL = "miel-vliegt-native-media-semantics-trace"
EDITION = "flight/nl/miel-vliegt-de-wereld-rond"

#: Behaviour ids and the native addresses whose trace resolves them.  Addresses
#: come from the static recovery in ``native_udsp_scene_commands.json`` and
#: ``native_udsp_scene_commands`` opcode 3; they are what the observer detours.
BEHAVIOURS: tuple[Mapping[str, Any], ...] = (
    {
        "id": "audio_completion",
        "opcodes": ("PLAY_CHARACTER_SOUND", "PLAY_SOUND", "PLAY_RADIO"),
        "startAddresses": ("0x00409910", "0x00409fc0"),
        "pollAddresses": ("0x0040a280", "0x0040a650"),
        "durationSource": "media_object+0x14",
        "openQuestion": "BLOCKING_VS_FIRE_AND_FORGET_AND_DURATION_SOURCE",
        "resolvedBlockerCode": "WEB_HEADLESS_ROUTE_COMPLETION_UNOBSERVED",
    },
    {
        "id": "randomframe_cadence",
        "opcodes": ("PLAY_CHARACTER_ANIMATION",),
        "startAddresses": ("0x0041afa0",),
        "randIatAddress": "0x0044c46c",
        "openQuestion": "RANDOMFRAME_RNG_SAMPLING_CADENCE",
        "resolvedBlockerCode": "FLIGHT_ACTOR_RANDOMFRAME_CADENCE_UNPROVEN",
    },
    {
        "id": "callback_interruption",
        "opcodes": ("PLAY_CHARACTER_ANIMATION",),
        "startAddresses": ("0x0041afa0",),
        "callbackSlot": "actor+0x194",
        "completionCallback": "0x0043c460",
        "openQuestion": "SAME_PART_INTERRUPT_AND_CALLBACK_REPLACEMENT",
        "resolvedBlockerCode": "FLIGHT_ACTOR_CALLBACK_INTERRUPTION_UNPROVEN",
    },
)

#: A promoted completion policy the web engine is allowed to honour once a
#: trace proves it.  Any other value is rejected -- the engine never invents a
#: completion policy, it only reads one back that a trace certified.
AUDIO_COMPLETION_POLICIES = (
    # audio starts on its own channel; the script advances the same update.
    "START_THEN_COMPLETE_SAME_UPDATE",
    # the script suspends until the traced media duration elapses.
    "BLOCK_UNTIL_TRACED_DURATION",
)
RANDOMFRAME_CADENCE_POLICIES = (
    "SAMPLE_ONCE_AT_START",
    "SAMPLE_EVERY_ENGINE_TICK",
)
CALLBACK_INTERRUPTION_POLICIES = (
    "REPLACE_PRIOR_CALLBACK_AND_PLAYBACK",
    "IGNORE_WHILE_BUSY",
    "COMPLETE_PRIOR_THEN_START",
)

POLICIES_BY_BEHAVIOUR = {
    "audio_completion": AUDIO_COMPLETION_POLICIES,
    "randomframe_cadence": RANDOMFRAME_CADENCE_POLICIES,
    "callback_interruption": CALLBACK_INTERRUPTION_POLICIES,
}

SHA256 = 64 * "0"


class MediaSemanticsContractError(ValueError):
    """A media-semantics trace receipt failed the fail-closed contract."""


def contract() -> dict[str, Any]:
    """Return the immutable emission-and-promotion contract."""

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "edition": EDITION,
        "traceProtocol": TRACE_PROTOCOL,
        "policy": {
            "promotionRequires": "hash-bound native media-semantics trace",
            "absentTrace": "UNPROVEN",
            "engineMayInventPolicy": False,
        },
        "behaviours": [
            {
                "id": behaviour["id"],
                "opcodes": list(behaviour["opcodes"]),
                "openQuestion": behaviour["openQuestion"],
                "resolvedBlockerCode": behaviour["resolvedBlockerCode"],
                "allowedPolicies": list(POLICIES_BY_BEHAVIOUR[behaviour["id"]]),
                "nativeSites": {
                    key: list(value) if isinstance(value, tuple) else value
                    for key, value in behaviour.items()
                    if key not in {
                        "id", "opcodes", "openQuestion",
                        "resolvedBlockerCode",
                    }
                },
            }
            for behaviour in BEHAVIOURS
        ],
    }


def json_contract() -> dict[str, Any]:
    return json.loads(json.dumps(contract(), sort_keys=True))


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 \
        and all(character in "0123456789abcdef" for character in value)


def validate_trace_receipt(receipt: Any) -> dict[str, Any]:
    """Fail-closed validation of one observer media-semantics trace receipt.

    A valid receipt certifies exactly one behaviour with one allowed policy,
    carries the native process/session identity, the observer binary hash, and
    the per-observation SHA-256 the observer accumulated.  Anything else is
    rejected; the web engine only promotes on a receipt that passes here.
    """

    if not isinstance(receipt, Mapping) or set(receipt) != {
        "schema", "protocol", "edition", "behaviourId", "policy",
        "observationCount", "observationsSha256", "nativeProcessId",
        "captureSessionId", "observerBinarySha256", "resolvedBlockerCode",
    }:
        raise MediaSemanticsContractError("media-semantics trace receipt shape differs")
    behaviour = next(
        (row for row in BEHAVIOURS if row["id"] == receipt.get("behaviourId")),
        None,
    )
    if receipt.get("schema") != 1 \
            or receipt.get("protocol") != TRACE_PROTOCOL \
            or receipt.get("edition") != EDITION \
            or behaviour is None \
            or receipt.get("policy") not in POLICIES_BY_BEHAVIOUR[behaviour["id"]] \
            or receipt.get("resolvedBlockerCode") != behaviour["resolvedBlockerCode"] \
            or type(receipt.get("observationCount")) is not int \
            or receipt.get("observationCount") <= 0 \
            or not _is_sha256(receipt.get("observationsSha256")) \
            or not _is_sha256(receipt.get("observerBinarySha256")) \
            or type(receipt.get("nativeProcessId")) is not int \
            or receipt.get("nativeProcessId") <= 0 \
            or not isinstance(receipt.get("captureSessionId"), str) \
            or not receipt["captureSessionId"].startswith("mvds-"):
        raise MediaSemanticsContractError("media-semantics trace receipt differs")
    return dict(receipt)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = json.dumps(json_contract(), indent=2, ensure_ascii=True) + "\n"
    if args.check:
        if not args.output.is_file() \
                or args.output.read_text(encoding="utf-8") != expected:
            raise MediaSemanticsContractError(
                "native media semantics contract differs"
            )
        print(f"PASS {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
