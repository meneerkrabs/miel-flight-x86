#!/usr/bin/env python3
"""Parse native audio/animation observations without inventing parity policy.

The observer emits a narrow diagnostic channel alongside the canonical MVT
scenario trace.  This consumer validates that channel fail-closed and produces
a deterministic observation-set digest.  Its output is deliberately not a
promotion receipt: native observations still need a classifier/differential
test before any web behaviour may move out of ``UNPROVEN``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROTOCOL = "miel-vliegt-native-media-semantics-observation"
SET_PROTOCOL = "miel-vliegt-native-media-semantics-observation-set"
EDITION = "flight/nl/miel-vliegt-de-wereld-rond"
PREFIX = "MVD "
UINT32_MAX = (1 << 32) - 1

TOP_LEVEL_KEYS = {
    "schema",
    "protocol",
    "sequence",
    "behaviour_id",
    "phase",
    "tick",
    "frame",
    "call_id",
    "site_rva",
    "values",
    "thread_id",
}
AUDIO_START_SITE = "0x00009fc0"
AUDIO_POLL_SITE = "0x0000a650"
RANDOMFRAME_SITES = {
    "0x00000405": "initial",
    "0x000005a2": "cadence",
}


class NativeMediaSemanticsTraceError(ValueError):
    """The native media-semantics observation channel was malformed."""


def _is_u32(value: Any) -> bool:
    return type(value) is int and 0 <= value <= UINT32_MAX


def _require_exact_mapping(
    value: Any, keys: set[str], description: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise NativeMediaSemanticsTraceError(f"{description} shape differs")
    return value


def _validate_record(value: Any) -> dict[str, Any]:
    record = _require_exact_mapping(value, TOP_LEVEL_KEYS, "observation")
    if record["schema"] != 1 or record["protocol"] != PROTOCOL:
        raise NativeMediaSemanticsTraceError("observation identity differs")
    for field in ("sequence", "tick", "frame", "call_id", "thread_id"):
        if not _is_u32(record[field]):
            raise NativeMediaSemanticsTraceError(
                f"observation {field} is not uint32"
            )
    if record["thread_id"] == 0:
        raise NativeMediaSemanticsTraceError("observation thread is zero")

    behaviour = record["behaviour_id"]
    phase = record["phase"]
    site = record["site_rva"]
    values = record["values"]
    if behaviour == "audio_completion" and phase == "audio_start":
        values = _require_exact_mapping(
            values, {"accepted", "replaced_active"}, "audio-start values"
        )
        if site != AUDIO_START_SITE or any(
            type(values[key]) is not bool for key in values
        ):
            raise NativeMediaSemanticsTraceError("audio-start contract differs")
    elif behaviour == "audio_completion" and phase == "audio_poll":
        values = _require_exact_mapping(
            values, {"complete", "poll_ordinal"}, "audio-poll values"
        )
        if (
            site != AUDIO_POLL_SITE
            or type(values["complete"]) is not bool
            or not _is_u32(values["poll_ordinal"])
        ):
            raise NativeMediaSemanticsTraceError("audio-poll contract differs")
    elif behaviour == "randomframe_cadence" and phase == "rng_draw":
        values = _require_exact_mapping(
            values, {"sampling_point", "value"}, "randomframe values"
        )
        if (
            site not in RANDOMFRAME_SITES
            or values["sampling_point"] != RANDOMFRAME_SITES.get(site)
            or not _is_u32(values["value"])
        ):
            raise NativeMediaSemanticsTraceError(
                "randomframe observation contract differs"
            )
    else:
        raise NativeMediaSemanticsTraceError(
            "observation behaviour or phase differs"
        )
    return dict(record)


def parse_observations(text: str) -> list[dict[str, Any]]:
    """Return validated records for this protocol from a mixed observer log."""

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.startswith(PREFIX):
            continue
        try:
            value = json.loads(line[len(PREFIX):])
        except json.JSONDecodeError as error:
            raise NativeMediaSemanticsTraceError(
                f"malformed diagnostic JSON on line {line_number}"
            ) from error
        if not isinstance(value, Mapping) or value.get("protocol") != PROTOCOL:
            continue
        records.append(_validate_record(value))
    if not records:
        raise NativeMediaSemanticsTraceError(
            "native media-semantics observations are absent"
        )
    if [record["sequence"] for record in records] != list(range(len(records))):
        raise NativeMediaSemanticsTraceError(
            "media-semantics sequence is not contiguous"
        )
    thread_ids = {record["thread_id"] for record in records}
    if len(thread_ids) != 1:
        raise NativeMediaSemanticsTraceError(
            "media-semantics observations crossed engine threads"
        )
    _validate_call_streams(records)
    return records


def _validate_call_streams(records: list[dict[str, Any]]) -> None:
    audio_calls: dict[int, dict[str, Any]] = {}
    next_audio_call = 0
    next_rng_call = 0
    for record in records:
        call_id = record["call_id"]
        if record["behaviour_id"] == "randomframe_cadence":
            if call_id != next_rng_call:
                raise NativeMediaSemanticsTraceError(
                    "randomframe call ids are not contiguous"
                )
            next_rng_call += 1
            continue
        if record["phase"] == "audio_start":
            if call_id != next_audio_call or call_id in audio_calls:
                raise NativeMediaSemanticsTraceError(
                    "audio call ids are not contiguous"
                )
            next_audio_call += 1
            audio_calls[call_id] = {
                "accepted": record["values"]["accepted"],
                "next_poll": 0,
            }
            continue
        call = audio_calls.get(call_id)
        if call is None or not call["accepted"]:
            raise NativeMediaSemanticsTraceError(
                "audio poll has no accepted start"
            )
        if record["values"]["poll_ordinal"] != call["next_poll"]:
            raise NativeMediaSemanticsTraceError(
                "audio poll ordinals are not contiguous"
            )
        call["next_poll"] += 1


def _canonical_observations(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in record.items() if key != "thread_id"}
        for record in records
    ]


def build_observation_set(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize validated evidence while keeping promotion fail-closed."""

    canonical = _canonical_observations(records)
    payload = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    audio = [row for row in records if row["behaviour_id"] == "audio_completion"]
    starts = [row for row in audio if row["phase"] == "audio_start"]
    polls = [row for row in audio if row["phase"] == "audio_poll"]
    random_draws = [
        row for row in records
        if row["behaviour_id"] == "randomframe_cadence"
    ]
    completed = {
        row["call_id"] for row in polls if row["values"]["complete"]
    }
    return {
        "schema": 1,
        "protocol": SET_PROTOCOL,
        "edition": EDITION,
        "observationCount": len(records),
        "observationsSha256": hashlib.sha256(payload).hexdigest(),
        "behaviours": {
            "audio_completion": {
                "starts": len(starts),
                "acceptedStarts": sum(
                    row["values"]["accepted"] for row in starts
                ),
                "activeReplacements": sum(
                    row["values"]["replaced_active"] for row in starts
                ),
                "polls": len(polls),
                "completedCalls": len(completed),
            },
            "randomframe_cadence": {
                "draws": len(random_draws),
                "initialDraws": sum(
                    row["values"]["sampling_point"] == "initial"
                    for row in random_draws
                ),
                "cadenceDraws": sum(
                    row["values"]["sampling_point"] == "cadence"
                    for row in random_draws
                ),
            },
        },
        "promotionEligible": False,
        "promotionReceipt": None,
    }


def consume_trace(path: Path) -> dict[str, Any]:
    return build_observation_set(
        parse_observations(path.read_text(encoding="utf-8"))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = consume_trace(args.trace)
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
