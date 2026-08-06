#!/usr/bin/env python3
"""Pinned native hook map for mission dispatch and location selectors.

This module is intentionally a *hook design* contract.  It proves that the
addresses and instruction shapes below belong to the pinned Dutch executable;
it does not turn static code into runtime parity.  A producer must install all
probes required by a selector and emit the observed pre/result/post facts.  A
missing probe is an unsupported receipt, never a partial success.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.native_mygghanget_contract import PeImage
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    from native_mygghanget_contract import PeImage


EXECUTABLE_SHA256 = (
    "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"
)
EDITION = "miel-vliegt-de-wereld-rond-nl"
PROTOCOL = "miel-vliegt-native-dispatch-hook-contract"
RUNTIME_STATUS = "NATIVE_TRACE_REQUIRED"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/native_dispatch_hook_contract.json"
PRODUCER_SOURCE_PATHS = (
    "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.h",
    "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.c",
    "tools/miel_vliegt/native_dispatch_semantic_wire.py",
)


# Windows include absolute addresses in call displacements, so these receipts
# are deliberately edition-local.  The complete executable hash is checked
# before any site is accepted.
SITE_SIGNATURES: dict[str, tuple[int, str]] = {
    "MISSION_FILE_PARSE": (0x00437670, "64a1000000006aff68f2a7440050648925"),
    "MISSION_INSERT": (0x00437610, "8b4424048948248b5104895028c7402c"),
    "MISSION_ACTION_EXECUTE": (0x00436270, "6aff6888a7440064a10000000050648925"),
    "ACTION_GROUND": (0x004362F1, "8b430885c00f84b20900008b4b1085c9"),
    "ACTION_BARN": (0x004364C9, "8b430885c00f84da0700008b4b1085c9"),
    "ACTION_FLIGHT": (0x00436497, "8b430885c00f840c080000e879f5fcff"),
    "ACTION_OUTRO": (0x0043675B, "e8c0f2fcff8b80ac01000068d4664500"),
    "ACTION_OUTRO_COMMIT": (0x00436789, "c680ac48000001e919050000"),
    "UDSP_ROOT_FACTORY": (0x0043CD70, "6aff6872aa440064a10000000050648925"),
    "SCENE_DISPATCH_GROUND": (0x00427210, "568bf16a0ce86a1402008b8ec8080000"),
    "SCENE_DISPATCH_BARN": (0x00416940, "568bf15733ff8b86ec1a00003bc77526"),
    "SCENE_DISPATCH_FLIGHT": (0x0042E540, "8b44240485c08981c03f000074078bc8"),
    "GENERIC_LOCATION_ENTER": (0x00425170, "83ec4853568bf15733db8b4650c64615"),
    "GENERIC_FINAL_MISSION_PRESENT": (0x004254C8, "8bc8e8c10b010084c0740c8b96cc08"),
    "GENERIC_FINAL_TRUE": (0x004254D3, "8b96cc0800008996d4080000e83c05fe"),
    "GROTTE_ENTER": (0x004417D0, "568bf1e89839feff8b8ebc08000085c9"),
    "GROTTE_STATE_SETTER": (0x00441830, "568bf18b4c24088bc183e80574274875"),
    "GROTTE_REFUEL_BRANCH": (0x00441865, "8a86a448000084c074298b86a0480000"),
    "RAYMOND_LOCATION_LOAD": (0x00441D00, "64a1000000006aff68a1ad440050648925"),
    "RAYMOND_FIRST_BRANCH": (0x00441E99, "8a869c48000084c0740768b4d54500eb"),
    "RAYMOND_STATE_SETTER": (0x00441FE0, "8b44240483ec4483e805568bf10f8495"),
    "RAYMOND_RESULT_BRANCH": (0x0044202F, "8a869448000084c00f856902000083be"),
    "EXHIBITION_STATE_SETTER": (0x00443D50, "83ec185356578b7c24288bc78bf183e8"),
    "EXHIBITION_PROJECTION": (0x00443D7E, "8b4e5c8d542418528b01ff50348b8ea8"),
    "EXHIBITION_LT_900": (0x00443DB4, "d944240cd81d84d94400899ed0080000"),
    "EXHIBITION_LT_900_SELECTED": (0x00443DCB, "8b8e944800008b96b8480000898ed0"),
    "EXHIBITION_LT_2200": (0x00443E45, "d944240cd81d80d94400dfe0f6c401"),
    "EXHIBITION_LT_2200_SELECTED": (0x00443E5A, "8b8eb44800008b8690480000518b8e"),
    "EXHIBITION_LT_2200_FINAL_TRUE": (0x00443EEF, "8b96a0480000578bce8996d4080000"),
    "EXHIBITION_GTE_2200": (0x00443F0C, "8b8ebc4800008b8698480000518b8ea8"),
    "EXHIBITION_GTE_2200_FINAL_TRUE": (0x00443F9F, "8b96a4480000578bce8996d4080000"),
    "EXHIBITION_FINAL_FALSE": (0x00444075, "578bcee8f324feff5f5e5b83c418c2"),
    "EXHIBITION_OUTRO": (0x00443FBC, "8b8ec04800008b869c480000518b8ea8"),
    "MYGGHANGET_ENTER": (0x00441A60, "568bf1c6869148000001e80137feff8b"),
    "MYGGHANGET_STATE_SETTER": (0x00441AF0, "8b44240485c0741583f80675178b4950"),
}


ACTION_ROUTES = {
    1: {
        "opcode": "PLAY_SCRIPT", "route": "GROUND",
        "dispatchCallsite": 0x00436308, "dispatchTarget": 0x00427210,
    },
    2: {
        "opcode": "PLAY_BARNSCRIPT", "route": "BARN",
        "dispatchCallsite": 0x004364E0, "dispatchTarget": 0x00416940,
    },
    3: {
        "opcode": "PLAY_SCRIPTMODEFLY", "route": "FLIGHT",
        "dispatchCallsite": 0x004364BF, "dispatchTarget": 0x0042E540,
    },
    21: {
        "opcode": "PLAY_OUTRO", "route": "LOCATION_POLICY",
        "commitAddress": 0x00436789, "outroRequestedOffset": 0x48AC,
    },
}


MISSION_LAYOUT = {
    "idObjectPointer": 0x08,
    "phaseObjectPointer": 0x0C,
    "propertyValue": 0x114,
    "actionHead": 0x30,
}
MISSION_PHASES = {1: "activate", 2: "complete", 3: "reward"}
ACTION_LAYOUT = {
    "phase": 0x00,
    "opcode": 0x04,
    "root": 0x08,
    "alternateRoot": 0x0C,
    "dispatcher": 0x10,
    "alternateDispatcher": 0x14,
    "executed": 0x18,
    "alternateExecuted": 0x19,
    "sourcePrevious": 0x1C,
    "sourceNext": 0x20,
}


SELECTORS: dict[str, dict[str, Any]] = {
    "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3": {
        "probes": ["GENERIC_LOCATION_ENTER", "GENERIC_FINAL_MISSION_PRESENT",
                   "GENERIC_FINAL_TRUE", "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 0x4C, "defaultRoot": 0x8D0,
                   "finalRoot": 0x8CC, "activeRoot": 0x8D4},
        "predicate": "finalMissionState != 3",
    },
    "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3": {
        "probes": ["GENERIC_LOCATION_ENTER", "GENERIC_FINAL_MISSION_PRESENT",
                   "GENERIC_FINAL_TRUE", "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 0x4C, "defaultRoot": 0x8D0,
                   "finalRoot": 0x8CC, "activeRoot": 0x8D4},
        "predicate": "finalMissionState == 3",
    },
    "ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED": {
        "probes": ["GROTTE_STATE_SETTER", "GROTTE_REFUEL_BRANCH", "UDSP_ROOT_FACTORY"],
        "fields": {"root": 0x48A0, "refuelArmed": 0x48A4,
                   "refuelConsumed": 0x48A5},
        "predicate": "event == 5 && refuelArmed == 1 && refuelConsumed == 0",
        "dispatchCallsite": 0x00441886,
    },
    "LOCATION_ENTER_FIRST_CHALLENGE": {
        "probes": ["RAYMOND_LOCATION_LOAD", "RAYMOND_FIRST_BRANCH", "UDSP_ROOT_FACTORY"],
        "fields": {"firstChallenge": 0x489C, "selectedRoot": 0x8D0},
        "predicate": "firstChallenge == 1",
        "factoryCallsite": 0x00441EB0,
    },
    "LOCATION_ENTER_SUBSEQUENT_CHALLENGE": {
        "probes": ["RAYMOND_LOCATION_LOAD", "RAYMOND_FIRST_BRANCH", "UDSP_ROOT_FACTORY"],
        "fields": {"firstChallenge": 0x489C, "selectedRoot": 0x8D0},
        "predicate": "firstChallenge == 0",
        "factoryCallsite": 0x00441EB0,
    },
    "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2": {
        "probes": ["RAYMOND_STATE_SETTER", "RAYMOND_RESULT_BRANCH", "UDSP_ROOT_FACTORY"],
        "fields": {"challengeActive": 0x4894, "challengeResult": 0x4898,
                   "root": 0x48A0},
        "predicate": "event == 6 && challengeActive == 0 && challengeResult == 2",
        "dispatchCallsite": 0x0044204F,
    },
    "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2": {
        "probes": ["RAYMOND_STATE_SETTER", "RAYMOND_RESULT_BRANCH", "UDSP_ROOT_FACTORY"],
        "fields": {"challengeActive": 0x4894, "challengeResult": 0x4898,
                   "root": 0x48A4},
        "predicate": "event == 6 && challengeActive == 0 && challengeResult != 2",
        "dispatchCallsite": 0x00442070,
    },
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900": {
        "probes": ["GENERIC_LOCATION_ENTER", "EXHIBITION_STATE_SETTER",
                   "EXHIBITION_PROJECTION", "EXHIBITION_LT_900",
                   "EXHIBITION_LT_900_SELECTED", "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 14, "outroRequested": 0x48AC, "root": 0x4894},
        "predicate": "event == 6 && outroRequested == 0 && finite(projectedMapX) && projectedMapX < 900",
    },
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_NE_3": {
        "probes": ["GENERIC_LOCATION_ENTER", "EXHIBITION_STATE_SETTER",
                   "EXHIBITION_PROJECTION", "EXHIBITION_LT_900",
                   "EXHIBITION_LT_2200", "EXHIBITION_LT_2200_SELECTED",
                   "EXHIBITION_LT_2200_FINAL_TRUE", "EXHIBITION_FINAL_FALSE",
                   "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 14, "outroRequested": 0x48AC, "root": 0x4890},
        "predicate": "event == 6 && outroRequested == 0 && finite(projectedMapX) && 900 <= projectedMapX < 2200 && finalMissionState != 3",
    },
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_NE_3": {
        "probes": ["GENERIC_LOCATION_ENTER", "EXHIBITION_STATE_SETTER", "EXHIBITION_PROJECTION",
                   "EXHIBITION_LT_900", "EXHIBITION_LT_2200",
                   "EXHIBITION_GTE_2200", "EXHIBITION_GTE_2200_FINAL_TRUE",
                   "EXHIBITION_FINAL_FALSE", "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 14, "outroRequested": 0x48AC, "root": 0x4898},
        "predicate": "event == 6 && outroRequested == 0 && finite(projectedMapX) && projectedMapX >= 2200 && finalMissionState != 3",
    },
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_EQ_3": {
        "probes": ["GENERIC_LOCATION_ENTER", "EXHIBITION_STATE_SETTER",
                   "EXHIBITION_PROJECTION", "EXHIBITION_LT_900",
                   "EXHIBITION_LT_2200", "EXHIBITION_LT_2200_SELECTED",
                   "EXHIBITION_LT_2200_FINAL_TRUE", "EXHIBITION_FINAL_FALSE",
                   "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 14, "outroRequested": 0x48AC, "root": 0x48A0},
        "predicate": "event == 6 && outroRequested == 0 && finite(projectedMapX) && 900 <= projectedMapX < 2200 && finalMissionState == 3",
    },
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_EQ_3": {
        "probes": ["GENERIC_LOCATION_ENTER", "EXHIBITION_STATE_SETTER", "EXHIBITION_PROJECTION",
                   "EXHIBITION_LT_900", "EXHIBITION_LT_2200",
                   "EXHIBITION_GTE_2200", "EXHIBITION_GTE_2200_FINAL_TRUE",
                   "EXHIBITION_FINAL_FALSE", "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 14, "outroRequested": 0x48AC, "root": 0x48A4},
        "predicate": "event == 6 && outroRequested == 0 && finite(projectedMapX) && projectedMapX >= 2200 && finalMissionState == 3",
    },
    "LOCATION_ENTER_OUTRO_REQUESTED": {
        "probes": ["GENERIC_LOCATION_ENTER", "EXHIBITION_STATE_SETTER",
                   "EXHIBITION_OUTRO", "UDSP_ROOT_FACTORY"],
        "fields": {"locationId": 14, "outroRequested": 0x48AC, "outroConsumed": 0x48AD,
                   "root": 0x489C},
        "predicate": "event == 6 && outroRequested == 1",
    },
    "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE": {
        "probes": ["MYGGHANGET_ENTER", "UDSP_ROOT_FACTORY",
                   "SCENE_DISPATCH_GROUND", "SCENE_DISPATCH_BARN",
                   "SCENE_DISPATCH_FLIGHT"],
        "fields": {"locationId": 0x4C, "activeRoot": 0x8D4,
                   "queuedRoot": 0x8C8, "defaultRoot": 0x8D0},
        "predicate": "locationId == 22 && queuedRoot == 0 && defaultRoot == 0 && activeRoot == 0 after the synchronous game-thread entry interval, every root-factory call bound a nonzero root to an exact canonical artifact path, and no root path in the mygghanget location domain was created; every route call must still have root-path provenance",
        "absenceWindow": [0x00441A60, 0x00441A93],
    },
}


class NativeDispatchHookContractError(ValueError):
    """Raised when the pinned hook map or a capability receipt is incomplete."""


def producer_sources() -> dict[str, str]:
    return {
        path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        for path in PRODUCER_SOURCE_PATHS
    }


def producer_build_sha256() -> str:
    encoded = json.dumps(
        producer_sources(), sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _relative_call_target(image: PeImage, address: int) -> int:
    offset = image.address_to_offset(address)
    if image.data[offset] != 0xE8:
        raise NativeDispatchHookContractError(f"{address:#x} is not a relative call")
    displacement = struct.unpack_from("<i", image.data, offset + 1)[0]
    return address + 5 + displacement


def verify_pinned_executable(executable: Path) -> PeImage:
    image = PeImage(executable)
    digest = hashlib.sha256(image.data).hexdigest()
    if digest != EXECUTABLE_SHA256:
        raise NativeDispatchHookContractError(
            f"dispatch hook executable SHA-256 drifted to {digest}"
        )
    for name, (address, expected_hex) in SITE_SIGNATURES.items():
        offset = image.address_to_offset(address)
        expected = bytes.fromhex(expected_hex)
        if image.data[offset:offset + len(expected)] != expected:
            raise NativeDispatchHookContractError(f"{name} signature drifted")

    for action in ACTION_ROUTES.values():
        callsite = action.get("dispatchCallsite")
        if callsite is not None and _relative_call_target(image, callsite) != action["dispatchTarget"]:
            raise NativeDispatchHookContractError(
                f"{action['opcode']} dispatch target drifted"
            )
    for selector, spec in SELECTORS.items():
        callsite = spec.get("dispatchCallsite")
        if callsite is not None and _relative_call_target(image, callsite) != 0x00427210:
            raise NativeDispatchHookContractError(f"{selector} GROUND target drifted")

    for address, expected in ((0x0044D984, 900.0), (0x0044D980, 2200.0)):
        value = struct.unpack_from("<f", image.data, image.address_to_offset(address))[0]
        if value != expected:
            raise NativeDispatchHookContractError(
                f"exhibition threshold {address:#x} drifted to {value!r}"
            )
    return image


def validate_capability_receipt(receipt: Any) -> dict[str, Any]:
    """Validate the producer's preflight without accepting partial hooks.

    This validates capability only.  Runtime observations still go through the
    semantic oracle and remain unproven until independently compared with web.
    """

    fields = {
        "schema", "protocol", "executableSha256", "runtimeParity",
        "installedProbes", "missionSourceBinding", "rootPathBinding",
        "inlineProjectedXCapture", "selectorCoverage",
    }
    if not isinstance(receipt, dict) or set(receipt) != fields:
        raise NativeDispatchHookContractError("hook capability receipt shape differs")
    if receipt["schema"] != 1 or type(receipt["schema"]) is not int:
        raise NativeDispatchHookContractError("hook capability schema differs")
    if receipt["protocol"] != PROTOCOL or receipt["executableSha256"] != EXECUTABLE_SHA256:
        raise NativeDispatchHookContractError("hook capability identity differs")
    if receipt["runtimeParity"] != RUNTIME_STATUS:
        raise NativeDispatchHookContractError("static hook map overclaims runtime parity")
    probes = receipt["installedProbes"]
    if not isinstance(probes, list) or len(probes) != len(set(probes)) \
            or set(probes) != set(SITE_SIGNATURES):
        raise NativeDispatchHookContractError("not every signature-checked probe is installed")
    for key in ("missionSourceBinding", "rootPathBinding", "inlineProjectedXCapture"):
        if receipt[key] is not True:
            raise NativeDispatchHookContractError(f"{key} is not supported")
    coverage = receipt["selectorCoverage"]
    if not isinstance(coverage, dict) or set(coverage) != set(SELECTORS) \
            or any(value is not True for value in coverage.values()):
        raise NativeDispatchHookContractError("selector coverage is incomplete")
    return receipt


def contract() -> dict[str, Any]:
    """Return the immutable static hook-design contract."""

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "claim": "PINNED_STATIC_HOOK_DESIGN",
        "edition": EDITION,
        "editionPolicy": "EDITION_LOCAL_ADDRESSES_NEVER_REUSED",
        "runtimeParity": RUNTIME_STATUS,
        "executableSha256": EXECUTABLE_SHA256,
        "producerSources": producer_sources(),
        "producerBuildSha256": producer_build_sha256(),
        "missionLayout": MISSION_LAYOUT,
        "missionPhases": MISSION_PHASES,
        "actionLayout": ACTION_LAYOUT,
        "actionRoutes": ACTION_ROUTES,
        "sites": {
            name: {"address": f"0x{address:08x}", "signature": signature}
            for name, (address, signature) in SITE_SIGNATURES.items()
        },
        "selectors": SELECTORS,
        "requirements": [
            "at 0x00437670 bind ECX container plus [ESP+8] exact source path; at 0x00437610 bind [ESP+4] mission pointer",
            "forward the 0x00436270 [ESP+4] phase argument exactly and preserve its ret 4 ABI; forward 0x00441d00 [ESP+4] and its BYTE AL result exactly",
            "derive source action ordinal as action-count-minus-one-minus-index while following action+0x1c",
            "bind root pointers to [ESP+8] exact runtime path returned by 0x0043cd70",
            "defer mission receipt emission until 0x00436270 returns and action+0x18 is observed as one",
            "treat PLAY_OUTRO as a deferred LOCATION_POLICY arm only after the exact 0x00436789 object+0x48ac commit; do not invent an immediate route/root callback",
            "bind exhibition policy to canonical entry location 14, suppress the generic claim for that entry, and require its exact terminal selector plus actual AL completion branch",
            "capture exhibition projectedMapX as raw IEEE-754 f32 bits and reject non-finite values in the host normalization boundary",
            "bound Mygghanget absence to one synchronous game-thread entry interval",
            "reject Mygghanget absence when any in-interval root-factory call cannot bind its returned nonzero root to an exact canonical artifact path, even when all root fields remain zero",
            "bind every runtime CAPABILITY to an external capture-plan job, native-slice hash, final observer-binary hash, and observer build-receipt hash before support",
            "open one engine-thread capture window immediately before one checked job target; atomically close after its first EVENT, reject zero events, and never rebind or reuse the process for another job",
            "make capture-window consumption process-lifetime monotonic: disable, re-arm, and rebind can never reset or reopen it",
            "do not treat MYGGHANGET_STATE_SETTER as an entry-absence predicate: it is outside 0x00441a60..0x00441a93 and remains inventory-only",
            "emit no supported receipt when any required probe or binding is missing",
        ],
    }


def json_contract() -> dict[str, Any]:
    return json.loads(json.dumps(contract(), sort_keys=True))


def validate_contract(document: Any) -> dict[str, Any]:
    if document != json_contract():
        raise NativeDispatchHookContractError(
            "native dispatch hook contract differs from the pinned design"
        )
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--producer-build-sha", action="store_true")
    parser.add_argument("--executable", type=Path)
    args = parser.parse_args()
    if args.producer_build_sha:
        print(producer_build_sha256())
        return 0
    if args.write and args.check:
        raise NativeDispatchHookContractError("--write and --check are mutually exclusive")
    expected = json_contract()
    if args.write:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if args.check or not args.write:
        try:
            checked = json.loads(args.output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise NativeDispatchHookContractError(
                "native dispatch hook contract artifact is unavailable"
            ) from error
        validate_contract(checked)
    if args.executable is not None:
        verify_pinned_executable(args.executable)
    print(
        f"native dispatch hook contract OK: missions=113, "
        f"selectors={len(SELECTORS)}, runtime={RUNTIME_STATUS}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
