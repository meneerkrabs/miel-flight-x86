#!/usr/bin/env python3
"""Validate owner-VM Flight diagnostics without promoting them to parity.

The owner's Parallels guest is a distinct diagnostic environment.  These
contracts bind a receipt to the reviewed original media and public transition
contract, require actual Direct3D7/device and raw-frame observations for a
Flight frame, and always leave hosted-runner and parity proof separate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_IDENTITY = ROOT / "content/miel_vliegt/source_identity.json"
DEFAULT_TRANSITIONS = ROOT / "content/miel_vliegt/native_scene_transitions.json"
ARROW_PROTOCOL = "miel-vliegt-owner-vm-arrow-diagnostic"
FRAME_PROTOCOL = "miel-vliegt-owner-vm-native-flight-frame"
TRANSITION_CONTRACT_ID = "miel-vliegt-native-scene-transitions-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
HEX32 = re.compile(r"^0x[0-9a-f]{8}$")
SCAN_CODE = re.compile(r"^0x[0-9a-f]{2}$")
HRESULT = re.compile(r"^0x[0-9A-F]{8}$")
CAPTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_FRAME_DIMENSION = 8192
FASTER_KEY_SCAN_CODES = frozenset({"0x2a", "0x36", "0x4e"})
AIRPLANE_COMPLETE_BITS = 0x1FF
AIRPLANE_COMPLETE_PREDICATE = (
    "barn.airplane(+0x160).completion(+0x128) == 0x1ff"
)

SOURCE_KEYS = {
    "edition", "iso_sha256", "executable_sha256",
    "transition_contract_sha256", "public_source_commit",
    "capture_tool_sha256",
}
ENVIRONMENT_KEYS = {
    "owner", "guest", "architecture", "audio", "renderer",
    "hosted_runner_validated",
}
PROCESS_KEYS = {
    "pid", "image_name", "architecture", "window_title", "before_alive",
    "after_alive",
}
ARROW_INPUT_KEYS = {
    "adapter_sha256", "adapter_record_bytes", "mouse_arrow_event",
    "escape_dispatch_event", "system_directinput_create_hresult",
    "owner_adapter_hosted_runner_validated",
}
MOUSE_EVENT_KEYS = {
    "sequence", "kind", "x", "y", "arrow_highlighted",
    "transition_observed",
}
KEY_EVENT_KEYS = {
    "sequence", "kind", "scan_code", "dispatch_observed",
    "mode_set_observed",
}
ARROW_STATE_KEYS = {
    "current_mode", "pending_mode", "barn_view", "airplane_complete",
    "airplane_pointer_nonnull", "airplane_completion_bits",
}
ARROW_PROOF_KEYS = {
    "owner_vm_only", "native_transition_evidence", "native_parity_evidence",
}
ARROW_TOP_KEYS = {
    "schema", "protocol", "capture_id", "source", "environment", "process",
    "input", "state", "proof_limits",
}
FRAME_INPUT_KEYS = {
    "adapter_sha256", "adapter_record_bytes",
    "directinput_getdevicedata_events", "login_submit_observed",
    "barn_escape_observed", "faster_key_scan_code",
    "faster_key_held_until_departure", "system_directinput_create_hresult",
    "owner_adapter_hosted_runner_validated",
}
TRANSITION_KEYS = {
    "id", "source_mode", "target_mode", "caller_site", "observed",
}
RUNTIME_KEYS = {
    "current_mode", "manager_ticks", "direct3d7_dll_loaded", "create_method",
    "device_interface", "create_calls", "successful_create_calls",
    "last_create_hresult", "device_nonnull", "create_results",
}
CREATE_RESULT_KEYS = {"caller_site", "hresult", "device_nonnull"}
FRAME_KEYS = {
    "width", "height", "format", "sequence", "capture_surface",
    "conversion", "pixel_sha256", "changed_pixel_count",
    "captured_before_process_exit",
}
FRAME_PROOF_KEYS = {
    "owner_vm_only", "hosted_runner_validated",
    "web_pixel_comparison_performed", "independent_web_source_compared",
    "nine_dimension_release_evidence", "native_parity_evidence",
}
FRAME_TOP_KEYS = {
    "schema", "protocol", "capture_id", "source", "environment", "process",
    "input", "prerequisites", "transitions", "runtime", "frame",
    "proof_limits",
}


class OwnerVMFlightReceiptError(ValueError):
    """Raised when an owner-VM receipt is unbound, contradictory, or overclaims."""


class DuplicateKeyError(ValueError):
    """Raised when duplicate JSON keys would silently replace evidence."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


_STRICT_DECODER = json.JSONDecoder(object_pairs_hook=_unique_object)


def _decode(value: str, label: str) -> dict[str, Any]:
    try:
        decoded = _STRICT_DECODER.decode(value)
    except DuplicateKeyError as error:
        raise OwnerVMFlightReceiptError(
            f"duplicate JSON key in {label}"
        ) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OwnerVMFlightReceiptError(f"{label} is invalid JSON") from error
    if not isinstance(decoded, dict):
        raise OwnerVMFlightReceiptError(f"{label} must be an object")
    return decoded


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        return _decode(path.read_text(encoding="utf-8"), label)
    except (OSError, UnicodeDecodeError) as error:
        raise OwnerVMFlightReceiptError(f"cannot read {label}: {path}") from error


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise OwnerVMFlightReceiptError(f"{label} fields differ")
    return value


def _integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int | None = None
) -> int:
    if type(value) is not int or value < minimum or (
        maximum is not None and value > maximum
    ):
        upper = "" if maximum is None else f"..{maximum}"
        raise OwnerVMFlightReceiptError(f"{label} must be {minimum}{upper}")
    return value


def _boolean(value: Any, label: str, expected: bool | None = None) -> bool:
    if type(value) is not bool or (expected is not None and value is not expected):
        suffix = "" if expected is None else f"={expected}"
        raise OwnerVMFlightReceiptError(f"{label} must be boolean{suffix}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise OwnerVMFlightReceiptError(f"{label} is not a SHA-256")
    return value


def _commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_COMMIT.fullmatch(value) is None:
        raise OwnerVMFlightReceiptError(f"{label} is not a Git commit")
    return value


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise OwnerVMFlightReceiptError(
            f"{label} must be lowercase 0x + 8 hex digits"
        )
    return value


def _scan_code(value: Any, label: str) -> str:
    if not isinstance(value, str) or SCAN_CODE.fullmatch(value) is None:
        raise OwnerVMFlightReceiptError(
            f"{label} must be lowercase 0x + 2 hex digits"
        )
    return value


def _hresult(value: Any, label: str) -> str:
    if not isinstance(value, str) or HRESULT.fullmatch(value) is None:
        raise OwnerVMFlightReceiptError(
            f"{label} must be uppercase 0x + 8 hex digits"
        )
    return value


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise OwnerVMFlightReceiptError(f"cannot hash {path}") from error


def _source_and_environment(
    receipt: dict[str, Any],
    *,
    source_identity_path: Path,
    transition_contract_path: Path,
    expected_public_commit: str | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    source = _fields(receipt.get("source"), SOURCE_KEYS, "source")
    environment = _fields(
        receipt.get("environment"), ENVIRONMENT_KEYS, "environment"
    )
    process = _fields(receipt.get("process"), PROCESS_KEYS, "process")
    identity = _load(source_identity_path, "reviewed source identity")
    identity_iso = identity.get("iso")
    identity_executable = identity.get("executable")
    if (
        identity.get("schema") != 1
        or source["edition"] != identity.get("edition")
        or not isinstance(identity_iso, dict)
        or not isinstance(identity_executable, dict)
        or source["iso_sha256"] != identity_iso.get("sha256")
        or source["executable_sha256"] != identity_executable.get("sha256")
    ):
        raise OwnerVMFlightReceiptError(
            "receipt original media identity differs from reviewed source"
        )
    _sha256(source["iso_sha256"], "source.iso_sha256")
    _sha256(source["executable_sha256"], "source.executable_sha256")
    _sha256(
        source["transition_contract_sha256"],
        "source.transition_contract_sha256",
    )
    if source["transition_contract_sha256"] != _sha256_file(
        transition_contract_path
    ):
        raise OwnerVMFlightReceiptError("transition contract bytes drifted")
    _commit(source["public_source_commit"], "source.public_source_commit")
    if (
        expected_public_commit is not None
        and source["public_source_commit"] != expected_public_commit
    ):
        _commit(expected_public_commit, "reviewer expected public source commit")
        raise OwnerVMFlightReceiptError(
            "receipt public source commit differs from reviewer expectation"
        )
    _sha256(source["capture_tool_sha256"], "source.capture_tool_sha256")

    expected_environment = {
        "owner": "OWNER_PARALLELS_PRIVATE_VM",
        "guest": "WINDOWS_11",
        "architecture": "ARM64_HOST_X86_GAME",
        "audio": "VIRTUAL_OUTPUT_PRESENT",
        "renderer": "SOFTWARE",
    }
    if any(environment.get(key) != value for key, value in expected_environment.items()):
        raise OwnerVMFlightReceiptError(
            "owner-VM environment identity differs"
        )
    _boolean(environment["hosted_runner_validated"], "environment.hosted", False)

    _integer(process["pid"], "process.pid", minimum=1)
    if (
        process["image_name"] != "MulleMeck.exe"
        or process["architecture"] != "x86"
        or process["window_title"] != "Miel Monteur"
    ):
        raise OwnerVMFlightReceiptError("process identity differs")
    _boolean(process["before_alive"], "process.before_alive", True)
    _boolean(process["after_alive"], "process.after_alive", True)
    return source, environment, process


def _routes(path: Path, executable_sha256: str, edition: str) -> dict[str, Any]:
    contract = _load(path, "native transition contract")
    contract_source = contract.get("source")
    if (
        contract.get("schema") != 1
        or contract.get("contract_id") != TRANSITION_CONTRACT_ID
        or not isinstance(contract_source, dict)
        or contract_source.get("edition") != edition
        or contract_source.get("executable_sha256") != executable_sha256
    ):
        raise OwnerVMFlightReceiptError(
            "transition contract source identity differs"
        )
    edges = contract.get("edges")
    if not isinstance(edges, list):
        raise OwnerVMFlightReceiptError("transition edges are invalid")
    barn = [
        edge for edge in edges
        if isinstance(edge, dict) and edge.get("id") == "barn.mygghanget"
    ]
    if len(barn) != 1:
        raise OwnerVMFlightReceiptError("barn transition is not uniquely bound")
    locations = contract.get("location_edges")
    if not isinstance(locations, list):
        raise OwnerVMFlightReceiptError("location transition edges are invalid")
    departure = [
        row.get("departure") for row in locations
        if isinstance(row, dict) and row.get("location") == "mode_mygghanget"
    ]
    if len(departure) != 1 or not isinstance(departure[0], dict):
        raise OwnerVMFlightReceiptError("Mygghanget departure is not unique")
    predicates = contract.get("predicates")
    if not isinstance(predicates, dict):
        raise OwnerVMFlightReceiptError("transition predicates are invalid")
    return {
        "barn_mygghanget": barn[0],
        "mygghanget_flight": departure[0],
        "airplane_complete_predicate": predicates.get("airplane_complete"),
    }


def _validate_airplane_prerequisite(
    value: Any, routes: dict[str, Any]
) -> bool:
    state = _fields(value, ARROW_STATE_KEYS, "airplane prerequisite")
    if routes.get("airplane_complete_predicate") != AIRPLANE_COMPLETE_PREDICATE:
        raise OwnerVMFlightReceiptError(
            "reviewed airplane completion predicate drifted"
        )
    if (
        state["current_mode"] != "mode_barn"
        or state["pending_mode"] is not None
        or state["barn_view"] != 0
    ):
        raise OwnerVMFlightReceiptError(
            "airplane prerequisite is outside the reviewed outside-barn state"
        )
    airplane_complete = _boolean(
        state["airplane_complete"], "state.airplane_complete"
    )
    pointer = _boolean(
        state["airplane_pointer_nonnull"],
        "state.airplane_pointer_nonnull",
    )
    bits = _integer(
        state["airplane_completion_bits"],
        "state.airplane_completion_bits",
        maximum=0xFFFFFFFF,
    )
    exact_complete = pointer and bits == AIRPLANE_COMPLETE_BITS
    if airplane_complete is not exact_complete:
        raise OwnerVMFlightReceiptError(
            "airplane completion predicate disagrees with observed state"
        )
    return exact_complete


def _top(receipt: dict[str, Any], expected: set[str], protocol: str) -> None:
    _fields(receipt, expected, "receipt")
    if receipt.get("schema") != 1 or type(receipt.get("schema")) is not int:
        raise OwnerVMFlightReceiptError("schema must be integer 1")
    if receipt.get("protocol") != protocol:
        raise OwnerVMFlightReceiptError("receipt protocol differs")
    capture_id = receipt.get("capture_id")
    if not isinstance(capture_id, str) or CAPTURE_ID.fullmatch(capture_id) is None:
        raise OwnerVMFlightReceiptError("capture_id is invalid")


def validate_arrow_diagnostic(
    receipt: dict[str, Any],
    *,
    source_identity_path: Path = DEFAULT_SOURCE_IDENTITY,
    transition_contract_path: Path = DEFAULT_TRANSITIONS,
    expected_public_commit: str | None = None,
) -> dict[str, Any]:
    """Classify the owner's arrow observation and name its missing input proof."""

    _top(receipt, ARROW_TOP_KEYS, ARROW_PROTOCOL)
    source, environment, process = _source_and_environment(
        receipt,
        source_identity_path=source_identity_path,
        transition_contract_path=transition_contract_path,
        expected_public_commit=expected_public_commit,
    )
    routes = _routes(
        transition_contract_path,
        source["executable_sha256"],
        source["edition"],
    )
    input_value = _fields(receipt.get("input"), ARROW_INPUT_KEYS, "input")
    airplane_complete = _validate_airplane_prerequisite(
        receipt.get("state"), routes
    )
    proof = _fields(
        receipt.get("proof_limits"), ARROW_PROOF_KEYS, "proof_limits"
    )
    _sha256(input_value["adapter_sha256"], "input.adapter_sha256")
    _integer(input_value["adapter_record_bytes"], "input.record_bytes", minimum=1)
    if input_value["adapter_record_bytes"] != 16:
        raise OwnerVMFlightReceiptError(
            "owner DirectInput adapter record width differs"
        )
    if _hresult(
        input_value["system_directinput_create_hresult"],
        "input.system_directinput_create_hresult",
    ) != "0x80070057":
        raise OwnerVMFlightReceiptError(
            "owner-VM system DirectInput failure identity differs"
        )
    _boolean(
        input_value["owner_adapter_hosted_runner_validated"],
        "input.owner_adapter_hosted_runner_validated",
        False,
    )

    mouse = _fields(
        input_value["mouse_arrow_event"], MOUSE_EVENT_KEYS, "mouse event"
    )
    escape = _fields(
        input_value["escape_dispatch_event"], KEY_EVENT_KEYS, "escape event"
    )
    _integer(mouse["sequence"], "mouse.sequence", minimum=1)
    _integer(mouse["x"], "mouse.x", minimum=0, maximum=65535)
    _integer(mouse["y"], "mouse.y", minimum=0, maximum=65535)
    if (
        mouse["kind"] != "MOUSE_LEFT"
        or _boolean(mouse["arrow_highlighted"], "mouse.arrow_highlighted") is not True
        or _boolean(mouse["transition_observed"], "mouse.transition") is not False
    ):
        raise OwnerVMFlightReceiptError("mouse arrow observation differs")
    _integer(escape["sequence"], "escape.sequence", minimum=1)
    if escape["sequence"] <= mouse["sequence"]:
        raise OwnerVMFlightReceiptError("escape observation is not after arrow")
    if (
        escape["kind"] != "KEYBOARD_SCAN_CODE"
        or _scan_code(escape["scan_code"], "escape.scan_code") != "0x01"
    ):
        raise OwnerVMFlightReceiptError("escape scan-code identity differs")
    escape_dispatch = _boolean(
        escape["dispatch_observed"], "escape.dispatch_observed"
    )
    mode_set = _boolean(escape["mode_set_observed"], "escape.mode_set_observed")

    _boolean(proof["owner_vm_only"], "proof.owner_vm_only", True)
    _boolean(proof["native_transition_evidence"], "proof.transition", False)
    _boolean(proof["native_parity_evidence"], "proof.parity", False)

    if not airplane_complete:
        blocker = "AIRPLANE_COMPLETION_UNPROVEN"
    elif not escape_dispatch:
        blocker = "BARN_ESCAPE_DISPATCH_UNOBSERVED"
    elif not mode_set:
        blocker = "BARN_MYGGHANGET_MODE_SET_UNOBSERVED"
    else:
        blocker = "OWNER_VM_ARROW_INPUT_DISPATCH_CANDIDATE_ONLY"

    return {
        "schema": 1,
        "protocol": "miel-vliegt-owner-vm-arrow-diagnostic-result",
        "status": (
            "CANDIDATE_ONLY"
            if blocker == "OWNER_VM_ARROW_INPUT_DISPATCH_CANDIDATE_ONLY"
            else "BLOCKED"
        ),
        "blocker_code": blocker,
        "capture_id": receipt["capture_id"],
        "source_identities": {
            key: source[key] for key in sorted(SOURCE_KEYS)
        },
        "environment": environment,
        "process": process,
        "static_prerequisite": {
            "transition_id": routes["barn_mygghanget"]["id"],
            "source_mode": "mode_barn",
            "target_mode": "mode_mygghanget",
            "mode_set_callsite": routes["barn_mygghanget"]["address"],
            "outside_barn_view": 0,
            "airplane_predicate": AIRPLANE_COMPLETE_PREDICATE,
            "airplane_pointer_nonnull": airplane_complete,
            "airplane_completion_bits": (
                AIRPLANE_COMPLETE_BITS if airplane_complete else None
            ),
            "airplane_complete": airplane_complete,
        },
        "observed": {
            "mouse_arrow_highlighted": True,
            "mouse_mode_transition": False,
            "escape_dispatch": escape_dispatch,
            "barn_mygghanget_mode_set": mode_set,
        },
        "required_owner_handoff": {
            "state": {
                "current_mode": "mode_barn",
                "pending_mode": None,
                "barn_view": 0,
                "airplane_complete": True,
                "airplane_pointer_nonnull": True,
                "airplane_completion_bits": AIRPLANE_COMPLETE_BITS,
            },
            "input": {
                "kind": "KEYBOARD_SCAN_CODE",
                "scan_code": "0x01",
                "name": "DIK_ESCAPE",
                "delivery": "original barn input dispatch",
            },
        },
        "proof_limits": proof,
    }


def _validate_transition(
    value: Any, expected: dict[str, Any], label: str
) -> dict[str, Any]:
    record = _fields(value, TRANSITION_KEYS, label)
    allowed_sites = {expected["address"]}
    alternates = expected.get("alternate_addresses", [])
    if alternates:
        allowed_sites.update(alternates)
    if (
        record["id"] != expected["id"]
        or record["source_mode"] != expected["source"]
        or record["target_mode"] != expected["target"]
        or _hex32(record["caller_site"], f"{label}.caller_site")
        not in allowed_sites
        or _boolean(record["observed"], f"{label}.observed") is not True
    ):
        raise OwnerVMFlightReceiptError(f"{label} differs from static contract")
    return record


def validate_flight_frame(
    receipt: dict[str, Any],
    frame_path: Path,
    *,
    source_identity_path: Path = DEFAULT_SOURCE_IDENTITY,
    transition_contract_path: Path = DEFAULT_TRANSITIONS,
    expected_public_commit: str | None = None,
) -> dict[str, Any]:
    """Validate an identity-bound owner-VM Flight frame as candidate evidence."""

    _top(receipt, FRAME_TOP_KEYS, FRAME_PROTOCOL)
    source, environment, process = _source_and_environment(
        receipt,
        source_identity_path=source_identity_path,
        transition_contract_path=transition_contract_path,
        expected_public_commit=expected_public_commit,
    )
    routes = _routes(
        transition_contract_path,
        source["executable_sha256"],
        source["edition"],
    )
    airplane_complete = _validate_airplane_prerequisite(
        receipt.get("prerequisites"), routes
    )
    if not airplane_complete:
        raise OwnerVMFlightReceiptError(
            "Flight frame requires the exact reviewed airplane prerequisite"
        )
    input_value = _fields(receipt.get("input"), FRAME_INPUT_KEYS, "input")
    _sha256(input_value["adapter_sha256"], "input.adapter_sha256")
    if input_value["adapter_record_bytes"] != 16:
        raise OwnerVMFlightReceiptError(
            "owner DirectInput adapter record width differs"
        )
    if _hresult(
        input_value["system_directinput_create_hresult"],
        "input.system_directinput_create_hresult",
    ) != "0x80070057":
        raise OwnerVMFlightReceiptError(
            "owner-VM system DirectInput failure identity differs"
        )
    _boolean(
        input_value["owner_adapter_hosted_runner_validated"],
        "input.owner_adapter_hosted_runner_validated",
        False,
    )
    _integer(
        input_value["directinput_getdevicedata_events"],
        "input.getdevicedata_events",
        minimum=1,
    )
    _boolean(input_value["login_submit_observed"], "input.login", True)
    _boolean(input_value["barn_escape_observed"], "input.escape", True)
    if _scan_code(
        input_value["faster_key_scan_code"], "input.faster_key_scan_code"
    ) not in FASTER_KEY_SCAN_CODES:
        raise OwnerVMFlightReceiptError("faster key is not in reviewed contract")
    _boolean(
        input_value["faster_key_held_until_departure"],
        "input.faster_key_held",
        True,
    )

    raw_transitions = receipt.get("transitions")
    if not isinstance(raw_transitions, list) or len(raw_transitions) != 2:
        raise OwnerVMFlightReceiptError("Flight frame transition set differs")
    expected_transitions = {
        "barn.mygghanget": {
            "id": routes["barn_mygghanget"]["id"],
            "source": routes["barn_mygghanget"]["source"],
            "target": routes["barn_mygghanget"]["target"],
            "address": routes["barn_mygghanget"]["address"],
        },
        "location.departure.mode_mygghanget": {
            "id": routes["mygghanget_flight"]["id"],
            "source": routes["mygghanget_flight"]["source"],
            "target": routes["mygghanget_flight"]["target"],
            "address": routes["mygghanget_flight"]["address"],
            "alternate_addresses": routes["mygghanget_flight"].get(
                "alternate_addresses", []
            ),
        },
    }
    if [row.get("id") for row in raw_transitions] != list(expected_transitions):
        raise OwnerVMFlightReceiptError("Flight frame transition identities differ")
    transitions = [
        _validate_transition(
            record, expected_transitions[record["id"]], f"transition[{index}]"
        )
        for index, record in enumerate(raw_transitions)
    ]

    runtime = _fields(receipt.get("runtime"), RUNTIME_KEYS, "runtime")
    manager_ticks = _integer(
        runtime["manager_ticks"], "runtime.manager_ticks", minimum=1
    )
    create_calls = _integer(runtime["create_calls"], "runtime.create_calls", minimum=1)
    successful_calls = _integer(
        runtime["successful_create_calls"],
        "runtime.successful_create_calls",
        minimum=0,
    )
    if runtime["current_mode"] != "mode_fly":
        raise OwnerVMFlightReceiptError(
            "Direct3D7 device creation evidence is incomplete"
        )
    create_results = runtime["create_results"]
    if not isinstance(create_results, list) or len(create_results) != create_calls:
        raise OwnerVMFlightReceiptError("Direct3D7 result count differs")
    normalized_results = []
    for index, result in enumerate(create_results):
        row = _fields(result, CREATE_RESULT_KEYS, f"runtime.create_results[{index}]")
        normalized_results.append({
            "caller_site": _hex32(
                row["caller_site"], f"runtime.create_results[{index}].caller_site"
            ),
            "hresult": _hresult(
                row["hresult"], f"runtime.create_results[{index}].hresult"
            ),
            "device_nonnull": _boolean(
                row["device_nonnull"],
                f"runtime.create_results[{index}].device_nonnull",
            ),
        })
    observed_successes = sum(
        row["hresult"] == "0x00000000" and row["device_nonnull"]
        for row in normalized_results
    )
    if (
        successful_calls < 1
        or successful_calls != observed_successes
        or not normalized_results
        or normalized_results[-1]["hresult"] != "0x00000000"
        or not normalized_results[-1]["device_nonnull"]
        or runtime["create_method"] != "IDirect3D7::CreateDevice"
        or runtime["device_interface"] != "IID_IDirect3DDevice7"
        or _hresult(runtime["last_create_hresult"], "runtime.hresult")
        != normalized_results[-1]["hresult"]
        or _boolean(runtime["device_nonnull"], "runtime.device_nonnull") is not True
    ):
        raise OwnerVMFlightReceiptError(
            "Direct3D7 device creation evidence is incomplete"
        )
    for row in normalized_results:
        if row["caller_site"] == "0x00000000":
            raise OwnerVMFlightReceiptError(
                "Direct3D7 device creation evidence is incomplete"
            )
    if _boolean(runtime["direct3d7_dll_loaded"], "runtime.dll_loaded") is not True:
        raise OwnerVMFlightReceiptError(
            "Direct3D7 device creation evidence is incomplete"
        )

    frame = _fields(receipt.get("frame"), FRAME_KEYS, "frame")
    frame_width = _integer(
        frame["width"], "frame.width", minimum=1, maximum=MAX_FRAME_DIMENSION
    )
    frame_height = _integer(
        frame["height"], "frame.height", minimum=1, maximum=MAX_FRAME_DIMENSION
    )
    if (
        frame["format"] != "RGBA8"
        or frame["capture_surface"] != "ORIGINAL_WINDOW_CLIENT"
        or frame["conversion"] != "CANONICAL_RGBA8_EXACT"
        or _boolean(
            frame["captured_before_process_exit"], "frame.before_exit", True
        ) is not True
    ):
        raise OwnerVMFlightReceiptError("frame capture contract differs")
    _integer(frame["sequence"], "frame.sequence", minimum=1)
    _sha256(frame["pixel_sha256"], "frame.pixel_sha256")
    changed = _integer(
        frame["changed_pixel_count"],
        "frame.changed_pixel_count",
        minimum=1,
        maximum=frame_width * frame_height,
    )
    if frame_path.is_symlink():
        raise OwnerVMFlightReceiptError("frame path may not be a symlink")
    try:
        pixels = frame_path.read_bytes()
    except OSError as error:
        raise OwnerVMFlightReceiptError("cannot read frame bytes") from error
    expected_bytes = frame_width * frame_height * 4
    if len(pixels) != expected_bytes:
        raise OwnerVMFlightReceiptError("frame dimensions do not match byte count")
    if hashlib.sha256(pixels).hexdigest() != frame["pixel_sha256"]:
        raise OwnerVMFlightReceiptError("frame bytes drifted from declared identity")
    samples = {pixels[index:index + 4] for index in range(0, len(pixels), 4)}
    if len(samples) < 2:
        raise OwnerVMFlightReceiptError("frame bytes contain no actual pixel variation")

    proof = _fields(
        receipt.get("proof_limits"), FRAME_PROOF_KEYS, "proof_limits"
    )
    _boolean(proof["owner_vm_only"], "proof.owner_vm_only", True)
    for field in FRAME_PROOF_KEYS - {"owner_vm_only"}:
        _boolean(proof[field], f"proof.{field}", False)

    return {
        "schema": 1,
        "protocol": "miel-vliegt-owner-vm-native-flight-frame-result",
        "status": "NATIVE_OWNER_VM_FLIGHT_FRAME_CANDIDATE_ONLY",
        "capture_id": receipt["capture_id"],
        "source_identities": {
            key: source[key] for key in sorted(SOURCE_KEYS)
        },
        "environment": environment,
        "process": process,
        "input": input_value,
        "prerequisites": {
            "current_mode": "mode_barn",
            "pending_mode": None,
            "barn_view": 0,
            "airplane_complete": True,
            "airplane_pointer_nonnull": True,
            "airplane_completion_bits": AIRPLANE_COMPLETE_BITS,
        },
        "transitions": transitions,
        "runtime": {
            "current_mode": "mode_fly",
            "manager_ticks": manager_ticks,
            "direct3d7_dll_loaded": True,
            "create_method": runtime["create_method"],
            "create_calls": create_calls,
            "successful_create_calls": successful_calls,
            "last_create_hresult": runtime["last_create_hresult"],
            "device_nonnull": True,
            "create_results": normalized_results,
        },
        "frame": {
            "width": frame_width,
            "height": frame_height,
            "format": "RGBA8",
            "sequence": frame["sequence"],
            "pixel_sha256": frame["pixel_sha256"],
            "changed_pixel_count": changed,
            "byte_count": len(pixels),
        },
        "proof_limits": proof,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--frame", type=Path)
    parser.add_argument("--receipt-type", choices=("arrow", "flight-frame"))
    parser.add_argument("--source-identity", type=Path, default=DEFAULT_SOURCE_IDENTITY)
    parser.add_argument("--transitions", type=Path, default=DEFAULT_TRANSITIONS)
    parser.add_argument("--expected-public-commit")
    args = parser.parse_args()
    if not args.receipt_type:
        parser.error("--receipt-type is required")
    receipt = _load(args.receipt, "owner-VM receipt")
    if args.receipt_type == "arrow":
        if args.frame is not None:
            parser.error("arrow diagnostics do not use --frame")
        result = validate_arrow_diagnostic(
            receipt,
            source_identity_path=args.source_identity,
            transition_contract_path=args.transitions,
            expected_public_commit=args.expected_public_commit,
        )
    else:
        if args.frame is None:
            parser.error("flight-frame requires --frame")
        result = validate_flight_frame(
            receipt,
            args.frame,
            source_identity_path=args.source_identity,
            transition_contract_path=args.transitions,
            expected_public_commit=args.expected_public_commit,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
