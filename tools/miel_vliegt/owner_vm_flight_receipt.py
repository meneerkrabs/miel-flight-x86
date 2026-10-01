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
import stat
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_IDENTITY = ROOT / "content/miel_vliegt/source_identity.json"
DEFAULT_TRANSITIONS = ROOT / "content/miel_vliegt/native_scene_transitions.json"
DEFAULT_OBSERVER_HOOK = (
    ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
)
ARROW_PROTOCOL = "miel-vliegt-owner-vm-arrow-diagnostic"
FRAME_PROTOCOL = "miel-vliegt-owner-vm-native-flight-frame"
TRANSITION_CONTRACT_ID = "miel-vliegt-native-scene-transitions-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
HEX32 = re.compile(r"^0x[0-9a-f]{8}$")
SCAN_CODE = re.compile(r"^0x[0-9a-f]{2}$")
HRESULT = re.compile(r"^0x[0-9A-F]{8}$")
CAPTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MODULE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Public native observation measured 640x457; the owner bridge's input
# coordinate contract is a 640x480 game client.
FRAME_CLIENT_GEOMETRIES = frozenset({(640, 457), (640, 480)})
ARROW_CLIENT_WIDTH = 640
ARROW_CLIENT_HEIGHT = 480
FASTER_KEY_SCAN_CODES = frozenset({"0x2a", "0x36", "0x4e"})
AIRPLANE_COMPLETE_BITS = 0x1FF
AIRPLANE_POINTER_OFFSET = 0x160
AIRPLANE_COMPLETION_OFFSET = 0x128
AIRPLANE_COMPLETE_PREDICATE = (
    "barn.airplane(+0x160).completion(+0x128) == 0x1ff"
)
BARN_LIFECYCLE = re.compile(
    r'\{"barn",\s*"mode_barn",\s*(0x[0-9a-f]{8})u'
)

SOURCE_KEYS = {
    "edition", "iso_sha256", "executable_sha256",
    "transition_contract_sha256", "public_source_commit",
    "public_source_tree", "validator_source_blob", "source_identity_blob",
    "observer_hook_blob", "transition_contract_blob", "capture_tool_sha256",
}
ENVIRONMENT_KEYS = {
    "owner", "guest", "architecture", "audio", "wave_out_devices",
    "audio_service_ready", "renderer",
    "hosted_runner_validated",
}
PROCESS_KEYS = {
    "pid", "image_name", "architecture", "window_title", "before_alive",
    "after_alive",
}
ARROW_INPUT_KEYS = {
    "adapter_sha256", "adapter_record_bytes",
    "directinput_getdevicedata_events", "getdevicedata_capture_id",
    "getdevicedata_process_id", "getdevicedata_image_name",
    "getdevicedata_record_format", "getdevicedata_stream_byte_count",
    "getdevicedata_stream_sha256", "mouse_arrow_event",
    "escape_dispatch_event", "system_directinput_create_hresult",
    "owner_adapter_hosted_runner_validated",
}
MOUSE_EVENT_KEYS = {
    "sequence", "manager_tick", "kind", "x", "y", "arrow_highlighted",
    "transition_observed",
}
KEY_EVENT_KEYS = {
    "sequence", "manager_tick", "kind", "scan_code", "dispatch_observed",
    "mode_set_observed",
}
ARROW_STATE_KEYS = {
    "capture_id", "process_id", "image_name", "manager_tick",
    "manager_ticks", "manager_pointer",
    "application_pointer", "airplane_pointer",
    "airplane_completion_pointer", "input_context_pointer",
    "cursor_pointer", "cursor_x", "cursor_y",
    "current_mode", "current_mode_pointer", "current_mode_vtable",
    "mode_loaded", "mode_opened", "pending_mode", "barn_view",
    "airplane_complete",
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
    "getdevicedata_capture_id", "getdevicedata_process_id",
    "getdevicedata_image_name",
    "getdevicedata_record_format", "getdevicedata_stream_byte_count",
    "getdevicedata_stream_sha256",
    "login_submit_manager_tick", "login_submit_event_id",
    "barn_escape_observed", "barn_escape_manager_tick",
    "barn_escape_event_id", "faster_key_scan_code",
    "faster_key_down_manager_tick", "faster_key_down_event_id",
    "faster_key_up_manager_tick", "faster_key_up_event_id",
    "faster_key_held_until_departure", "system_directinput_create_hresult",
    "owner_adapter_hosted_runner_validated",
}
TRANSITION_KEYS = {
    "capture_id", "process_id", "image_name", "id", "source_mode",
    "target_mode", "caller_site", "manager_tick", "observed",
}
RUNTIME_MEDIA_KEYS = {
    "measurement_capture_id", "measured_process_id", "measured_image_name",
    "iso_sha256", "executable_sha256", "measurement_method",
    "measurement_tool_sha256", "measurement_complete",
}
RUNTIME_KEYS = {
    "capture_id", "process_id", "image_name", "current_mode",
    "manager_pointer", "manager_ticks", "direct3d7_dll_loaded", "create_method",
    "direct3d7_load_manager_tick", "direct3d7_module",
    "direct3d7_module_sha256", "device_interface", "create_calls",
    "successful_create_calls", "last_create_hresult", "device_nonnull",
    "create_results",
}
CREATE_RESULT_KEYS = {
    "capture_id", "process_id", "image_name", "caller_module",
    "caller_module_sha256", "caller_address_kind", "caller_site",
    "manager_tick", "hresult", "device_nonnull",
}
FRAME_KEYS = {
    "width", "height", "capture_id", "process_id", "image_name", "format",
    "capture_tool_sha256", "sequence", "manager_tick", "capture_surface",
    "conversion", "pixel_sha256", "changed_pixel_count",
    "captured_before_process_exit",
}
FRAME_PROOF_KEYS = {
    "owner_vm_only", "hosted_runner_validated",
    "independent_runtime_media_hash", "web_pixel_comparison_performed",
    "independent_web_source_compared", "nine_dimension_release_evidence",
    "native_parity_evidence",
}
FRAME_TOP_KEYS = {
    "schema", "protocol", "capture_id", "source", "environment", "process",
    "input", "runtime_media", "prerequisites", "transitions", "runtime",
    "frame", "proof_limits",
}
BRIDGE_STATE_KEYS = {
    "ProcessId", "Application", "Manager", "CurrentMode", "CurrentVtable",
    "PendingMode", "Loaded", "Opened", "BarnView", "InputContext",
    "CursorObject", "CursorX", "CursorY",
}
BRIDGE_CLICK_KEYS = {
    "target", "delta", "cursorBefore", "cursorAfter", "barnViewBefore",
    "barnViewAfter", "openedBefore", "openedAfter", "injectionSeen",
}
BRIDGE_HEALTH_KEYS = {"ok", "service", "vm"}
BRIDGE_PROOF_KEYS = {
    "airplane_completion_evidence", "native_flight_transition",
    "direct3d7_device_evidence", "runtime_original_media_match",
    "native_parity_evidence",
}
BRIDGE_PROCESS_FIELDS = (
    "ProcessId", "Application", "Manager", "CurrentMode", "CurrentVtable",
    "InputContext", "CursorObject", "PendingMode", "Loaded", "Opened",
)


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


def _module_name(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or MODULE_NAME.fullmatch(value) is None
        or Path(value).name != value
    ):
        raise OwnerVMFlightReceiptError(f"{label} is not a module filename")
    return value


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise OwnerVMFlightReceiptError(f"cannot hash {path}") from error


def _git_output(arguments: list[str]) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *arguments],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise OwnerVMFlightReceiptError(
            "receipt public source revision is unavailable"
        ) from error


def _git_blob_bytes(object_id: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "blob", object_id],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise OwnerVMFlightReceiptError(
            "receipt public source revision is unavailable"
        ) from error


def _validator_source_bytes() -> bytes:
    try:
        return Path(__file__).read_bytes()
    except OSError as error:
        raise OwnerVMFlightReceiptError(
            "cannot read executing validator source"
        ) from error


def load_bridge_success(raw: str, requested: str) -> dict[str, Any]:
    """Select exactly one successful bounded bridge record from stdout."""

    records: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(raw):
        while cursor < len(raw) and raw[cursor].isspace():
            cursor += 1
        if cursor == len(raw):
            break
        try:
            value, cursor = _STRICT_DECODER.raw_decode(raw, cursor)
        except DuplicateKeyError as error:
            raise OwnerVMFlightReceiptError(
                "duplicate JSON key in bridge output"
            ) from error
        except json.JSONDecodeError as error:
            raise OwnerVMFlightReceiptError(
                "bridge output is not canonical JSON records"
            ) from error
        if not isinstance(value, dict) or type(value.get("ok")) is not bool:
            raise OwnerVMFlightReceiptError("bridge record shape differs")
        records.append(value)
    matches = [
        record for record in records
        if record["ok"] is True and requested in record
    ]
    if len(matches) != 1:
        raise OwnerVMFlightReceiptError(
            f"bridge output must contain exactly one success record for {requested}"
        )
    return matches[0]


def _observer_barn_vtable(path: Path) -> tuple[str, str]:
    try:
        raw = path.read_bytes()
        source = raw.decode(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise OwnerVMFlightReceiptError(
            "cannot read public observer source"
        ) from error
    if (
        path.absolute() != DEFAULT_OBSERVER_HOOK.absolute()
        and raw != DEFAULT_OBSERVER_HOOK.read_bytes()
    ):
        raise OwnerVMFlightReceiptError(
            "public observer hook bytes differ"
        )
    matches = BARN_LIFECYCLE.findall(source)
    if len(matches) != 1:
        raise OwnerVMFlightReceiptError(
            "public observer barn lifecycle is not uniquely bound"
        )
    return matches[0], hashlib.sha256(raw).hexdigest()


def _observer_hook_bytes() -> bytes:
    try:
        return DEFAULT_OBSERVER_HOOK.read_bytes()
    except OSError as error:
        raise OwnerVMFlightReceiptError(
            "cannot read public observer source"
        ) from error


def _bridge_state(value: Any) -> dict[str, Any]:
    state = _fields(value, BRIDGE_STATE_KEYS, "bridge state")
    for field in (
        "ProcessId", "Application", "Manager", "CurrentMode",
        "CursorObject",
    ):
        _integer(state[field], f"bridge state.{field}", minimum=1)
    if state["InputContext"] != state["Application"]:
        raise OwnerVMFlightReceiptError("bridge input context differs")
    if state["PendingMode"] != 0:
        raise OwnerVMFlightReceiptError("bridge state is not mode-settled")
    for field in ("Loaded", "Opened"):
        _integer(state[field], f"bridge state.{field}", minimum=0)
        if state[field] != 1:
            raise OwnerVMFlightReceiptError(
                f"bridge mode is not loaded and open: {field}"
            )
    barn_view = _integer(state["BarnView"], "bridge state.BarnView")
    if barn_view not in (0, 1):
        raise OwnerVMFlightReceiptError("bridge BarnView is invalid")
    _integer(state["CursorX"], "bridge state.CursorX", maximum=639)
    _integer(state["CursorY"], "bridge state.CursorY", maximum=479)
    return state


def _bridge_point(value: Any, label: str) -> list[int]:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(type(coordinate) is not int for coordinate in value)
    ):
        raise OwnerVMFlightReceiptError(f"{label} must be an integer pair")
    if not (0 <= value[0] <= 639 and 0 <= value[1] <= 479):
        raise OwnerVMFlightReceiptError(f"{label} is outside the game client")
    return value


def _bridge_click(value: Any) -> dict[str, Any]:
    click = _fields(value, BRIDGE_CLICK_KEYS, "bridge click")
    target = _bridge_point(click["target"], "click.target")
    delta = click["delta"]
    before = _bridge_point(click["cursorBefore"], "click.cursorBefore")
    after = _bridge_point(click["cursorAfter"], "click.cursorAfter")
    if (
        not isinstance(delta, list)
        or len(delta) != 2
        or any(type(offset) is not int for offset in delta)
        or after != target
        or [before[0] + delta[0], before[1] + delta[1]] != target
    ):
        raise OwnerVMFlightReceiptError("click geometry differs")
    barn_before = _integer(click["barnViewBefore"], "click.barnViewBefore")
    barn_after = _integer(click["barnViewAfter"], "click.barnViewAfter")
    opened_before = _integer(click["openedBefore"], "click.openedBefore")
    opened_after = _integer(click["openedAfter"], "click.openedAfter")
    if (
        barn_before not in (0, 1)
        or barn_after not in (0, 1)
        or opened_before != 1
        or opened_after != 1
        or _boolean(click["injectionSeen"], "click.injectionSeen") is not True
    ):
        raise OwnerVMFlightReceiptError("click state or injection differs")
    return {
        "target": target,
        "delta": delta,
        "cursor_before": before,
        "cursor_after": after,
        "barn_view_before": barn_before,
        "barn_view_after": barn_after,
        "opened_before": opened_before,
        "opened_after": opened_after,
        "injection_seen": True,
    }


def validate_bridge_observation(
    payload: dict[str, Any],
    *,
    observer_hook_path: Path = DEFAULT_OBSERVER_HOOK,
) -> dict[str, Any]:
    """Bind one bounded owner-VM bridge record without promoting it."""

    barn_vtable, observer_source_sha256 = _observer_barn_vtable(
        observer_hook_path
    )
    proof_limits = {key: False for key in BRIDGE_PROOF_KEYS}
    common = {
        "schema": 1,
        "protocol": "miel-vliegt-owner-vm-bridge-observation-result",
        "observer_hook_sha256": observer_source_sha256,
        "barn_mode_vtable": barn_vtable,
        "proof_limits": proof_limits,
    }
    if set(payload) == {"ok", "state"}:
        if payload["ok"] is not True:
            raise OwnerVMFlightReceiptError("bridge observation failed")
        state = _bridge_state(payload["state"])
        if state["CurrentVtable"] != barn_vtable:
            raise OwnerVMFlightReceiptError(
                "live current vtable differs from public barn vtable"
            )
        return {
            **common,
            "status": "NATIVE_OWNER_VM_BARN_STATE_DIAGNOSTIC_ONLY",
            "state": state,
        }
    if set(payload) == {"ok", "click"}:
        if payload["ok"] is not True:
            raise OwnerVMFlightReceiptError("bridge observation failed")
        click = _bridge_click(payload["click"])
        if (
            click["barn_view_before"] == 0
            and click["barn_view_after"] == 1
        ):
            status = "NATIVE_OWNER_VM_BARN_DOOR_NAVIGATION_CANDIDATE_ONLY"
        elif (
            click["barn_view_before"] == 1
            and click["barn_view_after"] == 0
        ):
            status = "NATIVE_OWNER_VM_BARN_OUTSIDE_RESTORE_CANDIDATE_ONLY"
        else:
            status = "NATIVE_OWNER_VM_BARN_CLICK_DIAGNOSTIC_ONLY"
        return {**common, "status": status, "click": click}
    raise OwnerVMFlightReceiptError("bridge success record fields differ")


def validate_bridge_health(value: Any) -> dict[str, str]:
    """Bind bridge evidence to the reviewed bounded service identity."""

    health = _fields(value, BRIDGE_HEALTH_KEYS, "bridge health")
    _boolean(health["ok"], "bridge health.ok", True)
    if (
        health["service"] != "flight-vm-bridge"
        or health["vm"] != "Windows 11"
    ):
        raise OwnerVMFlightReceiptError(
            "bridge service or VM identity differs"
        )
    return {"service": health["service"], "vm": health["vm"]}


def _load_source_identity(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        identity = _decode(
            raw.decode(encoding="utf-8"), "reviewed source identity"
        )
    except (OSError, UnicodeDecodeError) as error:
        raise OwnerVMFlightReceiptError(
            f"cannot read reviewed source identity: {path}"
        ) from error
    return identity, raw


def _reviewed_media_and_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
    identity, raw = _load_source_identity(path)
    if identity.get("schema") != 1:
        raise OwnerVMFlightReceiptError("reviewed source identity differs")
    media = {}
    for section in ("iso", "executable"):
        record = identity.get(section)
        if (
            not isinstance(record, dict)
            or set(record) != {"filename", "sha256"}
            or not isinstance(record["filename"], str)
            or not record["filename"]
        ):
            raise OwnerVMFlightReceiptError(
                f"reviewed {section} identity differs"
            )
        _sha256(record["sha256"], f"reviewed {section}.sha256")
        media[section] = dict(record)
    if not isinstance(identity.get("edition"), str) or not identity["edition"]:
        raise OwnerVMFlightReceiptError("reviewed edition identity differs")
    reviewed = {
        "edition": identity["edition"],
        "iso": media["iso"],
        "executable": media["executable"],
    }
    if path.absolute() != DEFAULT_SOURCE_IDENTITY.absolute():
        expected, expected_raw = _reviewed_media_and_bytes(
            DEFAULT_SOURCE_IDENTITY
        )
        if reviewed != expected:
            raise OwnerVMFlightReceiptError(
                "reviewed original media identity differs"
            )
        if raw != expected_raw:
            raise OwnerVMFlightReceiptError(
                "reviewed source identity bytes differ"
            )
    return reviewed, raw


def _reviewed_media(path: Path) -> dict[str, Any]:
    return _reviewed_media_and_bytes(path)[0]


def classify_bridge_state(
    health_payload: dict[str, Any],
    state_payload: dict[str, Any],
    *,
    source_identity_path: Path = DEFAULT_SOURCE_IDENTITY,
    transition_contract_path: Path = DEFAULT_TRANSITIONS,
) -> dict[str, Any]:
    """Turn one bounded bridge state into the exact missing owner step."""

    reviewed_media, source_identity_raw = _reviewed_media_and_bytes(
        source_identity_path
    )
    routes, transition_contract_sha256 = _routes(
        transition_contract_path,
        reviewed_media["executable"]["sha256"],
        reviewed_media["edition"],
    )
    barn_callsite = _hex32(
        routes["barn_mygghanget"]["address"],
        "barn transition callsite",
    )
    health = validate_bridge_health(health_payload)
    observation = validate_bridge_observation(state_payload)
    state = observation["state"]
    if state["BarnView"] == 1:
        blocker = "OWNER_VM_BARN_OUTSIDE_RESTORE_PENDING"
        handoff = {
            "restore": "outside BarnView 0",
            "prohibited_repeat_click": [450, 150],
        }
    else:
        blocker = "AIRPLANE_COMPLETION_AND_ESCAPE_INPUT_PENDING"
        handoff = {
            "state": {
                "capture_id": "owner-generated valid capture ID",
                "process_id": state["ProcessId"],
                "image_name": "MulleMeck.exe",
                "manager_tick": "positive integer <= manager_ticks",
                "manager_ticks": (
                    "positive integer >= prerequisite, arrow, and Escape ticks"
                ),
                "manager_pointer": state["Manager"],
                "application_pointer": state["Application"],
                "input_context_pointer": state["InputContext"],
                "airplane_pointer": (
                    state["Application"] + AIRPLANE_POINTER_OFFSET
                ),
                "airplane_completion_pointer": (
                    state["Application"]
                    + AIRPLANE_POINTER_OFFSET
                    + AIRPLANE_COMPLETION_OFFSET
                ),
                "cursor_pointer": state["CursorObject"],
                "cursor_x": state["CursorX"],
                "cursor_y": state["CursorY"],
                "current_mode": "mode_barn",
                "current_mode_pointer": state["CurrentMode"],
                "current_mode_vtable": observation["barn_mode_vtable"],
                "mode_loaded": True,
                "mode_opened": True,
                "pending_mode": None,
                "barn_view": 0,
                "airplane_complete": True,
                "airplane_pointer_nonnull": True,
                "airplane_completion_bits": AIRPLANE_COMPLETE_BITS,
            },
            "input_stream": {
                "capture_id": "same as the airplane state capture",
                "process_id": state["ProcessId"],
                "image_name": "MulleMeck.exe",
                "record_format": "DIRECTINPUT_BUFFERED_16_BYTE_LE",
                "event_count": "positive integer",
                "stream_byte_count": "event_count * 16",
                "stream_sha256": "SHA-256 of the private raw stream",
                "mouse_arrow_event_id": "1..event_count",
                "escape_dispatch_event_id": (
                    "later than the mouse event ID"
                ),
            },
            "airplane_pointer_nonnull": True,
            "airplane_completion_bits": AIRPLANE_COMPLETE_BITS,
            "escape_scan_code": "0x01",
            "escape_delivery": "original barn input dispatch",
            "barn_to_mygghanget_callsite": barn_callsite,
        }
    return {
        "schema": 1,
        "protocol": "miel-vliegt-owner-vm-bridge-state-result",
        "status": "BLOCKED",
        "blocker_code": blocker,
        "bridge_environment": health,
        "reviewed_media": reviewed_media,
        "source_identity_sha256": hashlib.sha256(
            source_identity_raw
        ).hexdigest(),
        "transition_contract_sha256": transition_contract_sha256,
        "observer_hook_sha256": observation["observer_hook_sha256"],
        "barn_mode_vtable": observation["barn_mode_vtable"],
        "process_id": state["ProcessId"],
        "state": {
            "barn_view": state["BarnView"],
            "cursor": [state["CursorX"], state["CursorY"]],
        },
        "required_owner_handoff": handoff,
        "proof_limits": {key: False for key in BRIDGE_PROOF_KEYS},
    }


def validate_bridge_sequence(
    before_payload: dict[str, Any],
    click_payload: dict[str, Any],
    after_payload: dict[str, Any],
    *,
    observer_hook_path: Path = DEFAULT_OBSERVER_HOOK,
) -> dict[str, Any]:
    """Bind one click to a single live before/after bridge process."""

    before_result = validate_bridge_observation(
        before_payload, observer_hook_path=observer_hook_path
    )
    click_result = validate_bridge_observation(
        click_payload, observer_hook_path=observer_hook_path
    )
    after_result = validate_bridge_observation(
        after_payload, observer_hook_path=observer_hook_path
    )
    if len({
        before_result["observer_hook_sha256"],
        click_result["observer_hook_sha256"],
        after_result["observer_hook_sha256"],
    }) != 1:
        raise OwnerVMFlightReceiptError(
            "observer hook revision drifted across bridge sequence"
        )
    before = before_result["state"]
    click = click_result["click"]
    after = after_result["state"]
    if (
        before_result["status"]
        != "NATIVE_OWNER_VM_BARN_STATE_DIAGNOSTIC_ONLY"
        or after_result["status"]
        != "NATIVE_OWNER_VM_BARN_STATE_DIAGNOSTIC_ONLY"
    ):
        raise OwnerVMFlightReceiptError("bridge sequence kinds differ")
    if click_result["status"] == (
        "NATIVE_OWNER_VM_BARN_DOOR_NAVIGATION_CANDIDATE_ONLY"
    ):
        sequence_status = (
            "NATIVE_OWNER_VM_BARN_DOOR_SEQUENCE_CANDIDATE_ONLY"
        )
    elif click_result["status"] == (
        "NATIVE_OWNER_VM_BARN_OUTSIDE_RESTORE_CANDIDATE_ONLY"
    ):
        sequence_status = (
            "NATIVE_OWNER_VM_BARN_OUTSIDE_RESTORE_SEQUENCE_CANDIDATE_ONLY"
        )
    else:
        raise OwnerVMFlightReceiptError("bridge sequence kinds differ")
    for field in BRIDGE_PROCESS_FIELDS:
        if before[field] != after[field]:
            raise OwnerVMFlightReceiptError(
                "bridge process identity drifted across click"
            )
    if (
        [before["CursorX"], before["CursorY"]] != click["cursor_before"]
        or before["BarnView"] != click["barn_view_before"]
    ):
        raise OwnerVMFlightReceiptError("pre-click state disagrees with click")
    if (
        [after["CursorX"], after["CursorY"]] != click["cursor_after"]
        or after["BarnView"] != click["barn_view_after"]
    ):
        raise OwnerVMFlightReceiptError(
            "post-click state disagrees with click"
        )
    return {
        "schema": 1,
        "protocol": "miel-vliegt-owner-vm-bridge-sequence-result",
        "status": sequence_status,
        "observer_hook_sha256": before_result["observer_hook_sha256"],
        "barn_mode_vtable": before_result["barn_mode_vtable"],
        "process_id": before["ProcessId"],
        "before": {
            "barn_view": before["BarnView"],
            "cursor": [before["CursorX"], before["CursorY"]],
        },
        "after": {
            "barn_view": after["BarnView"],
            "cursor": [after["CursorX"], after["CursorY"]],
        },
        "proof_limits": {key: False for key in BRIDGE_PROOF_KEYS},
    }


def _source_and_environment(
    receipt: dict[str, Any],
    *,
    source_identity_path: Path,
    expected_public_commit: str | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    source = _fields(receipt.get("source"), SOURCE_KEYS, "source")
    environment = _fields(
        receipt.get("environment"), ENVIRONMENT_KEYS, "environment"
    )
    process = _fields(receipt.get("process"), PROCESS_KEYS, "process")
    identity, identity_raw = _load_source_identity(source_identity_path)
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
    if (
        source_identity_path.absolute() != DEFAULT_SOURCE_IDENTITY.absolute()
        and (
            identity,
            identity_raw,
        ) != _load_source_identity(DEFAULT_SOURCE_IDENTITY)
    ):
        raise OwnerVMFlightReceiptError(
            "reviewed source identity bytes differ"
        )
    _sha256(source["iso_sha256"], "source.iso_sha256")
    _sha256(source["executable_sha256"], "source.executable_sha256")
    _sha256(
        source["transition_contract_sha256"],
        "source.transition_contract_sha256",
    )
    public_commit = _commit(
        source["public_source_commit"], "source.public_source_commit"
    )
    if (
        expected_public_commit is not None
        and public_commit != expected_public_commit
    ):
        _commit(expected_public_commit, "reviewer expected public source commit")
        raise OwnerVMFlightReceiptError(
            "receipt public source commit differs from reviewer expectation"
        )
    for field in (
        "public_source_tree", "validator_source_blob",
        "observer_hook_blob", "source_identity_blob", "transition_contract_blob",
    ):
        _commit(source[field], f"source.{field}")
    if _git_output(["cat-file", "-t", public_commit]) != "commit":
        raise OwnerVMFlightReceiptError(
            "receipt public source revision is not a commit"
        )
    expected_objects = {
        "public_source_tree": _git_output(
            ["rev-parse", f"{public_commit}^{{tree}}"]
        ),
        "validator_source_blob": _git_output(
            [
                "rev-parse",
                f"{public_commit}:tools/miel_vliegt/owner_vm_flight_receipt.py",
            ]
        ),
        "observer_hook_blob": _git_output(
            [
                "rev-parse",
                f"{public_commit}:tools/miel_vliegt/hangover/native_observer_hook.c",
            ]
        ),
        "source_identity_blob": _git_output(
            [
                "rev-parse",
                f"{public_commit}:content/miel_vliegt/source_identity.json",
            ]
        ),
        "transition_contract_blob": _git_output(
            [
                "rev-parse",
                f"{public_commit}:content/miel_vliegt/native_scene_transitions.json",
            ]
        ),
    }
    if any(
        source[field] != expected
        for field, expected in expected_objects.items()
    ):
        raise OwnerVMFlightReceiptError(
            "receipt public source revision objects differ"
        )
    if _git_blob_bytes(source["validator_source_blob"]) != (
        _validator_source_bytes()
    ):
        raise OwnerVMFlightReceiptError(
            "validator source object bytes differ"
        )
    if _git_blob_bytes(source["observer_hook_blob"]) != _observer_hook_bytes():
        raise OwnerVMFlightReceiptError(
            "observer hook source object bytes differ"
        )
    if _git_blob_bytes(source["source_identity_blob"]) != identity_raw:
        raise OwnerVMFlightReceiptError(
            "reviewed source identity object bytes differ"
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
    if (
        type(environment["wave_out_devices"]) is not int
        or environment["wave_out_devices"] < 1
    ):
        raise OwnerVMFlightReceiptError(
            "owner-VM audio readiness differs"
        )
    audio_service_ready = environment["audio_service_ready"]
    if type(audio_service_ready) is not bool or not audio_service_ready:
        raise OwnerVMFlightReceiptError(
            "owner-VM audio readiness differs"
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


def _load_transition(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        contract = _decode(
            raw.decode(encoding="utf-8"), "native transition contract"
        )
    except (OSError, UnicodeDecodeError) as error:
        raise OwnerVMFlightReceiptError(
            f"cannot read native transition contract: {path}"
        ) from error
    return contract, raw


def _routes(
    path: Path,
    executable_sha256: str,
    edition: str,
    *,
    transition_contract_blob: str | None = None,
) -> tuple[dict[str, Any], str]:
    contract, contract_bytes = _load_transition(path)
    if (
        path.absolute() != DEFAULT_TRANSITIONS.absolute()
        and contract_bytes != _load_transition(DEFAULT_TRANSITIONS)[1]
    ):
        raise OwnerVMFlightReceiptError(
            "reviewed transition contract bytes differ"
        )
    if transition_contract_blob is not None and (
        _git_blob_bytes(transition_contract_blob) != contract_bytes
    ):
        raise OwnerVMFlightReceiptError(
            "reviewed transition contract object bytes differ"
        )
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
    }, hashlib.sha256(contract_bytes).hexdigest()


def _validate_airplane_prerequisite(
    value: Any,
    routes: dict[str, Any],
    *,
    capture_id: str,
    process: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    state = _fields(value, ARROW_STATE_KEYS, "airplane prerequisite")
    expected_barn_vtable = _observer_barn_vtable(
        DEFAULT_OBSERVER_HOOK
    )[0]
    if routes.get("airplane_complete_predicate") != AIRPLANE_COMPLETE_PREDICATE:
        raise OwnerVMFlightReceiptError(
            "reviewed airplane completion predicate drifted"
        )
    state_capture_id = state["capture_id"]
    state_process_id = _integer(
        state["process_id"], "state.process_id", minimum=1
    )
    state_image_name = _module_name(
        state["image_name"], "state.image_name"
    )
    manager_tick = _integer(
        state["manager_tick"], "state.manager_tick", minimum=1
    )
    manager_ticks = _integer(
        state["manager_ticks"], "state.manager_ticks", minimum=1
    )
    manager_pointer = _integer(
        state["manager_pointer"],
        "state.manager_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    application_pointer = _integer(
        state["application_pointer"],
        "state.application_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    input_context_pointer = _integer(
        state["input_context_pointer"],
        "state.input_context_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    cursor_pointer = _integer(
        state["cursor_pointer"],
        "state.cursor_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    cursor_x = _integer(
        state["cursor_x"], "state.cursor_x", maximum=ARROW_CLIENT_WIDTH - 1
    )
    cursor_y = _integer(
        state["cursor_y"], "state.cursor_y", maximum=ARROW_CLIENT_HEIGHT - 1
    )
    current_mode_pointer = _integer(
        state["current_mode_pointer"],
        "state.current_mode_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    mode_loaded = _boolean(state["mode_loaded"], "state.mode_loaded")
    mode_opened = _boolean(state["mode_opened"], "state.mode_opened")
    airplane_pointer = _integer(
        state["airplane_pointer"],
        "state.airplane_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    airplane_completion_pointer = _integer(
        state["airplane_completion_pointer"],
        "state.airplane_completion_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    current_mode_vtable = _hex32(
        state["current_mode_vtable"],
        "state.current_mode_vtable",
    )
    if (
        not isinstance(state_capture_id, str)
        or CAPTURE_ID.fullmatch(state_capture_id) is None
        or state_capture_id != capture_id
        or state_process_id != process["pid"]
        or state_image_name != process["image_name"]
    ):
        raise OwnerVMFlightReceiptError(
            "airplane prerequisite identity differs"
        )
    if current_mode_vtable != expected_barn_vtable:
        raise OwnerVMFlightReceiptError(
            "current mode vtable differs"
        )
    if not mode_loaded or not mode_opened:
        raise OwnerVMFlightReceiptError(
            "barn mode lifecycle differs"
        )
    if input_context_pointer != application_pointer:
        raise OwnerVMFlightReceiptError(
            "input context object identity differs"
        )
    if (
        state["current_mode"] != "mode_barn"
        or state["pending_mode"] is not None
        or state["barn_view"] != 0
    ):
        raise OwnerVMFlightReceiptError(
            "airplane prerequisite is outside the reviewed outside-barn state"
        )
    if airplane_pointer != application_pointer + AIRPLANE_POINTER_OFFSET:
        raise OwnerVMFlightReceiptError(
            "airplane prerequisite object address differs"
        )
    if airplane_completion_pointer != (
        airplane_pointer + AIRPLANE_COMPLETION_OFFSET
    ):
        raise OwnerVMFlightReceiptError(
            "airplane completion address differs"
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
    return exact_complete, {
        "capture_id": state_capture_id,
        "process_id": state_process_id,
        "image_name": state_image_name,
        "manager_tick": manager_tick,
        "manager_ticks": manager_ticks,
        "manager_pointer": manager_pointer,
        "application_pointer": application_pointer,
        "input_context_pointer": input_context_pointer,
        "cursor_pointer": cursor_pointer,
        "cursor": [cursor_x, cursor_y],
        "current_mode_pointer": current_mode_pointer,
        "mode_loaded": mode_loaded,
        "mode_opened": mode_opened,
        "airplane_pointer": airplane_pointer,
        "airplane_completion_pointer": airplane_completion_pointer,
        "current_mode_vtable": current_mode_vtable,
    }


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
        expected_public_commit=expected_public_commit,
    )
    routes, transition_contract_sha256 = _routes(
        transition_contract_path,
        source["executable_sha256"],
        source["edition"],
        transition_contract_blob=source["transition_contract_blob"],
    )
    if source["transition_contract_sha256"] != transition_contract_sha256:
        raise OwnerVMFlightReceiptError("transition contract bytes drifted")
    input_value = _fields(receipt.get("input"), ARROW_INPUT_KEYS, "input")
    airplane_complete, prerequisite_observation = _validate_airplane_prerequisite(
        receipt.get("state"),
        routes,
        capture_id=receipt["capture_id"],
        process=process,
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
    event_count = _integer(
        input_value["directinput_getdevicedata_events"],
        "input.getdevicedata_events",
        minimum=1,
    )
    stream_process_id = _integer(
        input_value["getdevicedata_process_id"],
        "input.getdevicedata_process_id",
        minimum=1,
    )
    stream_image_name = _module_name(
        input_value["getdevicedata_image_name"],
        "input.getdevicedata_image_name",
    )
    stream_byte_count = _integer(
        input_value["getdevicedata_stream_byte_count"],
        "input.getdevicedata_stream_byte_count",
        minimum=1,
    )
    if (
        input_value["getdevicedata_capture_id"] != receipt["capture_id"]
        or stream_process_id != process["pid"]
        or stream_image_name != process["image_name"]
        or input_value["getdevicedata_record_format"]
        != "DIRECTINPUT_BUFFERED_16_BYTE_LE"
        or stream_byte_count != event_count * 16
        or SHA256.fullmatch(input_value["getdevicedata_stream_sha256"])
        is None
    ):
        raise OwnerVMFlightReceiptError(
            "owner arrow input stream identity differs"
        )

    mouse = _fields(
        input_value["mouse_arrow_event"], MOUSE_EVENT_KEYS, "mouse event"
    )
    escape = _fields(
        input_value["escape_dispatch_event"], KEY_EVENT_KEYS, "escape event"
    )
    _integer(mouse["sequence"], "mouse.sequence", minimum=1)
    mouse_manager_tick = _integer(
        mouse["manager_tick"], "mouse.manager_tick", minimum=1
    )
    mouse_x = _integer(mouse["x"], "mouse.x", minimum=0)
    mouse_y = _integer(mouse["y"], "mouse.y", minimum=0)
    if (
        mouse_x >= ARROW_CLIENT_WIDTH
        or mouse_y >= ARROW_CLIENT_HEIGHT
    ):
        raise OwnerVMFlightReceiptError(
            "mouse arrow client coordinates differ"
        )
    if (
        mouse["kind"] != "MOUSE_LEFT"
        or _boolean(mouse["arrow_highlighted"], "mouse.arrow_highlighted") is not True
        or _boolean(mouse["transition_observed"], "mouse.transition") is not False
    ):
        raise OwnerVMFlightReceiptError("mouse arrow observation differs")
    _integer(escape["sequence"], "escape.sequence", minimum=1)
    escape_manager_tick = _integer(
        escape["manager_tick"], "escape.manager_tick", minimum=1
    )
    if escape["sequence"] <= mouse["sequence"]:
        raise OwnerVMFlightReceiptError("escape observation is not after arrow")
    if mouse["sequence"] > event_count or escape["sequence"] > event_count:
        raise OwnerVMFlightReceiptError("owner arrow event identity differs")
    if (
        prerequisite_observation["manager_tick"] > mouse_manager_tick
        or mouse_manager_tick > escape_manager_tick
        or escape_manager_tick > prerequisite_observation["manager_ticks"]
    ):
        raise OwnerVMFlightReceiptError("owner arrow input chronology differs")
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
        "prerequisite_observation": prerequisite_observation,
        "environment": environment,
        "process": process,
        "input_stream": {
            "event_count": event_count,
            "capture_id": input_value["getdevicedata_capture_id"],
            "process_id": stream_process_id,
            "image_name": stream_image_name,
            "record_format": input_value["getdevicedata_record_format"],
            "stream_byte_count": stream_byte_count,
            "stream_sha256": input_value["getdevicedata_stream_sha256"],
            "mouse_arrow_event_id": mouse["sequence"],
            "mouse_arrow_manager_tick": mouse_manager_tick,
            "mouse_arrow_x": mouse_x,
            "mouse_arrow_y": mouse_y,
            "escape_dispatch_event_id": escape["sequence"],
            "escape_dispatch_manager_tick": escape_manager_tick,
        },
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
    value: Any,
    expected: dict[str, Any],
    label: str,
    *,
    capture_id: str,
    process: dict[str, Any],
) -> dict[str, Any]:
    record = _fields(value, TRANSITION_KEYS, label)
    transition_process_id = _integer(
        record["process_id"], f"{label}.process_id", minimum=1
    )
    transition_image_name = _module_name(
        record["image_name"], f"{label}.image_name"
    )
    if (
        record["capture_id"] != capture_id
        or transition_process_id != process["pid"]
        or transition_image_name != process["image_name"]
    ):
        raise OwnerVMFlightReceiptError(
            "Flight frame transition capture identity differs"
        )
    _integer(record["manager_tick"], f"{label}.manager_tick", minimum=1)
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


def _validate_runtime_media(
    value: Any,
    source: dict[str, Any],
    capture_id: str,
    process: dict[str, Any],
) -> dict[str, Any]:
    media = _fields(value, RUNTIME_MEDIA_KEYS, "runtime media")
    measurement_capture_id = media["measurement_capture_id"]
    measured_process_id = _integer(
        media["measured_process_id"],
        "runtime media.measured_process_id",
        minimum=1,
    )
    measured_image_name = _module_name(
        media["measured_image_name"],
        "runtime media.measured_image_name",
    )
    if (
        measurement_capture_id != capture_id
        or measured_process_id != process["pid"]
        or measured_image_name != process["image_name"]
    ):
        raise OwnerVMFlightReceiptError(
            "runtime media capture identity differs"
        )
    iso_sha256 = _sha256(media["iso_sha256"], "runtime media.iso_sha256")
    executable_sha256 = _sha256(
        media["executable_sha256"], "runtime media.executable_sha256"
    )
    measurement_tool_sha256 = _sha256(
        media["measurement_tool_sha256"],
        "runtime media.measurement_tool_sha256",
    )
    if (
        iso_sha256 != source["iso_sha256"]
        or executable_sha256 != source["executable_sha256"]
    ):
        raise OwnerVMFlightReceiptError(
            "runtime media identity differs from reviewed source"
        )
    if media["measurement_method"] != "SHA256_FULL_FILE":
        raise OwnerVMFlightReceiptError("runtime media measurement differs")
    _boolean(
        media["measurement_complete"],
        "runtime media.measurement_complete",
        True,
    )
    return {
        "measurement_capture_id": measurement_capture_id,
        "measured_process_id": measured_process_id,
        "measured_image_name": measured_image_name,
        "iso_sha256": iso_sha256,
        "executable_sha256": executable_sha256,
        "measurement_method": media["measurement_method"],
        "measurement_tool_sha256": measurement_tool_sha256,
        "measurement_complete": True,
    }


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
        expected_public_commit=expected_public_commit,
    )
    routes, transition_contract_sha256 = _routes(
        transition_contract_path,
        source["executable_sha256"],
        source["edition"],
        transition_contract_blob=source["transition_contract_blob"],
    )
    if source["transition_contract_sha256"] != transition_contract_sha256:
        raise OwnerVMFlightReceiptError("transition contract bytes drifted")
    runtime_media = _validate_runtime_media(
        receipt.get("runtime_media"),
        source,
        receipt["capture_id"],
        process,
    )
    airplane_complete, prerequisite_observation = _validate_airplane_prerequisite(
        receipt.get("prerequisites"),
        routes,
        capture_id=receipt["capture_id"],
        process=process,
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
    event_count = _integer(
        input_value["directinput_getdevicedata_events"],
        "input.getdevicedata_events",
        minimum=1,
    )
    getdevicedata_process_id = _integer(
        input_value["getdevicedata_process_id"],
        "input.getdevicedata_process_id",
        minimum=1,
    )
    getdevicedata_image_name = _module_name(
        input_value["getdevicedata_image_name"],
        "input.getdevicedata_image_name",
    )
    if (
        input_value["getdevicedata_capture_id"] != receipt["capture_id"]
        or getdevicedata_process_id != process["pid"]
        or getdevicedata_image_name != process["image_name"]
    ):
        raise OwnerVMFlightReceiptError(
            "owner input stream capture identity differs"
        )
    if (
        input_value["getdevicedata_record_format"]
        != "DIRECTINPUT_BUFFERED_16_BYTE_LE"
        or type(input_value["getdevicedata_stream_byte_count"]) is not int
        or input_value["getdevicedata_stream_byte_count"]
        != event_count * 16
        or SHA256.fullmatch(input_value["getdevicedata_stream_sha256"])
        is None
    ):
        raise OwnerVMFlightReceiptError(
            "owner input stream identity differs"
        )
    _boolean(input_value["login_submit_observed"], "input.login", True)
    _boolean(input_value["barn_escape_observed"], "input.escape", True)
    login_submit_tick = _integer(
        input_value["login_submit_manager_tick"],
        "input.login_submit_manager_tick",
        minimum=1,
    )
    barn_escape_tick = _integer(
        input_value["barn_escape_manager_tick"],
        "input.barn_escape_manager_tick",
        minimum=1,
    )
    faster_key_down_tick = _integer(
        input_value["faster_key_down_manager_tick"],
        "input.faster_key_down_manager_tick",
        minimum=1,
    )
    faster_key_up_tick = _integer(
        input_value["faster_key_up_manager_tick"],
        "input.faster_key_up_manager_tick",
        minimum=1,
    )
    raw_event_ids = (
        input_value["login_submit_event_id"],
        input_value["barn_escape_event_id"],
        input_value["faster_key_down_event_id"],
        input_value["faster_key_up_event_id"],
    )
    if any(
        type(event_id) is not int
        or event_id < 1
        or event_id > event_count
        for event_id in raw_event_ids
    ):
        raise OwnerVMFlightReceiptError(
            "owner input event identity differs"
        )
    login_submit_event_id = raw_event_ids[0]
    barn_escape_event_id = raw_event_ids[1]
    faster_key_down_event_id = raw_event_ids[2]
    faster_key_up_event_id = raw_event_ids[3]
    if not (
        login_submit_event_id < barn_escape_event_id
        and barn_escape_event_id < faster_key_down_event_id
        and faster_key_down_event_id < faster_key_up_event_id
    ):
        raise OwnerVMFlightReceiptError(
            "owner input event identity differs"
        )
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
            record,
            expected_transitions[record["id"]],
            f"transition[{index}]",
            capture_id=receipt["capture_id"],
            process=process,
        )
        for index, record in enumerate(raw_transitions)
    ]
    if transitions[0]["manager_tick"] >= transitions[1]["manager_tick"]:
        raise OwnerVMFlightReceiptError(
            "Flight frame transition chronology differs"
        )
    if not (
        login_submit_tick < transitions[0]["manager_tick"]
        and login_submit_tick <= barn_escape_tick
        and barn_escape_tick <= transitions[0]["manager_tick"]
        and transitions[0]["manager_tick"] < faster_key_down_tick
        and faster_key_down_tick <= transitions[1]["manager_tick"]
        and transitions[1]["manager_tick"] <= faster_key_up_tick
        and faster_key_down_tick < faster_key_up_tick
    ):
        raise OwnerVMFlightReceiptError(
            "owner input chronology differs"
        )
    prerequisite_tick = prerequisite_observation["manager_tick"]
    if not (
        login_submit_tick < prerequisite_tick
        and prerequisite_tick < barn_escape_tick
        and prerequisite_tick <= transitions[0]["manager_tick"]
    ):
        raise OwnerVMFlightReceiptError(
            "Flight frame prerequisite chronology differs"
        )

    runtime = _fields(receipt.get("runtime"), RUNTIME_KEYS, "runtime")
    runtime_process_id = _integer(
        runtime["process_id"], "runtime.process_id", minimum=1
    )
    runtime_image_name = _module_name(
        runtime["image_name"], "runtime.image_name"
    )
    if (
        runtime["capture_id"] != receipt["capture_id"]
        or runtime_process_id != process["pid"]
        or runtime_image_name != process["image_name"]
    ):
        raise OwnerVMFlightReceiptError(
            "Flight runtime capture identity differs"
        )
    runtime_manager_pointer = _integer(
        runtime["manager_pointer"],
        "runtime.manager_pointer",
        minimum=1,
        maximum=0xFFFFFFFF,
    )
    if prerequisite_observation["manager_pointer"] != runtime_manager_pointer:
        raise OwnerVMFlightReceiptError(
            "Flight frame Manager object identity differs"
        )
    manager_ticks = _integer(
        runtime["manager_ticks"], "runtime.manager_ticks", minimum=1
    )
    if prerequisite_observation["manager_ticks"] != manager_ticks:
        raise OwnerVMFlightReceiptError(
            "Flight frame Manager tick total differs"
        )
    if max(
        login_submit_tick,
        prerequisite_tick,
        barn_escape_tick,
        faster_key_down_tick,
        faster_key_up_tick,
    ) > manager_ticks:
        raise OwnerVMFlightReceiptError(
            "owner input chronology differs"
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
    direct3d7_module = _module_name(
        runtime["direct3d7_module"], "runtime.direct3d7_module"
    )
    direct3d7_module_sha256 = _sha256(
        runtime["direct3d7_module_sha256"],
        "runtime.direct3d7_module_sha256",
    )
    direct3d7_load_manager_tick = _integer(
        runtime["direct3d7_load_manager_tick"],
        "runtime.direct3d7_load_manager_tick",
        minimum=1,
    )
    if direct3d7_load_manager_tick > manager_ticks:
        raise OwnerVMFlightReceiptError(
            "Direct3D7 load chronology differs"
        )
    if (
        _boolean(runtime["direct3d7_dll_loaded"], "runtime.dll_loaded", True)
        is not True
        or direct3d7_module == process["image_name"]
        or Path(direct3d7_module).suffix.lower() != ".dll"
    ):
        raise OwnerVMFlightReceiptError(
            "Direct3D7 module identity differs"
        )
    create_results = runtime["create_results"]
    if not isinstance(create_results, list) or len(create_results) != create_calls:
        raise OwnerVMFlightReceiptError("Direct3D7 result count differs")
    normalized_results = []
    caller_module_hashes: dict[str, str] = {}
    previous_create_tick = transitions[-1]["manager_tick"]
    for index, result in enumerate(create_results):
        row = _fields(result, CREATE_RESULT_KEYS, f"runtime.create_results[{index}]")
        result_capture_id = row["capture_id"]
        result_process_id = _integer(
            row["process_id"],
            f"runtime.create_results[{index}].process_id",
            minimum=1,
        )
        result_image_name = _module_name(
            row["image_name"],
            f"runtime.create_results[{index}].image_name",
        )
        if (
            not isinstance(result_capture_id, str)
            or CAPTURE_ID.fullmatch(result_capture_id) is None
            or result_capture_id != receipt["capture_id"]
            or result_process_id != process["pid"]
            or result_image_name != process["image_name"]
        ):
            raise OwnerVMFlightReceiptError(
                "Direct3D7 result capture identity differs"
            )
        caller_module = _module_name(
            row["caller_module"],
            f"runtime.create_results[{index}].caller_module",
        )
        if caller_module != process["image_name"] and (
            Path(caller_module).suffix.lower() != ".dll"
        ):
            raise OwnerVMFlightReceiptError(
                "Direct3D7 caller module kind differs"
            )
        caller_module_sha256 = _sha256(
            row["caller_module_sha256"],
            f"runtime.create_results[{index}].caller_module_sha256",
        )
        previous_module_sha256 = caller_module_hashes.get(caller_module)
        if (
            previous_module_sha256 is not None
            and previous_module_sha256 != caller_module_sha256
        ):
            raise OwnerVMFlightReceiptError(
                "Direct3D7 caller module identity differs"
            )
        caller_module_hashes[caller_module] = caller_module_sha256
        if (
            caller_module == process["image_name"]
            and caller_module_sha256 != source["executable_sha256"]
        ):
            raise OwnerVMFlightReceiptError(
                "original executable caller identity differs"
            )
        if (
            caller_module == direct3d7_module
            and caller_module_sha256 != direct3d7_module_sha256
        ):
            raise OwnerVMFlightReceiptError(
                "Direct3D7 caller module identity differs"
            )
        if row["caller_address_kind"] != "RVA":
            raise OwnerVMFlightReceiptError(
                "Direct3D7 caller address kind differs"
            )
        caller_rva = _hex32(
            row["caller_site"],
            f"runtime.create_results[{index}].caller_site",
        )
        manager_tick = _integer(
            row["manager_tick"],
            f"runtime.create_results[{index}].manager_tick",
            minimum=1,
        )
        if manager_tick < previous_create_tick:
            raise OwnerVMFlightReceiptError(
                "Direct3D7 CreateDevice chronology differs"
            )
        previous_create_tick = manager_tick
        hresult = _hresult(
            row["hresult"], f"runtime.create_results[{index}].hresult"
        )
        device_nonnull = _boolean(
            row["device_nonnull"],
            f"runtime.create_results[{index}].device_nonnull",
        )
        if (hresult == "0x00000000") != device_nonnull:
            raise OwnerVMFlightReceiptError(
                "Direct3D7 result outcome differs"
            )
        normalized_results.append({
            "capture_id": result_capture_id,
            "process_id": result_process_id,
            "image_name": result_image_name,
            "caller_module": caller_module,
            "caller_module_sha256": caller_module_sha256,
            "caller_address_kind": "RVA",
            "caller_rva": caller_rva,
            "manager_tick": manager_tick,
            "hresult": hresult,
            "device_nonnull": device_nonnull,
        })
    observed_successes = sum(
        row["hresult"] == "0x00000000" and row["device_nonnull"]
        for row in normalized_results
    )
    if normalized_results[0]["manager_tick"] < direct3d7_load_manager_tick:
        raise OwnerVMFlightReceiptError(
            "Direct3D7 load chronology differs"
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
        if row["caller_rva"] == "0x00000000":
            raise OwnerVMFlightReceiptError(
                "Direct3D7 device creation evidence is incomplete"
            )
    frame = _fields(receipt.get("frame"), FRAME_KEYS, "frame")
    frame_capture_id = frame["capture_id"]
    frame_process_id = _integer(
        frame["process_id"], "frame.process_id", minimum=1
    )
    frame_image_name = _module_name(frame["image_name"], "frame.image_name")
    frame_capture_tool_sha256 = _sha256(
        frame["capture_tool_sha256"], "frame.capture_tool_sha256"
    )
    if (
        frame_capture_id != receipt["capture_id"]
        or frame_process_id != process["pid"]
        or frame_image_name != process["image_name"]
    ):
        raise OwnerVMFlightReceiptError(
            "Flight frame capture identity differs"
        )
    if frame_capture_tool_sha256 != source["capture_tool_sha256"]:
        raise OwnerVMFlightReceiptError(
            "Flight frame capture tool differs"
        )
    frame_width = _integer(
        frame["width"], "frame.width", minimum=1
    )
    frame_height = _integer(
        frame["height"], "frame.height", minimum=1
    )
    if (frame_width, frame_height) not in FRAME_CLIENT_GEOMETRIES:
        raise OwnerVMFlightReceiptError(
            "Flight frame geometry differs from the original client"
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
    frame_manager_tick = _integer(
        frame["manager_tick"], "frame.manager_tick", minimum=1
    )
    if (
        frame_manager_tick < previous_create_tick
        or frame_manager_tick > manager_ticks
    ):
        raise OwnerVMFlightReceiptError(
            "Flight frame chronology differs"
        )
    _sha256(frame["pixel_sha256"], "frame.pixel_sha256")
    changed = _integer(
        frame["changed_pixel_count"],
        "frame.changed_pixel_count",
        minimum=1,
        maximum=frame_width * frame_height,
    )
    if frame_path.is_symlink():
        raise OwnerVMFlightReceiptError("frame path may not be a symlink")
    expected_bytes = frame_width * frame_height * 4
    try:
        frame_stat = frame_path.stat()
    except OSError as error:
        raise OwnerVMFlightReceiptError("cannot read frame bytes") from error
    if not stat.S_ISREG(frame_stat.st_mode):
        raise OwnerVMFlightReceiptError("frame path is not a regular file")
    if frame_stat.st_size != expected_bytes:
        raise OwnerVMFlightReceiptError(
            "frame file size differs from the original client"
        )
    try:
        pixels = frame_path.read_bytes()
    except OSError as error:
        raise OwnerVMFlightReceiptError("cannot read frame bytes") from error
    if len(pixels) != expected_bytes:
        raise OwnerVMFlightReceiptError("frame dimensions do not match byte count")
    if hashlib.sha256(pixels).hexdigest() != frame["pixel_sha256"]:
        raise OwnerVMFlightReceiptError("frame bytes drifted from declared identity")
    rgb_samples = {
        pixels[index:index + 3] for index in range(0, len(pixels), 4)
    }
    rgba_samples = {
        pixels[index:index + 4] for index in range(0, len(pixels), 4)
    }
    if len(rgba_samples) < 2:
        raise OwnerVMFlightReceiptError("frame bytes contain no actual pixel variation")
    if len(rgb_samples) < 2:
        raise OwnerVMFlightReceiptError(
            "frame bytes contain no actual RGB pixel variation"
        )

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
        "runtime_media": runtime_media,
        "prerequisite_observation": prerequisite_observation,
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
            "capture_id": runtime["capture_id"],
            "process_id": runtime_process_id,
            "image_name": runtime_image_name,
            "current_mode": "mode_fly",
            "manager_pointer": runtime_manager_pointer,
            "manager_ticks": manager_ticks,
            "direct3d7_dll_loaded": True,
            "direct3d7_load_manager_tick": direct3d7_load_manager_tick,
            "direct3d7_module": direct3d7_module,
            "direct3d7_module_sha256": direct3d7_module_sha256,
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
            "capture_id": frame_capture_id,
            "process_id": frame_process_id,
            "image_name": frame_image_name,
            "capture_tool_sha256": frame_capture_tool_sha256,
            "format": "RGBA8",
            "sequence": frame["sequence"],
            "manager_tick": frame_manager_tick,
            "pixel_sha256": frame["pixel_sha256"],
            "changed_pixel_count": changed,
            "unique_rgb_values": len(rgb_samples),
            "byte_count": len(pixels),
        },
        "proof_limits": proof,
    }


def _load_bridge_file(
    path: Path | None, option: str, requested: str
) -> dict[str, Any]:
    if path is None:
        raise OwnerVMFlightReceiptError(
            f"bridge sequence requires --bridge-{option}"
        )
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise OwnerVMFlightReceiptError(
            f"cannot read bridge {option} record: {path}"
        ) from error
    return load_bridge_success(raw, requested)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path, nargs="?")
    parser.add_argument("--frame", type=Path)
    parser.add_argument(
        "--receipt-type",
        choices=("arrow", "flight-frame", "bridge-state", "bridge-sequence"),
    )
    parser.add_argument("--bridge-state", type=Path)
    parser.add_argument("--bridge-before", type=Path)
    parser.add_argument("--bridge-click", type=Path)
    parser.add_argument("--bridge-after", type=Path)
    parser.add_argument("--bridge-health", type=Path)
    parser.add_argument("--source-identity", type=Path, default=DEFAULT_SOURCE_IDENTITY)
    parser.add_argument("--transitions", type=Path, default=DEFAULT_TRANSITIONS)
    parser.add_argument("--expected-public-commit")
    args = parser.parse_args()
    if not args.receipt_type:
        parser.error("--receipt-type is required")
    if args.receipt_type == "bridge-state":
        if args.receipt is not None or args.frame is not None:
            parser.error("bridge state uses --bridge-health/state")
        if args.bridge_health is None or args.bridge_state is None:
            parser.error("bridge state requires --bridge-health and --bridge-state")
        result = classify_bridge_state(
            _load(args.bridge_health, "bridge health"),
            _load_bridge_file(args.bridge_state, "state", "state"),
            source_identity_path=args.source_identity,
            transition_contract_path=args.transitions,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.receipt_type == "bridge-sequence":
        if args.receipt is not None or args.frame is not None:
            parser.error("bridge sequences use --bridge-before/click/after")
        if args.bridge_health is None:
            parser.error("bridge sequences require --bridge-health")
        health = validate_bridge_health(
            _load(args.bridge_health, "bridge health")
        )
        result = validate_bridge_sequence(
            _load_bridge_file(args.bridge_before, "before", "state"),
            _load_bridge_file(args.bridge_click, "click", "click"),
            _load_bridge_file(args.bridge_after, "after", "state"),
            observer_hook_path=DEFAULT_OBSERVER_HOOK,
        )
        result["bridge_environment"] = health
    elif args.receipt_type == "arrow":
        if args.receipt is None:
            parser.error("arrow diagnostics require a receipt path")
        if args.frame is not None:
            parser.error("arrow diagnostics do not use --frame")
        receipt = _load(args.receipt, "owner-VM receipt")
        result = validate_arrow_diagnostic(
            receipt,
            source_identity_path=args.source_identity,
            transition_contract_path=args.transitions,
            expected_public_commit=args.expected_public_commit,
        )
    else:
        if args.receipt is None:
            parser.error("flight-frame requires a receipt path")
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
