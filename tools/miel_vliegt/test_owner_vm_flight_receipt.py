#!/usr/bin/env python3
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path
from unittest import mock

from tools.miel_vliegt import owner_vm_flight_receipt
from tools.miel_vliegt.owner_vm_flight_receipt import (
    OwnerVMFlightReceiptError,
    classify_bridge_state,
    load_bridge_success,
    validate_bridge_health,
    validate_arrow_diagnostic,
    validate_flight_frame,
    validate_bridge_observation,
    validate_bridge_sequence,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE_IDENTITY = ROOT / "content/miel_vliegt/source_identity.json"
TRANSITIONS = ROOT / "content/miel_vliegt/native_scene_transitions.json"
OBSERVER_HOOK = ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
FRAME_WIDTH = 640
FRAME_HEIGHT = 457


def _git(*arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


_git = lru_cache(maxsize=None)(_git)


def _identity() -> dict:
    value = json.loads(SOURCE_IDENTITY.read_text(encoding="utf-8"))
    commit = _git("rev-parse", "HEAD")
    return {
        "edition": value["edition"],
        "iso_sha256": value["iso"]["sha256"],
        "executable_sha256": value["executable"]["sha256"],
        "transition_contract_sha256": hashlib.sha256(
            TRANSITIONS.read_bytes()
        ).hexdigest(),
        "public_source_commit": commit,
        "public_source_tree": _git("rev-parse", f"{commit}^{{tree}}"),
        "validator_source_blob": _git(
            "rev-parse",
            f"{commit}:tools/miel_vliegt/owner_vm_flight_receipt.py",
        ),
        "source_identity_blob": _git(
            "rev-parse",
            f"{commit}:content/miel_vliegt/source_identity.json",
        ),
        "transition_contract_blob": _git(
            "rev-parse",
            f"{commit}:content/miel_vliegt/native_scene_transitions.json",
        ),
        "capture_tool_sha256": "2" * 64,
    }


def _environment() -> dict:
    return {
        "owner": "OWNER_PARALLELS_PRIVATE_VM",
        "guest": "WINDOWS_11",
        "architecture": "ARM64_HOST_X86_GAME",
        "audio": "VIRTUAL_OUTPUT_PRESENT",
        "wave_out_devices": 1,
        "audio_service_ready": True,
        "renderer": "SOFTWARE",
        "hosted_runner_validated": False,
    }


def _process() -> dict:
    return {
        "pid": 4321,
        "image_name": "MulleMeck.exe",
        "architecture": "x86",
        "window_title": "Miel Monteur",
        "before_alive": True,
        "after_alive": True,
    }


def _bridge_state(*, barn_view: int = 0, x: int = 100, y: int = 200) -> dict:
    return {
        "ProcessId": 1234,
        "Application": 0x11111111,
        "Manager": 0x22222222,
        "CurrentMode": 0x33333333,
        "CurrentVtable": "0x0044caec",
        "PendingMode": 0,
        "Loaded": 1,
        "Opened": 1,
        "BarnView": barn_view,
        "InputContext": 0x11111111,
        "CursorObject": 0x44444444,
        "CursorX": x,
        "CursorY": y,
    }


def _bridge_click() -> dict:
    return {
        "target": [450, 150],
        "delta": [350, -50],
        "cursorBefore": [100, 200],
        "cursorAfter": [450, 150],
        "barnViewBefore": 0,
        "barnViewAfter": 1,
        "openedBefore": 1,
        "openedAfter": 1,
        "injectionSeen": True,
    }


def _bridge_restore_click() -> dict:
    return {
        "target": [100, 200],
        "delta": [-350, 50],
        "cursorBefore": [450, 150],
        "cursorAfter": [100, 200],
        "barnViewBefore": 1,
        "barnViewAfter": 0,
        "openedBefore": 1,
        "openedAfter": 1,
        "injectionSeen": True,
    }


def _bridge_health() -> dict:
    return {
        "ok": True,
        "service": "flight-vm-bridge",
        "vm": "Windows 11",
    }


def _arrow_receipt() -> dict:
    return {
        "schema": 1,
        "protocol": "miel-vliegt-owner-vm-arrow-diagnostic",
        "capture_id": "owner-vm-arrow-20260930-001",
        "source": _identity(),
        "environment": _environment(),
        "process": _process(),
        "input": {
            "adapter_sha256": "3" * 64,
            "adapter_record_bytes": 16,
            "directinput_getdevicedata_events": 9,
            "getdevicedata_capture_id": "owner-vm-arrow-20260930-001",
            "getdevicedata_process_id": 4321,
            "getdevicedata_image_name": "MulleMeck.exe",
            "getdevicedata_record_format": "DIRECTINPUT_BUFFERED_16_BYTE_LE",
            "getdevicedata_stream_byte_count": 9 * 16,
            "getdevicedata_stream_sha256": "8" * 64,
            "system_directinput_create_hresult": "0x80070057",
            "owner_adapter_hosted_runner_validated": False,
            "mouse_arrow_event": {
                "sequence": 7,
                "manager_tick": 118,
                "kind": "MOUSE_LEFT",
                "x": 596,
                "y": 322,
                "arrow_highlighted": True,
                "transition_observed": False,
            },
            "escape_dispatch_event": {
                "sequence": 8,
                "manager_tick": 119,
                "kind": "KEYBOARD_SCAN_CODE",
                "scan_code": "0x01",
                "dispatch_observed": False,
                "mode_set_observed": False,
            },
        },
        "state": {
            "capture_id": "owner-vm-arrow-20260930-001",
            "process_id": 4321,
            "image_name": "MulleMeck.exe",
            "manager_tick": 118,
            "manager_ticks": 150,
            "manager_pointer": 0x20000000,
            "application_pointer": 0x10000000,
            "input_context_pointer": 0x10000000,
            "cursor_pointer": 0x40000000,
            "cursor_x": 100,
            "cursor_y": 200,
            "airplane_pointer": 0x10000160,
            "airplane_completion_pointer": 0x10000288,
            "current_mode": "mode_barn",
            "current_mode_pointer": 0x30000000,
            "current_mode_vtable": "0x0044caec",
            "mode_loaded": True,
            "mode_opened": True,
            "pending_mode": None,
            "barn_view": 0,
            "airplane_complete": True,
            "airplane_pointer_nonnull": True,
            "airplane_completion_bits": 0x1FF,
        },
        "proof_limits": {
            "owner_vm_only": True,
            "native_transition_evidence": False,
            "native_parity_evidence": False,
        },
    }


def _transition_records() -> list[dict]:
    return [
        {
            "capture_id": "owner-vm-flight-20260930-001",
            "process_id": 4321,
            "image_name": "MulleMeck.exe",
            "id": "barn.mygghanget",
            "source_mode": "mode_barn",
            "target_mode": "mode_mygghanget",
            "caller_site": "0x00419198",
            "manager_tick": 120,
            "observed": True,
        },
        {
            "capture_id": "owner-vm-flight-20260930-001",
            "process_id": 4321,
            "image_name": "MulleMeck.exe",
            "id": "location.departure.mode_mygghanget",
            "source_mode": "mode_mygghanget",
            "target_mode": "mode_fly",
            "caller_site": "0x004262ee",
            "manager_tick": 140,
            "observed": True,
        },
    ]


def _frame_file(directory: Path) -> tuple[Path, dict]:
    payload = bytearray(FRAME_WIDTH * FRAME_HEIGHT * 4)
    payload[:4] = b"\x12\x34\x56\x78"
    path = directory / "flight-frame.rgba"
    path.write_bytes(payload)
    return path, {
        "width": FRAME_WIDTH,
        "height": FRAME_HEIGHT,
        "capture_id": "owner-vm-flight-20260930-001",
        "process_id": 4321,
        "image_name": "MulleMeck.exe",
        "capture_tool_sha256": _identity()["capture_tool_sha256"],
        "format": "RGBA8",
        "sequence": 12,
        "manager_tick": 1502,
        "capture_surface": "ORIGINAL_WINDOW_CLIENT",
        "conversion": "CANONICAL_RGBA8_EXACT",
        "pixel_sha256": hashlib.sha256(payload).hexdigest(),
        "changed_pixel_count": 1,
        "captured_before_process_exit": True,
    }


def _frame_receipt(frame: dict) -> dict:
    return {
        "schema": 1,
        "protocol": "miel-vliegt-owner-vm-native-flight-frame",
        "capture_id": "owner-vm-flight-20260930-001",
        "source": _identity(),
        "environment": _environment(),
        "process": _process(),
        "input": {
            "adapter_sha256": "3" * 64,
            "adapter_record_bytes": 16,
            "system_directinput_create_hresult": "0x80070057",
            "owner_adapter_hosted_runner_validated": False,
            "directinput_getdevicedata_events": 19,
            "getdevicedata_capture_id": "owner-vm-flight-20260930-001",
            "getdevicedata_process_id": 4321,
            "getdevicedata_image_name": "MulleMeck.exe",
            "getdevicedata_record_format": "DIRECTINPUT_BUFFERED_16_BYTE_LE",
            "getdevicedata_stream_byte_count": 19 * 16,
            "getdevicedata_stream_sha256": "7" * 64,
            "login_submit_observed": True,
            "login_submit_manager_tick": 100,
            "login_submit_event_id": 4,
            "barn_escape_observed": True,
            "barn_escape_manager_tick": 119,
            "barn_escape_event_id": 7,
            "faster_key_scan_code": "0x2a",
            "faster_key_down_manager_tick": 135,
            "faster_key_down_event_id": 12,
            "faster_key_up_manager_tick": 141,
            "faster_key_up_event_id": 16,
            "faster_key_held_until_departure": True,
        },
        "transitions": _transition_records(),
        "runtime_media": {
            "measurement_capture_id": "owner-vm-flight-20260930-001",
            "measured_process_id": 4321,
            "measured_image_name": "MulleMeck.exe",
            "iso_sha256": _identity()["iso_sha256"],
            "executable_sha256": _identity()["executable_sha256"],
            "measurement_method": "SHA256_FULL_FILE",
            "measurement_tool_sha256": "6" * 64,
            "measurement_complete": True,
        },
        "prerequisites": {
            "capture_id": "owner-vm-flight-20260930-001",
            "process_id": 4321,
            "image_name": "MulleMeck.exe",
            "manager_tick": 110,
            "manager_ticks": 1502,
            "manager_pointer": 0x20000000,
            "application_pointer": 0x10000000,
            "input_context_pointer": 0x10000000,
            "cursor_pointer": 0x40000000,
            "cursor_x": 100,
            "cursor_y": 200,
            "airplane_pointer": 0x10000160,
            "airplane_completion_pointer": 0x10000288,
            "current_mode": "mode_barn",
            "current_mode_pointer": 0x30000000,
            "current_mode_vtable": "0x0044caec",
            "mode_loaded": True,
            "mode_opened": True,
            "pending_mode": None,
            "barn_view": 0,
            "airplane_complete": True,
            "airplane_pointer_nonnull": True,
            "airplane_completion_bits": 0x1FF,
        },
        "runtime": {
            "capture_id": "owner-vm-flight-20260930-001",
            "process_id": 4321,
            "image_name": "MulleMeck.exe",
            "current_mode": "mode_fly",
            "manager_pointer": 0x20000000,
            "manager_ticks": 1502,
            "direct3d7_dll_loaded": True,
            "direct3d7_load_manager_tick": 139,
            "direct3d7_module": "gtDirect3d.dll",
            "direct3d7_module_sha256": "4" * 64,
            "create_method": "IDirect3D7::CreateDevice",
            "device_interface": "IID_IDirect3DDevice7",
            "create_calls": 2,
            "successful_create_calls": 1,
            "last_create_hresult": "0x00000000",
            "device_nonnull": True,
            "create_results": [
                {
                    "capture_id": "owner-vm-flight-20260930-001",
                    "process_id": 4321,
                    "image_name": "MulleMeck.exe",
                    "caller_module": "MulleMeck.exe",
                    "caller_module_sha256": _identity()["executable_sha256"],
                    "caller_address_kind": "RVA",
                    "caller_site": "0x0042a95e",
                    "manager_tick": 141,
                    "hresult": "0x8007000E",
                    "device_nonnull": False,
                },
                {
                    "capture_id": "owner-vm-flight-20260930-001",
                    "process_id": 4321,
                    "image_name": "MulleMeck.exe",
                    "caller_module": "gtDirect3d.dll",
                    "caller_module_sha256": "4" * 64,
                    "caller_address_kind": "RVA",
                    "caller_site": "0x0042a95e",
                    "manager_tick": 142,
                    "hresult": "0x00000000",
                    "device_nonnull": True,
                },
            ],
        },
        "frame": frame,
        "proof_limits": {
            "owner_vm_only": True,
            "hosted_runner_validated": False,
            "independent_runtime_media_hash": False,
            "web_pixel_comparison_performed": False,
            "independent_web_source_compared": False,
            "nine_dimension_release_evidence": False,
            "native_parity_evidence": False,
        },
    }


class OwnerVMFlightArrowDiagnosticTests(unittest.TestCase):
    def test_owner_environment_records_audio_readiness(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(result["environment"]["wave_out_devices"], 1)
        self.assertTrue(result["environment"]["audio_service_ready"])

        for field, value in (
            ("wave_out_devices", 0),
            ("audio_service_ready", False),
        ):
            receipt = _arrow_receipt()
            receipt["environment"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "owner-VM audio readiness differs",
            ):
                validate_arrow_diagnostic(
                    receipt,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_arrow_receipt_binds_public_source_objects(self):
        receipt = _arrow_receipt()
        result = validate_arrow_diagnostic(
            receipt,
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["source_identities"]["public_source_tree"],
            _identity()["public_source_tree"],
        )
        self.assertEqual(
            result["source_identities"]["validator_source_blob"],
            _identity()["validator_source_blob"],
        )

        receipt["source"]["public_source_tree"] = "0" * 40
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "public source revision"
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_validator_source_blob_binds_executing_bytes(self):
        receipt = _arrow_receipt()
        with mock.patch.object(
            owner_vm_flight_receipt,
            "_validator_source_bytes",
            return_value=b"drifted validator source",
            create=True,
        ), self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "validator source object bytes differ",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_source_identity_blob_binds_exact_reviewed_bytes(self):
        receipt = _arrow_receipt()
        identity = json.loads(SOURCE_IDENTITY.read_text(encoding="utf-8"))
        reformatted = json.dumps(
            identity, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")

        with mock.patch.object(
            owner_vm_flight_receipt,
            "_load_source_identity",
            return_value=(identity, reformatted),
        ), self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "reviewed source identity object bytes differ",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_transition_contract_blob_binds_exact_reviewed_bytes(self):
        receipt = _arrow_receipt()
        contract = json.loads(TRANSITIONS.read_text(encoding="utf-8"))
        reformatted = json.dumps(
            contract, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        receipt["source"]["transition_contract_sha256"] = (
            hashlib.sha256(reformatted).hexdigest()
        )

        with mock.patch.object(
            owner_vm_flight_receipt,
            "_load_transition",
            return_value=(contract, reformatted),
        ), self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "reviewed transition contract object bytes differ",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_arrow_highlight_alone_names_the_missing_escape_dispatch(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(
            result["blocker_code"], "BARN_ESCAPE_DISPATCH_UNOBSERVED"
        )
        self.assertEqual(
            result["static_prerequisite"]["mode_set_callsite"], "0x00419198"
        )
        self.assertEqual(
            result["static_prerequisite"]["airplane_completion_bits"], 0x1FF
        )
        self.assertEqual(
            result["required_owner_handoff"]["input"],
            {
                "kind": "KEYBOARD_SCAN_CODE",
                "scan_code": "0x01",
                "name": "DIK_ESCAPE",
                "delivery": "original barn input dispatch",
            },
        )
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])

    def test_airplane_prerequisite_is_bound_to_its_capture_and_process(self):
        receipt = _arrow_receipt()
        result = validate_arrow_diagnostic(
            receipt,
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["prerequisite_observation"],
            {
                "capture_id": "owner-vm-arrow-20260930-001",
                "process_id": 4321,
                "image_name": "MulleMeck.exe",
                "manager_tick": 118,
                "manager_ticks": 150,
                "manager_pointer": 0x20000000,
                "application_pointer": 0x10000000,
                "input_context_pointer": 0x10000000,
                "cursor_pointer": 0x40000000,
                "cursor": [100, 200],
                "airplane_pointer": 0x10000160,
                "airplane_completion_pointer": 0x10000288,
                "current_mode_pointer": 0x30000000,
                "current_mode_vtable": "0x0044caec",
                "mode_loaded": True,
                "mode_opened": True,
            },
        )

        for field, value in (
            ("capture_id", "owner-vm-arrow-20260930-002"),
            ("process_id", 9999),
            ("image_name", "Other.exe"),
        ):
            drifted = _arrow_receipt()
            drifted["state"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "airplane prerequisite identity differs",
            ):
                validate_arrow_diagnostic(
                    drifted,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

        malformed_tick = _arrow_receipt()
        malformed_tick["state"]["manager_tick"] = 0
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "state.manager_tick"
        ):
            validate_arrow_diagnostic(
                malformed_tick,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_arrow_input_stream_is_bound_to_events_and_timeline(self):
        receipt = _arrow_receipt()
        result = validate_arrow_diagnostic(
            receipt,
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["input_stream"],
            {
                "event_count": 9,
                "capture_id": "owner-vm-arrow-20260930-001",
                "process_id": 4321,
                "image_name": "MulleMeck.exe",
                "record_format": "DIRECTINPUT_BUFFERED_16_BYTE_LE",
                "stream_byte_count": 144,
                "stream_sha256": "8" * 64,
                "mouse_arrow_event_id": 7,
                "mouse_arrow_manager_tick": 118,
                "mouse_arrow_x": 596,
                "mouse_arrow_y": 322,
                "escape_dispatch_event_id": 8,
                "escape_dispatch_manager_tick": 119,
            },
        )

        for field, value in (
            ("getdevicedata_capture_id", "owner-vm-arrow-20260930-002"),
            ("getdevicedata_process_id", 9999),
            ("getdevicedata_image_name", "Other.exe"),
            ("getdevicedata_stream_byte_count", 143),
        ):
            drifted = _arrow_receipt()
            drifted["input"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "owner arrow input stream identity differs",
            ):
                validate_arrow_diagnostic(
                    drifted,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

        out_of_range_escape = _arrow_receipt()
        out_of_range_escape["input"]["escape_dispatch_event"]["sequence"] = 10
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "owner arrow event identity differs"
        ):
            validate_arrow_diagnostic(
                out_of_range_escape,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

        early_mouse = _arrow_receipt()
        early_mouse["input"]["mouse_arrow_event"]["manager_tick"] = 117
        early_escape = _arrow_receipt()
        early_escape["input"]["escape_dispatch_event"]["manager_tick"] = 117
        for label, drifted in (
            ("mouse", early_mouse),
            ("escape", early_escape),
        ):
            with self.subTest(event=label), self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "owner arrow input chronology differs",
            ):
                validate_arrow_diagnostic(
                    drifted,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_arrow_mouse_event_stays_in_the_original_client(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(result["input_stream"]["mouse_arrow_x"], 596)
        self.assertEqual(result["input_stream"]["mouse_arrow_y"], 322)

        for field, value in (("x", 640), ("y", 480)):
            receipt = _arrow_receipt()
            receipt["input"]["mouse_arrow_event"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "mouse arrow client coordinates differ",
            ):
                validate_arrow_diagnostic(
                    receipt,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_manager_ticks_are_bound_to_one_manager_object(self):
        arrow_result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            arrow_result["prerequisite_observation"]["manager_pointer"],
            0x20000000,
        )

        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["runtime"]["manager_pointer"] = 0x20000001
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "Flight frame Manager object identity differs",
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_barn_mode_is_bound_to_its_reviewed_vtable(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["prerequisite_observation"]["current_mode_vtable"],
            "0x0044caec",
        )

        receipt = _arrow_receipt()
        receipt["state"]["current_mode_vtable"] = "0x0044caed"
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "current mode vtable differs",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_input_context_is_bound_to_the_application_object(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["prerequisite_observation"]["input_context_pointer"],
            result["prerequisite_observation"]["application_pointer"],
        )

        receipt = _arrow_receipt()
        receipt["state"]["input_context_pointer"] = (
            receipt["state"]["application_pointer"] + 1
        )
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "input context object identity differs",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_live_cursor_state_is_bound_to_the_capture(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["prerequisite_observation"]["cursor_pointer"],
            0x40000000,
        )
        self.assertEqual(
            result["prerequisite_observation"]["cursor"],
            [100, 200],
        )

        for field, value in (
            ("cursor_pointer", 0),
            ("cursor_x", 640),
            ("cursor_y", 480),
        ):
            receipt = _arrow_receipt()
            receipt["state"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                f"state.{field}",
            ):
                validate_arrow_diagnostic(
                    receipt,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_current_mode_object_is_bound_to_the_capture(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["prerequisite_observation"]["current_mode_pointer"],
            0x30000000,
        )

        receipt = _arrow_receipt()
        receipt["state"]["current_mode_pointer"] = 0
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "state.current_mode_pointer",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_barn_lifecycle_is_loaded_and_open(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertTrue(
            result["prerequisite_observation"]["mode_loaded"]
        )
        self.assertTrue(
            result["prerequisite_observation"]["mode_opened"]
        )

        for field in ("mode_loaded", "mode_opened"):
            receipt = _arrow_receipt()
            receipt["state"][field] = False
            with self.subTest(field=field), self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "barn mode lifecycle differs",
            ):
                validate_arrow_diagnostic(
                    receipt,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_arrow_input_cannot_exceed_total_manager_ticks(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(result["prerequisite_observation"]["manager_ticks"], 150)

        for manager_ticks in (117, 118):
            receipt = _arrow_receipt()
            receipt["state"]["manager_ticks"] = manager_ticks
            with self.subTest(manager_ticks=manager_ticks), \
                    self.assertRaisesRegex(
                        OwnerVMFlightReceiptError,
                        "owner arrow input chronology differs",
                    ):
                validate_arrow_diagnostic(
                    receipt,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

        malformed = _arrow_receipt()
        malformed["state"]["manager_ticks"] = 0
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "state.manager_ticks"
        ):
            validate_arrow_diagnostic(
                malformed,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_airplane_prerequisite_is_bound_to_live_object_addresses(self):
        result = validate_arrow_diagnostic(
            _arrow_receipt(),
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["prerequisite_observation"]["application_pointer"],
            0x10000000,
        )
        self.assertEqual(
            result["prerequisite_observation"]["airplane_pointer"],
            0x10000160,
        )
        self.assertEqual(
            result["prerequisite_observation"][
                "airplane_completion_pointer"
            ],
            0x10000288,
        )

        receipt = _arrow_receipt()
        receipt["state"]["airplane_pointer"] += 1
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "airplane prerequisite object address differs",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

        receipt = _arrow_receipt()
        receipt["state"]["airplane_completion_pointer"] += 1
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "airplane completion address differs",
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_incomplete_airplane_blocks_before_input_diagnosis(self):
        receipt = _arrow_receipt()
        receipt["state"]["airplane_complete"] = False
        receipt["state"]["airplane_pointer_nonnull"] = False
        receipt["state"]["airplane_completion_bits"] = 0
        result = validate_arrow_diagnostic(
            receipt,
            source_identity_path=SOURCE_IDENTITY,
            transition_contract_path=TRANSITIONS,
        )
        self.assertEqual(
            result["blocker_code"], "AIRPLANE_COMPLETION_UNPROVEN"
        )

    def test_airplane_boolean_cannot_overclaim_exact_completion_bits(self):
        receipt = _arrow_receipt()
        receipt["state"]["airplane_pointer_nonnull"] = False
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "airplane completion predicate"
        ):
            validate_arrow_diagnostic(
                receipt,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )

    def test_executable_or_contract_drift_is_rejected(self):
        for field, value in (
            ("executable_sha256", "b" * 64),
            ("transition_contract_sha256", "c" * 64),
        ):
            receipt = _arrow_receipt()
            receipt["source"][field] = value
            with self.subTest(field=field), self.assertRaises(
                OwnerVMFlightReceiptError
            ):
                validate_arrow_diagnostic(
                    receipt,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_transition_routes_hash_the_parsed_contract_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            transition_path = Path(directory) / "native_scene_transitions.json"
            transition_path.write_bytes(TRANSITIONS.read_bytes())
            contract = json.loads(TRANSITIONS.read_text(encoding="utf-8"))
            drifted = dict(contract, race_after_hash=True)
            identity = _identity()
            original_load = owner_vm_flight_receipt._load

            def drift_alternate_load(path, label):
                if path == transition_path:
                    return drifted
                return original_load(path, label)

            with mock.patch.object(
                owner_vm_flight_receipt,
                "_load",
                side_effect=drift_alternate_load,
            ):
                routes, transition_sha256 = owner_vm_flight_receipt._routes(
                    transition_path,
                    identity["executable_sha256"],
                    identity["edition"],
                )

            self.assertNotIn("race_after_hash", routes)
            self.assertEqual(
                transition_sha256,
                hashlib.sha256(TRANSITIONS.read_bytes()).hexdigest(),
            )


class OwnerVMFlightFrameReceiptTests(unittest.TestCase):
    def test_complete_owner_frame_stays_candidate_only(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            result = validate_flight_frame(
                _frame_receipt(frame),
                frame_path,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )
        self.assertEqual(
            result["status"], "NATIVE_OWNER_VM_FLIGHT_FRAME_CANDIDATE_ONLY"
        )
        self.assertEqual(result["runtime"]["create_calls"], 2)
        self.assertEqual(
            result["runtime"]["direct3d7_module"], "gtDirect3d.dll"
        )
        self.assertEqual(
            result["runtime"]["direct3d7_load_manager_tick"], 139
        )
        self.assertEqual(
            result["runtime"]["create_results"][0]["caller_module"],
            "MulleMeck.exe",
        )
        self.assertEqual(
            result["runtime"]["create_results"][0]["caller_rva"],
            "0x0042a95e",
        )
        self.assertEqual(result["frame"]["changed_pixel_count"], 1)
        self.assertEqual(result["frame"]["unique_rgb_values"], 2)
        self.assertEqual(result["frame"]["manager_tick"], 1502)
        self.assertEqual(
            result["frame"]["capture_id"],
            "owner-vm-flight-20260930-001",
        )
        self.assertEqual(
            result["frame"]["capture_tool_sha256"],
            _identity()["capture_tool_sha256"],
        )
        self.assertEqual(
            result["runtime_media"]["executable_sha256"],
            _identity()["executable_sha256"],
        )
        self.assertEqual(
            result["input"]["getdevicedata_stream_sha256"], "7" * 64
        )
        self.assertEqual(
            result["runtime_media"]["measurement_capture_id"],
            "owner-vm-flight-20260930-001",
        )
        self.assertFalse(
            result["proof_limits"]["independent_runtime_media_hash"]
        )
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])
        self.assertFalse(result["proof_limits"]["hosted_runner_validated"])

    def test_flight_frame_requires_the_exact_airplane_prerequisite(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["prerequisites"]["airplane_completion_bits"] = 0x1FE
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "airplane completion predicate"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_flight_frame_prerequisite_cannot_be_spliced_or_late(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            result = validate_flight_frame(
                receipt,
                frame_path,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )
            self.assertEqual(
                result["prerequisite_observation"],
                {
                    "capture_id": "owner-vm-flight-20260930-001",
                    "process_id": 4321,
                    "image_name": "MulleMeck.exe",
                    "manager_tick": 110,
                    "manager_ticks": 1502,
                    "manager_pointer": 0x20000000,
                    "application_pointer": 0x10000000,
                    "input_context_pointer": 0x10000000,
                    "cursor_pointer": 0x40000000,
                    "cursor": [100, 200],
                    "airplane_pointer": 0x10000160,
                    "airplane_completion_pointer": 0x10000288,
                    "current_mode_pointer": 0x30000000,
                    "current_mode_vtable": "0x0044caec",
                    "mode_loaded": True,
                    "mode_opened": True,
                },
            )

        for field, value, message in (
            (
                "capture_id",
                "owner-vm-arrow-20260930-001",
                "airplane prerequisite identity differs",
            ),
            ("process_id", 9999, "airplane prerequisite identity differs"),
            ("image_name", "Other.exe", "airplane prerequisite identity differs"),
            ("manager_tick", 120, "prerequisite chronology differs"),
            ("manager_ticks", 1501, "Manager tick total differs"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["prerequisites"][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(
                    OwnerVMFlightReceiptError, message
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_flight_frame_requires_matching_runtime_media_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["runtime_media"]["executable_sha256"] = "7" * 64
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "runtime media identity differs"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_flight_frame_rejects_drifted_source_identity_file(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            identity_path = Path(directory) / "source_identity.json"
            identity = json.loads(SOURCE_IDENTITY.read_text(encoding="utf-8"))
            identity["iso"]["sha256"] = "9" * 64
            identity_path.write_text(json.dumps(identity), encoding="utf-8")
            receipt["source"]["iso_sha256"] = "9" * 64
            receipt["runtime_media"]["iso_sha256"] = "9" * 64
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "reviewed source identity bytes differ",
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=identity_path,
                    transition_contract_path=TRANSITIONS,
                )

    def test_runtime_media_cannot_be_spliced_across_captures(self):
        for field, value in (
            ("measurement_capture_id", "other-capture"),
            ("measured_process_id", 9999),
            ("measured_image_name", "Other.exe"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["runtime_media"][field] = value
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "runtime media capture identity differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_runtime_state_cannot_be_spliced_across_captures(self):
        for field, value in (
            ("capture_id", "owner-vm-arrow-20260930-001"),
            ("process_id", 9999),
            ("image_name", "Other.exe"),
        ):
            with self.subTest(field=field), \
                    tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["runtime"][field] = value
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "Flight runtime capture identity differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_flight_frame_chronology_is_bound_to_manager_ticks(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["transitions"][1]["manager_tick"] = 119
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "transition chronology"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_owner_input_chronology_is_bound_to_manager_ticks(self):
        mutations = (
            ("login_submit_manager_tick", 120),
            ("barn_escape_manager_tick", 121),
            ("faster_key_down_manager_tick", 120),
            ("faster_key_up_manager_tick", 139),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["input"][field] = value
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "owner input chronology differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["runtime"]["create_results"][1]["manager_tick"] = 140
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "CreateDevice chronology"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_owner_input_claims_bind_getdevicedata_event_ids(self):
        mutations = (
            ("login_submit_event_id", 0),
            ("barn_escape_event_id", 20),
            ("faster_key_down_event_id", 7),
            ("faster_key_up_event_id", 12),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["input"][field] = value
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "owner input event identity differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["frame"]["manager_tick"] = 140
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "frame chronology"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_owner_input_stream_identity_is_fail_closed(self):
        mutations = (
            ("getdevicedata_record_format", "DIRECTINPUT_BUFFERED_8_BYTE"),
            ("getdevicedata_stream_byte_count", 18 * 16),
            ("getdevicedata_stream_sha256", "not-a-hash"),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["input"][field] = value
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "owner input stream identity differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_create_result_caller_module_identity_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["runtime"]["create_results"][0][
                "caller_module_sha256"
            ] = "5" * 64
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "original executable caller identity differs",
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_create_result_caller_module_kind_is_fail_closed(self):
        for caller_module in ("extensionless-module", "Other.exe"):
            with self.subTest(caller_module=caller_module), \
                    tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["runtime"]["create_results"][0]["caller_module"] = (
                    caller_module
                )
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "Direct3D7 caller module kind differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_create_results_cannot_be_spliced_across_captures(self):
        for row_index in (0, 1):
            for field, value in (
                ("capture_id", "owner-vm-arrow-20260930-001"),
                ("process_id", 9999),
                ("image_name", "Other.exe"),
            ):
                with self.subTest(row=row_index, field=field), \
                        tempfile.TemporaryDirectory() as directory:
                    frame_path, frame = _frame_file(Path(directory))
                    receipt = _frame_receipt(frame)
                    receipt["runtime"]["create_results"][row_index][field] = value
                    with self.assertRaisesRegex(
                        OwnerVMFlightReceiptError,
                        "Direct3D7 result capture identity differs",
                    ):
                        validate_flight_frame(
                            receipt,
                            frame_path,
                            source_identity_path=SOURCE_IDENTITY,
                            transition_contract_path=TRANSITIONS,
                        )

    def test_create_result_device_state_agrees_with_hresult(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["runtime"]["create_results"][0]["device_nonnull"] = True
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "Direct3D7 result outcome differs",
            ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_create_result_module_hash_is_stable_within_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            runtime = receipt["runtime"]
            repeated = copy.deepcopy(runtime["create_results"][1])
            runtime["create_results"][1]["caller_module"] = "Other.dll"
            runtime["create_results"][1][
                "caller_module_sha256"
            ] = "4" * 64
            repeated["caller_module"] = "Other.dll"
            repeated["caller_module_sha256"] = "5" * 64
            repeated["manager_tick"] = 143
            runtime["create_results"].append(repeated)
            runtime["create_calls"] = 3
            runtime["successful_create_calls"] = 2

            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "Direct3D7 caller module identity differs",
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_owner_input_stream_cannot_be_spliced_across_captures(self):
        for field, value in (
            ("getdevicedata_capture_id", "other-capture"),
            ("getdevicedata_process_id", 9999),
            ("getdevicedata_image_name", "Other.exe"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["input"][field] = value
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "owner input stream capture identity differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_direct3d7_module_identity_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["runtime"]["direct3d7_module"] = "MulleMeck.exe"
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "Direct3D7 module identity differs",
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_direct3d7_load_precedes_device_creation(self):
        for tick, message in (
            (142, "first Direct3D7 CreateDevice result"),
            (1503, "total Manager ticks"),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["runtime"]["direct3d7_load_manager_tick"] = tick
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "Direct3D7 load chronology differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["runtime"]["create_results"][1][
                "caller_module_sha256"
            ] = "9" * 64
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "Direct3D7 caller module identity differs",
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_frame_bytes_must_match_their_declared_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            payload = bytearray(frame_path.read_bytes())
            payload[:4] = b"\x99\x88\x77\x66"
            frame_path.write_bytes(payload)
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "frame bytes drifted"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_frame_file_must_be_a_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            _, frame = _frame_file(Path(directory))
            frame_path = Path(directory)
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "frame path is not a regular file",
            ):
                validate_flight_frame(
                    _frame_receipt(frame),
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_frame_file_size_is_checked_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            with frame_path.open("ab") as frame_file:
                frame_file.write(b"unbounded-extra-byte")
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "frame file size differs from the original client",
            ):
                validate_flight_frame(
                    _frame_receipt(frame),
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_flight_frame_requires_original_client_geometry(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path = Path(directory) / "flight-frame.rgba"
            payload = b"\x11\x22\x33\x44" + b"\x00" * 12
            frame_path.write_bytes(payload)
            frame = {
                "width": 2,
                "height": 2,
                "capture_id": "owner-vm-flight-20260930-001",
                "process_id": 4321,
                "image_name": "MulleMeck.exe",
                "capture_tool_sha256": _identity()["capture_tool_sha256"],
                "format": "RGBA8",
                "sequence": 12,
                "manager_tick": 1502,
                "capture_surface": "ORIGINAL_WINDOW_CLIENT",
                "conversion": "CANONICAL_RGBA8_EXACT",
                "pixel_sha256": hashlib.sha256(payload).hexdigest(),
                "changed_pixel_count": 1,
                "captured_before_process_exit": True,
            }
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "frame geometry differs"
            ):
                validate_flight_frame(
                    _frame_receipt(frame),
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

        with tempfile.TemporaryDirectory() as directory:
            frame_path = Path(directory) / "flight-frame.rgba"
            payload = bytearray(FRAME_WIDTH * 480 * 4)
            payload[:4] = b"\x12\x34\x56\x78"
            frame_path.write_bytes(payload)
            frame = {
                "width": FRAME_WIDTH,
                "height": 480,
                "capture_id": "owner-vm-flight-20260930-001",
                "process_id": 4321,
                "image_name": "MulleMeck.exe",
                "capture_tool_sha256": _identity()["capture_tool_sha256"],
                "format": "RGBA8",
                "sequence": 12,
                "manager_tick": 1502,
                "capture_surface": "ORIGINAL_WINDOW_CLIENT",
                "conversion": "CANONICAL_RGBA8_EXACT",
                "pixel_sha256": hashlib.sha256(payload).hexdigest(),
                "changed_pixel_count": 1,
                "captured_before_process_exit": True,
            }
            result = validate_flight_frame(
                _frame_receipt(frame),
                frame_path,
                source_identity_path=SOURCE_IDENTITY,
                transition_contract_path=TRANSITIONS,
            )
        self.assertEqual(result["frame"]["height"], 480)

    def test_flight_frame_cannot_be_spliced_across_captures(self):
        for field, value in (
            ("capture_id", "other-capture"),
            ("process_id", 9999),
            ("image_name", "Other.exe"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["frame"][field] = value
                with self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "Flight frame capture identity differs",
                ):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_flight_frame_binds_its_capture_tool_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["frame"]["capture_tool_sha256"] = "a" * 64
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "Flight frame capture tool differs",
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_manager_or_pixel_progress_cannot_replace_device_creation(self):
        mutations = (
            ("create_calls", 0),
            ("successful_create_calls", 0),
            ("last_create_hresult", "0x8007000E"),
            ("device_nonnull", False),
            ("direct3d7_dll_loaded", False),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                frame_path, frame = _frame_file(Path(directory))
                receipt = _frame_receipt(frame)
                receipt["runtime"][field] = value
                with self.assertRaises(OwnerVMFlightReceiptError):
                    validate_flight_frame(
                        receipt,
                        frame_path,
                        source_identity_path=SOURCE_IDENTITY,
                        transition_contract_path=TRANSITIONS,
                    )

    def test_parity_overclaim_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["proof_limits"]["native_parity_evidence"] = True
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "native_parity_evidence"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_transition_must_use_the_exact_reviewed_callsite(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["transitions"][1]["caller_site"] = "0x0041e450"
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "transition\\[1\\] differs"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_transitions_cannot_be_spliced_across_captures(self):
        for row_index in (0, 1):
            for field, value in (
                ("capture_id", "owner-vm-arrow-20260930-001"),
                ("process_id", 9999),
                ("image_name", "Other.exe"),
            ):
                with self.subTest(row=row_index, field=field), \
                        tempfile.TemporaryDirectory() as directory:
                    frame_path, frame = _frame_file(Path(directory))
                    receipt = _frame_receipt(frame)
                    receipt["transitions"][row_index][field] = value
                    with self.assertRaisesRegex(
                        OwnerVMFlightReceiptError,
                        "Flight frame transition capture identity differs",
                    ):
                        validate_flight_frame(
                            receipt,
                            frame_path,
                            source_identity_path=SOURCE_IDENTITY,
                            transition_contract_path=TRANSITIONS,
                        )

    def test_duplicate_transition_cannot_replace_the_departure_edge(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path, frame = _frame_file(Path(directory))
            receipt = _frame_receipt(frame)
            receipt["transitions"][1] = copy.deepcopy(
                receipt["transitions"][0]
            )
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "transition identities differ"
            ):
                validate_flight_frame(
                    receipt,
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_uniform_frame_bytes_are_not_actual_flight_pixel_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path = Path(directory) / "flight-frame.rgba"
            payload = bytes(FRAME_WIDTH * FRAME_HEIGHT * 4)
            frame_path.write_bytes(payload)
            frame = {
                "width": FRAME_WIDTH,
                "height": FRAME_HEIGHT,
                "capture_id": "owner-vm-flight-20260930-001",
                "process_id": 4321,
                "image_name": "MulleMeck.exe",
                "capture_tool_sha256": _identity()["capture_tool_sha256"],
                "format": "RGBA8",
                "sequence": 12,
                "manager_tick": 1502,
                "capture_surface": "ORIGINAL_WINDOW_CLIENT",
                "conversion": "CANONICAL_RGBA8_EXACT",
                "pixel_sha256": hashlib.sha256(payload).hexdigest(),
                "changed_pixel_count": 1,
                "captured_before_process_exit": True,
            }
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError, "no actual pixel variation"
            ):
                validate_flight_frame(
                    _frame_receipt(frame),
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )

    def test_alpha_only_frame_variation_is_not_flight_pixel_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path = Path(directory) / "flight-frame.rgba"
            payload = bytearray(FRAME_WIDTH * FRAME_HEIGHT * 4)
            payload[3] = 1
            frame_path.write_bytes(payload)
            frame = _frame_file(Path(directory))[1]
            frame_path.write_bytes(payload)
            frame["pixel_sha256"] = hashlib.sha256(payload).hexdigest()
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "frame bytes contain no actual RGB pixel variation",
            ):
                validate_flight_frame(
                    _frame_receipt(frame),
                    frame_path,
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=TRANSITIONS,
                )


class OwnerVMFlightReceiptCLITests(unittest.TestCase):
    def test_arrow_diagnostic_is_available_through_a_public_command(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "arrow.json"
            receipt_path.write_text(
                json.dumps(_arrow_receipt()), encoding="utf-8"
            )
            completed = subprocess.run(
                [
                    sys.executable, "-B",
                    str(ROOT / "tools/miel_vliegt/owner_vm_flight_receipt.py"),
                    str(receipt_path),
                    "--receipt-type", "arrow",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["blocker_code"], "BARN_ESCAPE_DISPATCH_UNOBSERVED"
        )
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])

    def test_bridge_sequence_is_available_through_a_public_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = root / "before.json"
            click = root / "click.json"
            after = root / "after.json"
            health = root / "health.json"
            health.write_text(json.dumps(_bridge_health()), encoding="utf-8")
            before.write_text(
                '{"ok":false,"error":"transport diagnostic"}'
                + json.dumps({"ok": True, "state": _bridge_state()}),
                encoding="utf-8",
            )
            click.write_text(
                json.dumps({"ok": True, "click": _bridge_click()}),
                encoding="utf-8",
            )
            after.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "state": _bridge_state(
                            barn_view=1, x=450, y=150
                        ),
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable, "-B",
                    str(ROOT / "tools/miel_vliegt/owner_vm_flight_receipt.py"),
                    "--receipt-type", "bridge-sequence",
                    "--bridge-health", str(health),
                    "--bridge-before", str(before),
                    "--bridge-click", str(click),
                    "--bridge-after", str(after),
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["status"],
            "NATIVE_OWNER_VM_BARN_DOOR_SEQUENCE_CANDIDATE_ONLY",
        )
        self.assertEqual(result["before"]["barn_view"], 0)
        self.assertEqual(result["after"]["barn_view"], 1)

    def test_bridge_health_is_fail_closed(self):
        self.assertEqual(
            validate_bridge_health(_bridge_health()),
            {
                "service": "flight-vm-bridge",
                "vm": "Windows 11",
            },
        )
        wrong_service = _bridge_health()
        wrong_service["service"] = "general-shell"
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "bridge service"
        ):
            validate_bridge_health(wrong_service)

    def test_bridge_state_names_the_current_owner_handoff(self):
        inside = classify_bridge_state(
            _bridge_health(),
            {"ok": True, "state": _bridge_state(barn_view=1, x=450, y=150)},
        )
        self.assertEqual(inside["status"], "BLOCKED")
        self.assertEqual(
            inside["blocker_code"], "OWNER_VM_BARN_OUTSIDE_RESTORE_PENDING"
        )
        self.assertEqual(inside["state"]["barn_view"], 1)
        self.assertEqual(inside["state"]["cursor"], [450, 150])
        self.assertFalse(inside["proof_limits"]["native_parity_evidence"])

        outside = classify_bridge_state(
            _bridge_health(),
            {"ok": True, "state": _bridge_state()},
        )
        self.assertEqual(
            outside["blocker_code"],
            "AIRPLANE_COMPLETION_AND_ESCAPE_INPUT_PENDING",
        )
        self.assertEqual(
            outside["required_owner_handoff"]["airplane_completion_bits"],
            0x1FF,
        )
        self.assertEqual(
            outside["required_owner_handoff"]["escape_scan_code"], "0x01"
        )
        self.assertEqual(
            outside["required_owner_handoff"]["barn_to_mygghanget_callsite"],
            "0x00419198",
        )
        self.assertEqual(
            outside["required_owner_handoff"]["state"],
            {
                "capture_id": "owner-generated valid capture ID",
                "process_id": 1234,
                "image_name": "MulleMeck.exe",
                "manager_tick": "positive integer <= manager_ticks",
                "manager_ticks": (
                    "positive integer >= prerequisite, arrow, and Escape ticks"
                ),
                "manager_pointer": 0x22222222,
                "application_pointer": 0x11111111,
                "input_context_pointer": 0x11111111,
                "cursor_pointer": 0x44444444,
                "cursor_x": 100,
                "cursor_y": 200,
                "airplane_pointer": 0x11111271,
                "airplane_completion_pointer": 0x11111399,
                "current_mode": "mode_barn",
                "current_mode_pointer": 0x33333333,
                "current_mode_vtable": "0x0044caec",
                "mode_loaded": True,
                "mode_opened": True,
                "pending_mode": None,
                "barn_view": 0,
                "airplane_complete": True,
                "airplane_pointer_nonnull": True,
                "airplane_completion_bits": 0x1FF,
            },
        )
        self.assertEqual(
            outside["required_owner_handoff"]["input_stream"],
            {
                "capture_id": "same as the airplane state capture",
                "process_id": 1234,
                "image_name": "MulleMeck.exe",
                "record_format": "DIRECTINPUT_BUFFERED_16_BYTE_LE",
                "event_count": "positive integer",
                "stream_byte_count": "event_count * 16",
                "stream_sha256": "SHA-256 of the private raw stream",
                "mouse_arrow_event_id": "1..event_count",
                "escape_dispatch_event_id": "later than the mouse event ID",
            },
        )
        self.assertEqual(
            outside["transition_contract_sha256"],
            hashlib.sha256(TRANSITIONS.read_bytes()).hexdigest(),
        )

    def test_bridge_state_rejects_transition_contract_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            contract_path = Path(directory) / "transitions.json"
            contract = json.loads(TRANSITIONS.read_text(encoding="utf-8"))
            edge = next(
                edge
                for edge in contract["edges"]
                if edge["id"] == "barn.mygghanget"
            )
            edge["address"] = "0x00419199"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "reviewed transition contract bytes differ",
            ):
                classify_bridge_state(
                    _bridge_health(),
                    {"ok": True, "state": _bridge_state()},
                    source_identity_path=SOURCE_IDENTITY,
                    transition_contract_path=contract_path,
                )

    def test_bridge_state_records_reviewed_media_without_runtime_match(self):
        result = classify_bridge_state(
            _bridge_health(),
            {"ok": True, "state": _bridge_state()},
            source_identity_path=SOURCE_IDENTITY,
        )
        identity = json.loads(SOURCE_IDENTITY.read_text(encoding="utf-8"))
        self.assertEqual(
            result["reviewed_media"],
            {
                "edition": "miel-vliegt-de-wereld-rond-nl",
                "iso": identity["iso"],
                "executable": identity["executable"],
            },
        )
        self.assertEqual(
            identity["iso"]["sha256"],
            "693a85370b704e743f56c7d6c39bc895"
            "74c1a74129ca351157e5b9514aaa3a60",
        )
        self.assertEqual(
            identity["executable"]["sha256"],
            "a84550b46612dc326177a67a84d6fd1e"
            "35aae3dc74361254611d1b03eda559a2",
        )
        self.assertEqual(
            result["source_identity_sha256"],
            hashlib.sha256(SOURCE_IDENTITY.read_bytes()).hexdigest(),
        )
        self.assertFalse(
            result["proof_limits"]["runtime_original_media_match"]
        )

    def test_bridge_state_rejects_drifted_media_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            identity_path = Path(directory) / "source_identity.json"
            identity = json.loads(
                SOURCE_IDENTITY.read_text(encoding="utf-8")
            )
            identity["executable"]["sha256"] = "0" * 64
            identity_path.write_text(
                json.dumps(identity), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "reviewed original media identity differs",
            ):
                classify_bridge_state(
                    _bridge_health(),
                    {"ok": True, "state": _bridge_state()},
                    source_identity_path=identity_path,
                )

    def test_reformatted_source_identity_is_not_an_exact_mirror(self):
        identity = json.loads(SOURCE_IDENTITY.read_text(encoding="utf-8"))
        rendered = json.dumps(identity, separators=(",", ":"))

        with tempfile.TemporaryDirectory() as directory, \
                self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "reviewed source identity bytes differ",
                ):
            identity_path = Path(directory) / "source_identity.json"
            identity_path.write_text(rendered, encoding="utf-8")
            classify_bridge_state(
                _bridge_health(),
                {"ok": True, "state": _bridge_state()},
                source_identity_path=identity_path,
            )

        with tempfile.TemporaryDirectory() as directory, \
                self.assertRaisesRegex(
                    OwnerVMFlightReceiptError,
                    "reviewed source identity bytes differ",
                ):
            frame_path, frame = _frame_file(Path(directory))
            identity_path = Path(directory) / "source_identity.json"
            identity_path.write_text(rendered, encoding="utf-8")
            validate_flight_frame(
                _frame_receipt(frame),
                frame_path,
                source_identity_path=identity_path,
                transition_contract_path=TRANSITIONS,
            )

    def test_bridge_state_is_available_through_a_public_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            health = root / "health.json"
            state = root / "state.json"
            health.write_text(json.dumps(_bridge_health()), encoding="utf-8")
            state.write_text(
                '{"ok":false,"error":"transport diagnostic"}'
                + json.dumps(
                    {
                        "ok": True,
                        "state": _bridge_state(
                            barn_view=1, x=450, y=150
                        ),
                    }
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable, "-B",
                    str(ROOT / "tools/miel_vliegt/owner_vm_flight_receipt.py"),
                    "--receipt-type", "bridge-state",
                    "--bridge-health", str(health),
                    "--bridge-state", str(state),
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["blocker_code"], "OWNER_VM_BARN_OUTSIDE_RESTORE_PENDING"
        )


class OwnerVMBridgeObservationTests(unittest.TestCase):
    def test_state_is_bound_to_the_public_barn_vtable(self):
        result = validate_bridge_observation(
            {"ok": True, "state": _bridge_state()},
            observer_hook_path=OBSERVER_HOOK,
        )
        self.assertEqual(
            result["status"], "NATIVE_OWNER_VM_BARN_STATE_DIAGNOSTIC_ONLY"
        )
        self.assertEqual(result["barn_mode_vtable"], "0x0044caec")
        self.assertEqual(result["state"]["BarnView"], 0)
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])

    def test_alternate_observer_hook_must_mirror_reviewed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            exact = Path(directory) / "native_observer_hook.c"
            exact.write_bytes(OBSERVER_HOOK.read_bytes())
            exact_result = validate_bridge_observation(
                {"ok": True, "state": _bridge_state()},
                observer_hook_path=exact,
            )
            self.assertEqual(
                exact_result["observer_hook_sha256"],
                hashlib.sha256(OBSERVER_HOOK.read_bytes()).hexdigest(),
            )

            drifted = Path(directory) / "drifted_observer_hook.c"
            drifted.write_text(
                OBSERVER_HOOK.read_text(encoding="utf-8")
                + "\n/* unrelated diagnostic comment */\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                OwnerVMFlightReceiptError,
                "public observer hook bytes differ",
            ):
                validate_bridge_observation(
                    {"ok": True, "state": _bridge_state()},
                    observer_hook_path=drifted,
                )

    def test_observer_hook_hash_uses_parsed_source_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            original = OBSERVER_HOOK.read_bytes()
            alternate = Path(directory) / "native_observer_hook.c"
            alternate.write_bytes(original)
            alternate_calls = 0

            def mutate_after_first_hash(path):
                nonlocal alternate_calls
                if path != alternate:
                    return hashlib.sha256(original).hexdigest()
                alternate_calls += 1
                if alternate_calls == 1:
                    alternate.write_bytes(
                        original + b"\n/* post-read drift */\n"
                    )
                    return hashlib.sha256(original).hexdigest()
                return hashlib.sha256(alternate.read_bytes()).hexdigest()

            with mock.patch.object(
                owner_vm_flight_receipt,
                "_sha256_file",
                side_effect=mutate_after_first_hash,
            ):
                vtable, observer_sha256 = (
                    owner_vm_flight_receipt._observer_barn_vtable(alternate)
                )

            self.assertEqual(vtable, "0x0044caec")
            self.assertEqual(
                observer_sha256,
                hashlib.sha256(original).hexdigest(),
            )
            self.assertEqual(alternate.read_bytes(), original)

    def test_door_click_is_navigation_candidate_only(self):
        result = validate_bridge_observation(
            {"ok": True, "click": _bridge_click()},
            observer_hook_path=OBSERVER_HOOK,
        )
        self.assertEqual(
            result["status"],
            "NATIVE_OWNER_VM_BARN_DOOR_NAVIGATION_CANDIDATE_ONLY",
        )
        self.assertEqual(result["click"]["barn_view_before"], 0)
        self.assertEqual(result["click"]["barn_view_after"], 1)
        self.assertFalse(result["proof_limits"]["native_flight_transition"])
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])

    def test_interior_door_restore_is_candidate_only(self):
        result = validate_bridge_observation(
            {"ok": True, "click": _bridge_restore_click()},
            observer_hook_path=OBSERVER_HOOK,
        )
        self.assertEqual(
            result["status"],
            "NATIVE_OWNER_VM_BARN_OUTSIDE_RESTORE_CANDIDATE_ONLY",
        )
        self.assertEqual(result["click"]["target"], [100, 200])
        self.assertEqual(result["click"]["barn_view_before"], 1)
        self.assertEqual(result["click"]["barn_view_after"], 0)
        self.assertFalse(
            result["proof_limits"]["airplane_completion_evidence"]
        )
        self.assertFalse(result["proof_limits"]["native_flight_transition"])
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])

    def test_vtable_or_injection_drift_fails_closed(self):
        wrong_vtable = {"ok": True, "state": _bridge_state()}
        wrong_vtable["state"]["CurrentVtable"] = "0x0044cf58"
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "barn vtable"
        ):
            validate_bridge_observation(
                wrong_vtable, observer_hook_path=OBSERVER_HOOK
            )

        wrong_click = {"ok": True, "click": _bridge_click()}
        wrong_click["click"]["injectionSeen"] = False
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "injection"
        ):
            validate_bridge_observation(
                wrong_click, observer_hook_path=OBSERVER_HOOK
            )

    def test_loader_selects_exactly_one_requested_success(self):
        raw = (
            '{"ok":false,"error":"transport diagnostic"}'
            '{"ok":true,"state":{"unused":true}}'
        )
        self.assertEqual(
            load_bridge_success(raw, "state"),
            {"ok": True, "state": {"unused": True}},
        )
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "one success"
        ):
            load_bridge_success(raw + '{"ok":true,"state":{}}', "state")

    def test_click_sequence_is_bound_to_one_live_process(self):
        result = validate_bridge_sequence(
            {"ok": True, "state": _bridge_state()},
            {"ok": True, "click": _bridge_click()},
            {
                "ok": True,
                "state": _bridge_state(barn_view=1, x=450, y=150),
            },
            observer_hook_path=OBSERVER_HOOK,
        )
        self.assertEqual(
            result["status"],
            "NATIVE_OWNER_VM_BARN_DOOR_SEQUENCE_CANDIDATE_ONLY",
        )
        self.assertEqual(result["before"]["barn_view"], 0)
        self.assertEqual(result["after"]["barn_view"], 1)
        self.assertEqual(result["before"]["cursor"], [100, 200])
        self.assertEqual(result["after"]["cursor"], [450, 150])
        self.assertNotIn("Application", result)
        self.assertNotIn("CurrentMode", result)
        self.assertFalse(
            result["proof_limits"]["airplane_completion_evidence"]
        )
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])

    def test_restore_sequence_is_bound_to_one_live_process(self):
        result = validate_bridge_sequence(
            {
                "ok": True,
                "state": _bridge_state(barn_view=1, x=450, y=150),
            },
            {"ok": True, "click": _bridge_restore_click()},
            {"ok": True, "state": _bridge_state()},
            observer_hook_path=OBSERVER_HOOK,
        )
        self.assertEqual(
            result["status"],
            "NATIVE_OWNER_VM_BARN_OUTSIDE_RESTORE_SEQUENCE_CANDIDATE_ONLY",
        )
        self.assertEqual(result["before"]["barn_view"], 1)
        self.assertEqual(result["after"]["barn_view"], 0)
        self.assertEqual(result["before"]["cursor"], [450, 150])
        self.assertEqual(result["after"]["cursor"], [100, 200])
        self.assertFalse(
            result["proof_limits"]["airplane_completion_evidence"]
        )
        self.assertFalse(result["proof_limits"]["native_parity_evidence"])

    def test_bridge_sequence_cannot_mix_observer_hook_revisions(self):
        observer_revisions = iter(("a" * 64, "a" * 64, "b" * 64))

        def changing_observer_hook(_path):
            return "0x0044caec", next(observer_revisions)

        with mock.patch.object(
            owner_vm_flight_receipt,
            "_observer_barn_vtable",
            side_effect=changing_observer_hook,
        ), self.assertRaisesRegex(
            OwnerVMFlightReceiptError,
            "observer hook revision drifted across bridge sequence",
        ):
            validate_bridge_sequence(
                {"ok": True, "state": _bridge_state()},
                {"ok": True, "click": _bridge_click()},
                {
                    "ok": True,
                    "state": _bridge_state(barn_view=1, x=450, y=150),
                },
                observer_hook_path=OBSERVER_HOOK,
            )

    def test_cross_process_or_post_click_state_drift_fails_closed(self):
        wrong_process = {"ok": True, "state": _bridge_state()}
        wrong_process["state"]["ProcessId"] += 1
        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "process identity"
        ):
            validate_bridge_sequence(
                wrong_process,
                {"ok": True, "click": _bridge_click()},
                {
                    "ok": True,
                    "state": _bridge_state(barn_view=1, x=450, y=150),
                },
                observer_hook_path=OBSERVER_HOOK,
            )

        with self.assertRaisesRegex(
            OwnerVMFlightReceiptError, "post-click state"
        ):
            validate_bridge_sequence(
                {"ok": True, "state": _bridge_state()},
                {"ok": True, "click": _bridge_click()},
                {"ok": True, "state": _bridge_state()},
                observer_hook_path=OBSERVER_HOOK,
            )


if __name__ == "__main__":
    unittest.main()
