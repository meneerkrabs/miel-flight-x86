#!/usr/bin/env python3
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.owner_vm_flight_receipt import (
    OwnerVMFlightReceiptError,
    load_bridge_success,
    validate_arrow_diagnostic,
    validate_flight_frame,
    validate_bridge_observation,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE_IDENTITY = ROOT / "content/miel_vliegt/source_identity.json"
TRANSITIONS = ROOT / "content/miel_vliegt/native_scene_transitions.json"
OBSERVER_HOOK = ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
FRAME_WIDTH = 640
FRAME_HEIGHT = 457


def _identity() -> dict:
    value = json.loads(SOURCE_IDENTITY.read_text(encoding="utf-8"))
    return {
        "edition": value["edition"],
        "iso_sha256": value["iso"]["sha256"],
        "executable_sha256": value["executable"]["sha256"],
        "transition_contract_sha256": hashlib.sha256(
            TRANSITIONS.read_bytes()
        ).hexdigest(),
        "public_source_commit": "1" * 40,
        "capture_tool_sha256": "2" * 64,
    }


def _environment() -> dict:
    return {
        "owner": "OWNER_PARALLELS_PRIVATE_VM",
        "guest": "WINDOWS_11",
        "architecture": "ARM64_HOST_X86_GAME",
        "audio": "VIRTUAL_OUTPUT_PRESENT",
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


def _bridge_state() -> dict:
    return {
        "ProcessId": 1234,
        "Application": 0x11111111,
        "Manager": 0x22222222,
        "CurrentMode": 0x33333333,
        "CurrentVtable": "0x0044caec",
        "PendingMode": 0,
        "Loaded": 1,
        "Opened": 1,
        "BarnView": 0,
        "InputContext": 0x11111111,
        "CursorObject": 0x44444444,
        "CursorX": 100,
        "CursorY": 200,
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
            "system_directinput_create_hresult": "0x80070057",
            "owner_adapter_hosted_runner_validated": False,
            "mouse_arrow_event": {
                "sequence": 7,
                "kind": "MOUSE_LEFT",
                "x": 596,
                "y": 322,
                "arrow_highlighted": True,
                "transition_observed": False,
            },
            "escape_dispatch_event": {
                "sequence": 8,
                "kind": "KEYBOARD_SCAN_CODE",
                "scan_code": "0x01",
                "dispatch_observed": False,
                "mode_set_observed": False,
            },
        },
        "state": {
            "current_mode": "mode_barn",
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
            "id": "barn.mygghanget",
            "source_mode": "mode_barn",
            "target_mode": "mode_mygghanget",
            "caller_site": "0x00419198",
            "observed": True,
        },
        {
            "id": "location.departure.mode_mygghanget",
            "source_mode": "mode_mygghanget",
            "target_mode": "mode_fly",
            "caller_site": "0x004262ee",
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
        "format": "RGBA8",
        "sequence": 12,
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
            "login_submit_observed": True,
            "barn_escape_observed": True,
            "faster_key_scan_code": "0x2a",
            "faster_key_held_until_departure": True,
        },
        "transitions": _transition_records(),
        "prerequisites": {
            "current_mode": "mode_barn",
            "pending_mode": None,
            "barn_view": 0,
            "airplane_complete": True,
            "airplane_pointer_nonnull": True,
            "airplane_completion_bits": 0x1FF,
        },
        "runtime": {
            "current_mode": "mode_fly",
            "manager_ticks": 1502,
            "direct3d7_dll_loaded": True,
            "create_method": "IDirect3D7::CreateDevice",
            "device_interface": "IID_IDirect3DDevice7",
            "create_calls": 2,
            "successful_create_calls": 1,
            "last_create_hresult": "0x00000000",
            "device_nonnull": True,
            "create_results": [
                {
                    "caller_site": "0x0042a95e",
                    "hresult": "0x8007000E",
                    "device_nonnull": False,
                },
                {
                    "caller_site": "0x0042a95e",
                    "hresult": "0x00000000",
                    "device_nonnull": True,
                },
            ],
        },
        "frame": frame,
        "proof_limits": {
            "owner_vm_only": True,
            "hosted_runner_validated": False,
            "web_pixel_comparison_performed": False,
            "independent_web_source_compared": False,
            "nine_dimension_release_evidence": False,
            "native_parity_evidence": False,
        },
    }


class OwnerVMFlightArrowDiagnosticTests(unittest.TestCase):
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
        self.assertEqual(result["frame"]["changed_pixel_count"], 1)
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
                "format": "RGBA8",
                "sequence": 12,
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


if __name__ == "__main__":
    unittest.main()
