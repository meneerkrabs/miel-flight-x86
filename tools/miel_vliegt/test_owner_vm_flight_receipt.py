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
            "manager_tick": 120,
            "observed": True,
        },
        {
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
            "login_submit_observed": True,
            "barn_escape_observed": True,
            "faster_key_scan_code": "0x2a",
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
                    "caller_module": "MulleMeck.exe",
                    "caller_module_sha256": _identity()["executable_sha256"],
                    "caller_address_kind": "RVA",
                    "caller_site": "0x0042a95e",
                    "manager_tick": 141,
                    "hresult": "0x8007000E",
                    "device_nonnull": False,
                },
                {
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
        self.assertEqual(
            result["runtime"]["create_results"][0]["caller_module"],
            "MulleMeck.exe",
        )
        self.assertEqual(
            result["runtime"]["create_results"][0]["caller_rva"],
            "0x0042a95e",
        )
        self.assertEqual(result["frame"]["changed_pixel_count"], 1)
        self.assertEqual(result["frame"]["manager_tick"], 1502)
        self.assertEqual(
            result["runtime_media"]["executable_sha256"],
            _identity()["executable_sha256"],
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

    def test_flight_frame_requires_original_client_geometry(self):
        with tempfile.TemporaryDirectory() as directory:
            frame_path = Path(directory) / "flight-frame.rgba"
            payload = b"\x11\x22\x33\x44" + b"\x00" * 12
            frame_path.write_bytes(payload)
            frame = {
                "width": 2,
                "height": 2,
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
