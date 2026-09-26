#!/usr/bin/env python3
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt.windows_native_fault_instruction_readiness import (
    WindowsNativeFaultInstructionReadinessError,
    classify,
)


RUN_ID = 36236736674
HEAD_SHA = "4df908285fb82cc417b10f34915aee0c13d313b9"
TESTED_TREE_SHA = "c0e7e0fc55a9122a4098eb626eeb18cfa054bf34"
PROBE_SOURCE_BLOB = "492edb55564777b0a8978ea0544a9f7767d8fd8b"
PROBE_EXE_SHA = "c410512ced447ac68895630a5785fb56f84c91b9cd5cbaec7ebc7fff31f7b71a"
WORKFLOW_SOURCE_BLOB = "ae88b3556e02d5083dd515e53db38567292d7792"
SOURCE_IDENTITY_BLOB = "81c38cc97d3b2dc153b8c65933784a85061dd3e5"
HEAD_BRANCH = "codex/flight-native-observer-20260926"


class WindowsNativeFaultInstructionTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.output = {
            "artifact_count": 0,
            "audio_entry_count": 38,
            "audio_entry_esi_unchanged": False,
            "audio_entry_same_thread": True,
            "audio_entry_verified": True,
            "b1c_changed_esi": False,
            "b1c_post_esi_category": "module",
            "b1c_post_matches_fatal": False,
            "b1c_single_step_seen": True,
            "button_labels_safe": ["", ""],
            "captured_height": 457,
            "captured_width": 640,
            "cd_mounted": True,
            "child_button_count": 0,
            "child_edit_count": 0,
            "child_static_count": 0,
            "create_calls": 0,
            "create_callsite_verified": True,
            "create_hr": None,
            "create_returns": 0,
            "create_success": 0,
            "debugger_attached": True,
            "device_nonnull": False,
            "dialog_reason": "none",
            "esi_block_categories": {
                "0x00409AF1": "near_null",
                "0x00409B10": "near_null",
                "0x00409B1C": "module",
            },
            "esi_block_hits": {
                "0x00409AF1": 502,
                "0x00409B10": 38,
                "0x00409B1C": 3,
            },
            "esi_block_matches_fatal": {
                "0x00409AF1": False,
                "0x00409B10": False,
                "0x00409B1C": False,
            },
            "esi_block_verified": {
                "0x00409AF1": True,
                "0x00409B10": True,
                "0x00409B1C": True,
            },
            "fatal_access_type": "read",
            "fatal_context_available": True,
            "fatal_exception_code": "0xC0000005",
            "fatal_exception_module": "MulleMeck.exe",
            "fatal_exception_rva": "0x00009B22",
            "fatal_fault_category": "unmapped",
            "fault_instruction_esi_plus_620": True,
            "fault_instruction_shape": "ACCESS_ESI_PLUS_620",
            "fault_mnemonic": "CMP",
            "fault_offset": 620,
            "fault_register": "ESI",
            "fault_register_category": "unmapped",
            "first_chance_av_count": 1,
            "gt_loaded": True,
            "hardware_dialog_closed": True,
            "hardware_selection_attempted": True,
            "hardware_selection_guard": "HARDWARE_CLICK_SENT",
            "hardware_selection_requested": True,
            "hardware_selection_sent": True,
            "instruction_shape_verified": True,
            "last_audio_arg_category": "module",
            "last_audio_ecx_category": "private",
            "last_audio_esi_category": "private",
            "last_audio_return_rva": "0x00009942",
            "last_b1c_after_audio_entry": True,
            "last_esi_transition_block": None,
            "manager_renders": 124,
            "manager_slots_verified": True,
            "manager_ticks": 125,
            "nonblack_pixels_max": 292480,
            "pixel_changes": 8,
            "pixel_samples": 11,
            "pre_fault_destinations": ["OTHER_REGISTER"],
            "pre_fault_instruction_shape": "OTHER",
            "pre_fault_mnemonics": ["MOV"],
            "pre_fault_writes_esi": False,
            "probe_sha256": PROBE_EXE_SHA,
            "process_alive_after_15s": False,
            "process_cpu_ms": 3140,
            "process_exit_code": 3221225477,
            "register_categories": {
                "EAX": "near_null",
                "EBP": "near_null",
                "EBX": "private",
                "ECX": "near_null",
                "EDI": "module",
                "EDX": "private",
                "ESI": "unmapped",
                "ESP": "private",
            },
            "stack_return_rvas": [
                {"module": "MulleMeck.exe", "rva": "0x00009942"},
                {"module": "MulleMeck.exe", "rva": "0x000086F3"},
                {"module": "MulleMeck.exe", "rva": "0x0000E0F5"},
                {"module": "MulleMeck.exe", "rva": "0x000058AC"},
            ],
            "stage": "native-observation",
            "status": "FAIL",
            "wave_out_devices": 0,
            "window_class": "none",
            "window_present": False,
            "window_title_safe": "",
        }

    def write_evidence(self, directory: Path, *, output=None):
        public_output = dict(self.output)
        public_output.update(output or {})
        rendered = json.dumps(
            public_output, sort_keys=True, separators=(",", ":")
        )
        log = (
            "checkout prefix\n"
            f"extract-in-one-job\tRun actions/checkout@v5\ttimestamp {HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {rendered}\n"
            "runner cleanup\n"
            "extract-in-one-job\tPost Run actions/checkout@v5\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": RUN_ID,
            "head_branch": HEAD_BRANCH,
            "head_sha": HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "workflow_name": "Native Flight Windows extraction readiness",
            "created_at": "2026-09-26T10:45:20Z",
            "updated_at": "2026-09-26T10:46:21Z",
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path: Path, log_path: Path):
        def source_blob(revision: str, path: str):
            return {
                "tools/miel_vliegt/windows_native_probe/native_probe.c": PROBE_SOURCE_BLOB,
                ".github/workflows/native-flight-windows-readiness.yml": WORKFLOW_SOURCE_BLOB,
                "content/miel_vliegt/source_identity.json": SOURCE_IDENTITY_BLOB,
            }[path]

        with mock.patch(
            "tools.miel_vliegt.windows_native_fault_instruction_readiness._commit_tree",
            return_value=TESTED_TREE_SHA,
        ), mock.patch(
            "tools.miel_vliegt.windows_native_fault_instruction_readiness._source_blob",
            side_effect=source_blob,
        ):
            return classify(
                manifest_path,
                log_path,
                expected_run_id=RUN_ID,
                expected_head_sha=HEAD_SHA,
                expected_head_branch=HEAD_BRANCH,
                expected_tested_tree_sha=TESTED_TREE_SHA,
                expected_probe_source_blob=PROBE_SOURCE_BLOB,
                expected_probe_executable_sha256=PROBE_EXE_SHA,
                expected_workflow_source_blob=WORKFLOW_SOURCE_BLOB,
                expected_source_identity_blob=SOURCE_IDENTITY_BLOB,
            )

    def test_fault_instruction_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        self.assertEqual(
            receipt["status"], "NATIVE_FAULT_INSTRUCTION_BOUND_DIAGNOSTIC_ONLY"
        )
        instruction = receipt["fault_instruction"]
        self.assertTrue(instruction["shape_verified"])
        self.assertEqual(instruction["mnemonic"], "CMP")
        self.assertEqual(instruction["shape"], "ACCESS_ESI_PLUS_620")
        self.assertTrue(instruction["esi_plus_620"])
        self.assertEqual(instruction["pre_fault_mnemonics"], ["MOV"])
        self.assertEqual(
            instruction["pre_fault_destinations"], ["OTHER_REGISTER"]
        )
        self.assertFalse(instruction["pre_fault_writes_esi"])
        self.assertFalse(receipt["raw_instruction_bytes_published"])
        limits = receipt["proof_limits"]
        self.assertFalse(limits["esi_writing_instruction_proven"])
        self.assertFalse(limits["fatal_root_cause_proven"])
        self.assertFalse(limits["audio_service_absence_caused_fault_proven"])
        self.assertFalse(limits["direct3d_device_creation_called"])
        self.assertFalse(limits["complete_native_gameplay_progress"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_source_identities_distinguish_git_blobs_from_sha256(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        identities = receipt["source_identities"]
        self.assertEqual(
            set(identities),
            {
                "probe_source_path",
                "probe_source_blob_id",
                "probe_executable_sha256",
                "workflow_source_path",
                "workflow_source_blob_id",
                "source_identity_path",
                "source_identity_blob_id",
            },
        )
        for name in (
            "probe_source_blob_id",
            "workflow_source_blob_id",
            "source_identity_blob_id",
        ):
            self.assertRegex(identities[name], r"^[0-9a-f]{40}$")
        self.assertEqual(identities["probe_executable_sha256"], PROBE_EXE_SHA)

    def test_unavailable_instruction_shape_cannot_substitute(self):
        unavailable = {
            "instruction_shape_verified": False,
            "fault_instruction_shape": "UNAVAILABLE",
            "fault_instruction_esi_plus_620": False,
            "fault_mnemonic": "UNAVAILABLE",
            "pre_fault_instruction_shape": "UNAVAILABLE",
            "pre_fault_mnemonics": [],
            "pre_fault_destinations": [],
            "pre_fault_writes_esi": False,
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=unavailable
            )
            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "fault instruction boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_pre_fault_mov_cannot_become_esi_write_or_root_cause(self):
        overclaim = {
            "status": "NATIVE_RENDER_DIAGNOSTIC_ONLY",
            "pre_fault_destinations": ["ESI"],
            "pre_fault_writes_esi": True,
            "create_calls": 1,
            "create_returns": 1,
            "create_success": 1,
            "device_nonnull": True,
            "process_alive_after_15s": True,
            "window_present": True,
            "process_exit_code": 0,
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=overclaim
            )
            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "fault instruction boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_identity_and_log_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(
                directory, output={"probe_sha256": "1" * 64}
            )
            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "observer probe identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = "0" * 40
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "run identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "log bytes differ",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_incidental_checkout_mention_cannot_substitute_for_checkout(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            checkout_line = (
                f"extract-in-one-job\tRun actions/checkout@v5\ttimestamp {HEAD_SHA}\n"
            ).encode("ascii")
            incidental_line = (
                f"unrelated diagnostic mentions Run actions/checkout {HEAD_SHA}\n"
            ).encode("ascii")
            raw_log = log_path.read_bytes().replace(
                checkout_line, incidental_line
            )
            self.assertNotEqual(raw_log, log_path.read_bytes())
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "checkout identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_incidental_post_cleanup_mention_cannot_substitute_for_cleanup(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            cleanup_line = (
                "extract-in-one-job\tPost Run actions/checkout@v5\tcleanup\n"
            ).encode("ascii")
            incidental_line = (
                "unrelated diagnostic mentions Post Run actions/checkout cleanup\n"
            ).encode("ascii")
            raw_log = log_path.read_bytes().replace(
                cleanup_line, incidental_line
            )
            self.assertNotEqual(raw_log, log_path.read_bytes())
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "post-checkout cleanup is missing",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_incidental_job_step_mention_cannot_substitute_for_step(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            reviewed_step = (
                "Probe private game extraction without an artifact"
            ).encode("ascii")
            unrelated_step = (
                "unrelated setup step mentions "
                "Probe private game extraction without an artifact"
            ).encode("ascii")
            raw_log = log_path.read_bytes().replace(
                reviewed_step, unrelated_step, 1
            )
            self.assertNotEqual(raw_log, log_path.read_bytes())
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "public output job step differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_cross_job_records_cannot_substitute_for_reviewed_chronology(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            raw_log = log_path.read_bytes().replace(
                b"extract-in-one-job\t", b"unrelated-job\t"
            )
            self.assertNotEqual(raw_log, log_path.read_bytes())
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                WindowsNativeFaultInstructionReadinessError,
                "checkout identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)


if __name__ == "__main__":
    unittest.main()
