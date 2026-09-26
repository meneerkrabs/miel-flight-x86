#!/usr/bin/env python3
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt.windows_native_observation_readiness import (
    WindowsNativeObservationReadinessError,
    classify_entry_transition,
    classify_fatal_context,
    classify_fatal_exception,
    classify,
    classify_hardware_progress,
    classify_renderer_selector,
)


RUN_ID = 36233389765
HEAD_SHA = "56c9ff39cf2020e333745fbde5a10e355187ec16"
TESTED_TREE_SHA = "59e7ac3f0a7f8fde16f40085288183b3113e76e4"
PROBE_SOURCE_SHA = "b2e6464a5fb75e11f3f7fc2589d42df0e6cb6731"
PROBE_EXE_SHA = "359d65e1b7e42f5d99b8e272fb4fb6b304b9b748585556760c65f28d04a9b3fa"
HEAD_BRANCH = "codex/flight-native-observer-20260926"
SELECTOR_RUN_ID = 36234230567
SELECTOR_HEAD_SHA = "2f033a0e5143452457ff09bd580744b16007137e"
SELECTOR_TREE_SHA = "d33a302507af6a49a05d89544a3778b3ea57cfe7"
SELECTOR_PROBE_SOURCE_SHA = (
    "18992874a7973ebfc6045a502f8dfdbf7051c603"
)
SELECTOR_PROBE_EXE_SHA = (
    "ab127a09d8d95278aca37033c928c644e6047c5e21c8cf8400738c33cfca3bd7"
)
HARDWARE_RUN_ID = 36234420812
HARDWARE_HEAD_SHA = "5fe9219bdd784c8b26c4d124cd877435710f79f5"
HARDWARE_TREE_SHA = "519c94b7c7e5c695d9684bd6bef6959f11bd8e93"
HARDWARE_PROBE_SOURCE_SHA = (
    "324712b7d990abdd055ca1839e64cb2c15eb0a21"
)
HARDWARE_PROBE_EXE_SHA = (
    "e10db1874c0821a2d3457d08217a774b4913aef5d0f05ce128db0e35d2b103b3"
)
FATAL_RUN_ID = 36234614734
FATAL_HEAD_SHA = "e4c125232789e3b073619350ac3747b4e9a0add6"
FATAL_TREE_SHA = "d4b8b7210b3fada0b06ec7e3dc4534ad31c1fb7a"
FATAL_PROBE_SOURCE_SHA = (
    "99f60c2bcd495976168add94a50a96aa0fb1ac06"
)
FATAL_PROBE_EXE_SHA = (
    "ce654f023ef5894e493d506bf55e9036b7fc191883cd134c62a35a592dd9e7dc"
)
CONTEXT_RUN_ID = 36235197653
CONTEXT_HEAD_SHA = "7ebb3fbdc57399a920a2d47ea8fc7db1d626443e"
CONTEXT_TREE_SHA = "347327f59b92e53b9f386e3bcd27b6fcc111e3f0"
CONTEXT_PROBE_SOURCE_SHA = (
    "44cdb58d3b6469ff5040a9fffd8cb02cf738e628"
)
CONTEXT_PROBE_EXE_SHA = (
    "58e3e6fd7716c525b30f8dc43b5c9c17fcb4a1a6eb34093abd0ff42d14a980b2"
)
ENTRY_RUN_ID = 36235520637
ENTRY_HEAD_SHA = "607edf474fe9b5ab7774638d26a36e0289857434"
ENTRY_TREE_SHA = "016cedb2243dd9f010e36c2f53ab526bb283565a"
ENTRY_PROBE_SOURCE_SHA = (
    "91bf37634830ba8048b08cd0a72ffbf6e045bec3"
)
ENTRY_PROBE_EXE_SHA = (
    "f3ec7723b57cbbf661b21df3bb15744c60cf8b2d8d54a67a64d7fc490552b241"
)


class WindowsNativeObservationReadinessTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.output = {
            "cd_mounted": True,
            "probe_sha256": PROBE_EXE_SHA,
            "manager_slots_verified": True,
            "window_present": True,
            "pixel_changes": 0,
            "create_callsite_verified": False,
            "process_alive_after_15s": True,
            "create_hr": None,
            "status": "FAIL",
            "nonblack_pixels_max": 42757,
            "child_static_count": 0,
            "captured_height": 140,
            "stage": "native-observation",
            "manager_ticks": 0,
            "create_returns": 0,
            "manager_renders": 0,
            "create_calls": 0,
            "artifact_count": 0,
            "gt_loaded": False,
            "dialog_reason": "unknown_dialog",
            "child_button_count": 2,
            "window_class": "#32770",
            "child_edit_count": 1,
            "process_cpu_ms": 187,
            "process_exit_code": 0,
            "captured_width": 318,
            "create_success": 0,
            "pixel_samples": 116,
            "device_nonnull": False,
        }

    def write_evidence(self, directory: Path, *, output=None):
        public_output = dict(self.output)
        public_output.update(output or {})
        rendered = json.dumps(
            public_output, sort_keys=True, separators=(",", ":")
        )
        log = (
            "checkout prefix\n"
            f"Run actions/checkout\ttimestamp {HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {rendered}\n"
            "runner cleanup\n"
            "Post Run actions/checkout\tcleanup\n"
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
            "created_at": "2026-09-26T09:38:29Z",
            "updated_at": "2026-09-26T09:40:25Z",
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path: Path, log_path: Path):
        with mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._commit_tree",
            return_value=TESTED_TREE_SHA,
        ), mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._source_blob",
            return_value=PROBE_SOURCE_SHA,
        ):
            return classify(
                manifest_path,
                log_path,
                expected_run_id=RUN_ID,
                expected_head_sha=HEAD_SHA,
                expected_head_branch=HEAD_BRANCH,
                expected_tested_tree_sha=TESTED_TREE_SHA,
                expected_probe_source_sha256=PROBE_SOURCE_SHA,
                expected_probe_executable_sha256=PROBE_EXE_SHA,
            )

    def test_static_dialog_observation_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        self.assertEqual(
            receipt["status"], "NATIVE_UI_DIALOG_DIAGNOSTIC_ONLY"
        )
        self.assertTrue(receipt["process_alive_after_15s"])
        self.assertTrue(receipt["window_present"])
        self.assertEqual(receipt["window_class"], "#32770")
        self.assertEqual(receipt["captured_width"], 318)
        self.assertEqual(receipt["captured_height"], 140)
        self.assertEqual(receipt["pixel_samples"], 116)
        self.assertEqual(receipt["pixel_changes"], 0)
        limits = receipt["proof_limits"]
        self.assertFalse(limits["direct3d_module_loaded"])
        self.assertFalse(limits["direct3d_device_creation_called"])
        self.assertFalse(limits["manager_ticks_observed"])
        self.assertFalse(limits["native_pixel_changes_observed"])
        self.assertFalse(limits["native_gameplay_progress"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_static_dialog_pixels_cannot_be_promoted_to_renderer_progress(self):
        promotion = {
            "status": "NATIVE_RENDER_DIAGNOSTIC_ONLY",
            "gt_loaded": True,
            "create_callsite_verified": True,
            "create_calls": 1,
            "create_returns": 1,
            "create_success": 1,
            "device_nonnull": True,
            "manager_ticks": 2,
            "manager_renders": 2,
            "pixel_changes": 1,
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=promotion
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "static dialog renderer boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_run_source_probe_and_log_identity_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = "0" * 40
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError, "run identity differs"
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(
                directory, output={"probe_sha256": "1" * 64}
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "observer probe identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_output_step_chronology_and_exact_types_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            raw_log = log_path.read_bytes().replace(
                b"Probe private game extraction without an artifact",
                b"unrelated setup step",
                1,
            )
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "public output job step differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            for message, insertion_index in (
                ("public output precedes checkout", 0),
                (
                    "public output follows post-checkout cleanup",
                    None,
                ),
            ):
                with self.subTest(message=message):
                    manifest_path, log_path = self.write_evidence(directory)
                    lines = log_path.read_text(encoding="utf-8").splitlines()
                    output_index = next(
                        index for index, line in enumerate(lines)
                        if '"probe_sha256"' in line
                    )
                    output_line = lines.pop(output_index)
                    if insertion_index is None:
                        insertion_index = next(
                            index for index, line in enumerate(lines)
                            if line.startswith("Post Run actions/checkout")
                        ) + 1
                    lines.insert(insertion_index, output_line)
                    raw_log = ("\n".join(lines) + "\n").encode("utf-8")
                    log_path.write_bytes(raw_log)
                    manifest = json.loads(
                        manifest_path.read_text(encoding="utf-8")
                    )
                    manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
                    manifest["log_bytes"] = len(raw_log)
                    manifest_path.write_text(
                        json.dumps(manifest), encoding="utf-8"
                    )
                    with self.assertRaisesRegex(
                        WindowsNativeObservationReadinessError, message
                    ):
                        self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(
                directory, output={"gt_loaded": 1, "manager_ticks": False}
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "public output types differ",
            ):
                self.classify_evidence(manifest_path, log_path)


class WindowsNativeRendererSelectorTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.output = {
            "create_hr": None,
            "profile_submit_guard": "not_requested",
            "pixel_samples": 36,
            "stage": "native-observation",
            "process_cpu_ms": 265,
            "profile_submit_sent": False,
            "create_returns": 0,
            "profile_dialog_identified": False,
            "process_alive_after_15s": True,
            "captured_height": 140,
            "manager_ticks": 0,
            "child_edit_count": 1,
            "child_static_count": 0,
            "process_exit_code": 0,
            "probe_sha256": SELECTOR_PROBE_EXE_SHA,
            "window_class": "#32770",
            "manager_slots_verified": True,
            "profile_dialog_closed": False,
            "captured_width": 318,
            "dialog_reason": "unknown_dialog",
            "status": "FAIL",
            "artifact_count": 0,
            "child_button_count": 2,
            "create_callsite_verified": False,
            "nonblack_pixels_max": 42757,
            "manager_renders": 0,
            "cd_mounted": True,
            "gt_loaded": False,
            "window_present": True,
            "create_success": 0,
            "create_calls": 0,
            "profile_submit_attempted": False,
            "window_title_safe": "REDACTED",
            "pixel_changes": 0,
            "profile_submit_accepted": False,
            "profile_submit_requested": False,
            "button_labels_safe": ["Hardware", "Software"],
            "ui_profile_hint": False,
            "device_nonnull": False,
        }

    def write_evidence(self, directory: Path, *, output=None):
        public_output = dict(self.output)
        public_output.update(output or {})
        rendered = json.dumps(
            public_output, sort_keys=True, separators=(",", ":")
        )
        log = (
            "checkout prefix\n"
            f"Run actions/checkout\ttimestamp {SELECTOR_HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {rendered}\n"
            "runner cleanup\n"
            "Post Run actions/checkout\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": SELECTOR_RUN_ID,
            "head_branch": HEAD_BRANCH,
            "head_sha": SELECTOR_HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "workflow_name": "Native Flight Windows extraction readiness",
            "created_at": "2026-09-26T09:55:33Z",
            "updated_at": "2026-09-26T09:56:40Z",
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path: Path, log_path: Path):
        with mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._commit_tree",
            return_value=SELECTOR_TREE_SHA,
        ), mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._source_blob",
            return_value=SELECTOR_PROBE_SOURCE_SHA,
        ):
            return classify_renderer_selector(
                manifest_path,
                log_path,
                expected_run_id=SELECTOR_RUN_ID,
                expected_head_sha=SELECTOR_HEAD_SHA,
                expected_head_branch=HEAD_BRANCH,
                expected_tested_tree_sha=SELECTOR_TREE_SHA,
                expected_probe_source_sha256=SELECTOR_PROBE_SOURCE_SHA,
                expected_probe_executable_sha256=SELECTOR_PROBE_EXE_SHA,
            )

    def test_passive_renderer_selector_labels_are_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        self.assertEqual(
            receipt["status"],
            "NATIVE_RENDERER_SELECTOR_PASSIVE_DIAGNOSTIC_ONLY",
        )
        self.assertEqual(
            receipt["button_labels_safe"], ["Hardware", "Software"]
        )
        self.assertEqual(receipt["window_title_safe"], "REDACTED")
        self.assertEqual(receipt["pixel_samples"], 36)
        self.assertEqual(receipt["pixel_changes"], 0)
        limits = receipt["proof_limits"]
        self.assertFalse(limits["renderer_selection_input_sent"])
        self.assertFalse(limits["direct3d_module_loaded"])
        self.assertFalse(limits["direct3d_device_creation_called"])
        self.assertFalse(limits["manager_ticks_observed"])
        self.assertFalse(limits["native_pixel_changes_observed"])
        self.assertFalse(limits["native_gameplay_progress"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_renderer_selector_labels_cannot_claim_input_or_progress(self):
        overclaim = {
            "profile_submit_requested": True,
            "profile_submit_attempted": True,
            "profile_submit_sent": True,
            "profile_submit_accepted": True,
            "profile_dialog_closed": True,
            "profile_submit_guard": "SUBMITTED",
            "gt_loaded": True,
            "create_callsite_verified": True,
            "create_calls": 1,
            "create_returns": 1,
            "create_success": 1,
            "device_nonnull": True,
            "manager_ticks": 2,
            "manager_renders": 2,
            "pixel_changes": 1,
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=overclaim
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "passive renderer-selector boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_selector_identity_safe_labels_and_log_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(
                directory, output={"button_labels_safe": ["Hardware", "Cancel"]}
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "passive renderer-selector boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(
                directory,
                output={
                    "window_title_safe": "Unreviewed raw title",
                    "probe_sha256": "1" * 64,
                },
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "observer probe identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = "0" * 40
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "run identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)


class WindowsNativeHardwareProgressTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.output = {
            "create_success": 0,
            "window_class": "none",
            "create_calls": 0,
            "child_edit_count": 0,
            "device_nonnull": False,
            "process_cpu_ms": 2640,
            "probe_sha256": HARDWARE_PROBE_EXE_SHA,
            "hardware_selection_requested": True,
            "hardware_selection_guard": "HARDWARE_CLICK_SENT",
            "create_returns": 0,
            "manager_slots_verified": True,
            "pixel_samples": 8,
            "gt_loaded": True,
            "window_title_safe": "",
            "captured_height": 457,
            "hardware_dialog_closed": True,
            "process_alive_after_15s": False,
            "dialog_reason": "none",
            "button_labels_safe": ["", ""],
            "artifact_count": 0,
            "child_static_count": 0,
            "manager_ticks": 120,
            "pixel_changes": 6,
            "process_exit_code": 3221225477,
            "create_hr": None,
            "hardware_selection_sent": True,
            "manager_renders": 119,
            "captured_width": 640,
            "nonblack_pixels_max": 290688,
            "status": "FAIL",
            "child_button_count": 0,
            "window_present": False,
            "create_callsite_verified": True,
            "stage": "native-observation",
            "cd_mounted": True,
            "hardware_selection_attempted": True,
        }

    def write_evidence(self, directory: Path, *, output=None):
        public_output = dict(self.output)
        public_output.update(output or {})
        rendered = json.dumps(
            public_output, sort_keys=True, separators=(",", ":")
        )
        log = (
            "checkout prefix\n"
            f"Run actions/checkout\ttimestamp {HARDWARE_HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {rendered}\n"
            "runner cleanup\n"
            "Post Run actions/checkout\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": HARDWARE_RUN_ID,
            "head_branch": HEAD_BRANCH,
            "head_sha": HARDWARE_HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "workflow_name": "Native Flight Windows extraction readiness",
            "created_at": "2026-09-26T09:59:40Z",
            "updated_at": "2026-09-26T10:00:26Z",
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path: Path, log_path: Path):
        with mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._commit_tree",
            return_value=HARDWARE_TREE_SHA,
        ), mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._source_blob",
            return_value=HARDWARE_PROBE_SOURCE_SHA,
        ):
            return classify_hardware_progress(
                manifest_path,
                log_path,
                expected_run_id=HARDWARE_RUN_ID,
                expected_head_sha=HARDWARE_HEAD_SHA,
                expected_head_branch=HEAD_BRANCH,
                expected_tested_tree_sha=HARDWARE_TREE_SHA,
                expected_probe_source_sha256=HARDWARE_PROBE_SOURCE_SHA,
                expected_probe_executable_sha256=HARDWARE_PROBE_EXE_SHA,
            )

    def test_hardware_progress_and_fatal_exit_remain_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        self.assertEqual(
            receipt["status"], "NATIVE_HARDWARE_PROGRESS_CRASH_DIAGNOSTIC_ONLY"
        )
        progress = receipt["runtime_progress"]
        self.assertTrue(progress["hardware_selection_sent"])
        self.assertTrue(progress["direct3d_module_loaded"])
        self.assertEqual(progress["manager_ticks"], 120)
        self.assertEqual(progress["manager_renders"], 119)
        self.assertEqual(progress["pixel_samples"], 8)
        self.assertEqual(progress["pixel_changes"], 6)
        self.assertEqual(progress["captured_width"], 640)
        self.assertEqual(progress["captured_height"], 457)
        failure = receipt["failure_boundary"]
        self.assertFalse(failure["process_alive_after_15s"])
        self.assertEqual(failure["process_exit_code"], 3221225477)
        self.assertEqual(failure["process_exit_code_hex"], "0xC0000005")
        self.assertTrue(failure["fatal_access_violation_inferred_from_exit_code"])
        limits = receipt["proof_limits"]
        self.assertFalse(limits["direct3d_device_creation_called"])
        self.assertFalse(limits["direct3d_device_created"])
        self.assertFalse(limits["process_survived_15s"])
        self.assertFalse(limits["fatal_exception_module_proven"])
        self.assertFalse(limits["fatal_exception_rva_proven"])
        self.assertFalse(limits["complete_native_gameplay_progress"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_hardware_progress_cannot_become_device_or_stable_gameplay(self):
        overclaim = {
            "status": "NATIVE_RENDER_DIAGNOSTIC_ONLY",
            "create_calls": 1,
            "create_returns": 1,
            "create_success": 1,
            "device_nonnull": True,
            "process_alive_after_15s": True,
            "window_present": True,
            "window_class": "NativeGame",
            "process_exit_code": 0,
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=overclaim
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "hardware progress crash boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_hardware_identity_and_log_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(
                directory, output={"probe_sha256": "1" * 64}
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "observer probe identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = "0" * 40
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "run identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)


class WindowsNativeFatalExceptionTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.output = {
            "hardware_selection_guard": "HARDWARE_CLICK_SENT",
            "fatal_access_type": "read",
            "window_present": False,
            "process_exit_code": 3221225477,
            "probe_sha256": FATAL_PROBE_EXE_SHA,
            "cd_mounted": True,
            "process_alive_after_15s": False,
            "gt_loaded": True,
            "pixel_changes": 5,
            "fatal_exception_rva": "0x00009B22",
            "captured_height": 457,
            "create_callsite_verified": True,
            "device_nonnull": False,
            "artifact_count": 0,
            "fatal_fault_category": "unmapped",
            "child_static_count": 0,
            "captured_width": 640,
            "child_button_count": 0,
            "create_hr": None,
            "pixel_samples": 8,
            "create_calls": 0,
            "dialog_reason": "none",
            "status": "FAIL",
            "nonblack_pixels_max": 290688,
            "create_success": 0,
            "hardware_selection_sent": True,
            "hardware_selection_requested": True,
            "stage": "native-observation",
            "manager_renders": 124,
            "child_edit_count": 0,
            "fatal_exception_code": "0xC0000005",
            "window_title_safe": "",
            "first_chance_av_count": 1,
            "process_cpu_ms": 2296,
            "hardware_selection_attempted": True,
            "fatal_exception_module": "MulleMeck.exe",
            "manager_ticks": 125,
            "manager_slots_verified": True,
            "hardware_dialog_closed": True,
            "create_returns": 0,
            "button_labels_safe": ["", ""],
            "window_class": "none",
        }

    def write_evidence(self, directory: Path, *, output=None):
        public_output = dict(self.output)
        public_output.update(output or {})
        rendered = json.dumps(
            public_output, sort_keys=True, separators=(",", ":")
        )
        log = (
            "checkout prefix\n"
            f"Run actions/checkout\ttimestamp {FATAL_HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {rendered}\n"
            "runner cleanup\n"
            "Post Run actions/checkout\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": FATAL_RUN_ID,
            "head_branch": HEAD_BRANCH,
            "head_sha": FATAL_HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "workflow_name": "Native Flight Windows extraction readiness",
            "created_at": "2026-09-26T10:03:17Z",
            "updated_at": "2026-09-26T10:04:16Z",
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path: Path, log_path: Path):
        with mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._commit_tree",
            return_value=FATAL_TREE_SHA,
        ), mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._source_blob",
            return_value=FATAL_PROBE_SOURCE_SHA,
        ):
            return classify_fatal_exception(
                manifest_path,
                log_path,
                expected_run_id=FATAL_RUN_ID,
                expected_head_sha=FATAL_HEAD_SHA,
                expected_head_branch=HEAD_BRANCH,
                expected_tested_tree_sha=FATAL_TREE_SHA,
                expected_probe_source_sha256=FATAL_PROBE_SOURCE_SHA,
                expected_probe_executable_sha256=FATAL_PROBE_EXE_SHA,
            )

    def test_located_fatal_exception_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        self.assertEqual(
            receipt["status"], "NATIVE_FATAL_EXCEPTION_LOCATED_DIAGNOSTIC_ONLY"
        )
        located = receipt["fatal_exception"]
        self.assertEqual(located["code"], "0xC0000005")
        self.assertEqual(located["module"], "MulleMeck.exe")
        self.assertEqual(located["rva"], "0x00009B22")
        self.assertEqual(located["access_type"], "read")
        self.assertEqual(located["fault_category"], "unmapped")
        self.assertEqual(located["first_chance_av_count"], 1)
        progress = receipt["runtime_progress"]
        self.assertEqual(progress["manager_ticks"], 125)
        self.assertEqual(progress["manager_renders"], 124)
        self.assertEqual(progress["pixel_changes"], 5)
        limits = receipt["proof_limits"]
        self.assertFalse(limits["direct3d_device_creation_called"])
        self.assertFalse(limits["direct3d_device_created"])
        self.assertFalse(limits["fatal_root_cause_proven"])
        self.assertFalse(limits["fatal_fault_target_address_proven"])
        self.assertFalse(limits["fatal_call_stack_proven"])
        self.assertFalse(limits["complete_native_gameplay_progress"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_unavailable_exception_fields_cannot_substitute_for_location(self):
        unavailable = {
            "fatal_exception_code": None,
            "fatal_exception_module": "unknown",
            "fatal_exception_rva": None,
            "fatal_access_type": "unavailable",
            "fatal_fault_category": "unavailable",
            "first_chance_av_count": 0,
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=unavailable
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "located fatal exception boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_fatal_location_cannot_become_device_or_parity_proof(self):
        overclaim = {
            "status": "NATIVE_RENDER_DIAGNOSTIC_ONLY",
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
                WindowsNativeObservationReadinessError,
                "located fatal exception boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_fatal_identity_and_log_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(
                directory, output={"probe_sha256": "1" * 64}
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "observer probe identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = "0" * 40
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "run identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)


class WindowsNativeFatalContextTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.output = {
            "hardware_selection_attempted": True,
            "window_class": "none",
            "fatal_exception_code": "0xC0000005",
            "dialog_reason": "none",
            "child_button_count": 0,
            "process_cpu_ms": 2093,
            "pixel_changes": 5,
            "probe_sha256": CONTEXT_PROBE_EXE_SHA,
            "create_callsite_verified": True,
            "process_exit_code": 3221225477,
            "hardware_selection_requested": True,
            "gt_loaded": True,
            "fatal_fault_category": "unmapped",
            "manager_renders": 121,
            "fatal_exception_rva": "0x00009B22",
            "first_chance_av_count": 1,
            "register_categories": {
                "EAX": "near_null",
                "EBX": "private",
                "ECX": "near_null",
                "EDX": "private",
                "ESI": "unmapped",
                "EDI": "module",
                "EBP": "near_null",
                "ESP": "private",
            },
            "window_title_safe": "",
            "fatal_context_available": True,
            "create_calls": 0,
            "fault_register": "ESI",
            "fatal_exception_module": "MulleMeck.exe",
            "hardware_dialog_closed": True,
            "captured_width": 640,
            "hardware_selection_sent": True,
            "captured_height": 457,
            "manager_ticks": 122,
            "create_success": 0,
            "nonblack_pixels_max": 290688,
            "fatal_access_type": "read",
            "create_returns": 0,
            "status": "FAIL",
            "window_present": False,
            "hardware_selection_guard": "HARDWARE_CLICK_SENT",
            "button_labels_safe": ["", ""],
            "artifact_count": 0,
            "fault_offset": 620,
            "fault_register_category": "unmapped",
            "child_static_count": 0,
            "stack_return_rvas": [
                {"module": "MulleMeck.exe", "rva": "0x00009942"},
                {"module": "MulleMeck.exe", "rva": "0x000086F3"},
                {"module": "MulleMeck.exe", "rva": "0x0000E0F5"},
                {"module": "MulleMeck.exe", "rva": "0x000058AC"},
            ],
            "device_nonnull": False,
            "process_alive_after_15s": False,
            "manager_slots_verified": True,
            "pixel_samples": 9,
            "cd_mounted": True,
            "stage": "native-observation",
            "child_edit_count": 0,
            "debugger_attached": True,
            "create_hr": None,
        }

    def write_evidence(self, directory: Path, *, output=None):
        public_output = dict(self.output)
        public_output.update(output or {})
        rendered = json.dumps(
            public_output, sort_keys=True, separators=(",", ":")
        )
        log = (
            "checkout prefix\n"
            f"Run actions/checkout\ttimestamp {CONTEXT_HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {rendered}\n"
            "runner cleanup\n"
            "Post Run actions/checkout\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": CONTEXT_RUN_ID,
            "head_branch": HEAD_BRANCH,
            "head_sha": CONTEXT_HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "workflow_name": "Native Flight Windows extraction readiness",
            "created_at": "2026-09-26T10:14:43Z",
            "updated_at": "2026-09-26T10:15:28Z",
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path: Path, log_path: Path):
        with mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._commit_tree",
            return_value=CONTEXT_TREE_SHA,
        ), mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._source_blob",
            return_value=CONTEXT_PROBE_SOURCE_SHA,
        ):
            return classify_fatal_context(
                manifest_path,
                log_path,
                expected_run_id=CONTEXT_RUN_ID,
                expected_head_sha=CONTEXT_HEAD_SHA,
                expected_head_branch=HEAD_BRANCH,
                expected_tested_tree_sha=CONTEXT_TREE_SHA,
                expected_probe_source_sha256=CONTEXT_PROBE_SOURCE_SHA,
                expected_probe_executable_sha256=CONTEXT_PROBE_EXE_SHA,
            )

    def test_fatal_context_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        self.assertEqual(
            receipt["status"], "NATIVE_FATAL_CONTEXT_BOUND_DIAGNOSTIC_ONLY"
        )
        context = receipt["fatal_context"]
        self.assertTrue(context["available"])
        self.assertTrue(context["debugger_attached"])
        self.assertEqual(context["fault_register"], "ESI")
        self.assertEqual(context["fault_offset"], 620)
        self.assertEqual(context["fault_register_category"], "unmapped")
        self.assertEqual(context["register_categories"]["ESI"], "unmapped")
        self.assertEqual(len(context["stack_return_rvas"]), 4)
        self.assertTrue(all(
            row["module"] == "MulleMeck.exe"
            for row in context["stack_return_rvas"]
        ))
        self.assertFalse(receipt["raw_register_values_published"])
        limits = receipt["proof_limits"]
        self.assertFalse(limits["fatal_fault_target_address_proven"])
        self.assertFalse(limits["fatal_call_stack_proven"])
        self.assertFalse(limits["fatal_root_cause_proven"])
        self.assertFalse(limits["direct3d_device_creation_called"])
        self.assertFalse(limits["complete_native_gameplay_progress"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_partial_fatal_context_cannot_substitute_for_bound_context(self):
        partial = {
            "fatal_context_available": False,
            "fault_register": None,
            "fault_offset": None,
            "fault_register_category": None,
            "register_categories": {
                name: "unavailable" for name in (
                    "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
                )
            },
            "stack_return_rvas": [],
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=partial
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "fatal context boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_fatal_context_cannot_become_root_cause_or_device_proof(self):
        overclaim = {
            "status": "NATIVE_RENDER_DIAGNOSTIC_ONLY",
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
                WindowsNativeObservationReadinessError,
                "fatal context boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_fatal_context_identity_and_log_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(
                directory, output={"probe_sha256": "1" * 64}
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "observer probe identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = "0" * 40
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "run identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)


class WindowsNativeEntryTransitionTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.output = {
            "child_static_count": 0,
            "fault_register": "ESI",
            "window_class": "none",
            "audio_entry_count": 38,
            "last_audio_arg_category": "module",
            "manager_slots_verified": True,
            "pixel_samples": 9,
            "first_chance_av_count": 1,
            "pixel_changes": 6,
            "fatal_exception_module": "MulleMeck.exe",
            "hardware_selection_guard": "HARDWARE_CLICK_SENT",
            "child_edit_count": 0,
            "process_cpu_ms": 2437,
            "last_audio_ecx_category": "private",
            "button_labels_safe": ["", ""],
            "process_exit_code": 3221225477,
            "hardware_selection_requested": True,
            "create_callsite_verified": True,
            "fault_register_category": "unmapped",
            "audio_entry_same_thread": True,
            "stack_return_rvas": [
                {"module": "MulleMeck.exe", "rva": "0x00009942"},
                {"module": "MulleMeck.exe", "rva": "0x000086F3"},
                {"module": "MulleMeck.exe", "rva": "0x0000E0F5"},
                {"module": "MulleMeck.exe", "rva": "0x000058AC"},
            ],
            "captured_width": 640,
            "fatal_access_type": "read",
            "manager_renders": 120,
            "fault_offset": 620,
            "create_hr": None,
            "process_alive_after_15s": False,
            "nonblack_pixels_max": 290688,
            "debugger_attached": True,
            "create_returns": 0,
            "window_present": False,
            "create_success": 0,
            "fatal_context_available": True,
            "artifact_count": 0,
            "fatal_fault_category": "unmapped",
            "last_audio_esi_category": "private",
            "fatal_exception_rva": "0x00009B22",
            "gt_loaded": True,
            "hardware_selection_attempted": True,
            "register_categories": {
                "EAX": "near_null",
                "EBX": "private",
                "ECX": "near_null",
                "EDX": "private",
                "ESI": "unmapped",
                "EDI": "module",
                "EBP": "near_null",
                "ESP": "private",
            },
            "stage": "native-observation",
            "child_button_count": 0,
            "create_calls": 0,
            "dialog_reason": "none",
            "manager_ticks": 121,
            "status": "FAIL",
            "last_audio_return_rva": "0x00009942",
            "hardware_dialog_closed": True,
            "fatal_exception_code": "0xC0000005",
            "device_nonnull": False,
            "captured_height": 457,
            "audio_entry_esi_unchanged": False,
            "audio_entry_verified": True,
            "cd_mounted": True,
            "hardware_selection_sent": True,
            "window_title_safe": "",
            "probe_sha256": ENTRY_PROBE_EXE_SHA,
        }

    def write_evidence(self, directory: Path, *, output=None):
        public_output = dict(self.output)
        public_output.update(output or {})
        rendered = json.dumps(
            public_output, sort_keys=True, separators=(",", ":")
        )
        log = (
            "checkout prefix\n"
            f"Run actions/checkout\ttimestamp {ENTRY_HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {rendered}\n"
            "runner cleanup\n"
            "Post Run actions/checkout\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": ENTRY_RUN_ID,
            "head_branch": HEAD_BRANCH,
            "head_sha": ENTRY_HEAD_SHA,
            "status": "completed",
            "conclusion": "failure",
            "workflow_name": "Native Flight Windows extraction readiness",
            "created_at": "2026-09-26T10:21:03Z",
            "updated_at": "2026-09-26T10:21:59Z",
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path: Path, log_path: Path):
        with mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._commit_tree",
            return_value=ENTRY_TREE_SHA,
        ), mock.patch(
            "tools.miel_vliegt.windows_native_observation_readiness._source_blob",
            return_value=ENTRY_PROBE_SOURCE_SHA,
        ):
            return classify_entry_transition(
                manifest_path,
                log_path,
                expected_run_id=ENTRY_RUN_ID,
                expected_head_sha=ENTRY_HEAD_SHA,
                expected_head_branch=HEAD_BRANCH,
                expected_tested_tree_sha=ENTRY_TREE_SHA,
                expected_probe_source_sha256=ENTRY_PROBE_SOURCE_SHA,
                expected_probe_executable_sha256=ENTRY_PROBE_EXE_SHA,
            )

    def test_entry_to_fault_esi_transition_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)

        self.assertEqual(
            receipt["status"], "NATIVE_ENTRY_TRANSITION_DIAGNOSTIC_ONLY"
        )
        entry = receipt["entry_observation"]
        self.assertTrue(entry["verified"])
        self.assertEqual(entry["count"], 38)
        self.assertTrue(entry["same_thread_as_fatal"])
        self.assertEqual(entry["esi_category"], "private")
        self.assertEqual(entry["ecx_category"], "private")
        self.assertEqual(entry["argument_category"], "module")
        self.assertEqual(entry["return_rva"], "0x00009942")
        transition = receipt["esi_transition"]
        self.assertEqual(transition["at_entry"], "private")
        self.assertEqual(transition["at_fault"], "unmapped")
        self.assertTrue(transition["changed_inside_function"])
        self.assertFalse(receipt["raw_register_values_published"])
        limits = receipt["proof_limits"]
        self.assertFalse(limits["invalid_entry_esi_proven"])
        self.assertFalse(limits["mutation_instruction_proven"])
        self.assertFalse(limits["fatal_root_cause_proven"])
        self.assertFalse(limits["direct3d_device_creation_called"])
        self.assertFalse(limits["complete_native_gameplay_progress"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_missing_entry_observation_cannot_substitute_for_transition(self):
        missing = {
            "audio_entry_verified": False,
            "audio_entry_count": 0,
            "last_audio_esi_category": "unavailable",
            "last_audio_ecx_category": "unavailable",
            "last_audio_arg_category": "unavailable",
            "last_audio_return_rva": None,
            "audio_entry_same_thread": False,
            "audio_entry_esi_unchanged": False,
        }
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(
                Path(raw), output=missing
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "entry transition boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_esi_change_cannot_become_invalid_input_or_device_proof(self):
        overclaim = {
            "status": "NATIVE_RENDER_DIAGNOSTIC_ONLY",
            "audio_entry_esi_unchanged": True,
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
                WindowsNativeObservationReadinessError,
                "entry transition boundary differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_entry_identity_and_log_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(
                directory, output={"probe_sha256": "1" * 64}
            )
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "observer probe identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = "0" * 40
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError,
                "run identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeObservationReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)


if __name__ == "__main__":
    unittest.main()
