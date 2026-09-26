#!/usr/bin/env python3
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt.windows_native_observation_readiness import (
    WindowsNativeObservationReadinessError,
    classify,
)


RUN_ID = 36233389765
HEAD_SHA = "56c9ff39cf2020e333745fbde5a10e355187ec16"
TESTED_TREE_SHA = "59e7ac3f0a7f8fde16f40085288183b3113e76e4"
PROBE_SOURCE_SHA = "b2e6464a5fb75e11f3f7fc2589d42df0e6cb6731"
PROBE_EXE_SHA = "359d65e1b7e42f5d99b8e272fb4fb6b304b9b748585556760c65f28d04a9b3fa"
HEAD_BRANCH = "codex/flight-native-observer-20260926"


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


if __name__ == "__main__":
    unittest.main()
