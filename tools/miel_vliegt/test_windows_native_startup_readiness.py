import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.windows_native_startup_readiness import (
    WindowsNativeStartupReadinessError,
    classify,
)


RUN_ID = 36229580425
HEAD_SHA = "ef633e643f71300d975ef0dcadf4830161d3160f"
MERGED_SHA = "a738ef2c9b73ea158445608d5be5d6c0082ccb62"
TESTED_TREE_SHA = "634845c2116cb8f4909cb4061d069c4600da6426"
ISO_SHA = "693a85370b704e743f56c7d6c39bc89574c1a74129ca351157e5b9514aaa3a60"
EXE_SHA = "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"


class WindowsNativeStartupReadinessTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.public_result = {
            "executable_sha256_matched": True,
            "cd_mounted": True,
            "artifact_count": 0,
            "status": "NATIVE_STARTUP_DIAGNOSTIC_ONLY",
            "iso_sha256_matched": True,
            "process_alive_after_15s": True,
            "window_present": True,
        }

    def write_evidence(self, directory, *, public_result=None, output=None):
        public_result = self.public_result if public_result is None else public_result
        public_output = dict(self.public_result)
        public_output.update(output or {})
        log = (
            "checkout prefix\n"
            f"extract-in-one-job\tRun actions/checkout@v5\ttimestamp {HEAD_SHA}\n"
            "runner middle\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            f"timestamp {json.dumps(public_output, sort_keys=True, separators=(',', ':'))}\n"
            "runner cleanup\n"
            "Post Run actions/checkout\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": RUN_ID,
            "head_sha": HEAD_SHA,
            "merged_sha": MERGED_SHA,
            "tested_tree_matches_master": True,
            "status": "success",
            "artifact_count": 0,
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
            "public_result": public_result,
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def classify_evidence(self, manifest_path, log_path):
        return classify(
            manifest_path,
            log_path,
            expected_run_id=RUN_ID,
            expected_head_sha=HEAD_SHA,
            expected_merged_sha=MERGED_SHA,
            expected_tested_tree_sha=TESTED_TREE_SHA,
            expected_iso_sha256=ISO_SHA,
            expected_executable_sha256=EXE_SHA,
        )

    def test_live_window_is_startup_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)
        self.assertEqual(receipt["status"], "NATIVE_STARTUP_DIAGNOSTIC_ONLY")
        self.assertTrue(receipt["original_process_started"])
        self.assertTrue(receipt["process_alive_after_15s"])
        self.assertTrue(receipt["window_present"])
        limits = receipt["proof_limits"]
        self.assertFalse(limits["direct3d_device_created"])
        self.assertFalse(limits["manager_initialized"])
        self.assertFalse(limits["native_pixels_captured"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_run_identity_tree_and_public_result_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "run identity differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=1,
                    expected_head_sha=HEAD_SHA,
                    expected_merged_sha=MERGED_SHA,
                    expected_tested_tree_sha=TESTED_TREE_SHA,
                    expected_iso_sha256=ISO_SHA,
                    expected_executable_sha256=EXE_SHA,
                )

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["tested_tree_matches_master"] = False
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "tested tree identity differs"
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(
                directory, output={"window_present": False}
            )
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "public output differs"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_log_hash_and_public_type_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(
                directory, output={"process_alive_after_15s": 1}
            )
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "public output types differ"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_checkout_identity_must_appear_in_bound_log(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            raw_log = log_path.read_bytes().replace(HEAD_SHA.encode("ascii"), b"0" * 40)
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "checkout identity differs"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_incidental_head_mention_does_not_prove_checkout(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            checkout_line = (
                f"extract-in-one-job\tRun actions/checkout@v5\ttimestamp {HEAD_SHA}\n"
            ).encode("ascii")
            incidental_line = (
                f"unrelated diagnostic mentions Run actions/checkout {HEAD_SHA}\n"
            ).encode("ascii")
            raw_log = log_path.read_bytes().replace(checkout_line, incidental_line)
            self.assertNotEqual(raw_log, log_path.read_bytes())
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "checkout identity differs"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_tested_tree_identity_is_bound(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError,
                "tested tree identity differs",
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=RUN_ID,
                    expected_head_sha=HEAD_SHA,
                    expected_merged_sha=MERGED_SHA,
                    expected_tested_tree_sha="0" * 40,
                    expected_iso_sha256=ISO_SHA,
                    expected_executable_sha256=EXE_SHA,
                )

    def test_run_head_must_be_a_commit_object(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            raw_log = log_path.read_bytes().replace(
                HEAD_SHA.encode("ascii"), TESTED_TREE_SHA.encode("ascii")
            )
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = TESTED_TREE_SHA
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError,
                "tested source revision is not a commit",
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=RUN_ID,
                    expected_head_sha=TESTED_TREE_SHA,
                    expected_merged_sha=MERGED_SHA,
                    expected_tested_tree_sha=TESTED_TREE_SHA,
                    expected_iso_sha256=ISO_SHA,
                    expected_executable_sha256=EXE_SHA,
                )

    def test_public_output_must_follow_checkout(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            lines = log_path.read_text(encoding="utf-8").splitlines()
            checkout_index = next(
                index for index, line in enumerate(lines)
                if "\tRun actions/checkout@v5\t" in line
            )
            output_index = next(
                index for index, line in enumerate(lines)
                if '"status"' in line and line.rstrip().endswith("}")
            )
            output_line = lines.pop(output_index)
            lines.insert(checkout_index, output_line)
            raw_log = ("\n".join(lines) + "\n").encode("utf-8")
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError,
                "public output precedes checkout",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_public_output_must_precede_post_checkout_cleanup(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            lines = log_path.read_text(encoding="utf-8").splitlines()
            output_index = next(
                index for index, line in enumerate(lines)
                if '"status"' in line and line.rstrip().endswith("}")
            )
            post_index = next(
                index for index, line in enumerate(lines)
                if line.startswith("Post Run actions/checkout")
            )
            output_line = lines.pop(output_index)
            lines.insert(post_index, output_line)
            raw_log = ("\n".join(lines) + "\n").encode("utf-8")
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError,
                "public output follows post-checkout cleanup",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_public_output_must_come_from_the_reviewed_startup_step(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            reviewed_step = (
                "Probe private game extraction without an artifact"
            ).encode("ascii")
            unreviewed_step = (
                b"unrelated setup step mentions "
                b"Probe private game extraction without an artifact"
            )
            raw_log = log_path.read_bytes().replace(reviewed_step, unreviewed_step, 1)
            self.assertNotEqual(raw_log, log_path.read_bytes())
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError,
                "public output job step differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_manifest_public_result_types_cannot_use_boolean_integer_equivalence(self):
        drift = {
            "artifact_count": False,
            "iso_sha256_matched": 1,
            "executable_sha256_matched": 1,
            "cd_mounted": 1,
            "process_alive_after_15s": 1,
            "window_present": 1,
        }
        for field, value in drift.items():
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    manifest_path, log_path = self.write_evidence(directory)
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["public_result"][field] = value
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    with self.assertRaisesRegex(
                        WindowsNativeStartupReadinessError,
                        "public result types differ",
                    ):
                        self.classify_evidence(manifest_path, log_path)

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            rendered = manifest_path.read_text(encoding="utf-8")
            duplicated = rendered.replace(
                '{"run_id": 36229580425,',
                '{"run_id": 36229580425,"run_id": 36229580425,',
                1,
            )
            self.assertNotEqual(rendered, duplicated)
            manifest_path.write_text(duplicated, encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsNativeStartupReadinessError, "duplicate JSON key"
            ):
                self.classify_evidence(manifest_path, log_path)


if __name__ == "__main__":
    unittest.main()
