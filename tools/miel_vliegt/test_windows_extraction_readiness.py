import copy
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from tools.miel_vliegt import windows_extraction_readiness as extraction_readiness
from tools.miel_vliegt.windows_extraction_readiness import (
    WindowsExtractionReadinessError,
    classify,
    main,
)


RUN_ID = 36229051318
HEAD_SHA = "8798716c256770b821e1ddb68a71add46ec344dd"
TESTED_TREE_SHA = "5338d73e8567051cc4c0b97fece63fe257130bdf"
ISO_SHA = "693a85370b704e743f56c7d6c39bc89574c1a74129ca351157e5b9514aaa3a60"
EXE_SHA = "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"


class WindowsExtractionReadinessTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.public_status = {
            "iso_sha256_matched": True,
            "executable_sha256_matched": True,
            "native_game_started": False,
        }

    def write_evidence(
        self,
        directory: Path,
        *,
        public_status=None,
        output=None,
    ):
        public_status = self.public_status if public_status is None else public_status
        public_output = {
            "status": "EXTRACTION_READY",
            "artifact_count": 0,
            "iso_sha256_matched": True,
            "executable_sha256_matched": True,
        }
        public_output.update(output or {})
        log = (
            "runner setup\n"
            f"extract-in-one-job\tRun actions/checkout@v5\ttimestamp {HEAD_SHA}\n"
            "extract-in-one-job\tProbe private game extraction without an artifact\t"
            "runner timestamp "
            f"{json.dumps(public_output, sort_keys=True, separators=(',', ':'))}\n"
            "runner cleanup\n"
            "extract-in-one-job\tPost Run actions/checkout@v5\tcleanup\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": RUN_ID,
            "head_sha": HEAD_SHA,
            "status": "success",
            "artifact_count": 0,
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
            "public_status": public_status,
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
            expected_iso_sha256=ISO_SHA,
            expected_executable_sha256=EXE_SHA,
        )

    def test_successful_extraction_is_readiness_only(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = self.classify_evidence(manifest_path, log_path)
        self.assertEqual(receipt["status"], "EXTRACTION_READY")
        self.assertTrue(receipt["extraction_ready"])
        self.assertFalse(receipt["native_game_started"])
        limits = receipt["proof_limits"]
        self.assertFalse(limits["original_process_started"])
        self.assertFalse(limits["direct3d_device_created"])
        self.assertFalse(limits["manager_initialized"])
        self.assertFalse(limits["native_pixels_captured"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_source_identity_filename_cannot_drift(self):
        identity = {
            "schema": 1,
            "iso": {"filename": "renamed.iso", "sha256": ISO_SHA},
            "executable": {
                "filename": "MulleMeck.exe", "sha256": EXE_SHA
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            identity_path = directory / "identity.json"
            identity_path.write_text(json.dumps(identity), encoding="utf-8")
            arguments = [
                "windows_extraction_readiness.py",
                "--manifest", str(manifest_path),
                "--log", str(log_path),
                "--run-id", str(RUN_ID),
                "--head-sha", HEAD_SHA,
                "--identity", str(identity_path),
            ]
            with mock.patch("sys.argv", arguments), \
                    redirect_stdout(StringIO()):
                with self.assertRaisesRegex(
                    WindowsExtractionReadinessError,
                    "source identity differs",
                ):
                    main()

    def test_working_tree_identity_cannot_substitute_for_head_identity(self):
        drifted_identity = {
            "schema": 1,
            "iso": {"filename": "working-tree.iso", "sha256": ISO_SHA},
            "executable": {
                "filename": "MulleMeck.exe", "sha256": EXE_SHA
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            identity_path = directory / "identity.json"
            identity_path.write_text(
                json.dumps(drifted_identity), encoding="utf-8"
            )
            arguments = [
                "windows_extraction_readiness.py",
                "--manifest", str(manifest_path),
                "--log", str(log_path),
                "--run-id", str(RUN_ID),
                "--head-sha", HEAD_SHA,
                "--identity", str(identity_path),
            ]
            original_load = extraction_readiness._load

            def load_identity_only(path, label):
                if label in ("source identity", "reviewed source identity"):
                    return drifted_identity
                return original_load(path, label)

            with mock.patch("sys.argv", arguments), \
                    mock.patch(
                        "tools.miel_vliegt.windows_extraction_readiness._load",
                        side_effect=load_identity_only,
                    ), redirect_stdout(StringIO()):
                with self.assertRaisesRegex(
                    WindowsExtractionReadinessError,
                    "source identity differs",
                ):
                    main()

    def test_identity_and_public_output_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            with self.assertRaisesRegex(
                WindowsExtractionReadinessError, "run identity differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=1,
                    expected_head_sha=HEAD_SHA,
                    expected_iso_sha256=ISO_SHA,
                    expected_executable_sha256=EXE_SHA,
                )

            manifest_path, log_path = self.write_evidence(
                directory,
                output={"iso_sha256_matched": False},
            )
            with self.assertRaisesRegex(
                WindowsExtractionReadinessError, "public output differs"
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(
                directory,
                public_status={
                    "iso_sha256_matched": True,
                    "executable_sha256_matched": True,
                    "native_game_started": True,
                },
                output={"status": "GAME_STARTED"},
            )
            with self.assertRaisesRegex(
                WindowsExtractionReadinessError, "extraction output promotes a claim"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_run_head_must_be_a_commit_object(self):
        non_commit_revision = TESTED_TREE_SHA
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            raw_log = log_path.read_bytes().replace(
                HEAD_SHA.encode("ascii"), non_commit_revision.encode("ascii")
            )
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = non_commit_revision
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsExtractionReadinessError,
                "tested source revision is not a commit",
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=RUN_ID,
                    expected_head_sha=non_commit_revision,
                    expected_iso_sha256=ISO_SHA,
                    expected_executable_sha256=EXE_SHA,
                )

    def test_log_and_manifest_hash_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                WindowsExtractionReadinessError, "log bytes differ"
            ):
                self.classify_evidence(manifest_path, log_path)

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["public_status"]["executable_sha256_matched"] = False
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsExtractionReadinessError, "public status differs"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_checkout_identity_must_appear_in_bound_log(self):
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
                WindowsExtractionReadinessError, "checkout identity differs"
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_public_output_must_come_from_the_reviewed_extraction_step(self):
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
            raw_log = log_path.read_bytes().replace(
                reviewed_step, unreviewed_step, 1
            )
            self.assertNotEqual(raw_log, log_path.read_bytes())
            log_path.write_bytes(raw_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(raw_log).hexdigest()
            manifest["log_bytes"] = len(raw_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                WindowsExtractionReadinessError,
                "public output job step differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_extraction_output_chronology_and_cleanup_are_structural(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            cleanup_line = (
                "extract-in-one-job\tPost Run actions/checkout@v5\tcleanup\n"
            ).encode("ascii")
            incidental_line = (
                "unrelated diagnostic mentions "
                "Post Run actions/checkout cleanup\n"
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
                WindowsExtractionReadinessError,
                "post-checkout cleanup is missing",
            ):
                self.classify_evidence(manifest_path, log_path)

            for message, insertion_index in (
                ("public output precedes checkout", 0),
                ("public output follows post-checkout cleanup", None),
            ):
                with self.subTest(message=message):
                    manifest_path, log_path = self.write_evidence(directory)
                    lines = log_path.read_text(encoding="utf-8").splitlines()
                    output_index = next(
                        index for index, line in enumerate(lines)
                        if '"status"' in line
                    )
                    output_line = lines.pop(output_index)
                    if insertion_index is None:
                        insertion_index = next(
                            index for index, line in enumerate(lines)
                            if line.startswith(
                                "extract-in-one-job\tPost Run actions/checkout@v5"
                            )
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
                        WindowsExtractionReadinessError, message
                    ):
                        self.classify_evidence(manifest_path, log_path)

    def test_public_output_types_cannot_use_boolean_integer_equivalence(self):
        drift = {
            "artifact_count": False,
            "iso_sha256_matched": 1,
            "executable_sha256_matched": 1,
        }
        for field, value in drift.items():
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as raw:
                    manifest_path, log_path = self.write_evidence(
                        Path(raw), output={field: value}
                    )
                    with self.assertRaisesRegex(
                        WindowsExtractionReadinessError,
                        "public output types differ",
                    ):
                        self.classify_evidence(manifest_path, log_path)

    def test_cross_job_records_cannot_substitute_for_extraction_chronology(self):
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
                WindowsExtractionReadinessError,
                "checkout identity differs",
            ):
                self.classify_evidence(manifest_path, log_path)

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            rendered = manifest_path.read_text(encoding="utf-8")
            duplicated = rendered.replace(
                '{"run_id": 36229051318,',
                '{"run_id": 36229051318,"run_id": 36229051318,',
                1,
            )
            self.assertNotEqual(rendered, duplicated)
            manifest_path.write_text(duplicated, encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsExtractionReadinessError, "duplicate JSON key"
            ):
                self.classify_evidence(manifest_path, log_path)


if __name__ == "__main__":
    unittest.main()
