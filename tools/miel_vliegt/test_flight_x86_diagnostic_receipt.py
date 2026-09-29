import copy
import contextlib
import hashlib
import json
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt.flight_x86_diagnostic_receipt import (
    FlightX86DiagnosticReceiptError,
    classify,
    main,
)


HEAD_SHA = "6b381fb9977f29a8ffc3d8101b1a17439f56044a"
TESTED_TREE_SHA = "8ea077b2bdc48042a8b3a949d90a5f5abb4963dd"
LOG_SHA = "7" * 64
EXE_SHA = "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"
OBSERVER_SHA = "6ed49d48dd68f0207acc8746f56c3a12e8146bc3b072e933a16a03f5263e32d8"
REAL_DINPUT_SHA = "e3c8e741dcf735378483fe69dfee4dd86512299323b9b3f9a657d14f288efb09"
PATCH_RECEIPT_SHA = "7fd5955b55b171564a67b9f3009e332d8792eb96810feccfe0f9da1872737672"


class FlightX86DiagnosticReceiptTests(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.checks = {
            "proxy_observer_ready": True,
            "observer_initialized": True,
            "login_pending_observed": True,
            "login_activation_observed": False,
        }
        self.launcher = {
            "schema": 1,
            "protocol": "miel-vliegt-native-observer-launch",
            "status": "FAIL",
            "phase": "proxy",
            "detail": "target-exited-before-proxy-bootstrap",
            "scene": "flight",
            "bootstrap_strategy": (
                "dinput-post-loader-worker-or-call-bootstrap"
            ),
            "input_idle_probe_timeout_ms": 0,
            "proxy_bootstrap_timeout_ms": 600000,
            "original_executable_sha256": EXE_SHA,
            "patched_executable_sha256": EXE_SHA,
            "observer_dll_sha256": OBSERVER_SHA,
            "real_dinput_sha256": REAL_DINPUT_SHA,
            "patch_receipt_sha256": PATCH_RECEIPT_SHA,
            "checks": self.checks,
        }
        self.diagnostic = {
            "schema": 1,
            "protocol": "miel-flight-bounded-log-diagnostics",
            "status": "DIAGNOSTIC_ONLY",
            "logs": [
                {
                    "alias": "log_01",
                    "known_error_codes": [],
                    "markers": {"CreateDevice": 8},
                    "role": "wine",
                    "size_bytes": 100,
                    "tail_bytes": 100,
                    "wine_error_count": 0,
                },
                {
                    "alias": "log_02",
                    "known_error_codes": ["E_OUTOFMEMORY"],
                    "markers": {"CreateDevice": 89, "MVP_EXC": 90},
                    "role": "proxy",
                    "size_bytes": 2000,
                    "tail_bytes": 2000,
                    "wine_error_count": 0,
                },
            ],
        }

    def write_evidence(self, directory: Path, diagnostic=None, checks=None):
        diagnostic = self.diagnostic if diagnostic is None else diagnostic
        checks = self.checks if checks is None else checks
        launcher = copy.deepcopy(self.launcher)
        launcher["checks"] = checks
        log = (
            "public runner prefix\n"
            f"RECEIPT CONTENT: {json.dumps(launcher, separators=(',', ':'))}\n"
            "public runner suffix\n"
            f"{json.dumps(diagnostic, sort_keys=True, separators=(',', ':'))}\n"
        ).encode("utf-8")
        log_path = directory / "run.log"
        log_path.write_bytes(log)
        manifest = {
            "run_id": 36226599632,
            "head_sha": HEAD_SHA,
            "status": "failure",
            "artifact_count": 0,
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "log_bytes": len(log),
            "receipt": {
                "phase": launcher["phase"],
                "detail": launcher["detail"],
                "checks": checks,
            },
            "bounded_diagnostic": diagnostic,
        }
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, log_path

    def test_counts_stay_aggregate_diagnostics_not_causal_proof(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            receipt = classify(
                manifest_path,
                log_path,
                expected_run_id=36226599632,
                expected_head_sha=HEAD_SHA,
                expected_executable_sha256=EXE_SHA,
                expected_observer_dll_sha256=OBSERVER_SHA,
                expected_real_dinput_sha256=REAL_DINPUT_SHA,
                expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
            )
        self.assertEqual(receipt["status"], "DIAGNOSTIC_ONLY")
        self.assertEqual(
            receipt["launcher_boundary"]["last_proven_boundary"],
            "target-exited-after-login-pending-before-activation",
        )
        self.assertEqual(
            receipt["aggregate_diagnostics"]["markers"]["CreateDevice"],
            97,
        )
        self.assertEqual(
            receipt["aggregate_diagnostics"]["known_error_codes"],
            ["E_OUTOFMEMORY"],
        )
        limits = receipt["proof_limits"]
        self.assertFalse(limits["causal_device_failure_path_proven"])
        self.assertFalse(limits["device_creation_reached_proven"])
        self.assertFalse(limits["successful_device_creation_proven"])
        self.assertFalse(limits["manager_initialization_proven"])
        self.assertFalse(limits["native_parity_evidence"])

    def test_run_head_must_be_a_commit_object(self):
        non_commit_revision = TESTED_TREE_SHA
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["head_sha"] = non_commit_revision
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError,
                "tested source revision is not a commit",
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=non_commit_revision,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_log_byte_drift_and_summary_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            log_path.write_bytes(log_path.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "log bytes differ"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            manifest_path, log_path = self.write_evidence(directory)
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "run identity differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=1,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["bounded_diagnostic"]["logs"][0]["markers"]["CreateDevice"] = 7
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "bounded diagnostic differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_unreviewed_categorical_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            diagnostic = copy.deepcopy(self.diagnostic)
            diagnostic["logs"][0]["markers"]["SECRET_MARKER"] = 1
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "diagnostic marker differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            rendered = manifest_path.read_text(encoding="utf-8")
            duplicated = rendered.replace(
                '{"run_id": 36226599632,',
                '{"run_id": 36226599632,"run_id": 36226599632,',
                1,
            )
            self.assertNotEqual(rendered, duplicated)
            manifest_path.write_text(duplicated, encoding="utf-8")
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "duplicate JSON key"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            manifest_path, log_path = self.write_evidence(directory)
            raw_log = log_path.read_bytes()
            duplicated_log = raw_log.replace(
                b'"alias":"log_01"',
                b'"alias":"log_01","alias":"log_01"',
                1,
            )
            self.assertNotEqual(raw_log, duplicated_log)
            log_path.write_bytes(duplicated_log)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(duplicated_log).hexdigest()
            manifest["log_bytes"] = len(duplicated_log)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "duplicate JSON key"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_byte_identical_target_identity_is_required(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            manifest_path, log_path = self.write_evidence(directory)
            raw_log = log_path.read_bytes()
            mutated = raw_log.replace(
                f'"patched_executable_sha256":"{EXE_SHA}"'.encode("ascii"),
                f'"patched_executable_sha256":"{"b" * 64}"'.encode("ascii"),
                1,
            )
            self.assertNotEqual(raw_log, mutated)
            log_path.write_bytes(mutated)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["log_sha256"] = hashlib.sha256(mutated).hexdigest()
            manifest["log_bytes"] = len(mutated)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError,
                "byte-identical target identity differs",
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_executable_identity_is_bound_to_the_reviewed_source(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.launcher["original_executable_sha256"] = "c" * 64
            self.launcher["patched_executable_sha256"] = "c" * 64
            manifest_path, log_path = self.write_evidence(directory)
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError,
                "executable identity differs",
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_every_launcher_source_identity_is_bound_to_reviewed_input(self):
        reviewed = {
            "observer_dll_sha256": OBSERVER_SHA,
            "real_dinput_sha256": REAL_DINPUT_SHA,
            "patch_receipt_sha256": PATCH_RECEIPT_SHA,
        }
        original_launcher = copy.deepcopy(self.launcher)
        for field, reviewed_hash in reviewed.items():
            with self.subTest(field=field):
                self.launcher = copy.deepcopy(original_launcher)
                self.launcher[field] = "c" * 64
                with tempfile.TemporaryDirectory() as raw:
                    manifest_path, log_path = self.write_evidence(Path(raw))
                    with self.assertRaisesRegex(
                        FlightX86DiagnosticReceiptError,
                        "identity differs",
                    ):
                        classify(
                            manifest_path,
                            log_path,
                            expected_run_id=36226599632,
                            expected_head_sha=HEAD_SHA,
                            expected_executable_sha256=EXE_SHA,
                            expected_observer_dll_sha256=OBSERVER_SHA,
                            expected_real_dinput_sha256=REAL_DINPUT_SHA,
                            expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                        )

    def test_failed_run_receipt_cannot_claim_launcher_success(self):
        with tempfile.TemporaryDirectory() as raw:
            self.launcher["status"] = "PASS"
            manifest_path, log_path = self.write_evidence(Path(raw))
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "launcher status differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_classifier_accepts_only_the_flight_launcher_scene(self):
        with tempfile.TemporaryDirectory() as raw:
            self.launcher["scene"] = "roy_mccoy"
            manifest_path, log_path = self.write_evidence(Path(raw))
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "launcher scene differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_launcher_bootstrap_contract_cannot_drift(self):
        drift = {
            "bootstrap_strategy": "unreviewed-bootstrap",
            "input_idle_probe_timeout_ms": 1,
            "proxy_bootstrap_timeout_ms": 599999,
        }
        original_launcher = copy.deepcopy(self.launcher)
        for field, value in drift.items():
            with self.subTest(field=field):
                self.launcher = copy.deepcopy(original_launcher)
                self.launcher[field] = value
                with tempfile.TemporaryDirectory() as raw:
                    manifest_path, log_path = self.write_evidence(Path(raw))
                    with self.assertRaisesRegex(
                        FlightX86DiagnosticReceiptError,
                        "launcher bootstrap contract differs",
                    ):
                        classify(
                            manifest_path,
                            log_path,
                            expected_run_id=36226599632,
                            expected_head_sha=HEAD_SHA,
                            expected_executable_sha256=EXE_SHA,
                            expected_observer_dll_sha256=OBSERVER_SHA,
                            expected_real_dinput_sha256=REAL_DINPUT_SHA,
                            expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                        )

    def test_public_collector_bounds_are_enforced(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            diagnostic = copy.deepcopy(self.diagnostic)
            diagnostic["logs"][0]["size_bytes"] = 64 * 1024 + 1
            diagnostic["logs"][0]["tail_bytes"] = 64 * 1024 + 1
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "diagnostic tail exceeds bound"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            manifest_path, log_path = self.write_evidence(directory)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["artifact_count"] = False
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "run artifact count differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            diagnostic = copy.deepcopy(self.diagnostic)
            diagnostic["schema"] = True
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "bounded diagnostic protocol differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_categorical_counts_must_fit_the_bounded_tail(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            diagnostic = copy.deepcopy(self.diagnostic)
            diagnostic["logs"][0]["markers"]["CreateDevice"] = 9
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "diagnostic marker count exceeds tail"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            diagnostic = copy.deepcopy(self.diagnostic)
            diagnostic["logs"][0]["wine_error_count"] = 17
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "wine error count exceeds tail"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            diagnostic = copy.deepcopy(self.diagnostic)
            diagnostic["logs"][0]["markers"]["MVP_DI"] = 1
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "diagnostic categorical bytes exceed tail"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_enriched_device_outcomes_stay_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            diagnostic = copy.deepcopy(self.diagnostic)
            for row in diagnostic["logs"]:
                row["tail_truncated"] = False
                row["device_outcomes"] = []
                row["exception_classes"] = {}
            proxy = diagnostic["logs"][1]
            proxy["markers"]["MVP_EXC"] = 2
            proxy["device_outcomes"] = [
                {"route": "HAL", "hresult": "0x8007000E", "device": "NULL"},
                {
                    "route": "RGB_RETRY",
                    "hresult": "0x8007000E",
                    "device": "NULL",
                },
            ]
            proxy["exception_classes"] = {"DEBUG_PRINT": 2}
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            receipt = classify(
                manifest_path,
                log_path,
                expected_run_id=36226599632,
                expected_head_sha=HEAD_SHA,
                expected_executable_sha256=EXE_SHA,
                expected_observer_dll_sha256=OBSERVER_SHA,
                expected_real_dinput_sha256=REAL_DINPUT_SHA,
                expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
            )
        self.assertEqual(receipt["status"], "DIAGNOSTIC_ONLY")
        self.assertEqual(len(receipt["device_outcomes"]), 2)
        self.assertEqual(
            {row["route"] for row in receipt["device_outcomes"]},
            {"HAL", "RGB_RETRY"},
        )
        self.assertEqual(receipt["exception_classes"], {"DEBUG_PRINT": 2})
        self.assertTrue(receipt["proof_limits"]["device_creation_reached_proven"])
        self.assertFalse(receipt["proof_limits"]["successful_device_creation_proven"])
        self.assertFalse(receipt["proof_limits"]["manager_initialization_proven"])
        self.assertFalse(receipt["proof_limits"]["native_parity_evidence"])

    def test_enriched_device_outcomes_fail_closed_on_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            diagnostic = copy.deepcopy(self.diagnostic)
            for row in diagnostic["logs"]:
                row["tail_truncated"] = False
                row["device_outcomes"] = []
                row["exception_classes"] = {}
            proxy = diagnostic["logs"][1]
            proxy["markers"]["MVP_EXC"] = 2
            proxy["device_outcomes"] = [
                {"route": "UNREVIEWED", "hresult": "0x8007000E", "device": "NULL"},
            ]
            proxy["exception_classes"] = {"DEBUG_PRINT": 2}
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "device outcome differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            diagnostic["logs"][1]["device_outcomes"] = [
                {"route": "HAL", "hresult": "0x8007000E", "device": "NULL"},
            ]
            diagnostic["logs"][1]["exception_classes"] = {"DEBUG_PRINT": 1}
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "exception count differs from markers"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

            diagnostic["logs"][1]["markers"]["MVP_EXC"] = 1
            diagnostic["logs"][1]["exception_classes"] = {"DEBUG_PRINT": 1}
            diagnostic["logs"][1]["known_error_codes"] = []
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError,
                "device outcome error code is missing",
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_enriched_device_outcomes_must_come_from_the_proxy_log(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            diagnostic = copy.deepcopy(self.diagnostic)
            for row in diagnostic["logs"]:
                row["tail_truncated"] = False
                row["device_outcomes"] = []
                row["exception_classes"] = {}
            diagnostic["logs"][1]["markers"]["MVP_EXC"] = 0
            wine = diagnostic["logs"][0]
            wine["device_outcomes"] = [
                {"route": "HAL", "hresult": "0x8007000E", "device": "NULL"},
            ]
            wine["known_error_codes"] = ["E_OUTOFMEMORY"]
            manifest_path, log_path = self.write_evidence(
                directory, diagnostic=diagnostic
            )
            with self.assertRaisesRegex(
                FlightX86DiagnosticReceiptError, "device outcome role differs"
            ):
                classify(
                    manifest_path,
                    log_path,
                    expected_run_id=36226599632,
                    expected_head_sha=HEAD_SHA,
                    expected_executable_sha256=EXE_SHA,
                    expected_observer_dll_sha256=OBSERVER_SHA,
                    expected_real_dinput_sha256=REAL_DINPUT_SHA,
                    expected_patch_receipt_sha256=PATCH_RECEIPT_SHA,
                )

    def test_cli_prints_only_the_bounded_reviewed_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest_path, log_path = self.write_evidence(Path(raw))
            output = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    "flight-x86-diagnostic",
                    "--manifest", str(manifest_path),
                    "--log", str(log_path),
                    "--run-id", "36226599632",
                    "--head-sha", HEAD_SHA,
                    "--executable-sha256", EXE_SHA,
                    "--observer-dll-sha256", OBSERVER_SHA,
                    "--real-dinput-sha256", REAL_DINPUT_SHA,
                    "--patch-receipt-sha256", PATCH_RECEIPT_SHA,
                ],
            ), contextlib.redirect_stdout(output):
                self.assertEqual(main(), 0)
        receipt = json.loads(output.getvalue())
        rendered = json.dumps(receipt, sort_keys=True)
        self.assertEqual(receipt["status"], "DIAGNOSTIC_ONLY")
        self.assertIn("native_parity_evidence", rendered)
        self.assertNotIn("public runner prefix", rendered)


if __name__ == "__main__":
    unittest.main()
