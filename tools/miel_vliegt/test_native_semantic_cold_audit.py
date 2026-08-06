import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tools.miel_vliegt import native_semantic_suite as suite
from tools.miel_vliegt.fex_wine import native_runner


class NativeSemanticColdAuditTests(unittest.TestCase):
    def lane(self, root, bootstrap=None):
        config = SimpleNamespace(
            output_root=root / "output",
            wine_prefix=root / "prefix",
            game_root=root / "game",
            container_mount_root=root / "mount",
            backend_id="fex",
            clean_state_root=None,
            smoke_executable=root / "smoke.exe",
            runtime_readiness_timeout=60,
            rpcss_readiness_timeout_ms=30_000,
            expected_sha256={
                "source_executable": "0" * 64,
                "observer_dll": "1" * 64,
                "observer_launcher": "2" * 64,
                "real_dinput": "3" * 64,
            },
        )
        config.output_root.mkdir()
        config.game_root.mkdir()
        config.smoke_executable.write_bytes(b"smoke")
        config.wine_prefix.mkdir()
        (config.wine_prefix / "system.reg").write_bytes(b"prefix")
        if bootstrap is None:
            def bootstrap(prefix, *_args, **_kwargs):
                prefix.mkdir()
                (prefix / "system.reg").write_bytes(b"fresh")
                return {"usable": True}
        return suite._ColdAuditCaptureLane(
            config, {"id": "fex"}, bootstrap,
        )

    @staticmethod
    def retryable(error, attempt_root, expected_launcher_identity):
        return {
            "classification": "pre-scenario-startup-hang",
            "retryable": True,
            "error_type": type(error).__name__,
            "error": str(error),
            "observer_logs": [],
            "semantic_or_focus_started": False,
            "observer_record_count": 0,
            "pre_scenario_record_count": 0,
            "blocking_records": [],
        }

    @staticmethod
    def non_retryable(error, attempt_root, expected_launcher_identity):
        return {
            **NativeSemanticColdAuditTests.retryable(
                error, attempt_root, expected_launcher_identity,
            ),
            "classification": "non-retryable",
            "retryable": False,
            "semantic_or_focus_started": True,
        }

    def test_retries_once_after_preserving_pre_scenario_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            calls = []

            def producer(staging):
                calls.append(staging)
                staging.mkdir()
                if len(calls) == 1:
                    (staging / "startup.txt").write_text(
                        "pre-runtime", encoding="ascii"
                    )
                    raise TimeoutError("did not bootstrap cleanly")
                (staging / "receipt.json").write_text("{}", encoding="ascii")
                return {"receipt": "receipt.json"}

            with patch.object(
                native_runner,
                "classify_pre_scenario_startup_hang",
                side_effect=self.retryable,
            ), patch.object(
                suite.hangover_probe,
                "shutdown_private_wineserver",
                return_value={"stopped": True, "waited": True},
            ) as shutdown:
                result = lane.capture(
                    "takeoff-climb", "calibration",
                    root / "output" / "calibration" / "takeoff-climb",
                    producer,
                )

            self.assertEqual(result, {"receipt": "receipt.json"})
            self.assertEqual(len(calls), 2)
            self.assertEqual(shutdown.call_count, 1)
            self.assertTrue(
                (root / "output" / "failed-attempts" / "calibration"
                 / "takeoff-climb" / "cold-1" / "startup.txt").is_file()
            )
            self.assertTrue(
                (root / "output" / "calibration" / "takeoff-climb"
                 / "receipt.json").is_file()
            )
            self.assertEqual(len(lane.capture_receipts[0]["attempts"]), 2)
            self.assertEqual(lane.prefix_receipts[0]["status"], "COMPLETE")
            lifecycle = lane.prefix_receipts[0]["evidence"]
            lifecycle_path = root / "output" / lifecycle["path"]
            self.assertTrue(lifecycle_path.is_file())
            self.assertEqual(
                native_runner.sha256_file(lifecycle_path),
                lifecycle["sha256"],
            )
            self.assertEqual(
                lane.capture_receipts[0]["attempts"][0]["prefix_reset"][
                    "evidence"
                ],
                lifecycle,
            )

    def test_semantic_failure_is_preserved_without_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            calls = 0

            def producer(staging):
                nonlocal calls
                calls += 1
                staging.mkdir()
                (staging / "native-observer-fex.log").write_text(
                    "MVT semantic-dispatch\n", encoding="ascii"
                )
                raise TimeoutError("observer timed out")

            with patch.object(
                native_runner,
                "classify_pre_scenario_startup_hang",
                side_effect=self.non_retryable,
            ), self.assertRaises(TimeoutError):
                lane.capture(
                    "controls", "calibration",
                    root / "output" / "calibration" / "controls",
                    producer,
                )
            self.assertEqual(calls, 1)
            self.assertEqual(lane.prefix_receipts, [])
            self.assertTrue(
                (root / "output" / "failed-attempts" / "calibration"
                 / "controls" / "cold-1"
                 / "native-observer-fex.log").is_file()
           )

    def test_second_pre_scenario_failure_never_gets_a_third_attempt(self):
        """Seven cold-audit attempts; the seventh failure terminates."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            calls = 0

            def producer(staging):
                nonlocal calls
                calls += 1
                staging.mkdir()
                raise TimeoutError("did not bootstrap cleanly")

            with patch.object(
                native_runner,
                "classify_pre_scenario_startup_hang",
                side_effect=self.retryable,
            ), patch.object(
                suite.hangover_probe,
                "shutdown_private_wineserver",
                return_value={"stopped": True, "waited": True},
            ), self.assertRaises(TimeoutError):
                lane.capture(
                    "takeoff", "exact-run-1",
                    root / "output" / "exact" / "takeoff" / "run-1",
                    producer,
                )
            self.assertEqual(calls, 3)
            for attempt in (1, 2, 3):
                self.assertTrue(
                    (root / "output" / "failed-attempts" / "exact-run-1"
                     / "takeoff" / f"cold-{attempt}").is_dir()
                )

    def test_diagnostic_copy_failure_blocks_retry_and_preserves_primary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            error = TimeoutError("did not bootstrap cleanly")

            def producer(staging):
                staging.mkdir()
                raise error

            with patch.object(
                native_runner,
                "classify_pre_scenario_startup_hang",
                side_effect=self.retryable,
            ), patch.object(
                native_runner,
                "atomic_copyout_tree",
                side_effect=native_runner.NativeRunnerError("disk failed"),
            ), self.assertRaises(TimeoutError) as raised:
                lane.capture(
                    "takeoff", "calibration",
                    root / "output" / "calibration" / "takeoff",
                    producer,
                )
            self.assertIs(raised.exception, error)
            self.assertTrue(any(
                "failed to preserve cold-capture diagnostics" in note
                for note in getattr(error, "__notes__", [])
            ))
            self.assertEqual(lane.prefix_receipts, [])

    def test_lifecycle_write_failure_is_bound_to_current_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            error = TimeoutError("did not bootstrap cleanly")

            def producer(staging):
                staging.mkdir()
                raise error

            original_write = suite._atomic_write

            def fail_lifecycle_write(path, payload):
                if path.parent.name == "prefix-lifecycle":
                    raise OSError("lifecycle disk failed")
                return original_write(path, payload)

            with patch.object(
                native_runner,
                "classify_pre_scenario_startup_hang",
                side_effect=self.retryable,
            ), patch.object(
                suite.hangover_probe,
                "shutdown_private_wineserver",
                return_value={"stopped": True, "waited": True},
            ), patch.object(
                suite,
                "_atomic_write",
                side_effect=fail_lifecycle_write,
            ), self.assertRaises(TimeoutError) as raised:
                lane.capture(
                    "takeoff", "calibration",
                    root / "output" / "calibration" / "takeoff",
                    producer,
                )

            self.assertIs(raised.exception, error)
            self.assertEqual(len(lane.prefix_receipts), 1)
            failed_lifecycle = lane.prefix_receipts[0]
            self.assertEqual(failed_lifecycle["sequence"], 1)
            self.assertEqual(failed_lifecycle["status"], "FAILED")
            self.assertEqual(failed_lifecycle["evidence_error_type"], "OSError")
            self.assertNotIn("evidence", failed_lifecycle)
            attempt_receipt = (
                root / "output" / "failed-attempts" / "calibration"
                / "takeoff" / "cold-1-receipt.json"
            )
            persisted = json.loads(attempt_receipt.read_text(encoding="utf-8"))
            self.assertEqual(
                persisted["prefix_reset"]["sequence"],
                failed_lifecycle["sequence"],
            )
            self.assertTrue(any(
                "cold-prefix reset blocked retry: lifecycle disk failed" in note
                for note in getattr(error, "__notes__", [])
            ))

    def test_rebootstrap_fails_before_deleting_unstopped_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bootstrap = Mock(return_value={"usable": True})
            lane = self.lane(root, bootstrap=bootstrap)
            with patch.object(
                suite.hangover_probe,
                "shutdown_private_wineserver",
                return_value={"stopped": False, "waited": False},
            ), self.assertRaisesRegex(
                suite.SuiteRunError, "could not stop"
            ):
                lane.rebootstrap("test")
            self.assertTrue(lane.config.wine_prefix.is_dir())
            bootstrap.assert_not_called()
            self.assertEqual(lane.prefix_receipts[0]["status"], "FAILED")
            lifecycle = lane.prefix_receipts[0]["evidence"]
            lifecycle_path = root / "output" / lifecycle["path"]
            self.assertTrue(lifecycle_path.is_file())
            self.assertEqual(
                native_runner.sha256_file(lifecycle_path),
                lifecycle["sha256"],
            )


if __name__ == "__main__":
    unittest.main()
