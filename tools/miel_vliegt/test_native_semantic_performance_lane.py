import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.miel_vliegt import native_semantic_suite as suite
from tools.miel_vliegt.fex_wine import native_runner


class NativeSemanticPerformanceLaneTests(unittest.TestCase):
    def lane(self, root):
        lane = object.__new__(suite._SealedPrefixLane)
        lane.config = SimpleNamespace(
            tmpfs_staging_root=root / "tmpfs",
            wine_prefix=root / "tmpfs" / "prefix",
            output_root=root / "output",
            tmpfs_bytes_per_job=2 * 1024**3,
            expected_sha256={
                "source_executable": "0" * 64,
                "observer_dll": "1" * 64,
                "observer_launcher": "2" * 64,
                "real_dinput": "3" * 64,
            },
        )
        lane.config.tmpfs_staging_root.mkdir()
        lane.config.output_root.mkdir()
        lane.identity = {"sha256": "3" * 64}
        lane.capture_receipts = []
        lane.pair = {"root": str(root / "seals")}
        return lane

    def install_lifecycle(self, lane):
        prepares = []
        removals = []
        verifications = []

        def prepare(slot):
            prepares.append(slot)
            lane.config.wine_prefix.mkdir()
            (lane.config.wine_prefix / "system.reg").write_bytes(b"prefix")
            return {"slot": slot}

        def remove():
            removals.append(True)
            if lane.config.wine_prefix.exists():
                shutil.rmtree(lane.config.wine_prefix)

        def verify(slot):
            verifications.append(slot)
            return {"slot": slot, "tree_sha256": "4" * 64}

        lane._prepare = prepare
        lane._remove_clone = remove
        lane._verify_slot = verify
        return prepares, removals, verifications

    def test_retries_exactly_once_only_before_scenario_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            prepares, removals, verifications = self.install_lifecycle(lane)
            calls = []

            def producer(staging):
                calls.append(staging)
                if len(calls) == 1:
                    (staging / "startup.txt").write_text("waiting", encoding="ascii")
                    raise TimeoutError("observer timed out")
                (staging / "receipt.json").write_text("{}", encoding="ascii")
                return {"receipt": "receipt.json"}

            destination = root / "output" / "exact" / "run-1"
            classification = {
                "classification": "pre-scenario-startup-hang",
                "retryable": True,
            }
            with patch.object(
                native_runner,
                "classify_pre_scenario_startup_hang",
                return_value=classification,
            ):
                result = lane.capture(
                    "A", "scene", "exact", destination, producer,
                )
            self.assertEqual(result, {"receipt": "receipt.json"})
            self.assertEqual(len(calls), 2)
            self.assertEqual(prepares, ["A", "A"])
            self.assertEqual(len(removals), 2)
            self.assertEqual(verifications, ["A", "A"])
            self.assertFalse(lane.config.wine_prefix.exists())
            self.assertFalse(any(lane.config.tmpfs_staging_root.iterdir()))
            self.assertTrue(destination.is_dir())
            self.assertEqual(
                len(lane.capture_receipts[0]["attempts"]), 2
            )

    def test_never_retries_after_semantic_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            prepares, removals, _verifications = self.install_lifecycle(lane)
            calls = 0

            def producer(staging):
                nonlocal calls
                calls += 1
                (staging / "native-observer-fex.log").write_text(
                    '{"event":"session.dispatched"}\n', encoding="utf-8"
                )
                raise TimeoutError("observer timed out")

            with self.assertRaises(TimeoutError):
                lane.capture(
                    "A", "scene", "exact",
                    root / "output" / "exact" / "run-1", producer,
                )
            self.assertEqual(calls, 1)
            self.assertEqual(prepares, ["A"])
            self.assertEqual(len(removals), 1)
            self.assertFalse(lane.config.wine_prefix.exists())
            self.assertFalse(any(lane.config.tmpfs_staging_root.iterdir()))

    def test_copyout_failure_still_cleans_clone_and_tmpfs_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            _prepares, removals, verifications = self.install_lifecycle(lane)

            def producer(staging):
                (staging / "receipt.json").write_text("{}", encoding="ascii")
                return {"receipt": "receipt.json"}

            with patch.object(
                native_runner, "atomic_copyout_tree",
                side_effect=native_runner.NativeRunnerError("copyout exploded"),
            ):
                with self.assertRaisesRegex(
                    native_runner.NativeRunnerError, "copyout exploded"
                ):
                    lane.capture(
                        "A", "scene", "exact",
                        root / "output" / "exact" / "run-1", producer,
                    )
            self.assertEqual(len(removals), 1)
            self.assertEqual(verifications, ["A"])
            self.assertFalse(lane.config.wine_prefix.exists())
            self.assertFalse(any(lane.config.tmpfs_staging_root.iterdir()))

    def test_stale_absolute_staging_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = self.lane(root)
            self.install_lifecycle(lane)

            def producer(staging):
                (staging / "receipt.json").write_text("{}", encoding="ascii")
                return {"path": str(staging / "receipt.json")}

            with self.assertRaisesRegex(
                suite.SuiteRunError, "absolute tmpfs staging path"
            ):
                lane.capture(
                    "A", "scene", "exact",
                    root / "output" / "exact" / "run-1", producer,
                )

    def test_final_cleanup_does_not_mask_primary_error(self):
        class BrokenLane:
            def close(self):
                raise RuntimeError("cleanup failed")

        error = ValueError("primary failed")
        with self.assertRaisesRegex(ValueError, "primary failed") as raised:
            with suite._performance_lane_lifecycle(BrokenLane()):
                raise error
        self.assertTrue(
            any(
                "performance lane final cleanup failed" in note
                for note in getattr(raised.exception, "__notes__", [])
            )
        )


if __name__ == "__main__":
    unittest.main()
