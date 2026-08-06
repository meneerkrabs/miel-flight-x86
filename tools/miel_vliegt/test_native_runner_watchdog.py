import sys
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import hangover_probe


class NativeRunnerWatchdogTests(unittest.TestCase):
    def test_run_records_phase_timestamps_without_watchdog(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = hangover_probe.run(
                [sys.executable, "-c", "pass"],
                cwd=Path(temporary),
                timeout=2,
            )
        phases = result["phase_timestamps"]
        self.assertGreaterEqual(
            phases["completed_monotonic_ns"], phases["started_monotonic_ns"]
        )
        self.assertEqual(
            phases["duration_ns"],
            phases["completed_monotonic_ns"] - phases["started_monotonic_ns"],
        )
        self.assertFalse(result["watchdog"]["captured"])

    def test_watchdog_captures_once_before_scenario_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observer_log = root / "native-observer-fex.log"
            diagnostic = root / "watchdog.json"
            result = hangover_probe.run(
                [sys.executable, "-c", "import time; time.sleep(1.3)"],
                cwd=root,
                timeout=2,
                watchdog={
                    "diagnostic_path": diagnostic,
                    "observer_log": observer_log,
                    "after_seconds": 1,
                },
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["watchdog"]["captured"])
            self.assertTrue(diagnostic.is_file())
            receipt = diagnostic.read_text(encoding="utf-8")
            self.assertIn("pre-scenario-startup", receipt)
            self.assertIn("non-invasive-host-observation", receipt)

    def test_invalid_watchdog_is_rejected_before_process_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "watchdog"):
                hangover_probe.run(
                    [sys.executable, "-c", "raise SystemExit(99)"],
                    cwd=Path(temporary),
                    timeout=2,
                    watchdog={"unexpected": True},
                )


if __name__ == "__main__":
    unittest.main()
