import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.native_flight_consensus import (
    ConsensusError,
    _canonical,
    build_consensus,
    project_trace,
)


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "content/miel_vliegt/native_default_flight_consensus.json"
CAPTURE = ROOT / "tmp/miel-flight-live-input-route-v6-two-run"


class NativeFlightConsensusTest(unittest.TestCase):
    def test_tracked_artifact_is_fail_closed_and_self_consistent(self):
        value = json.loads(ARTIFACT.read_text(encoding="utf-8"))
        self.assertEqual(value["protocol"], "miel-vliegt-native-flight-consensus")
        self.assertEqual(value["status"], "CANDIDATE_PARTIAL_NATIVE_EVIDENCE")
        self.assertIs(value["promotion_allowed"], False)
        self.assertEqual(value["determinism"]["run_count"], 2)
        self.assertEqual(value["determinism"]["sample_count"], 30)
        self.assertEqual(
            value["determinism"]["projection_sha256"],
            hashlib.sha256(_canonical(value["samples"])).hexdigest(),
        )
        self.assertIn("web trajectory equivalence", value["coverage"]["not_proved"])
        self.assertIn("contact response", value["coverage"]["not_proved"])

    @unittest.skipUnless(CAPTURE.exists(), "ignored native source captures are not present")
    def test_tracked_artifact_rebuilds_from_both_native_runs(self):
        logs = [CAPTURE / f"observer-run{number}.log" for number in (1, 2)]
        launchers = [CAPTURE / f"launcher-run{number}.json" for number in (1, 2)]
        rebuilt = build_consensus(logs, launchers)
        tracked = json.loads(ARTIFACT.read_text(encoding="utf-8"))
        self.assertEqual(rebuilt, tracked)

    def test_projection_rejects_missing_ticks(self):
        trace = {"records": [
            {"channel": "clock.tick", "tick": 1, "values": {}},
        ]}
        with self.assertRaisesRegex(ConsensusError, "contiguous"):
            project_trace(trace)


if __name__ == "__main__":
    unittest.main()
