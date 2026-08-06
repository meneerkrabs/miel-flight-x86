import hashlib
import json
import unittest
from pathlib import Path

from tools.miel_vliegt import native_scenario_artifacts as artifacts


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_ROOT = (
    ROOT / "content/miel_vliegt/native_fex_default_calibration"
)
RECEIPT_PATH = ARTIFACT_ROOT / "receipt.json"
SCENARIO_PATH = ARTIFACT_ROOT / "scenario.json"
REPLAY_PATH = ARTIFACT_ROOT / "replay.mvo"
LOCAL_SOURCE_CAPTURE = Path("/private/tmp/fex-flight-capture-COMPLETE.log")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class NativeFexCalibrationCandidateTest(unittest.TestCase):
    def setUp(self):
        self.receipt = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
        self.scenario = artifacts.load_scenario(SCENARIO_PATH)

    def test_tracked_candidate_rebuilds_the_exact_replay(self):
        self.assertEqual(
            artifacts.sha256_file(SCENARIO_PATH),
            self.receipt["calibrated_scenario"]["sha256"],
        )
        self.assertEqual(
            artifacts.scenario_sha256(self.scenario),
            self.receipt["calibrated_scenario"]["semantic_sha256"],
        )
        replay = artifacts.build_native_replay_script(self.scenario)
        self.assertEqual(replay, REPLAY_PATH.read_bytes())
        self.assertEqual(
            artifacts.sha256_file(REPLAY_PATH),
            self.receipt["native_replay"]["sha256"],
        )
        self.assertEqual(
            len(replay),
            self.receipt["native_replay"]["byte_length"],
        )
        self.assertTrue(
            replay.startswith(
                (
                    self.receipt["native_replay"]["format"] + "\n"
                ).encode("ascii")
            )
        )

    def test_calibration_state_and_transcripts_are_hash_bound(self):
        state = self.scenario["initial_state"]["values"]
        rng = self.scenario["rng_transcript"]
        self.assertEqual(
            len(state),
            self.receipt["calibrated_scenario"][
                "runtime_initial_state_count"
            ],
        )
        self.assertEqual(
            _canonical_sha256(state),
            self.receipt["calibration"]["runtime_initial_state_sha256"],
        )
        self.assertEqual(
            len(rng["draws"]),
            self.receipt["calibrated_scenario"]["runtime_rng_draw_count"],
        )
        self.assertEqual(
            len(rng["flight_activation_dt_f32_bits"]),
            self.receipt["calibrated_scenario"][
                "flight_activation_clock_tick_count"
            ],
        )
        self.assertEqual(
            self.receipt["native_replay"]["runtime_initial_state_count"],
            len(state),
        )

    def test_candidate_cannot_claim_exact_or_parity_promotion(self):
        promotion = self.receipt["promotion"]
        self.assertEqual(self.receipt["status"], "CALIBRATION_REPLAY_READY")
        self.assertIs(self.receipt["production_claim"], False)
        self.assertIs(self.receipt["promotion_allowed"], False)
        self.assertEqual(promotion["native_calibration_capture_count"], 1)
        self.assertEqual(promotion["bound_exact_capture_count"], 0)
        self.assertEqual(promotion["paired_exact_scenario_count"], 0)
        self.assertEqual(promotion["parity_promotion_count"], 0)
        self.assertEqual(
            promotion["required_next_evidence"],
            "TWO_INDEPENDENT_BOUND_EXACT_REPLAYS",
        )
        self.assertIs(
            self.receipt["framebuffer_candidate"]["raw_artifact_bound"],
            False,
        )
        self.assertIs(
            self.receipt["framebuffer_candidate"]["parity_evidence"],
            False,
        )

    @unittest.skipUnless(
        LOCAL_SOURCE_CAPTURE.exists(),
        "external hash-pinned Oracle calibration capture is unavailable",
    )
    def test_external_source_capture_rederives_the_tracked_candidate(self):
        source = self.receipt["source"]
        calibration = self.receipt["calibration"]
        trace_receipt = self.receipt["semantic_trace"]
        self.assertEqual(
            artifacts.sha256_file(LOCAL_SOURCE_CAPTURE),
            source["capture_sha256"],
        )
        self.assertEqual(
            LOCAL_SOURCE_CAPTURE.stat().st_size,
            source["capture_byte_length"],
        )

        trace = artifacts.parse_semantic_log(
            LOCAL_SOURCE_CAPTURE, require_complete=True,
        )
        self.assertEqual(trace["scenario_id"], self.receipt["scenario"])
        self.assertEqual(
            trace["semantic_sha256"], trace_receipt["semantic_sha256"],
        )
        self.assertEqual(trace["record_count"], trace_receipt["record_count"])
        self.assertEqual(
            trace["channel_counts"], trace_receipt["channel_counts"],
        )

        state = artifacts.extract_calibrated_runtime_initial_state(
            LOCAL_SOURCE_CAPTURE,
        )
        self.assertEqual(state, self.scenario["initial_state"]["values"])
        activation_rng = artifacts.extract_flight_activation_rng(
            LOCAL_SOURCE_CAPTURE,
        )
        activation_clock = artifacts.extract_flight_activation_clock(
            LOCAL_SOURCE_CAPTURE,
        )
        self.assertEqual(
            activation_rng["count"],
            calibration["flight_activation_rng_draw_count"],
        )
        self.assertEqual(
            activation_rng["sha256"],
            calibration["flight_activation_rng_sha256"],
        )
        self.assertEqual(
            activation_clock["count"],
            calibration["flight_activation_clock_tick_count"],
        )
        self.assertEqual(
            activation_clock["sha256"],
            calibration["flight_activation_clock_sha256"],
        )

        with self.assertRaisesRegex(
            artifacts.ArtifactError,
            "runtime initial-state readback order drifted",
        ):
            artifacts.extract_bound_runtime_initial_state(
                LOCAL_SOURCE_CAPTURE,
            )


if __name__ == "__main__":
    unittest.main()
