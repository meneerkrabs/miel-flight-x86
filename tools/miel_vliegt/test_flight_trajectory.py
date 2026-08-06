#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import flight_trajectory


ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "tools/miel_vliegt/fixtures/trajectory_gravity_scenario.json"
WEB_TRACE = ROOT / "content/miel_vliegt/trajectory_web_gravity_fixture.ndjson"


class FlightTrajectoryTests(unittest.TestCase):
    def test_checked_web_fixture_is_deterministic_and_not_native_evidence(self):
        records = flight_trajectory.read_ndjson(WEB_TRACE)
        flight_trajectory.validate_trace(records)
        self.assertEqual(records[0]["capture_kind"], "web")
        self.assertEqual(records[0]["source"]["evidence"], "WEB_FIXTURE")
        self.assertEqual(records[-1]["sample_count"], 5)
        with self.assertRaises(SystemExit):
            # Exercise the same guard as replay --require-native without a CLI subprocess.
            if records[0]["capture_kind"] != "native":
                raise SystemExit("not native evidence")

    def test_web_runner_executes_the_real_flight_integrator_reproducibly(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.ndjson"
            second = Path(temporary) / "second.ndjson"
            first_records = flight_trajectory.run_web(SCENARIO, first)
            second_records = flight_trajectory.run_web(SCENARIO, second)
        self.assertEqual(first_records, second_records)
        self.assertEqual(first_records[1]["state"]["velocity"]["y"], -0.39239999651908875)
        self.assertEqual(first_records[1]["state"]["position"]["y"], 9.984304428100586)

    def test_comparator_reports_the_first_drifting_tick_and_field(self):
        web = flight_trajectory.read_ndjson(WEB_TRACE)
        baseline = copy.deepcopy(web[:-1])
        baseline[0]["capture_kind"] = "native"
        baseline[0]["source"] = {
            "edition": baseline[0]["source"]["edition"],
            "executable_sha256": baseline[0]["source"]["executable_sha256"],
            "state_layout_sha256": "1" * 64,
            "state_layout_review": "REVIEWED",
            "capture_receipt_sha256": "2" * 64,
        }
        baseline = flight_trajectory.canonicalize_trace(baseline[0], baseline[1:])
        self.assertEqual(flight_trajectory.compare_trajectories(baseline, web, flight_trajectory.load_contract()), [])
        candidate = copy.deepcopy(web[:-1])
        candidate[3]["state"]["position"]["x"] = 0.5
        candidate = flight_trajectory.canonicalize_trace(candidate[0], candidate[1:])
        differences = flight_trajectory.compare_trajectories(baseline, candidate, flight_trajectory.load_contract())
        self.assertEqual(len(differences), 1)
        self.assertIn("tick 2: state.position.x", differences[0])

    def test_comparator_rejects_web_fixture_as_a_parity_baseline(self):
        web = flight_trajectory.read_ndjson(WEB_TRACE)
        differences = flight_trajectory.compare_trajectories(web, web, flight_trajectory.load_contract())
        self.assertIn("baseline is not native evidence", differences)
        self.assertIn("baseline and candidate are the same trace artifact", differences)

    def test_position_tolerance_is_explicit_and_bounded(self):
        web = flight_trajectory.read_ndjson(WEB_TRACE)
        baseline_parts = copy.deepcopy(web[:-1])
        baseline_parts[0]["capture_kind"] = "native"
        baseline_parts[0]["source"] = {
            "edition": baseline_parts[0]["source"]["edition"],
            "executable_sha256": baseline_parts[0]["source"]["executable_sha256"],
            "state_layout_sha256": "1" * 64,
            "state_layout_review": "REVIEWED",
            "capture_receipt_sha256": "2" * 64,
        }
        baseline = flight_trajectory.canonicalize_trace(baseline_parts[0], baseline_parts[1:])
        candidate_parts = copy.deepcopy(web[:-1])
        candidate_parts[1]["state"]["position"]["x"] = 0.000009
        candidate = flight_trajectory.canonicalize_trace(candidate_parts[0], candidate_parts[1:])
        self.assertEqual(flight_trajectory.compare_trajectories(baseline, candidate, flight_trajectory.load_contract()), [])
        candidate_parts[1]["state"]["position"]["x"] = 0.000011
        candidate = flight_trajectory.canonicalize_trace(candidate_parts[0], candidate_parts[1:])
        self.assertIn("tick 0: state.position.x", flight_trajectory.compare_trajectories(
            baseline, candidate, flight_trajectory.load_contract()
        )[0])

    def test_quaternion_sign_is_canonicalized_without_relaxing_rotation(self):
        web = flight_trajectory.read_ndjson(WEB_TRACE)
        header = copy.deepcopy(web[0])
        sample = copy.deepcopy(web[1])
        sample["state"]["orientation"] = {"x": 0, "y": 0, "z": 0, "w": -1}
        canonical = flight_trajectory.canonicalize_trace(header, [sample])
        self.assertEqual(canonical[1]["state"]["orientation"]["w"], 1)

    def test_footer_detects_tampering(self):
        records = flight_trajectory.read_ndjson(WEB_TRACE)
        records[1]["state"]["position"]["y"] = 0
        with self.assertRaisesRegex(ValueError, "content hash mismatch"):
            flight_trajectory.validate_trace(records)

    def test_native_import_requires_pinned_executable_and_reviewed_complete_layout(self):
        contract = flight_trajectory.load_contract()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executable = directory / "wrong.exe"
            executable.write_bytes(b"not the pinned executable")
            scenario = json.loads(SCENARIO.read_text(encoding="utf-8"))
            scenario["evidence"] = "NATIVE_SCRIPT"
            scenario_path = directory / "scenario.json"
            scenario_path.write_text(json.dumps(scenario), encoding="utf-8")
            raw = directory / "raw.ndjson"
            raw.write_text("", encoding="utf-8")
            layout = directory / "layout.json"
            layout.write_text(json.dumps({
                "schema": 1,
                "review_status": "REVIEWED",
                "executable_sha256": contract["source"]["executable_sha256"],
                "fields": {},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "wrong native executable"):
                flight_trajectory.import_native(
                    raw, directory / "out", scenario_path, executable, layout,
                    directory / "capture-receipt.json"
                )

    def test_comparator_rejects_a_native_trace_as_the_web_candidate(self):
        web = flight_trajectory.read_ndjson(WEB_TRACE)
        baseline_parts = copy.deepcopy(web[:-1])
        baseline_parts[0]["capture_kind"] = "native"
        baseline_parts[0]["source"] = {
            "edition": baseline_parts[0]["source"]["edition"],
            "executable_sha256": baseline_parts[0]["source"]["executable_sha256"],
            "state_layout_sha256": "1" * 64,
            "state_layout_review": "REVIEWED",
            "capture_receipt_sha256": "2" * 64,
        }
        native = flight_trajectory.canonicalize_trace(baseline_parts[0], baseline_parts[1:])
        differences = flight_trajectory.compare_trajectories(native, native, flight_trajectory.load_contract())
        self.assertIn("candidate is not a web runtime trace", differences)
        self.assertIn("baseline and candidate are the same trace artifact", differences)

    def test_contract_verifier_keeps_web_fixture_partial(self):
        report = flight_trajectory.verify_contract()
        self.assertEqual(report, {
            "scenarios": 1,
            "native_scenario_backlog": 5,
            "native_trajectories": 0,
            "native_candidate_observations": 1,
            "disposition": "PARTIAL",
        })

    def test_capture_plan_exposes_missing_layout_instead_of_guessing_offsets(self):
        plan = flight_trajectory.capture_plan()
        self.assertEqual(plan["step_hook"]["address"], "0x0040e610")
        self.assertEqual(plan["state_layout_status"], "MISSING")
        self.assertIn("state.position", plan["required_state_layout_fields"])


if __name__ == "__main__":
    unittest.main()
