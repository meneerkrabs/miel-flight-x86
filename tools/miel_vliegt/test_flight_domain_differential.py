import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import flight_domain_differential as domain
from tools.miel_vliegt import native_scenario_artifacts as artifacts


def _initial_state(root: Path) -> dict:
    fixture = root / "fixtures/user0.dat"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(b"\x01")
    one_fields = {
        "flight.active", "flight.orientation_w", "flight.propulsion_scale",
        "flight.fuel_capacity", "flight.fuel", "flight.integrity",
        "flight.maximum_integrity", "flight.controls_enabled",
    }
    values = []
    for name, encoding in artifacts.RUNTIME_STATE_FIELDS:
        if encoding == "u8":
            value_hex = "01" if name in one_fields else "00"
        else:
            value_hex = "3f800000" if name in one_fields else "00000000"
        values.append({
            "name": name, "encoding": encoding, "value_hex": value_hex,
        })
    return {
        "files": [{
            "role": "user-profile",
            "path": "fixtures/user0.dat",
            "byte_length": 1,
            "sha256": artifacts.sha256_file(fixture),
        }],
        "values": values,
    }


class FlightDomainDifferentialTest(unittest.TestCase):
    def test_detached_suite_keeps_specs_hashed_without_claiming_missing_save_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts.materialize_scenario_suite(root, _initial_state(root))
            (root / "fixtures/user0.dat").unlink()
            suite = domain._load_detached_suite(root / "suite-spec.json")
            self.assertEqual(suite["scenario_order"], list(artifacts.SCENARIO_ID_ORDER))
            self.assertIs(suite["production_claim"], False)

            suite_path = root / "suite-spec.json"
            drifted_suite = json.loads(suite_path.read_text(encoding="utf-8"))
            drifted_suite["scenarios"][0]["observation_profile"]["omit_mask"] = (
                "0x0000"
            )
            suite_path.write_text(json.dumps(drifted_suite), encoding="utf-8")
            with self.assertRaisesRegex(
                domain.DomainDifferentialError, "observation profile differs",
            ):
                domain._load_detached_suite(suite_path)
            suite_path.write_text(json.dumps(suite), encoding="utf-8")

            replay = root / suite["scenarios"][0]["native_replay"]["path"]
            replay.write_bytes(replay.read_bytes() + b"drift\n")
            with self.assertRaisesRegex(
                domain.DomainDifferentialError, "file hash drifted",
            ):
                domain._load_detached_suite(root / "suite-spec.json")

    def test_headless_node_capture_is_a_state_trace_not_framebuffer_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = artifacts.materialize_scenario_suite(root, _initial_state(root))
            entry = manifest["scenarios"][0]
            capture = domain._run_web_capture(root / entry["scenario"]["path"])
            self.assertEqual(capture["trace"]["scenario"]["id"], entry["id"])
            self.assertEqual(
                len(capture["trace"]["frames"]),
                capture["trace"]["scenario"]["input_script"]["tick_count"],
            )
            self.assertIs(capture["renderer"]["framebuffer_evidence"], False)
            self.assertTrue(all(
                "pixel_checkpoint" not in frame.get("render", {})
                for frame in capture["trace"]["frames"]
            ))

    def test_missing_native_rows_and_check_mode_are_fail_closed_and_deterministic(self):
        rows = domain._missing_native_domains()
        self.assertEqual(list(rows), [
            "timing", "controls", "physics", "systems", "collision", "camera",
            "render",
        ])
        self.assertTrue(all(
            row["status"] == "NATIVE_EVIDENCE_MISSING"
            for row in rows.values()
        ))
        self.assertTrue(all(
            "capture specs" in row["first_divergence"]["reason"]
            for row in rows.values()
        ))

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            files = {
                "manifest.json": json.dumps({"status": "DIAGNOSTIC_ONLY"}) + "\n",
                "web-traces/example.json": "{}\n",
            }
            domain.write_or_check(output, files, check=False)
            domain.write_or_check(output, files, check=True)
            (output / "manifest.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                domain.DomainDifferentialError, "artifact is stale",
            ):
                domain.write_or_check(output, files, check=True)


if __name__ == "__main__":
    unittest.main()
