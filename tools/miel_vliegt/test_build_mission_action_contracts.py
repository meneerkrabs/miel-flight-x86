#!/usr/bin/env python3
import json
import unittest
from pathlib import Path

from tools.miel_vliegt.build_mission_action_contracts import build, validate


ROOT = Path(__file__).resolve().parents[2]


class MissionActionContractTests(unittest.TestCase):
    def test_generated_contract_covers_every_harvested_action_without_equivalence_claims(self):
        source = json.loads((ROOT / "content/miel_vliegt/uds_flight_contracts.json").read_text())
        artifact = build(source)
        validate(source, artifact)
        self.assertEqual(len(artifact["actions"]), 20)
        self.assertEqual(
            sum(row["occurrences"] for row in artifact["actions"]),
            sum(source["action_counts"].values()),
        )
        self.assertEqual({row["disposition"] for row in artifact["actions"]}, {"PARTIAL"})

    def test_validator_rejects_a_silently_reclassified_opcode(self):
        source = json.loads((ROOT / "content/miel_vliegt/uds_flight_contracts.json").read_text())
        artifact = build(source)
        artifact["actions"][0]["owner"] = "mission-state"
        with self.assertRaisesRegex(ValueError, "invalid action boundary owner"):
            validate(source, artifact)


if __name__ == "__main__":
    unittest.main()
