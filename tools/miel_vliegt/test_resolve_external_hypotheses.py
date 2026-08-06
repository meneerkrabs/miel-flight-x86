from __future__ import annotations

import unittest

from tools.miel_vliegt.resolve_external_hypotheses import build_resolutions, harvest_map_actions


def source(actions):
    return {
        "missions": [{
            "id": 1,
            "name": "fixture",
            "source": "data/Missions/fixture.txt",
            "dependencies": [],
            "actions": actions,
        }]
    }


def registry(points=None, rule=False):
    claim = ({"kind": "MISSION_RULE", "requirements": []} if rule else
             {"kind": "MISSION_COORDINATES", "points": points or []})
    return {"hypotheses": [{"id": "fixture", "claim": claim}]}


class ResolveExternalHypothesesTests(unittest.TestCase):
    def test_harvests_typed_static_and_random_map_actions(self):
        rows = harvest_map_actions(source([
            {"command": "ADD_MAPEVENT", "arguments": "event, asset, 0, 10, 5, 20, 15"},
            {"command": "ADD_MAPEVENTRANDOMPOS", "arguments": "random, asset, 1, 30, 6, 40, 20, 150"},
        ]))
        self.assertEqual(rows[0]["values"]["x"], 10)
        self.assertNotIn("placement_radius", rows[0]["values"])
        self.assertEqual(rows[1]["values"]["placement_radius"], 150)

    def test_exact_point_is_corroborated_without_becoming_parity_evidence(self):
        result = build_resolutions(registry([{
            "item_id": "part", "x": 30, "y": 40, "placement_radius": 150
        }]), source([{
            "command": "ADD_MAPEVENTRANDOMPOS",
            "arguments": "event, asset, 1, 30, 6, 40, 20, 150",
        }]))
        self.assertEqual(result["counts"]["FIRST_PARTY_SOURCE_CORROBORATED"], 1)
        self.assertFalse(result["evidence_policy"]["corroboration_is_runtime_parity"])
        self.assertEqual(result["parity_evidence_exports"], [])

    def test_radius_conflict_is_reported_as_partial(self):
        result = build_resolutions(registry([{
            "item_id": "part", "x": 30, "y": 40, "placement_radius": 50
        }]), source([{
            "command": "ADD_MAPEVENTRANDOMPOS",
            "arguments": "event, asset, 1, 30, 6, 40, 20, 150",
        }]))
        row = result["resolutions"][0]
        self.assertEqual(row["status"], "PARTIALLY_CORROBORATED")
        self.assertEqual(row["point_resolutions"][0]["conflicting_fields"], ["placement_radius"])

    def test_missing_coordinate_and_rule_stay_unverified(self):
        missing = build_resolutions(registry([{
            "item_id": "part", "x": 999, "y": 999, "placement_radius": None
        }]), source([]))
        rule = build_resolutions(registry(rule=True), source([]))
        self.assertEqual(missing["counts"]["UNVERIFIED"], 1)
        self.assertEqual(rule["counts"]["UNVERIFIED"], 1)

    def test_erik_yarn_issue_requires_the_exact_original_sequence(self):
        mission_source = {
            "missions": [{
                "id": 36,
                "name": "erik_needhelp_thread",
                "source": "data/Missions/erzon.txt",
                "dependencies": [
                    *[{"state": "activate", "type": "mission_notactivated", "data": str(value)} for value in (601, 602, 603, 604)],
                    {"state": "complete", "type": "map_event", "data": "found_mobilephone_special"},
                    {"state": "reward", "type": "arrive", "data": "3"},
                ],
                "actions": [
                    {"state": "activate", "command": "ADD_MAPEVENTRANDOMPOS", "arguments": "found_mobilephone_special, mobiltelefon_erik, 1, 1855, 25, 1441, 25, 1000"},
                    {"state": "reward", "command": "PLAY_SCRIPT", "arguments": "sam_scribbler, erik_getthread"},
                    {"state": "reward", "command": "GET_ITEM", "arguments": "sytrad_atle"},
                ],
            }]
        }
        issue_registry = {"hypotheses": [{
            "id": "issue2.erik.yarn",
            "claim": {"kind": "MISSION_RULE", "requirements": []},
        }]}
        result = build_resolutions(issue_registry, mission_source)
        self.assertEqual(result["counts"]["FIRST_PARTY_SOURCE_CORROBORATED"], 1)
        self.assertFalse(result["evidence_policy"]["corroboration_is_runtime_parity"])

    def test_malformed_action_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "arguments; expected"):
            harvest_map_actions(source([{"command": "ADD_MAPEVENT", "arguments": "too, short"}]))


if __name__ == "__main__":
    unittest.main()
