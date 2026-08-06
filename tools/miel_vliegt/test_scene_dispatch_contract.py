#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import scene_dispatch_contract as dispatch


class SceneDispatchContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = dispatch.generate(
            dispatch.DEFAULT_MISSIONS,
            dispatch.DEFAULT_LOCATIONS,
            dispatch.DEFAULT_UDSP,
        )

    def test_generated_contract_covers_all_locations_and_routes(self):
        self.assertEqual(self.contract["edition"], "miel-vliegt-de-wereld-rond-nl")
        self.assertEqual(len(self.contract["locations"]), 18)
        self.assertEqual(
            {row["locationId"] for row in self.contract["locations"]},
            {2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22},
        )
        self.assertEqual(
            {row["route"] for row in self.contract["missionActions"]},
            {"GROUND", "BARN", "FLIGHT", "LOCATION_POLICY"},
        )
        self.assertEqual(len(self.contract["missionActions"]), 113)

    def test_artifact_keys_not_locale_paths_drive_dispatch(self):
        artifacts = self.contract["artifacts"]
        self.assertTrue(artifacts)
        self.assertTrue(all(row["artifactKey"].startswith("LOCATION_SCRIPT:") for row in artifacts))
        self.assertTrue(all("path" not in row for row in artifacts))
        self.assertIn(
            "LOCATION_SCRIPT:brejton_bord/getblankets",
            {row["artifactKey"] for row in artifacts},
        )

    def test_special_policies_and_expected_absences_are_explicit(self):
        locations = {row["domainId"]: row for row in self.contract["locations"]}
        self.assertEqual(locations["grotte_grundlig"]["policy"], "GROTTE_REFUEL")
        self.assertEqual(locations["raymond_rajser"]["policy"], "RAYMOND_CHALLENGE")
        self.assertEqual(locations["varldsutstallning"]["policy"], "EXHIBITION_SELECTOR")
        self.assertEqual(locations["mygghanget"]["policy"], "BESPOKE_NO_UDSP")
        self.assertIsNone(locations["mygghanget"]["defaultRoot"])
        self.assertEqual(
            {(row["domainId"], row["dispatchId"]) for row in self.contract["expectedAbsences"]},
            {("mygghanget", None), ("raymond_rajser", "allfinished"),
             ("varldsutstallning", "allfinished")},
        )

    def test_every_mission_action_resolves_to_harvested_udsp_artifact(self):
        keys = {row["artifactKey"] for row in self.contract["artifacts"]}
        for action in self.contract["missionActions"]:
            self.assertIn(action["artifactKey"], keys)

    def test_missing_or_drifted_source_fails_closed(self):
        missions = json.loads(dispatch.DEFAULT_MISSIONS.read_text(encoding="utf-8"))
        locations = json.loads(dispatch.DEFAULT_LOCATIONS.read_text(encoding="utf-8"))
        udsp = json.loads(dispatch.DEFAULT_UDSP.read_text(encoding="utf-8"))
        broken = copy.deepcopy(udsp)
        broken["scripts"] = [
            row for row in broken["scripts"]
            if not (row.get("domain_id") == "grotte_grundlig" and row.get("dispatch_id") == "refuel")
        ]
        with self.assertRaisesRegex(ValueError, "missing UDSP scene artifact"):
            dispatch.build_contract(
                missions, locations, broken,
                sources={"missions": {}, "locations": {}, "udsp": {}},
            )

        wrong_edition = copy.deepcopy(locations)
        wrong_edition["source"]["edition"] = "other-edition"
        with self.assertRaisesRegex(ValueError, "requested edition differs"):
            dispatch.build_contract(
                missions, wrong_edition, udsp,
                edition="expected-edition",
                sources={"missions": {}, "locations": {}, "udsp": {}},
            )

    def test_check_mode_compares_canonical_bytes(self):
        payload = dispatch.render(self.contract)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dispatch.json"
            output.write_text(payload, encoding="utf-8")
            self.assertEqual(output.read_text(encoding="utf-8"), payload)


if __name__ == "__main__":
    unittest.main()
