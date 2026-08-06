#!/usr/bin/env python3
import copy
import unittest

from tools.miel_vliegt import native_scene_transitions as transitions


EXPECTED_LOCATIONS = {
    2: "mode_roymccoy",
    3: "mode_samscribbler",
    4: "mode_turetapp",
    6: "mode_atleartillerist",
    7: "mode_violawallmark",
    8: "mode_samposanna",
    9: "mode_brejtonbord",
    10: "mode_grottegrundlig",
    11: "mode_gabriellagourmet",
    12: "mode_richardrevers",
    13: "mode_victorvulcan",
    14: "mode_varldsutstallning",
    15: "mode_vermontvrak",
    16: "mode_fionafalk",
    17: "mode_dorisdigital",
    20: "mode_raymondrajser",
    21: "mode_ernsteremit",
    22: "mode_mygghanget",
}


class NativeSceneTransitionTests(unittest.TestCase):
    def setUp(self):
        self.contract = transitions.load_contract()

    def validate_structure(self, contract):
        return transitions.validate_contract(contract, verify_artifacts=False)

    def test_inventory_contains_22_manager_modes_and_exact_location_mapping(self):
        self.assertEqual(len(self.contract["modes"]), 22)
        core = {
            row["id"]: row["mode"]
            for row in self.contract["modes"] if row["mode_type"] == "core"
        }
        self.assertEqual(core, transitions.CORE_MODES)
        locations = {
            row["location_id"]: row["mode"]
            for row in self.contract["modes"] if row["mode_type"] == "location"
        }
        self.assertEqual(locations, EXPECTED_LOCATIONS)

    def test_mode_fly_is_a_manager_active_core_mode_not_an_auxiliary(self):
        flight = next(row for row in self.contract["modes"] if row["id"] == "flight")
        self.assertEqual(flight, {
            "id": "flight",
            "mode": "mode_fly",
            "mode_type": "core",
            "mode_address": "0x00454f0c",
            "constructor": "0x0042a3a0",
        })
        self.assertEqual(self.contract["manager"]["current_mode_offset"], "0x18c")
        self.assertEqual(self.contract["manager"]["pending_mode_offset"], "0x190")

    def test_every_location_has_exact_landing_and_departure_edges(self):
        rows = self.contract["location_edges"]
        self.assertEqual(len(rows), 18)
        locations = set(EXPECTED_LOCATIONS.values())
        self.assertEqual({row["location"] for row in rows}, locations)
        for row in rows:
            self.assertEqual(row["landing"]["source"], "mode_fly")
            self.assertEqual(row["landing"]["target"], row["location"])
            self.assertEqual(row["departure"]["source"], row["location"])
            self.assertEqual(row["departure"]["target"], "mode_fly")
            self.assertEqual(row["landing"]["site_role"], "producer")
            self.assertEqual(row["landing"]["address"], "0x00430fa4")
            self.assertEqual(row["landing"]["commit_address"], "0x0042c790")
            self.assertEqual(row["departure"]["site_role"], "commit")
            self.assertEqual(row["departure"]["address"], "0x00425c2e")
            self.assertEqual(row["departure"]["alternate_addresses"], [
                "0x00425cb1", "0x00425e90", "0x00425fe5", "0x004262ee",
            ])
            self.assertEqual(row["departure"]["owner_address"], "0x00425ab0")

    def test_parity_projection_excludes_every_open_or_nonnatural_edge(self):
        expanded = transitions.expanded_edges(self.contract)
        parity = transitions.natural_parity_edges(self.contract)
        self.assertEqual(len(expanded), 48)
        self.assertEqual(len(parity), 25)
        self.assertTrue(all(edge["evidence_status"] == "PROVEN_STATIC" for edge in parity))
        parity_ids = {edge["id"] for edge in parity}
        self.assertNotIn("varldsutstallning.credits", parity_ids)
        self.assertNotIn("location.barn.generic_return", parity_ids)
        self.assertNotIn("debug.engine_mode", parity_ids)

    def test_open_hooks_are_pinned_and_fail_closed(self):
        hooks = {row["id"]: row for row in self.contract["required_native_hooks"]}
        self.assertEqual(hooks["location_departure_state"]["address"], "0x00426570")
        self.assertEqual(hooks["generic_return_activator"]["watch"], "active location +0x487c")
        self.assertEqual(hooks["outro_callback"]["address"], "0x0043f770")
        credits = next(edge for edge in self.contract["edges"] if edge["id"] == "varldsutstallning.credits")
        self.assertEqual(credits["evidence_status"], "NATIVE_TRACE_REQUIRED")
        self.assertFalse(credits["parity_eligible"])

    def test_artifact_and_executable_identities_are_pinned(self):
        self.assertEqual(
            self.contract["source"]["executable_sha256"],
            "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2",
        )
        pins = self.contract["source"]["artifacts"]
        self.assertEqual(set(pins), transitions.REQUIRED_ARTIFACTS)
        self.assertTrue(all(len(pin["sha256"]) == 64 for pin in pins.values()))

    def test_mode_inventory_drift_fails(self):
        broken = copy.deepcopy(self.contract)
        broken["modes"].pop()
        with self.assertRaisesRegex(ValueError, "exactly 22"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        locations = [row for row in broken["modes"] if row["mode_type"] == "location"]
        locations[0]["location_id"] = locations[1]["location_id"]
        with self.assertRaisesRegex(ValueError, "duplicate location IDs"):
            self.validate_structure(broken)

    def test_source_artifact_drift_fails(self):
        broken = copy.deepcopy(self.contract)
        broken["source"]["artifacts"]["native_scene_probe"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned artifact drifted"):
            transitions.validate_contract(broken)

    def test_trace_required_edge_cannot_be_promoted_by_editing_json_only(self):
        broken = copy.deepcopy(self.contract)
        broken["location_edges"][0]["departure"]["evidence_status"] = "PROVEN_STATIC"
        broken["location_edges"][0]["departure"]["parity_eligible"] = True
        with self.assertRaisesRegex(ValueError, "promoted without trace evidence"):
            self.validate_structure(broken)

    def test_landing_producer_cannot_be_relabelled_as_commit(self):
        broken = copy.deepcopy(self.contract)
        landing = broken["location_edges"][0]["landing"]
        landing["site_role"] = "commit"
        landing["commit_address"] = landing["address"]
        with self.assertRaisesRegex(ValueError, "landing producer/commit roles drifted"):
            self.validate_structure(broken)

    def test_common_update_owner_cannot_be_relabelled_as_departure_site(self):
        broken = copy.deepcopy(self.contract)
        departure = broken["location_edges"][0]["departure"]
        departure["address"] = departure["owner_address"]
        departure.pop("owner_address")
        departure.pop("alternate_addresses")
        with self.assertRaisesRegex(ValueError, "departure owner/commit roles drifted"):
            self.validate_structure(broken)

    def test_unresolved_and_debug_edges_cannot_escape_their_categories(self):
        broken = copy.deepcopy(self.contract)
        broken["unresolved_edges"][0]["natural"] = True
        broken["unresolved_edges"][0]["parity_eligible"] = True
        with self.assertRaisesRegex(ValueError, "unresolved edge escaped"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["debug_edges"][0]["evidence_status"] = "PROVEN_STATIC"
        with self.assertRaisesRegex(ValueError, "debug edge escaped"):
            self.validate_structure(broken)


if __name__ == "__main__":
    unittest.main()
