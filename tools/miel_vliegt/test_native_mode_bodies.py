#!/usr/bin/env python3
import copy
import unittest

from tools.miel_vliegt import native_mode_bodies as mode_bodies


class NativeModeBodyTests(unittest.TestCase):
    def setUp(self):
        self.contract = mode_bodies.load_contract()

    def validate_structure(self, contract):
        return mode_bodies.validate_contract(contract, verify_artifacts=False)

    def test_all_22_modes_have_exact_six_phase_lifecycle(self):
        self.assertEqual(len(self.contract["modes"]), 22)
        self.assertEqual(
            {row["id"] for row in self.contract["modes"]},
            set(mode_bodies.EXPECTED_BODIES),
        )
        for row in self.contract["modes"]:
            self.assertEqual(set(row["lifecycle"]), set(mode_bodies.PHASES))
            self.assertEqual(row["runtime_body_equivalence"], "UNPROVEN")
            self.assertFalse(row["parity_eligible"])

    def test_lifecycle_slots_and_base_flags_are_explicit(self):
        self.assertEqual(
            self.contract["engine"]["lifecycle_vtable_slots"],
            mode_bodies.LIFECYCLE_SLOTS,
        )
        self.assertEqual(self.contract["engine"]["base_state_fields"], {
            "loaded_u8": "0x14",
            "open_u8": "0x15",
        })

    def test_shared_entries_are_derived_from_per_mode_rows(self):
        self.assertEqual(
            self.contract["shared_lifecycle_entries"],
            mode_bodies.shared_lifecycle_entries(self.contract["modes"]),
        )
        tick = next(
            row for row in self.contract["shared_lifecycle_entries"]
            if row["phase"] == "tick" and row["entry"] == "0x00440000"
        )
        self.assertEqual(len(tick["modes"]), 13)

    def test_def_roots_are_linked_without_inventing_mygghanget_scripts(self):
        rows = {row["id"]: row for row in self.contract["modes"]}
        self.assertEqual(rows["barn"]["def_root"], "data/Scripts/Locations/barn")
        self.assertEqual(rows["barn"]["def_file_count"], 3)
        self.assertIsNone(rows["mygghanget"]["def_root"])
        self.assertEqual(rows["mygghanget"]["def_file_count"], 0)
        roots = [row for row in rows.values() if row["def_root"]]
        self.assertEqual(len(roots), 18)
        self.assertEqual(sum(row["def_file_count"] for row in roots), 164)

    def test_viola_loader_function_and_vtable_inner_entry_stay_distinct(self):
        viola = next(row for row in self.contract["modes"] if row["id"] == "viola_wallmark")
        self.assertEqual(viola["loader_function"], "0x00444db0")
        self.assertEqual(viola["lifecycle"]["load"], "0x00444e30")

    def test_body_capture_requires_paired_original_identity(self):
        capture = self.contract["body_capture"]
        self.assertEqual(capture["event_kind"], "BODY")
        self.assertEqual(capture["edges"], ["ENTER", "LEAVE"])
        self.assertIn("vtable", capture["required_fields"])
        self.assertIn("depth", capture["required_fields"])
        self.assertIn("static address presence never promotes", capture["promotion_rule"])

    def test_manager_flight_unload_exception_is_not_runtime_evidence(self):
        manager = self.contract["engine"]["manager"]
        self.assertEqual(manager["unload_skip_mode"], "mode_fly")
        flight = next(row for row in self.contract["modes"] if row["id"] == "flight")
        self.assertEqual(flight["lifecycle"]["unload"], "0x0042c400")
        self.assertFalse(flight["parity_eligible"])

    def test_digest_and_parity_edits_fail_closed(self):
        broken = copy.deepcopy(self.contract)
        broken["modes"][0]["static_summary"] = "guessed"
        with self.assertRaisesRegex(ValueError, "digest-locked"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["modes"][0]["runtime_body_equivalence"] = "EQUIVALENT"
        broken["modes"][0]["parity_eligible"] = True
        with self.assertRaisesRegex(ValueError, "escaped fail-closed"):
            self.validate_structure(broken)

    def test_artifact_hash_drift_fails(self):
        broken = copy.deepcopy(self.contract)
        broken["source"]["artifacts"]["native_scene_probe"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned mode body artifact drifted"):
            mode_bodies.validate_contract(broken)


if __name__ == "__main__":
    unittest.main()
