import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import harvest_dutch_help_contract


class DutchHelpContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.help_file = Path(self.temporary.name) / "MIELMONTEUR.HLP"
        fragments = [
            fragment
            for _, _, _, evidence in harvest_dutch_help_contract.RULES
            for fragment in evidence
        ]
        # Each rule is local in the real topic stream. Keeping the synthetic
        # fixture compact also tests deterministic sequential matching.
        self.help_file.write_bytes(
            harvest_dutch_help_contract.WINHELP_MAGIC
            + b"\0"
            + b"\0".join(fragment.encode("latin-1") for fragment in fragments)
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_harvests_all_reviewed_behavior_categories(self):
        contract = harvest_dutch_help_contract.harvest(self.help_file)
        self.assertEqual(
            set(contract["categories"]),
            {"controls", "aircraft_build", "flight_safety", "navigation", "hangar_tools", "album_save"},
        )
        self.assertEqual(contract["counts"]["rules"], 26)
        self.assertEqual(contract["source"]["filename"], "MIELMONTEUR.HLP")
        required = next(
            rule for rule in contract["categories"]["aircraft_build"]
            if rule["id"] == "required_parts"
        )
        self.assertEqual(len(required["evidence"]), 8)

    def test_changed_help_fragment_is_a_hard_failure(self):
        data = self.help_file.read_bytes().replace(
            b"Klik op de vuilnisbak.", b"Klik op de afvalbak."
        )
        self.help_file.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "lost exact fragment"):
            harvest_dutch_help_contract.harvest(self.help_file)

    def test_rejects_non_winhelp_input(self):
        self.help_file.write_bytes(b"plain text")
        with self.assertRaisesRegex(ValueError, "not a Windows 3.x help file"):
            harvest_dutch_help_contract.harvest(self.help_file)


if __name__ == "__main__":
    unittest.main()
