#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.x86_drop_oracle import CONTRACT, ROOT, verify_artifact


ARTIFACT = ROOT / "content/miel_vliegt/x86_drop_oracle.json"


class X86DropOracleTests(unittest.TestCase):
    def test_receipt_binds_original_release_and_ballistics_to_web_runtime(self):
        receipt = verify_artifact(ARTIFACT)
        self.assertEqual(receipt["differential_result"], "PASS")
        self.assertEqual(receipt["release"]["field28_bits"], 0)
        self.assertEqual(receipt["release"]["field2c_bits"], 0x3C23D70A)
        self.assertTrue(receipt["release"]["held_cleared"])
        self.assertEqual(len(receipt["cases"]), 8)
        settled = {item["id"] for item in receipt["cases"] if item["settled"]}
        self.assertEqual(settled, {"outside-settle", "inside-settle", "shelf-row-4"})

    def test_runtime_tampering_invalidates_the_receipt(self):
        receipt = json.loads(ARTIFACT.read_text())
        receipt["cases"][0]["field2c_bits"] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "ballistic differential drifted"):
                verify_artifact(path)

    def test_contract_keeps_release_and_all_three_view_fragments_pinned(self):
        contract = json.loads(CONTRACT.read_text())
        self.assertEqual(
            [item["native_unit"] for item in contract["release"]["closure"]],
            ["fn_00413f90", "fn_00417b40"],
        )
        self.assertEqual([item["view"] for item in contract["ballistics"]["fragments"]], [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
