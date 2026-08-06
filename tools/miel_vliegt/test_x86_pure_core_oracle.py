#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.x86_pure_core_oracle import (
    CONTRACT, ROOT, first_difference, validate_contract, verify_artifact,
)


ARTIFACT = ROOT / "content/miel_vliegt/x86_pure_core_receipt.json"


class X86PureCoreOracleTests(unittest.TestCase):
    def test_contract_pins_a_real_import_free_native_physics_fold(self):
        contract, _, index, matrix = validate_contract(ROOT)
        function = next(
            row for row in index["functions"]
            if row["address"] == contract["function"]["address"]
        )
        self.assertEqual(function["name"], "airplane.fold_part_properties")
        self.assertEqual(function["calls"], [function["address"]])
        self.assertEqual(function["imports"], [])
        self.assertEqual(function["unresolved_indirect_calls"], [])
        self.assertEqual(function["unresolved_direct_calls"], [])
        self.assertEqual(len(matrix["definitions"]), 30)

    def test_tracked_receipt_is_current_and_first_divergence_is_empty(self):
        receipt = verify_artifact(ARTIFACT, ROOT)
        self.assertEqual(receipt["differential_result"], "PASS")
        self.assertIsNone(receipt["first_divergence"])
        self.assertEqual(receipt["case_count"], 30)

    def test_first_divergence_reports_exact_float_lane(self):
        native = {"component_mask": 1, "counted_parts": 2, "float_bits": [0, 7, 9]}
        web = {"component_mask": 1, "counted_parts": 2, "float_bits": [0, 8, 9]}
        self.assertEqual(first_difference(native, web), {
            "field": "float_bits", "index": 1, "native": 7, "web": 8,
        })

    def test_verifier_rejects_a_forged_pass(self):
        receipt = json.loads(ARTIFACT.read_text())
        receipt["cases"][0]["counted_parts"] += 1
        with tempfile.TemporaryDirectory() as directory:
            forged = Path(directory) / "receipt.json"
            forged.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "stored differential drifted"):
                verify_artifact(forged, ROOT)


if __name__ == "__main__":
    unittest.main()
