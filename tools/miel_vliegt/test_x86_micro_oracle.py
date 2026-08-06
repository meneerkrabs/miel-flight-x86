#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.x86_micro_oracle import (
    CONTRACT, ROOT, OracleError, validate_contract, validate_web_case_coverage, verify_artifact,
)


ARTIFACT = ROOT / "content/miel_vliegt/x86_micro_oracle_airworthiness.json"


class X86MicroOracleTests(unittest.TestCase):
    def test_only_closed_import_free_functions_are_allowlisted(self):
        contract, _, index = validate_contract()
        functions = {item["name"]: item for item in index["functions"]}
        self.assertEqual(
            [item["native_name"] for item in contract["functions"]],
            ["airplane.is_airworthy", "airplane.first_missing_component"],
        )
        for item in contract["functions"]:
            native = functions[item["native_name"]]
            self.assertEqual(native["imports"], [])
            self.assertEqual(native["unresolved_indirect_calls"], [])

    def test_receipt_is_an_exhaustive_original_x86_to_web_differential(self):
        receipt = verify_artifact(ARTIFACT)
        self.assertEqual(receipt["native_case_count"], 1030)
        self.assertEqual(receipt["differential_case_count"], 1024)
        self.assertEqual(receipt["differential_result"], "PASS")
        by_mask = {item["component_mask"]: item for item in receipt["cases"]}
        self.assertEqual(by_mask[0x38]["first_missing_component"], 0)
        self.assertTrue(by_mask[0x1FF]["airworthy"])
        self.assertFalse(by_mask[0x3FF]["airworthy"])
        self.assertFalse(by_mask[0x3FF]["differential"])

    def test_receipt_cannot_be_promoted_after_runtime_tampering(self):
        receipt = json.loads(ARTIFACT.read_text())
        receipt["cases"][0]["airworthy"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "differential drifted"):
                verify_artifact(path)

    def test_receipt_scope_is_bound_to_the_allowlisted_functions(self):
        receipt = json.loads(ARTIFACT.read_text())
        receipt["evidence_scope"] = ["airplane.complete_component_mask", "unrelated.behavior"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-scope.json"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "evidence scope drifted"):
                verify_artifact(path)

    def test_duplicate_web_masks_cannot_fake_full_differential_coverage(self):
        contract, _, _ = validate_contract()
        duplicate = {
            "component_mask": 0,
            "airworthy": False,
            "first_missing_component": 5,
        }
        with self.assertRaisesRegex(OracleError, "every differential mask exactly once"):
            validate_web_case_coverage(contract, [duplicate] * 512)

    def test_oracle_is_regenerated_from_the_private_executable_in_ci(self):
        workflow = (ROOT / ".github/workflows/deploy-oracle.yml").read_text()
        regeneration = (ROOT / "tools/miel_vliegt/regenerate_flight_content.sh").read_text()
        self.assertIn("regenerate_flight_content.sh iso/Mielvliegt.iso", workflow)
        self.assertIn("trap 'rm -rf -- \"$WORK\"' EXIT", regeneration)
        self.assertIn('if [[ -n "${FLIGHT_WORK_DIR:-}" ]]', regeneration)
        self.assertIn('x86_micro_oracle.py" verify', regeneration)
        self.assertIn('--executable "$SYS/MulleMeck.exe"', regeneration)


if __name__ == "__main__":
    unittest.main()
