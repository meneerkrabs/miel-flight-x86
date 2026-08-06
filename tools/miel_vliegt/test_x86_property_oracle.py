#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.x86_micro_oracle import ROOT
from tools.miel_vliegt.x86_property_oracle import resolve_jobs, verify_artifact


ARTIFACT = ROOT / "content/miel_vliegt/x86_property_fold.json"


class X86PropertyOracleTests(unittest.TestCase):
    def test_parallelism_is_bounded(self):
        self.assertEqual(resolve_jobs("4"), 4)
        for value in ("0", "33"):
            with self.assertRaisesRegex(ValueError, "between 1 and 32"):
                resolve_jobs(value)

    def test_production_reconstruction_uses_bounded_parallel_workers(self):
        workflow = (ROOT / ".github/workflows/deploy-oracle.yml").read_text()
        self.assertIn('PROPERTY_ORACLE_JOBS: "4"', workflow)
        self.assertIn("regenerate_flight_content.sh iso/Mielvliegt.iso", workflow)

    def test_receipt_covers_all_source_pairs_stress_masks_and_default_airplane(self):
        receipt = verify_artifact(ARTIFACT)
        self.assertEqual(receipt["case_count"], 66334)
        self.assertEqual(receipt["differential_result"], "PASS")
        by_id = {item["id"]: item for item in receipt["cases"]}
        self.assertEqual(by_id["part-96"]["component_mask"], 0x108)
        self.assertEqual(by_id["part-281"]["component_mask"], 0x004)
        self.assertIn("parts-96-281", by_id)
        self.assertEqual(len(by_id["stress-9-high-low"]["part_ids"]), 32)
        self.assertEqual(by_id["default-airplane"]["component_mask"], 0x1CF)
        self.assertEqual(by_id["default-airplane"]["counted_parts"], 6)
        self.assertEqual(by_id["default-airplane"]["float_bits"][0], 0x41300000)
        self.assertEqual(by_id["default-airplane"]["float_bits"][1], 0x40200000)

    def test_stored_native_result_cannot_be_tampered(self):
        receipt = json.loads(ARTIFACT.read_text())
        receipt["cases"][1]["component_mask"] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "differential drifted"):
                verify_artifact(path)

    def test_fake_trace_cannot_promote_native_equivalence(self):
        receipt = json.loads(ARTIFACT.read_text())
        trace_id = receipt["cases"][1]["trace"]
        receipt["trace_catalog"][trace_id] = {
            "instruction_count": 1,
            "trace_sha256": "0" * 64,
            "read_set": [{}],
            "write_set": [{}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake-trace.json"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "trace is incomplete"):
                verify_artifact(path)


if __name__ == "__main__":
    unittest.main()
