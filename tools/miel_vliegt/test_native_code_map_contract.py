import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class NativeCodeMapContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = json.loads(
            (ROOT / "content/miel_vliegt/native_function_index.json").read_text(encoding="utf-8")
        )
        cls.code_map = json.loads(
            (ROOT / "content/miel_vliegt/native_code_map.json").read_text(encoding="utf-8")
        )

    def test_every_recovered_function_has_one_stable_classified_record(self):
        rows = self.code_map["functions"]
        self.assertEqual(len(rows), 1369)
        self.assertEqual(len({row["id"] for row in rows}), 1369)
        self.assertTrue(self.code_map["summary"]["inventory_disposition_complete"])
        self.assertFalse(self.code_map["summary"]["semantic_classification_complete"])
        self.assertEqual(self.code_map["summary"]["ownership"], {
            "candidate": 106, "reviewed": 14, "unassigned": 1249,
        })
        self.assertEqual(sum(self.code_map["summary"]["kinds"].values()), 1369)

    def test_scc_and_call_references_are_total(self):
        function_ids = {row["id"] for row in self.code_map["functions"]}
        scc_ids = {component["id"] for component in self.code_map["sccs"]}
        self.assertEqual(len(scc_ids), 1367)
        for row in self.code_map["functions"]:
            self.assertIn(row["scc"], scc_ids)
            self.assertTrue(set(row["calls"]) <= function_ids)
            self.assertTrue(set(row["callers"]) <= function_ids)
        self.assertEqual(self.code_map["summary"]["cyclic_sccs"], 25)
        self.assertEqual(self.code_map["summary"]["largest_scc"], 2)

    def test_unknown_control_flow_and_bytes_remain_visible(self):
        summary = self.code_map["summary"]
        self.assertEqual(summary["functions_with_unresolved_indirect_calls"], 430)
        self.assertEqual(summary["unresolved_indirect_call_sites"], 1981)
        self.assertEqual(summary["functions_with_unresolved_direct_calls"], 16)
        self.assertEqual(summary["unresolved_direct_call_sites"], 31)
        self.assertEqual(summary["unresolved_switch_or_indirect_branches"], 143)
        self.assertEqual(summary["basic_blocks_with_unknown_bytes"], 9)
        coverage = summary["executable_byte_coverage"]
        self.assertEqual(coverage["unknown_skipdata_bytes"], 19)
        self.assertEqual(coverage["uncovered_executable_bytes"], 0)
        self.assertFalse(coverage["semantic_coverage_claimed"])

    def test_index_and_map_basic_block_totals_match(self):
        self.assertEqual(self.index["counts"]["basic_blocks"], 14925)
        self.assertEqual(self.code_map["summary"]["basic_blocks"], 14925)
        indexed_ids = {
            block["id"]
            for function in self.index["functions"] for block in function["basic_blocks"]
        }
        mapped_ids = {
            block_id
            for function in self.code_map["functions"] for block_id in function["basic_blocks"]
        }
        self.assertEqual(mapped_ids, indexed_ids)


if __name__ == "__main__":
    unittest.main()
