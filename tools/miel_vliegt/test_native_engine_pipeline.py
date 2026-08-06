#!/usr/bin/env python3
import copy
import unittest
from pathlib import Path

from tools.miel_vliegt.build_native_engine_pipeline import (
    ABI_CONTRACTS, BOUNDARY_OUTPUT, CODE_MAP, IMPORT_AUDIT,
    IMPORT_BOUNDARY_OUTPUT, INDEX, OUTPUT, STAGES, SUBSYSTEMS,
    build, build_boundary_from_root, build_from_root, load_json,
)


ROOT = Path(__file__).resolve().parents[2]


class NativeEnginePipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = [
            load_json(ROOT / INDEX), load_json(ROOT / CODE_MAP),
            load_json(ROOT / SUBSYSTEMS), load_json(ROOT / ABI_CONTRACTS),
        ]
        cls.result = build_from_root(ROOT)

    def test_tracked_contract_is_exactly_reproducible(self):
        self.assertEqual(load_json(ROOT / OUTPUT), self.result)
        self.assertEqual(self.result["summary"]["functions"], 1369)
        self.assertFalse(self.result["summary"]["release_ready"])

    def test_every_function_has_stable_pe_cfg_abi_and_fail_closed_stages(self):
        source_by_id = {
            f"fn_{int(row['address'], 16):08x}": row
            for row in self.documents[0]["functions"]
        }
        self.assertEqual(len(self.result["functions"]), 1369)
        for row in self.result["functions"]:
            self.assertRegex(row["id"], r"^fn_[0-9a-f]{8}$")
            self.assertRegex(row["pe"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(row["cfg"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                row["native_interfaces"],
                {
                    "imports": sorted(source_by_id[row["id"]].get("imports") or []),
                    "fallback": f"native-function:{row['id']}",
                },
            )
            self.assertIn(row["abi_ir"]["status"], {"UNKNOWN", "REVIEWED"})
            seen_missing = False
            for stage in STAGES:
                if row["stages"][stage] == "MISSING":
                    seen_missing = True
                else:
                    self.assertFalse(seen_missing, f"{row['id']} skipped {stage}")

    def test_only_native_differential_rows_can_be_functionally_pure(self):
        pure = [
            row for row in self.result["functions"]
            if row["classification"]["effect_class"] == "FUNCTIONAL_PURE"
        ]
        self.assertEqual(
            {row["id"] for row in pure},
            {"fn_0040fe30", "fn_004102d0", "fn_004102f0"},
        )
        self.assertTrue(all(row["stages"]["differential"] == "PASS" for row in pure))
        self.assertEqual(
            {row["disposition"] for row in pure}, {"GAME_BEHAVIOR"}
        )
        self.assertTrue(all(
            row["boundary_evidence_receipt"]["path"] == BOUNDARY_OUTPUT
            for row in pure
        ))
        self.assertEqual(
            sum(row["disposition"] == "UNKNOWN" for row in self.result["functions"]),
            1366,
        )

    def test_reviewed_game_behavior_boundary_is_exactly_reproducible(self):
        boundary = build_boundary_from_root(ROOT)
        self.assertEqual(load_json(ROOT / BOUNDARY_OUTPUT), boundary)
        self.assertEqual(boundary["disposition"], "GAME_BEHAVIOR")
        self.assertEqual(
            {row["functionId"] for row in boundary["claims"]},
            {"fn_0040fe30", "fn_004102d0", "fn_004102f0"},
        )
        self.assertEqual(
            {row["functionId"] for row in boundary["sourceEvidence"]},
            {row["functionId"] for row in boundary["claims"]},
        )

    def test_all_import_thunks_are_audited_without_conceptual_promotions(self):
        audited = [
            row for row in self.result["functions"]
            if "import_thunk_audit" in row["evidence"]
        ]
        self.assertEqual(len(audited), 24)
        self.assertTrue(all(row["disposition"] == "UNKNOWN" for row in audited))
        self.assertTrue(all(
            row["evidence"]["import_thunk_audit"]["status"] == "UNKNOWN"
            for row in audited
        ))
        self.assertIn(IMPORT_AUDIT, self.result["input_hashes"])
        self.assertIn(IMPORT_BOUNDARY_OUTPUT, self.result["input_hashes"])

    def test_import_audit_cannot_promote_a_row_by_receipt_edit(self):
        audit = copy.deepcopy(load_json(ROOT / IMPORT_AUDIT))
        audit["decisions"][0]["status"] = "COMPLETE"
        with self.assertRaisesRegex(ValueError, "audit drifted"):
            build(*self.documents, ROOT, audit)

    def test_purity_claim_fails_closed_when_receipt_is_absent(self):
        abi = copy.deepcopy(self.documents[3])
        abi["functions"][0]["differential"]["receipt"] = "content/missing.json"
        with self.assertRaisesRegex(ValueError, "functional purity requires"):
            build(*self.documents[:3], abi, ROOT)

    def test_reviewed_abi_cannot_float_to_another_native_identity(self):
        abi = copy.deepcopy(self.documents[3])
        abi["functions"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "reviewed ABI identity drifted"):
            build(*self.documents[:3], abi, ROOT)


if __name__ == "__main__":
    unittest.main()
