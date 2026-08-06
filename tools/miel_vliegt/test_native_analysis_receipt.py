#!/usr/bin/env python3
import unittest

from tools.miel_vliegt.native_analysis_receipt import build


class NativeAnalysisReceiptTests(unittest.TestCase):
    def test_preserves_exact_function_and_indirect_site_identity(self):
        index = {
            "source": {"sha256": "a" * 64},
            "functions": [{
                "address": "0x00401000", "end": "0x00401020", "sha256": "b" * 64,
                "unresolved_indirect_calls": [{"address": "0x00401008"}],
                "branch_sites": [{
                    "address": "0x00401010",
                    "kind": "unresolved_switch_or_indirect_jump",
                }],
            }],
        }
        code_map = {"functions": [{
            "address": "0x00401000",
            "ownership": {"status": "reviewed", "disposition": "GAME_OWNED"},
        }]}
        receipt = build(index, code_map)
        self.assertEqual(receipt["source_sha256"], "a" * 64)
        self.assertEqual(receipt["functions"][0]["ownership_status"], "reviewed")
        self.assertEqual(receipt["unresolved_indirect_calls"], ["0x00401008"])
        self.assertEqual(receipt["unresolved_indirect_branches"], ["0x00401010"])


if __name__ == "__main__":
    unittest.main()
