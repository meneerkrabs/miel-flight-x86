#!/usr/bin/env python3
import unittest

from tools.miel_vliegt.x86_first_party_oracle import ROOT, verify_artifact


class X86FirstPartyOracleTests(unittest.TestCase):
    def test_receipt_executes_cc_without_promoting_equivalence(self):
        receipt = verify_artifact(ROOT / "content/miel_vliegt/x86_first_party_aggregation.json")
        self.assertFalse(receipt["equivalence_claimed"])
        scenarios = {item["id"]: item for item in receipt["scenarios"]}
        self.assertGreater(scenarios["aggregate-default"]["first_party_instruction_count"], 0)
        self.assertEqual(scenarios["aggregate-default"]["component_mask"], 0x1CF)
        self.assertEqual(scenarios["aggregate-default"]["counted_parts"], 6)


if __name__ == "__main__":
    unittest.main()
