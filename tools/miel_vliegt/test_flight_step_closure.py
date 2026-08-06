#!/usr/bin/env python3
import json
import unittest
from pathlib import Path

from tools.miel_vliegt.build_flight_step_closure import ROOT, build


EXE = Path("/private/tmp/miel-vliegt-installed/System_Files/MulleMeck.exe")


@unittest.skipUnless(EXE.is_file(), "private installed executable is unavailable")
class FlightStepClosureTests(unittest.TestCase):
    def test_artifact_is_exactly_derived_and_cannot_claim_execution(self):
        index = json.loads((ROOT / "content/miel_vliegt/native_function_index.json").read_text())
        expected = build(index, EXE)
        tracked = json.loads((ROOT / "content/miel_vliegt/flight_step_closure.json").read_text())
        self.assertEqual(tracked, expected)
        self.assertEqual(tracked["status"], "BLOCKED_CLOSURE")
        self.assertEqual(tracked["blockers"]["unresolved_step_indirect_calls"], 20)
        self.assertEqual(tracked["indirect_calls"][0]["operand"], "[this.vtable+4]")
        self.assertIsNone(tracked["indirect_calls"][0]["target"])


if __name__ == "__main__":
    unittest.main()
