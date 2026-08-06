#!/usr/bin/env python3
import json
import unittest
from pathlib import Path

from tools.miel_vliegt.map_engine_subsystems import SUBSYSTEMS, build, classify_import


ROOT = Path(__file__).resolve().parents[2]


class EngineSubsystemMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = json.loads((ROOT / "content/miel_vliegt/native_function_index.json").read_text())
        cls.code_map = json.loads((ROOT / "content/miel_vliegt/native_code_map.json").read_text())
        cls.result = build(cls.index, cls.code_map)

    def test_every_import_is_classified_into_an_engine_or_platform_boundary(self):
        self.assertEqual(self.result["summary"]["imports"], 334)
        self.assertEqual(self.result["summary"]["classified_imports"], 334)
        self.assertEqual({row["id"] for row in self.result["subsystems"]}, set(SUBSYSTEMS))

    def test_known_cc_and_uds_apis_define_the_expected_clean_room_boundaries(self):
        self.assertEqual(classify_import("UdsPack.dll!?Read@UpFile@@QAEIPAXII@Z"), "package_io")
        self.assertEqual(classify_import("Cc.dll!?CreateRoom@CcWorld@@QAEPAVCcRoom@@PAD@Z"), "scenegraph")
        self.assertEqual(classify_import("Cc.dll!?EulerODE@CcODE@@QAEXM@Z"), "physics_collision")
        self.assertEqual(classify_import("Cc.dll!?LoadTexture@GtTextureGroup@@QAAPAVGtTextureReference@@PADZZ"), "rendering")

    def test_reviewed_physics_functions_reach_the_physics_boundary(self):
        functions = {row["id"]: row for row in self.result["functions"]}
        self.assertIn("physics_collision", functions["fn_0040e610"]["reachable_subsystems"])
        self.assertIn("physics_collision", functions["fn_0040fbb0"]["reachable_subsystems"])

    def test_subsystem_map_never_claims_semantic_coverage(self):
        self.assertFalse(self.result["summary"]["semantic_coverage_claimed"])
        self.assertEqual(self.result["summary"]["functions"], 1369)


if __name__ == "__main__":
    unittest.main()
