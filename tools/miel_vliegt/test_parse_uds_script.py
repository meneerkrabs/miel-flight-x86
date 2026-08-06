#!/usr/bin/env python3
import unittest
from dataclasses import asdict

from tools.miel_vliegt.parse_uds_script import UdsScript


NESTED = """CHARACTER_SCRIPT
{
NAME stand
NODE
{
LOOP
COMM WAIT, 1, WAIT
NODE
{
COMM PLAY_CHARACTER_ANIMATION, 2, 0, 4, ANIMATION_LINEAR, WAIT
}
COMM WAIT, 2, WAIT_RANDOM
}
NODE
{
COMM WAIT, 3, WAIT
}
}
"""


class UdsScriptAstTests(unittest.TestCase):
    def test_nested_nodes_preserve_parentage_repeat_scope_and_source_order(self):
        script = UdsScript.parse(NESTED, source="nested.def")

        self.assertEqual([command.node for command in script.commands], [1, 2, 1, 3])
        self.assertEqual([command.loop for command in script.commands], [True, False, True, False])
        self.assertEqual(asdict(script.structure), {
            "node": None,
            "repeat": False,
            "children": (
                {
                    "node": 1,
                    "repeat": True,
                    "children": (
                        {"command": 0},
                        {
                            "node": 2,
                            "repeat": False,
                            "children": ({"command": 1},),
                        },
                        {"command": 2},
                    ),
                },
                {
                    "node": 3,
                    "repeat": False,
                    "children": ({"command": 3},),
                },
            ),
        })

    def test_structure_rejects_unbalanced_or_detached_node_blocks(self):
        with self.assertRaisesRegex(ValueError, "NODE must be followed"):
            UdsScript.parse("LOCATION_SCRIPT\n{\nNODE\nCOMM WAIT, 1, WAIT\n}\n")
        with self.assertRaisesRegex(ValueError, "unclosed"):
            UdsScript.parse("LOCATION_SCRIPT\n{\nNODE\n{\nCOMM WAIT, 1, WAIT\n}\n")

    def test_animation_manifest_names_native_arguments_without_reinterpreting_values(self):
        script = UdsScript.parse(NESTED, source="nested.def")

        self.assertEqual(script.manifest()["animations"], [{
            "part_id": 2,
            "animation_id": 0,
            "playback_rate_fps": 4,
            "playback": "ANIMATION_LINEAR",
            "modifier": "WAIT",
            "repeat_count": None,
            "line": 10,
            "node": 2,
            "loop": False,
        }])


if __name__ == "__main__":
    unittest.main()
