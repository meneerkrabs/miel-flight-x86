import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.miel_vliegt import harvest_uds_scene_scripts as scene_contract


CHARACTER_DEFINITION = """\
CHARACTER
{
  NAME mulle
  PART
  {
    ID 0
    NAME body
    POS 0, 0
    ANIMATION_SEQUENCE 1, body, 3
    {
      0
      1
    }
    ANIMATION_SEQUENCE 1, body_alt, 1
    {
      2
    }
  }
}
"""

LOCATION_SCRIPT = """\
LOCATION_SCRIPT
{
NAME intro
NODE
{
COMM POSITION_CHARACTER mulle, 10, -20
COMM PLAY_CHARACTER_SCRIPT mulle, stand, WAIT
COMM FUTURE_DIALOGUE 7, words that must never be stored
}
}
"""

CHARACTER_SCRIPT = """\
CHARACTER_SCRIPT
{
NAME stand
NODE
{
COMM PLAY_CHARACTER_ANIMATION 0, 1, 8, ANIMATION_LINEAR, WAIT
COMM WAIT 1.5, WAIT
}
}
"""


def stale_character_definition(name):
    return f"""\
CHARACTER
{{
  NAME {name}
  PART
  {{
    ID 1
    NAME arm
    POS 0, 0
    ANIMATION 0, arm
  }}
}}
"""


STALE_SCRIPTS = {
    "data\\Scripts\\Characters\\ernst\\stand.def": """CHARACTER_SCRIPT
{
NAME stand
NODE
{
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM PLAY_CHARACTER_ANIMATION 1, 1, 8, ANIMATION_LINEAR, WAIT
}
}
""",
    "data\\Scripts\\Characters\\fiona\\talk.def": """CHARACTER_SCRIPT
{
NAME talk
NODE
{
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM PLAY_CHARACTER_ANIMATION 1, 1, 0, ANIMATION_LINEAR, WAIT
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM PLAY_CHARACTER_ANIMATION 1, 1, 0, ANIMATION_LINEAR, WAIT
}
}
""",
    "data\\Scripts\\Characters\\linus\\talk.def": """CHARACTER_SCRIPT
{
NAME talk
NODE
{
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM WAIT 0, WAIT
COMM PLAY_CHARACTER_ANIMATION 1, 2, 2, ANIMATION_RANDOMFRAME, LOOP
}
}
""",
}


class FakeArchive:
    payloads = {
        "data\\Scripts\\Locations\\barn\\intro.def": LOCATION_SCRIPT.encode("latin-1"),
        "data\\Scripts\\Characters\\mulle\\character.def": CHARACTER_DEFINITION.encode("latin-1"),
        "data\\Scripts\\Characters\\mulle\\stand.def": CHARACTER_SCRIPT.encode("latin-1"),
        **{
            f"data\\Scripts\\Characters\\{name}\\character.def":
                stale_character_definition(name).encode("latin-1")
            for name in ("ernst", "fiona", "linus")
        },
        **{path: text.encode("latin-1") for path, text in STALE_SCRIPTS.items()},
    }

    def __init__(self, _path):
        self.files = [SimpleNamespace(path=path) for path in self.payloads]
        self.header = SimpleNamespace(version_major=1, version_minor=1)

    def payload(self, entry):
        return self.payloads[entry.path]


class UdsSceneScriptContractTests(unittest.TestCase):
    def test_harvest_covers_coupled_roots_and_redacts_unclassified_text(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "data.up"
            archive.write_bytes(b"fixture")
            with mock.patch.object(scene_contract, "UdspArchive", FakeArchive):
                first = scene_contract.harvest(archive)
                second = scene_contract.harvest(archive)

        self.assertEqual(first, second)
        self.assertEqual(first["counts"]["def_files"], 9)
        self.assertEqual(first["coverage"]["resolved_character_script_dispatches"], 1)
        self.assertEqual(first["coverage"]["actor_animation_resolution"], {
            "commands": 5,
            "resolved": 1,
            "stale_selection_misses": [
                {"path": "data/Scripts/Characters/ernst/stand.def", "command_index": 3,
                 "part_id": 1, "animation_id": 1},
                {"path": "data/Scripts/Characters/fiona/talk.def", "command_index": 3,
                 "part_id": 1, "animation_id": 1},
                {"path": "data/Scripts/Characters/fiona/talk.def", "command_index": 7,
                 "part_id": 1, "animation_id": 1},
                {"path": "data/Scripts/Characters/linus/talk.def", "command_index": 4,
                 "part_id": 1, "animation_id": 2},
            ],
        })
        self.assertEqual(first["schema"], 2)
        self.assertIn("structure", first["scripts"][0])
        future = next(
            command
            for script in first["scripts"]
            for command in script["commands"]
            if command["opcode"] == "FUTURE_DIALOGUE"
        )
        self.assertEqual(future["arguments"][0], 7)
        self.assertTrue(all(value == {"redacted": "unclassified_text"} for value in future["arguments"][1:]))
        encoded = scene_contract.encode(first)
        self.assertNotIn("words that must never be stored", encoded)

    def test_character_descriptor_preserves_shipped_source_anomalies(self):
        parsed = scene_contract.parse_character_definition(
            CHARACTER_DEFINITION, source="character.def"
        )
        part = parsed["parts"][0]
        self.assertEqual(part["duplicate_animation_sequence_ids"], [1])
        self.assertEqual(part["animation_sequences"][0]["declared_frame_count"], 3)
        self.assertEqual(part["animation_sequences"][0]["frames"], [0, 1])

    def test_parser_and_dispatch_gaps_fail_closed(self):
        broken_payloads = dict(FakeArchive.payloads)
        broken_payloads["data\\Scripts\\Locations\\barn\\intro.def"] = b"LOCATION_SCRIPT\nNAME intro\nCOMM ,\n"
        broken_archive = type("BrokenArchive", (FakeArchive,), {"payloads": broken_payloads})
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "data.up"
            archive.write_bytes(b"fixture")
            with mock.patch.object(scene_contract, "UdspArchive", broken_archive):
                with self.assertRaisesRegex(ValueError, "failed to parse executable DEF"):
                    scene_contract.harvest(archive)

        unresolved_payloads = dict(FakeArchive.payloads)
        unresolved_payloads.pop("data\\Scripts\\Characters\\mulle\\stand.def")
        unresolved_archive = type("UnresolvedArchive", (FakeArchive,), {"payloads": unresolved_payloads})
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "data.up"
            archive.write_bytes(b"fixture")
            with mock.patch.object(scene_contract, "UdspArchive", unresolved_archive):
                with self.assertRaisesRegex(ValueError, "unresolved PLAY_CHARACTER_SCRIPT"):
                    scene_contract.harvest(archive)

    def test_duplicate_normalized_paths_fail_closed(self):
        class DuplicateArchive(FakeArchive):
            def __init__(self, _path):
                super().__init__(_path)
                self.files.append(SimpleNamespace(path="DATA\\SCRIPTS\\LOCATIONS\\BARN\\INTRO.DEF"))

        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "data.up"
            archive.write_bytes(b"fixture")
            with mock.patch.object(scene_contract, "UdspArchive", DuplicateArchive):
                with self.assertRaisesRegex(ValueError, "duplicate normalized DEF path"):
                    scene_contract.harvest(archive)

    def test_missing_shipped_stale_selection_set_fails_even_when_empty(self):
        payloads = {
            key: value for key, value in FakeArchive.payloads.items()
            if "\\ernst\\" not in key and "\\fiona\\" not in key and "\\linus\\" not in key
        }
        no_stale_archive = type("NoStaleArchive", (FakeArchive,), {"payloads": payloads})
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "data.up"
            archive.write_bytes(b"fixture")
            with mock.patch.object(scene_contract, "UdspArchive", no_stale_archive):
                with self.assertRaisesRegex(ValueError, "stale-selection allowlist drifted"):
                    scene_contract.harvest(archive)

    def test_generated_contract_invariants(self):
        contract_path = Path(__file__).parents[2] / "content/miel_vliegt/uds_scene_scripts.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        self.assertEqual(contract["coverage"]["all_archive_def_files_covered"], 264)
        self.assertEqual(contract["counts"]["location_scripts"], 164)
        self.assertEqual(contract["counts"]["character_scripts"], 74)
        self.assertEqual(contract["counts"]["character_definitions"], 26)
        self.assertEqual(contract["counts"]["commands"], 2320)
        self.assertEqual(contract["counts"]["loop_commands"], 242)
        self.assertEqual(contract["counts"]["redacted_arguments"], 0)
        self.assertEqual(contract["counts"]["animations"], 371)
        self.assertEqual(contract["coverage"]["actor_animation_resolution"]["resolved"], 367)
        self.assertEqual(
            contract["coverage"]["actor_animation_resolution"]["stale_selection_misses"],
            [
                {"path": "data/Scripts/Characters/ernst/stand.def", "command_index": 3,
                 "part_id": 1, "animation_id": 1},
                {"path": "data/Scripts/Characters/fiona/talk.def", "command_index": 3,
                 "part_id": 1, "animation_id": 1},
                {"path": "data/Scripts/Characters/fiona/talk.def", "command_index": 7,
                 "part_id": 1, "animation_id": 1},
                {"path": "data/Scripts/Characters/linus/talk.def", "command_index": 4,
                 "part_id": 1, "animation_id": 2},
            ],
        )
        self.assertEqual(len(contract["scenes"]), 18)
        self.assertEqual(contract["coverage"]["scripts_with_nested_composites"], 1)
        self.assertEqual(contract["coverage"]["maximum_composite_depth"], 2)
        self.assertIn("barn", {scene["id"] for scene in contract["scenes"]})
        self.assertEqual(contract["coverage"]["unresolved_character_script_dispatches"], [])
        self.assertEqual(contract["coverage"]["unresolved_character_directories"], [])
        self.assertEqual(
            set(contract["command_vocabulary"]["counts"]),
            set(scene_contract.ARGUMENT_KINDS),
        )


if __name__ == "__main__":
    unittest.main()
