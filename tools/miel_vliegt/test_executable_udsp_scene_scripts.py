#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import executable_udsp_scene_scripts as executable


class ExecutableUdspSceneScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = executable.build_contract()

    def test_real_edition_lowers_exact_native_command_graph(self):
        counts = self.contract["counts"]
        self.assertEqual(counts["scripts"], 238)
        self.assertEqual(counts["rawCommandNodes"], 2320)
        self.assertEqual(counts["executableCommandNodes"], 2302)
        self.assertEqual(counts["removedCommandNodes"], 18)
        self.assertEqual(counts["sourceCharacterSounds"], 310)
        self.assertEqual(counts["removedZeroTakeCharacterSounds"], 18)
        self.assertEqual(counts["removedDirectParserDiscards"], 0)
        self.assertEqual(counts["oneTakeCharacterSounds"], 234)
        self.assertEqual(counts["multipleTakeCharacterSounds"], 58)
        self.assertEqual(counts["nativeOpcode5Nodes"], 234)
        self.assertEqual(counts["nativeOpcode6Nodes"], 58)
        identities = self.contract["sourceIdentities"]
        self.assertEqual(
            identities["nativeExecutableSha256"],
            identities["nativeVoiceExecutableSha256"],
        )
        self.assertEqual(len(set(identities.values())), 3)

    def test_all_scripts_and_source_indices_are_preserved(self):
        raw = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        self.assertEqual(
            [script["path"] for script in self.contract["scripts"]],
            [script["path"] for script in raw["scripts"]],
        )
        for source, lowered in zip(raw["scripts"], self.contract["scripts"], strict=True):
            self.assertEqual(lowered["sourceSha256"], source["sha256"])
            indices = [command["sourceCommandIndex"] for command in lowered["commands"]]
            self.assertEqual(indices, sorted(indices))
            self.assertEqual(len(indices), len(set(indices)))

    def test_atle_talk_and_all_zero_take_sources_are_removed_not_substituted(self):
        removed = self.contract["removedCommands"]
        self.assertEqual(len(removed), 18)
        atle = next(
            row for row in removed
            if row["path"] == "data/Scripts/Locations/atle_artillerist/talk.def"
        )
        self.assertEqual(atle["sourceOpcode"], "PLAY_CHARACTER_SOUND")
        self.assertEqual(atle["arguments"], ["atle", 1001, "H", "WAIT"])
        self.assertEqual(atle["reason"], "ABSENT_NO_COMMAND_NODE")
        self.assertTrue(any(row["arguments"][1] == 2001 for row in removed))
        self.assertTrue(all(row["arguments"][1] in {6, 1001, 2001} for row in removed))

    def test_single_and_multiple_takes_lower_to_native_5_and_6(self):
        commands = [command for script in self.contract["scripts"] for command in script["commands"]]
        single = next(command for command in commands if command.get("nativeOpcode") == 5)
        self.assertEqual(single["sourceOpcode"], "PLAY_CHARACTER_SOUND")
        self.assertEqual(single["nativeOpcode"], 5)
        self.assertNotIn("takes", single)

        multiple = next(command for command in commands if command.get("nativeOpcode") == 6)
        self.assertEqual(multiple["sourceOpcode"], "PLAY_CHARACTER_SOUND")
        self.assertGreater(len(multiple["takes"]), 1)
        take_numbers = [row["take"] for row in multiple["takes"]]
        self.assertEqual(take_numbers, sorted(set(take_numbers)))
        self.assertTrue(all(1 <= take < 100 for take in take_numbers))
        self.assertEqual(multiple["modifier"], "WAIT")

    def test_barn_sounds_bind_existing_native_take_arrays(self):
        commands = [
            command
            for script in self.contract["scripts"]
            for command in script["commands"]
            if command["sourceOpcode"] == "PLAY_MULLEBARNSOUND"
        ]
        self.assertEqual(len(commands), 3)
        by_clip = {command["arguments"][0]: command for command in commands}
        self.assertEqual(set(by_clip), {40, 41, 184})
        self.assertEqual([row["take"] for row in by_clip[40]["takes"]], [1, 2])
        self.assertEqual([row["take"] for row in by_clip[41]["takes"]], [1, 2])
        self.assertEqual([row["take"] for row in by_clip[184]["takes"]], [1])
        self.assertTrue(all(command["nativeOpcode"] == 14 for command in commands))

    def test_sound_and_radio_bind_exact_take_one_without_requested_rng(self):
        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        media_by_key = {
            (
                row["opcode"], row["owner"].lower(), row["scriptNumber"],
                row["bank"].lower(),
            ): row
            for row in assets["media"]
            if row["opcode"] in {"PLAY_SOUND", "PLAY_RADIO"}
        }
        commands = [
            command
            for script in self.contract["scripts"]
            for command in script["commands"]
            if command["sourceOpcode"] in {"PLAY_SOUND", "PLAY_RADIO"}
        ]
        self.assertEqual(len(commands), 13)
        for command in commands:
            arguments = command["arguments"]
            media = media_by_key[(
                command["sourceOpcode"], arguments[0].lower(), arguments[1],
                arguments[2].lower(),
            )]
            take_one = [row for row in media["variants"] if row["take"] == 1]
            self.assertEqual(len(take_one), 1)
            self.assertEqual(command["assetKey"], take_one[0]["key"])
            self.assertNotIn("takes", command)
            self.assertNotIn("requestedRng", command)

        multi_take = next(
            command for command in commands
            if command["sourceOpcode"] == "PLAY_RADIO"
            and command["arguments"][:3] == ["mia", 1, "B"]
        )
        self.assertEqual(multi_take["assetKey"], "flight-voice-mi-01-0001-b")

    def test_sound_and_radio_preserve_source_identity_and_modifier_semantics(self):
        raw = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        raw_by_path = {script["path"]: script for script in raw["scripts"]}
        for script in self.contract["scripts"]:
            source_commands = raw_by_path[script["path"]]["commands"]
            for command in script["commands"]:
                if command["sourceOpcode"] not in {"PLAY_SOUND", "PLAY_RADIO"}:
                    continue
                source = source_commands[command["sourceCommandIndex"]]
                self.assertEqual(command["sourceOpcode"], source["opcode"])
                self.assertEqual(command["arguments"], source["arguments"])
                self.assertEqual(command["sourceNode"], source["node"])
                self.assertEqual(command["loop"], source["loop"])
                expected_modifier = "WAIT" if len(source["arguments"]) == 4 else None
                self.assertEqual(command["modifier"], expected_modifier)

    def test_sound_and_radio_fail_closed_on_missing_take_one_or_ambiguity(self):
        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        native = json.loads(executable.DEFAULT_NATIVE.read_text())

        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        media = next(
            row for row in assets["media"]
            if row["opcode"] == "PLAY_RADIO" and len(row["variants"]) > 1
        )
        media["variants"] = [row for row in media["variants"] if row["take"] != 1]
        with self.assertRaisesRegex(ValueError, "exactly one take 1"):
            executable.build_contract_data(scripts, assets, native)

        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        media = next(row for row in assets["media"] if row["opcode"] == "PLAY_SOUND")
        assets["media"].append(copy.deepcopy(media))
        with self.assertRaisesRegex(ValueError, "ambiguous fixed-take asset media key"):
            executable.build_contract_data(scripts, assets, native)

        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        media = next(row for row in assets["media"] if row["opcode"] == "PLAY_RADIO")
        take_one_key = next(row["key"] for row in media["variants"] if row["take"] == 1)
        audio = next(row for row in assets["audio"] if row["key"] == take_one_key)
        assets["audio"].append(copy.deepcopy(audio))
        with self.assertRaisesRegex(ValueError, "exactly one audio row"):
            executable.build_contract_data(scripts, assets, native)

        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        assets["media"] = [
            row for row in assets["media"]
            if not (row["opcode"] == "PLAY_SOUND" and row["scriptNumber"] == 270)
        ]
        with self.assertRaisesRegex(ValueError, "asset/source fixed-take media references"):
            executable.build_contract_data(scripts, assets, native)

    def test_sound_and_radio_fail_closed_on_media_identity_drift(self):
        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        native = json.loads(executable.DEFAULT_NATIVE.read_text())

        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        media = next(row for row in assets["media"] if row["opcode"] == "PLAY_SOUND")
        media["resolvedClip"] += 1
        with self.assertRaisesRegex(ValueError, "fixed-take media identity drifted"):
            executable.build_contract_data(scripts, assets, native)

        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        media = next(row for row in assets["media"] if row["opcode"] == "PLAY_RADIO")
        take_one_key = next(row["key"] for row in media["variants"] if row["take"] == 1)
        audio = next(row for row in assets["audio"] if row["key"] == take_one_key)
        audio["bank"] = "drift"
        with self.assertRaisesRegex(ValueError, "fixed-take audio identity drifted"):
            executable.build_contract_data(scripts, assets, native)

        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        command = next(
            command
            for script in scripts["scripts"]
            for command in script["commands"]
            if command["opcode"] == "PLAY_SOUND"
        )
        command["arguments"][-1] = "LOOP"
        with self.assertRaisesRegex(ValueError, "PLAY_SOUND arity/modifier drifted"):
            executable.build_contract_data(
                scripts,
                json.loads(executable.DEFAULT_ASSETS.read_text()),
                native,
            )

    def test_alternate_edition_prefix_resolves_its_own_take_one_asset(self):
        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        native = json.loads(executable.DEFAULT_NATIVE.read_text())
        assets["edition"] = "synthetic-alternate-edition"
        assets["resolution"]["ownerPrefixes"]["mia"] = "xy"
        media = next(
            row for row in assets["media"]
            if row["opcode"] == "PLAY_RADIO" and row["owner"] == "mia"
        )
        media["resolvedPrefix"] = "xy"
        for variant in media["variants"]:
            previous_key = variant["key"]
            variant["key"] = previous_key.replace("flight-voice-mi-", "flight-voice-xy-")
            audio = next(row for row in assets["audio"] if row["key"] == previous_key)
            audio["key"] = variant["key"]
            audio["prefix"] = "xy"

        contract = executable.build_contract_data(scripts, assets, native)
        command = next(
            command
            for script in contract["scripts"]
            for command in script["commands"]
            if command["sourceOpcode"] == "PLAY_RADIO"
            and command["arguments"][:3] == ["mia", 1, "B"]
        )
        self.assertEqual(contract["edition"], "synthetic-alternate-edition")
        self.assertEqual(command["assetKey"], "flight-voice-xy-01-0001-b")
        self.assertEqual(command["arguments"], ["mia", 1, "B", "WAIT"])

    def test_language_editions_may_have_take_gaps_and_direct_opcode_6_is_discarded(self):
        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        native = json.loads(executable.DEFAULT_NATIVE.read_text())
        media = next(
            row for row in assets["media"]
            if row["opcode"] == "PLAY_CHARACTER_SOUND" and len(row["variants"]) > 1
        )
        media["variants"][1]["take"] = 3
        contract = executable.build_contract_data(scripts, assets, native)
        lowered = next(
            command
            for script in contract["scripts"]
            for command in script["commands"]
            if command.get("nativeOpcode") == 6
            and command["arguments"][0].lower() == media["owner"].lower()
            and command["arguments"][1] == media["scriptNumber"]
            and command["arguments"][2].lower() == media["bank"].lower()
        )
        self.assertEqual([row["take"] for row in lowered["takes"]][:2], [1, 3])

        script = scripts["scripts"][0]
        source_index = len(script["commands"])
        script["commands"].append({
            "opcode": "PLAY_CHARACTER_SOUND_RANDOM",
            "arity": 0,
            "node": None,
            "loop": False,
            "arguments": [],
        })
        script["structure"]["children"].append({"command": source_index})
        contract = executable.build_contract_data(
            scripts, json.loads(executable.DEFAULT_ASSETS.read_text()), native
        )
        self.assertEqual(contract["counts"]["removedDirectParserDiscards"], 1)
        self.assertEqual(
            next(
                row["reason"] for row in contract["removedCommands"]
                if row["sourceOpcode"] == "PLAY_CHARACTER_SOUND_RANDOM"
            ),
            "DISCARD_DIRECT_OPCODE_NATIVE_PARSER",
        )

    def test_structure_references_executable_indices_and_keeps_empty_composites(self):
        synthetic = {
            "node": None,
            "repeat": False,
            "children": [
                {"node": 1, "repeat": False, "children": [{"command": 0}]},
                {"command": 1},
            ],
        }
        lowered = executable.lower_structure(synthetic, {0: None, 1: 0})
        self.assertEqual(
            lowered,
            {
                "node": None,
                "repeat": False,
                "children": [
                    {"node": 1, "repeat": False, "children": []},
                    {"command": 0, "sourceCommand": 1},
                ],
            },
        )

    def test_ambiguous_asset_resolution_fails_closed(self):
        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        native = json.loads(executable.DEFAULT_NATIVE.read_text())
        referenced_media = next(
            row for row in assets["media"]
            if row["opcode"] == "PLAY_CHARACTER_SOUND"
        )
        assets["media"].append(copy.deepcopy(referenced_media))
        with self.assertRaisesRegex(ValueError, "ambiguous asset media key"):
            executable.build_contract_data(scripts, assets, native)

    def test_missing_asset_and_non_wait_random_sound_fail_closed(self):
        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        native = json.loads(executable.DEFAULT_NATIVE.read_text())
        assets["media"] = [
            row for row in assets["media"]
            if not (
                row["opcode"] == "PLAY_CHARACTER_SOUND"
                and row["owner"] == "atle"
                and row["scriptNumber"] == 5
            )
        ]
        with self.assertRaisesRegex(ValueError, "asset/source PLAY_CHARACTER_SOUND"):
            executable.build_contract_data(scripts, assets, native)

        assets = json.loads(executable.DEFAULT_ASSETS.read_text())
        reference = next(
            row for row in assets["media"]
            if row["opcode"] == "PLAY_CHARACTER_SOUND" and row["references"]
        )["references"][0]
        reference["path"] = "data/Scripts/Locations/not-the-source.def"
        with self.assertRaisesRegex(ValueError, "asset/source PLAY_CHARACTER_SOUND"):
            executable.build_contract_data(
                json.loads(executable.DEFAULT_SCRIPTS.read_text()), assets, native
            )

        scripts = json.loads(executable.DEFAULT_SCRIPTS.read_text())
        command = next(
            command
            for script in scripts["scripts"]
            for command in script["commands"]
            if command["opcode"] == "PLAY_CHARACTER_SOUND"
        )
        command["arguments"][-1] = "LOOP"
        with self.assertRaisesRegex(ValueError, "must use WAIT"):
            executable.build_contract_data(
                scripts,
                json.loads(executable.DEFAULT_ASSETS.read_text()),
                native,
            )

    def test_hash_or_generated_output_drift_fails_closed(self):
        broken = copy.deepcopy(self.contract)
        broken["sources"]["assets"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "generated executable UDSP contract drifted"):
            executable.validate_contract(broken)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "contract.json"
            output.write_text("{}")
            with self.assertRaisesRegex(ValueError, "generated artifact drifted"):
                executable.check_output(output)

    def test_both_private_build_paths_lower_after_scene_asset_resolution(self):
        for relative in (
            "tools/miel_vliegt/regenerate_flight_content.sh",
            "deployment/hydrate-proven-flight-payloads.sh",
        ):
            script = (executable.ROOT / relative).read_text(encoding="utf-8")
            asset_call = script.index("tools/miel_vliegt/flight_scene_assets.py")
            lower_call = script.index("tools/miel_vliegt/executable_udsp_scene_scripts.py")
            self.assertLess(asset_call, lower_call)

        dockerfile = (
            executable.ROOT / "deployment/docker/Dockerfile.boten"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "COPY ./content/miel_vliegt/executable_udsp_scene_scripts.json "
            "./assets/executable_udsp_scene_scripts.json",
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()
