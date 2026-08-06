import hashlib
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path, PureWindowsPath

from tools.miel_vliegt.flight_scene_assets import (
    ArchiveSource,
    DirectorySource,
    SourceEntry,
    SourceIndex,
    build_scene_asset_contract,
    extract_native_voice_contract,
    export_scene_assets,
)
from tools.miel_vliegt.native_mygghanget_contract import (
    extract_native_mygghanget_contract,
)
from tools.miel_vliegt import native_udsp_scene_commands


ROOT = Path(__file__).resolve().parents[2]
NATIVE_UDSP_FIXTURE = json.loads(
    (ROOT / "content/miel_vliegt/native_udsp_scene_commands.json").read_text()
)
NATIVE_EXECUTABLE_SHA256 = NATIVE_UDSP_FIXTURE["source"]["executable_sha256"]


def gti(red: int, green: int, blue: int) -> bytes:
    pixels = bytes((blue, green, red, 255))
    image = struct.pack("<5I", 8, 1, 1, 0, 1) + pixels
    return b"GtIm" + b"Imag" + struct.pack("<I", len(image)) + image


def wav(marker: bytes) -> bytes:
    payload = b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, 8000, 8000, 1, 8)
    payload += b"data" + struct.pack("<I", len(marker)) + marker
    return b"RIFF" + struct.pack("<I", len(payload) + 4) + b"WAVE" + payload


def synthetic_voice_executable(path: Path) -> None:
    data = bytearray(0x2400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x00400000)
    section = optional + 0xE0
    struct.pack_into(
        "<8sIIIIIIHHI", data, section, b".data\0\0\0", 0x2200, 0x1000,
        0x2200, 0x200, 0, 0, 0, 0, 0xC0000040,
    )
    table_offset = 0x400
    for index, (owner, prefix) in enumerate(((b"atle", b"aa"), (b"mulle", b"mm"))):
        record = owner + b"\0" * (32 - len(owner)) + prefix + b"\0"
        data[table_offset + index * 35:table_offset + (index + 1) * 35] = record
    formats = (
        b"data\\sound\\voices\\%s%02u%04u.wav\0",
        b"data\\sound\\voices\\%s\\%s%02u%04u%s.wav\0",
    )
    format_offsets = (0x900, 0xA00)
    for offset, value in zip(format_offsets, formats):
        data[offset:offset + len(value)] = value
    builder = 0xC00
    data[builder:builder + 9] = bytes.fromhex("64a1000000006aff68")
    for index, offset in enumerate(format_offsets):
        address = 0x00401000 + (offset - 0x200)
        struct.pack_into("<I", data, builder + 0x30 + index * 8, address)
    data[builder + 0x80:builder + 0x86] = bytes.fromhex("4383fb640f8c")
    data[0x1200:0x1207] = bytes.fromhex("83ff01755b33ff")
    path.write_bytes(data)


class FlightSceneAssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        files = {
            "data/Graphics/Locations/test_site/background/layer.gti": gti(1, 2, 3),
            "data/Graphics/Characters/atle/atle_k1_00.gti": gti(4, 5, 6),
            "data/Graphics/Characters/mulle/mulle_k1_00.gti": gti(7, 8, 9),
            "data/Sound/Voices/h/AA010001H.WAV": wav(b"A"),
            "data/Sound/Voices/h/AA020001H.WAV": wav(b"B"),
            "data/Sound/Voices/b/MM010040B.WAV": wav(b"C"),
            "data/Sound/Voices/b/MM010041B.WAV": wav(b"D"),
        }
        for relative, payload in files.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)

        self.scripts_path = self.root / "scripts.json"
        scripts = {
            "schema": 2,
            "claim": "SOURCE_STRUCTURE_EXACT",
            "source": {"archive": "data.up", "sha256": "0" * 64, "udsp_version": "1.1"},
            "referenced_character_ids": ["atle", "mulle"],
            "character_definitions": [
                {"character_id": "atle"},
                {"character_id": "mulle"},
            ],
            "scenes": [
                {
                    "id": "test_site",
                    "script_paths": ["data/Scripts/Locations/test_site/talk.def"],
                    "characters": ["atle", "mulle"],
                },
                {
                    "id": "barn",
                    "script_paths": ["data/Scripts/Locations/barn/radio.def"],
                    "characters": [],
                },
            ],
            "scripts": [
                {
                    "path": "data/Scripts/Locations/test_site/talk.def",
                    "type": "LOCATION_SCRIPT", "domain_id": "test_site",
                    "dispatch_id": "talk",
                    "commands": [
                        {"opcode": "POSITION_CHARACTER", "arguments": ["atle", 1, 2]},
                        {"opcode": "PLAY_CHARACTER_SCRIPT", "arguments": ["atle", "stand", "WAIT"]},
                        {"opcode": "POSITION_CHARACTER", "arguments": ["mulle", 3, 4]},
                        {"opcode": "PLAY_CHARACTER_SOUND", "node": None, "loop": False,
                         "arguments": ["atle", 1, "H", "WAIT"]},
                        {"opcode": "PLAY_CHARACTER_SOUND", "node": None, "loop": False,
                         "arguments": ["atle", 1001, "H", "WAIT"]},
                        {"opcode": "PLAY_SOUND", "node": None, "loop": False,
                         "arguments": ["mulle", 40, "B", "WAIT"]},
                    ],
                },
                {
                    "path": "data/Scripts/Locations/barn/radio.def",
                    "type": "LOCATION_SCRIPT", "domain_id": "barn",
                    "dispatch_id": "radio",
                    "commands": [
                        {"opcode": "PLAY_MULLEBARNSOUND", "node": None, "loop": False,
                         "arguments": [40, "WAIT"]},
                        {"opcode": "PLAY_MULLEBARNSOUND", "node": None, "loop": False,
                         "arguments": [41, "WAIT"]},
                    ],
                },
                {
                    "path": "data/Scripts/Characters/atle/stand.def",
                    "type": "CHARACTER_SCRIPT", "domain_id": "atle",
                    "dispatch_id": "stand", "commands": [],
                },
            ],
            "media_references": [
                {
                    "path": "data/Scripts/Locations/test_site/talk.def", "node": None,
                    "loop": False, "opcode": "PLAY_CHARACTER_SOUND", "owner": "atle",
                    "id": 1, "bank": "H",
                },
                {
                    "path": "data/Scripts/Locations/test_site/talk.def", "node": None,
                    "loop": False, "opcode": "PLAY_CHARACTER_SOUND", "owner": "atle",
                    "id": 1001, "bank": "H",
                },
                {
                    "path": "data/Scripts/Locations/test_site/talk.def", "node": None,
                    "loop": False, "opcode": "PLAY_SOUND", "owner": "mulle",
                    "id": 40, "bank": "B",
                },
                {
                    "path": "data/Scripts/Locations/barn/radio.def", "node": None,
                    "loop": False, "opcode": "PLAY_MULLEBARNSOUND", "owner": "barn",
                    "id": 40,
                },
                {
                    "path": "data/Scripts/Locations/barn/radio.def", "node": None,
                    "loop": False, "opcode": "PLAY_MULLEBARNSOUND", "owner": "barn",
                    "id": 41,
                },
            ],
        }
        self.scripts_path.write_text(json.dumps(scripts) + "\n", encoding="utf-8")
        self.dispatch_path = self.root / "dispatch.json"
        dispatch = {
            "schema": 1,
            "contract": "miel-vliegt-scene-dispatch",
            "edition": "synthetic-test",
            "sources": {
                "udsp": {"sha256": hashlib.sha256(self.scripts_path.read_bytes()).hexdigest()}
            },
            "locations": [{"domainId": "test_site"}],
        }
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")
        self.native_mygghanget = {
            "schema": 1,
            "contract": "miel-vliegt-native-mygghanget",
            "claim": "STATIC_CODE_EXACT",
            "claimLimit": [
                "RUNTIME_EXECUTION_UNPROVEN",
                "FRAMEBUFFER_PARITY_UNPROVEN",
            ],
            "source": {"filename": "synthetic.exe", "sha256": NATIVE_EXECUTABLE_SHA256},
            "generator": {
                "path": "tools/miel_vliegt/native_mygghanget_contract.py",
                "sha256": hashlib.sha256(
                    (ROOT / "tools/miel_vliegt/native_mygghanget_contract.py").read_bytes()
                ).hexdigest(),
            },
            "mode": {"id": "mygghanget", "locationId": 22},
            "bootstrapInputContract": {
                "input": {
                    "api": "SendInput", "kind": "keyboard-scan-code",
                    "scanCode": "0x01", "nativeKeyCode": 1,
                    "name": "DIK_ESCAPE",
                },
                "dispatch": {
                    "entry": "0x00417160",
                    "entryReceipt": {"address": "0x00417160", "size": 35},
                    "lookupAddress": "0x004175b9",
                    "lookupReceipt": {"address": "0x004175b9", "size": 30},
                    "lookupTable": "0x004176fc", "lookupIndex": 0,
                    "jumpTable": "0x004176e4", "action": "0x004175d7",
                    "outsideViewBranch": "0x00417614",
                    "handler": "0x00419100",
                },
                "startEngine": {
                    "input": {
                        "api": "SendInput",
                        "kind": "keyboard-scan-code-held-until-departure",
                        "scanCode": "0x2a",
                        "nativeScanCodes": [42, 54, 78],
                        "name": "DIK_LSHIFT_OR_EQUIVALENT_FASTER",
                    },
                    "sample": {
                        "entry": "0x0041da3c",
                        "receipt": {"address": "0x0041da3c", "size": 59},
                        "managerNodeField": "0x74",
                        "throttleAdjust": "0x0040f8d0",
                    },
                    "gate": {
                        "entry": "0x0042611f",
                        "receipt": {"address": "0x0042611f", "size": 48},
                        "sharedFlightField": "0x5c",
                        "throttleField": "0x148",
                        "latchField": "0x8b4",
                        "thresholdAddress": "0x0044c748",
                        "thresholdF32": 0.5,
                    },
                    "directDeparture": {
                        "offscreenTestEntry": "0x004262c9",
                        "receipt": {"address": "0x004262c9", "size": 42},
                        "modeSetCallsite": "0x004262ee",
                        "targetMode": "mode_fly",
                    },
                },
                "preconditions": [
                    "current-mode-is-mode_barn", "pending-mode-is-null",
                    "barn-view-field-0x190-is-zero",
                    "airplane-complete-predicate-is-true",
                ],
                "postconditions": [
                    "mode_mygghanget-field-0x999-set-to-one",
                    "mode_mygghanget-open-selects-state-five",
                    "native-faster-sample-field-0x74-becomes-one",
                    "shared-flight-throttle-field-0x148-reaches-at-least-0.5",
                    "state-five-callsite-0x004262ee-requests-mode_fly-after-offscreen-test",
                    "alternate-state-zero-callsite-0x00425c2e-requests-mode_fly-after-offscreen-test",
                ],
                "policy": "REAL_INPUT_ONLY_NO_DIRECT_HANDLER_OR_STATE_MODE_WRITE",
            },
            "assets": {
                "sky": {
                    "condition": "nice",
                    "bank": "b",
                    "discoveryPolicy": "contiguous-rectangular-grid",
                },
                "presentationBoundary": {
                    "directory": "Data/Graphics/Misc",
                    "loaderReceipt": {
                        "address": "0x004051c8", "size": 164, "sha256": "2" * 64,
                    },
                    "generalSiblings": ["takeoff_general", "land_general_00"],
                    "renderer": {
                        "entry": "0x00405970",
                        "receipt": {"address": "0x00405970", "size": 118},
                        "selectorHandleBase": "0x1d4",
                        "selectorToHandleField": {
                            "1": "0x1d8", "2": "0x1dc", "3": "0x1e0",
                            "4": "0x1e4", "5": "0x1e8",
                        },
                        "inputSemantics": "NONE_STATIC_RENDER_ONLY",
                    },
                    "resources": [
                        {
                            "role": "loading",
                            "assetName": "loading_mygghanget_general",
                            "handleField": "0x1e8",
                            "loadAddress": "0x004051ed",
                            "classification": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
                        },
                        {
                            "role": "start-engine",
                            "assetName": "startengine_mygghanget",
                            "handleField": "0x1dc",
                            "loadAddress": "0x0040522b",
                            "classification": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
                        },
                        {
                            "role": "land",
                            "assetName": "land_mygghanget",
                            "handleField": "0x1e4",
                            "loadAddress": "0x00405259",
                            "classification": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
                        },
                    ],
                },
            },
            "voice": {
                "owner": "mulle",
                "scriptNumber": 42,
                "bank": "b",
                "takeDomain": [1, 2, 3, 4, 5],
                "selection": "one-native-rand-modulo-take-count-plus-one",
            },
        }

    def tearDown(self):
        self.temp.cleanup()

    def build(self, *, prefix_entries=None, native_udsp_path=None, native_source_sha=None):
        source = DirectorySource(self.source)
        native = {
            "schema": 1,
            "contract": "miel-vliegt-native-voice-filename",
            "source": {
                "filename": "synthetic.exe",
                "sha256": native_source_sha or NATIVE_EXECUTABLE_SHA256,
            },
            "ownerPrefixTable": {
                "entries": prefix_entries or [
                    {"owner": "atle", "prefix": "aa"},
                    {"owner": "mulle", "prefix": "mm"},
                ],
            },
            "filenameBuilder": {"zeroMatch": {"result": "ABSENT_NO_COMMAND_NODE"}},
        }
        return build_scene_asset_contract(
            self.dispatch_path,
            self.scripts_path,
            source,
            source,
            native,
            self.native_mygghanget,
            native_udsp_path or ROOT / "content/miel_vliegt/native_udsp_scene_commands.json",
        )

    def add_native_service_media(
        self, judge_prefix="ju", award_prefix="mm", diploma_prefix="dd"
    ):
        scripts = json.loads(self.scripts_path.read_text())
        test_site = next(
            script for script in scripts["scripts"]
            if script.get("path") == "data/Scripts/Locations/test_site/talk.def"
        )
        barn = next(
            script for script in scripts["scripts"]
            if script.get("path") == "data/Scripts/Locations/barn/radio.def"
        )
        test_site["commands"].extend([
            {"opcode": "JUDGE_AIRPLANE", "arguments": [], "node": None, "loop": False},
            {"opcode": "AWARD_DIPLOMA", "arguments": [0], "node": None, "loop": False},
        ])
        barn["commands"].append({
            "opcode": "AWARD_DIPLOMA", "arguments": [1], "node": None, "loop": False,
        })
        self.scripts_path.write_text(json.dumps(scripts) + "\n", encoding="utf-8")
        dispatch = json.loads(self.dispatch_path.read_text())
        dispatch["sources"]["udsp"]["sha256"] = hashlib.sha256(
            self.scripts_path.read_bytes()
        ).hexdigest()
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")

        for bank, prefix, clips in (
            ("f", judge_prefix, range(4, 9)),
            ("y", award_prefix, (451, 452, 453, 456, 454, 455)),
            ("x", diploma_prefix, (38,)),
        ):
            directory = self.source / f"data/Sound/Voices/{bank}"
            directory.mkdir(parents=True, exist_ok=True)
            for clip in clips:
                name = f"{prefix.upper()}01{clip:04d}{bank.upper()}.WAV"
                (directory / name).write_bytes(wav(f"{bank}:{clip}".encode()))

    def test_builds_edition_driven_pack_with_explicit_voice_takes(self):
        contract, payloads = self.build()
        self.assertEqual(contract["domains"]["locations"], ["test_site"])
        self.assertEqual(contract["domains"]["characters"], ["atle", "mulle"])
        self.assertEqual(contract["resolution"]["ownerPrefixes"], {"atle": "aa", "mulle": "mm"})
        self.assertEqual(contract["resolution"]["barnBank"], "b")
        self.assertEqual(contract["counts"], {
            "locationDomains": 1,
            "characterDomains": 2,
            "images": 3,
            "logicalMedia": 5,
            "audioVariants": 4,
            "unresolvedMedia": 1,
        })
        atle = next(item for item in contract["media"] if item["owner"] == "atle" and item["scriptNumber"] == 1)
        self.assertEqual(atle["variants"], [
            {
                "key": "flight-voice-aa-01-0001-h", "take": 1,
                "sourceSha256": "5292db9176d7c18a0a5930f051aa643b2353bbc263b89700512fad372ce2be91",
            },
            {
                "key": "flight-voice-aa-02-0001-h", "take": 2,
                "sourceSha256": "69c5abc076499b33a80b2eb57b4e49951aef1d942bc9bd2247cf866770223317",
            },
        ])
        self.assertEqual(contract["unresolvedReferencedMedia"], [{
            "opcode": "PLAY_CHARACTER_SOUND",
            "owner": "atle",
            "scriptNumber": 1001,
            "resolvedPrefix": "aa",
            "bank": "h",
            "reference": {
                "path": "data/Scripts/Locations/test_site/talk.def",
                "node": None,
                "loop": False,
            },
        }])
        output = self.root / "web"
        export_scene_assets(contract, payloads, output)
        pack = json.loads((output / "flight_scene_assets.json").read_text())
        self.assertNotIn("flight_scene_assets", pack)
        self.assertEqual(list(pack), [
            "flight_scene_shared",
            "flight_scene_location_test_site",
            "flight_scene_barn",
        ])
        self.assertEqual(sum(map(len, pack.values())), 7)
        sections = {section["key"]: section for section in contract["packSections"]}
        shared = sections["flight_scene_shared"]
        self.assertEqual(shared["assetKeys"], ["flight-voice-mm-01-0040-b"])
        location = sections["flight_scene_location_test_site"]
        self.assertEqual(location["dependencyState"], "PROVEN_UDSP_SCRIPT_CLOSURE")
        self.assertEqual(location["dependencies"], ["flight_scene_shared"])
        self.assertEqual(location["characters"], ["atle", "mulle"])
        self.assertEqual(location["characterScripts"], [
            "data/Scripts/Characters/atle/stand.def"
        ])
        self.assertEqual(location["counts"], {"assets": 5, "images": 3, "audio": 2})
        self.assertEqual(location["closureCounts"], {"assets": 6, "images": 3, "audio": 3})
        barn = sections["flight_scene_barn"]
        self.assertEqual(barn["counts"], {"assets": 1, "images": 0, "audio": 1})
        self.assertEqual(barn["closureCounts"], {"assets": 2, "images": 0, "audio": 2})
        self.assertTrue((output / "miel-vliegt/scenes/locations/test-site/background-layer.png").is_file())
        self.assertTrue((output / "miel-vliegt/scenes/audio/h/aa010001h.wav").is_file())

    def test_extracts_native_prefix_builder_and_zero_node_provenance(self):
        executable = self.root / "synthetic.exe"
        synthetic_voice_executable(executable)
        contract = extract_native_voice_contract(executable, {"atle"})
        self.assertEqual(contract["ownerPrefixTable"]["entries"], [
            {"owner": "atle", "prefix": "aa"},
            {"owner": "mulle", "prefix": "mm"},
        ])
        self.assertEqual(contract["filenameBuilder"]["takeScan"], {
            "address": "0x00401a80", "startInclusive": 1, "endExclusive": 100,
            "signature": "4383fb640f8c",
        })
        self.assertEqual(
            contract["filenameBuilder"]["zeroMatch"]["result"],
            "ABSENT_NO_COMMAND_NODE",
        )

    def test_native_owner_table_prevents_archive_prefix_guessing(self):
        (self.source / "data/Sound/Voices/h/BB010001H.WAV").write_bytes(wav(b"X"))
        contract, _ = self.build()
        atle = next(item for item in contract["media"] if item["owner"] == "atle" and item["scriptNumber"] == 1)
        self.assertEqual(atle["resolvedPrefix"], "aa")

    def test_radio_alert_assets_close_every_play_radio_scene_through_shared_pack(self):
        voices = self.source / "data/Sound/Voices/b"
        expected_hashes = {}
        for clip in (43, 44):
            for take in (1, 2):
                name = f"MM{take:02d}{clip:04d}B.WAV"
                payload = wav(bytes((clip, take)))
                (voices / name).write_bytes(payload)
                expected_hashes[name] = hashlib.sha256(payload).hexdigest()

        scripts = json.loads(self.scripts_path.read_text())
        additions = []
        for script in scripts["scripts"]:
            if script.get("type") != "LOCATION_SCRIPT":
                continue
            command = {
                "opcode": "PLAY_RADIO", "node": None, "loop": False,
                "arguments": ["atle", 1, "H", "WAIT"],
            }
            script["commands"].append(command)
            additions.append({
                "path": script["path"], "node": None, "loop": False,
                "opcode": "PLAY_RADIO", "owner": "atle", "id": 1, "bank": "H",
            })
        scripts["media_references"].extend(additions)
        self.scripts_path.write_text(json.dumps(scripts) + "\n", encoding="utf-8")
        dispatch = json.loads(self.dispatch_path.read_text())
        dispatch["sources"]["udsp"]["sha256"] = hashlib.sha256(
            self.scripts_path.read_bytes()
        ).hexdigest()
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")

        contract, _ = self.build()
        alerts = [
            media for media in contract["media"]
            if media["opcode"] == "NATIVE_RADIO_ALERT"
        ]
        self.assertEqual([media["scriptNumber"] for media in alerts], [43, 44])
        for media in alerts:
            self.assertEqual(media["resolvedPrefix"], "mm")
            self.assertEqual(media["bank"], "b")
            self.assertEqual([item["take"] for item in media["variants"]], [1, 2])
            self.assertEqual(
                {reference["domainId"] for reference in media["references"]},
                {"test_site", "barn"},
            )
            for variant in media["variants"]:
                asset = next(item for item in contract["audio"] if item["key"] == variant["key"])
                name = PureWindowsPath(asset["source"]).name
                self.assertEqual(asset["sourceSha256"], expected_hashes[name])
                self.assertEqual(variant["sourceSha256"], asset["sourceSha256"])

        sections = {section["domainId"]: section for section in contract["packSections"]
                    if "domainId" in section}
        alert_keys = {
            variant["key"] for media in alerts for variant in media["variants"]
        }
        shared = next(section for section in contract["packSections"]
                      if section["kind"] == "shared")
        self.assertTrue(alert_keys.issubset(set(shared["assetKeys"])))
        for domain in ("test_site", "barn"):
            self.assertEqual(sections[domain]["dependencies"], ["flight_scene_shared"])
            self.assertTrue(alert_keys.issubset(
                set(sections[domain]["requiredSharedAssetKeys"])
            ))

    def test_radio_alert_take_domain_fails_closed_on_gaps(self):
        voices = self.source / "data/Sound/Voices/b"
        for name in ("MM010043B.WAV", "MM030043B.WAV", "MM010044B.WAV"):
            (voices / name).write_bytes(wav(name.encode()))
        scripts = json.loads(self.scripts_path.read_text())
        script = next(item for item in scripts["scripts"] if item["domain_id"] == "test_site")
        script["commands"].append({
            "opcode": "PLAY_RADIO", "node": None, "loop": False,
            "arguments": ["atle", 1, "H", "WAIT"],
        })
        scripts["media_references"].append({
            "path": script["path"], "node": None, "loop": False,
            "opcode": "PLAY_RADIO", "owner": "atle", "id": 1, "bank": "H",
        })
        self.scripts_path.write_text(json.dumps(scripts) + "\n", encoding="utf-8")
        dispatch = json.loads(self.dispatch_path.read_text())
        dispatch["sources"]["udsp"]["sha256"] = hashlib.sha256(
            self.scripts_path.read_bytes()
        ).hexdigest()
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "empty or non-contiguous"):
            self.build()

    def test_native_service_audio_uses_edition_prefixes_and_shared_closure(self):
        self.add_native_service_media(
            judge_prefix="xy", award_prefix="zz", diploma_prefix="dd"
        )
        voices = self.source / "data/Sound/Voices/b"
        (voices / "ZZ010040B.WAV").write_bytes(wav(b"z40"))
        (voices / "ZZ010041B.WAV").write_bytes(wav(b"z41"))
        contract, _ = self.build(prefix_entries=[
            {"owner": "atle", "prefix": "aa"},
            {"owner": "domaren", "prefix": "xy"},
            {"owner": "mulle", "prefix": "zz"},
            {"owner": "doris", "prefix": "dd"},
        ])

        judge = [
            media for media in contract["media"]
            if media["opcode"] == "NATIVE_JUDGE_AIRPLANE_AUDIO"
        ]
        awards = [
            media for media in contract["media"]
            if media["opcode"] == "NATIVE_AWARD_DIPLOMA_AUDIO"
        ]
        manager = [
            media for media in contract["media"]
            if media["opcode"] == "NATIVE_DIPLOMA_MANAGER_AUDIO"
        ]
        self.assertEqual([media["scriptNumber"] for media in judge], list(range(4, 9)))
        self.assertEqual(
            [media["scriptNumber"] for media in awards],
            [451, 452, 453, 454, 455, 456],
        )
        for media in judge:
            self.assertEqual(media["resolvedPrefix"], "xy")
            self.assertEqual(media["nativeImplicit"], {
                "sourceOpcode": "JUDGE_AIRPLANE",
                "requiredTake": 1,
                "placement": "SHARED_NATIVE_SERVICE_MEDIA",
                "semanticStatus": "UNPROVEN",
                "parityEligible": False,
            })
            self.assertEqual(
                {reference["domainId"] for reference in media["references"]},
                {"test_site"},
            )
            self.assertEqual([variant["take"] for variant in media["variants"]], [1])
        for media in awards:
            self.assertEqual(media["resolvedPrefix"], "zz")
            self.assertEqual(media["nativeImplicit"]["sourceOpcode"], "AWARD_DIPLOMA")
            self.assertEqual(
                {reference["domainId"] for reference in media["references"]},
                {"test_site", "barn"},
            )
        self.assertEqual(len(manager), 1)
        self.assertEqual(manager[0]["scriptNumber"], 38)
        self.assertEqual(manager[0]["resolvedPrefix"], "dd")
        self.assertEqual(manager[0]["bank"], "x")
        self.assertEqual(manager[0]["nativeImplicit"], {
            "sourceOpcode": "AWARD_DIPLOMA",
            "requiredTake": 1,
            "placement": "SHARED_NATIVE_SERVICE_MEDIA",
            "semanticStatus": "UNPROVEN",
            "parityEligible": False,
        })
        self.assertEqual(
            {reference["domainId"] for reference in manager[0]["references"]},
            {"test_site", "barn"},
        )

        shared = next(
            section for section in contract["packSections"] if section["kind"] == "shared"
        )
        implicit_keys = {
            variant["key"]
            for media in judge + awards + manager
            for variant in media["variants"]
        }
        self.assertTrue(implicit_keys.issubset(set(shared["assetKeys"])))
        sections = {
            section.get("domainId"): section for section in contract["packSections"]
        }
        self.assertTrue(implicit_keys.issubset(
            set(sections["test_site"]["requiredSharedAssetKeys"])
        ))
        award_keys = {
            variant["key"] for media in awards for variant in media["variants"]
        }
        self.assertTrue(award_keys.issubset(
            set(sections["barn"]["requiredSharedAssetKeys"])
        ))

    def test_native_implicit_media_missing_duplicate_and_contract_gap_fail_closed(self):
        self.add_native_service_media()
        prefixes = [
            {"owner": "atle", "prefix": "aa"},
            {"owner": "domaren", "prefix": "ju"},
            {"owner": "mulle", "prefix": "mm"},
            {"owner": "doris", "prefix": "dd"},
        ]
        missing = self.source / "data/Sound/Voices/f/JU010006F.WAV"
        missing.unlink()
        with self.assertRaisesRegex(ValueError, "requires exactly one archive entry"):
            self.build(prefix_entries=prefixes)
        missing.write_bytes(wav(b"f:6"))

        with self.assertRaisesRegex(ValueError, "duplicate case-insensitive source path"):
            SourceIndex([
                type("SyntheticSource", (), {
                    "entries": lambda _self: [
                        SourceEntry("data/Sound/Voices/f/JU010006F.WAV", lambda: wav(b"a")),
                        SourceEntry("DATA/sound/voices/F/ju010006f.wav", lambda: wav(b"a")),
                    ],
                })(),
            ])

        native = json.loads(
            (ROOT / "content/miel_vliegt/native_udsp_scene_commands.json").read_text()
        )
        native["observed_runtime_contracts"]["10"]["media_identity"]["clip_domain"] = [
            4, 5, 7, 8,
        ]
        broken = self.root / "native-udsp-gap.json"
        broken.write_text(json.dumps(native) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JUDGE_AIRPLANE score"):
            self.build(prefix_entries=prefixes, native_udsp_path=broken)

        with self.assertRaisesRegex(ValueError, "semantics and edition voice-prefix executable differ"):
            self.build(prefix_entries=prefixes, native_source_sha="0" * 64)

    def test_fails_closed_when_required_graphic_domain_is_empty(self):
        (self.source / "data/Graphics/Locations/test_site/background/layer.gti").unlink()
        with self.assertRaisesRegex(ValueError, "required location graphic domain has no GTI"):
            self.build()

    def test_rejects_harvested_media_reference_drift_from_raw_commands(self):
        scripts = json.loads(self.scripts_path.read_text())
        scripts["media_references"][0]["path"] = "data/Scripts/Locations/test_site/missing.def"
        self.scripts_path.write_text(json.dumps(scripts) + "\n", encoding="utf-8")
        dispatch = json.loads(self.dispatch_path.read_text())
        dispatch["sources"]["udsp"]["sha256"] = hashlib.sha256(self.scripts_path.read_bytes()).hexdigest()
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "drifted from raw scene commands"):
            self.build()

    def add_mygghanget_assets(self):
        graphic = self.source / "data/Graphics/Locations/mygghanget/layer.gti"
        graphic.parent.mkdir(parents=True)
        graphic.write_bytes(gti(10, 11, 12))
        sky = self.source / "data/Graphics/Locations/sky/nice"
        sky.mkdir(parents=True)
        for row in (1, 2):
            for column in (1, 2, 3, 4):
                (sky / f"b{row}_{column}.gti").write_bytes(
                    gti(row * 10, column * 10, row + column)
                )
        misc = self.source / "data/Graphics/Misc"
        misc.mkdir(parents=True)
        for index, name in enumerate((
            "loading_mygghanget_general",
            "startengine_mygghanget",
            "land_mygghanget",
        )):
            (misc / f"{name}.gti").write_bytes(gti(20 + index, 30 + index, 40 + index))
        voices = self.source / "data/Sound/Voices/b"
        for take in range(1, 6):
            (voices / f"MM{take:02d}0042B.WAV").write_bytes(wav(bytes([take])))
        dispatch = json.loads(self.dispatch_path.read_text())
        dispatch["locations"].append({
            "domainId": "mygghanget", "policy": "BESPOKE_NO_UDSP"
        })
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")

    def test_closes_bespoke_location_from_native_assets_without_inventing_udsp(self):
        self.add_mygghanget_assets()
        contract, _ = self.build()
        section = next(
            item for item in contract["packSections"]
            if item["key"] == "flight_scene_location_mygghanget"
        )
        self.assertEqual(
            section["dependencyState"], "PROVEN_NATIVE_BESPOKE_STATIC_CLOSURE"
        )
        self.assertEqual(section["characters"], [])
        self.assertEqual(section["characterScripts"], [])
        self.assertEqual(section["unresolvedDependencies"], [])
        self.assertEqual(len(section["requiredSharedAssetKeys"]), 11)
        self.assertEqual(
            len([key for key in section["requiredSharedAssetKeys"] if "shared-sky-nice-b" in key]),
            8,
        )
        self.assertEqual(section["counts"], {"assets": 6, "images": 1, "audio": 5})
        self.assertEqual(section["closureCounts"], {"assets": 17, "images": 12, "audio": 5})
        boundary = [
            item for item in contract["images"]
            if item["domainKind"] == "presentation-boundary"
        ]
        self.assertEqual([item["role"] for item in boundary], [
            "loading", "start-engine", "land",
        ])
        media = next(
            item for item in contract["media"]
            if item["opcode"] == "NATIVE_MYGGHANGET_VOICE"
        )
        self.assertEqual(media["resolvedPrefix"], "mm")
        self.assertEqual(media["scriptNumber"], 42)
        self.assertEqual(media["bank"], "b")
        self.assertEqual([item["take"] for item in media["variants"]], [1, 2, 3, 4, 5])
        self.assertEqual(contract["sources"]["nativeMygghanget"], self.native_mygghanget)

    def test_fails_closed_when_native_mygghanget_take_domain_differs_from_edition(self):
        self.add_mygghanget_assets()
        voices = self.source / "data/Sound/Voices/b"
        (voices / "MM050042B.WAV").unlink()
        with self.assertRaisesRegex(ValueError, "Mygghanget native take domain"):
            self.build()
        (voices / "MM050042B.WAV").write_bytes(wav(b"5"))
        (voices / "MM060042B.WAV").write_bytes(wav(b"6"))
        with self.assertRaisesRegex(ValueError, "Mygghanget native take domain"):
            self.build()

    def test_resolves_native_voice_bank_independently_from_native_sky_bank(self):
        self.add_mygghanget_assets()
        voice_root = self.source / "data/Sound/Voices"
        (voice_root / "n").mkdir()
        for take in range(1, 6):
            (voice_root / "b" / f"MM{take:02d}0042B.WAV").rename(
                voice_root / "n" / f"MM{take:02d}0042N.WAV"
            )
        self.native_mygghanget["voice"]["bank"] = "n"

        contract, _ = self.build()

        media = next(
            item for item in contract["media"]
            if item["opcode"] == "NATIVE_MYGGHANGET_VOICE"
        )
        self.assertEqual(media["bank"], "n")
        self.assertEqual([item["take"] for item in media["variants"]], [1, 2, 3, 4, 5])

    def test_fails_closed_when_native_mygghanget_sky_grid_has_a_gap(self):
        self.add_mygghanget_assets()
        (self.source / "data/Graphics/Locations/sky/nice/b2_3.gti").unlink()
        with self.assertRaisesRegex(ValueError, "Mygghanget sky grid"):
            self.build()

    def test_fails_closed_when_native_mygghanget_presentation_resource_is_missing(self):
        self.add_mygghanget_assets()
        (self.source / "data/Graphics/Misc/startengine_mygghanget.gti").unlink()
        with self.assertRaisesRegex(ValueError, "Mygghanget presentation resource"):
            self.build()

    def test_rejects_missing_character_script_dependency(self):
        scripts = json.loads(self.scripts_path.read_text())
        scripts["scripts"] = [
            item for item in scripts["scripts"]
            if item["path"] != "data/Scripts/Characters/atle/stand.def"
        ]
        self.scripts_path.write_text(json.dumps(scripts) + "\n", encoding="utf-8")
        dispatch = json.loads(self.dispatch_path.read_text())
        dispatch["sources"]["udsp"]["sha256"] = hashlib.sha256(
            self.scripts_path.read_bytes()
        ).hexdigest()
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing character script"):
            self.build()

    def test_rejects_cross_domain_scene_script(self):
        scripts = json.loads(self.scripts_path.read_text())
        location = scripts["scripts"][0]
        location["domain_id"] = "other_site"
        self.scripts_path.write_text(json.dumps(scripts) + "\n", encoding="utf-8")
        dispatch = json.loads(self.dispatch_path.read_text())
        dispatch["sources"]["udsp"]["sha256"] = hashlib.sha256(
            self.scripts_path.read_bytes()
        ).hexdigest()
        self.dispatch_path.write_text(json.dumps(dispatch) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "crosses its declared domain"):
            self.build()

    def test_export_rejects_duplicate_keys_across_asset_types(self):
        contract, payloads = self.build()
        contract["audio"][0]["key"] = contract["images"][0]["key"]
        with self.assertRaisesRegex(ValueError, "duplicate exported Phaser asset key"):
            export_scene_assets(contract, payloads, self.root / "web")


class CheckedInFlightSceneAssetContractTest(unittest.TestCase):
    def test_contract_is_current_payload_free_and_internally_closed(self):
        path = ROOT / "content/miel_vliegt/flight_scene_asset_contract.json"
        contract = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(contract["schema"], 1)
        self.assertEqual(contract["contract"], "miel-vliegt-flight-scene-assets")
        for key in ("dispatch", "scripts", "generator", "nativeUdspCommands"):
            source = contract["sources"][key]
            source_path = ROOT / source["path"]
            self.assertEqual(hashlib.sha256(source_path.read_bytes()).hexdigest(), source["sha256"])
            self.assertFalse(Path(source["path"]).is_absolute())
        probe = json.loads((ROOT / "content/miel_vliegt/native_scene_probe.json").read_text())
        self.assertEqual(
            contract["sources"]["nativeVoice"]["source"]["sha256"],
            probe["source"]["executable_sha256"],
        )
        native = contract["sources"]["nativeVoice"]
        self.assertEqual(
            {key: native["ownerPrefixTable"][key] for key in ("address", "recordSize", "recordCount")},
            {"address": "0x00455bd0", "recordSize": 35, "recordCount": 29},
        )
        self.assertEqual(native["filenameBuilder"], {
            "address": "0x0041b240",
            "sha256First512Bytes": "86f74e9914a4dcb6c3af036e7f37e042763258d91c3aaf43dac82d35178297c5",
            "formats": [
                "data\\sound\\voices\\%s%02u%04u.wav",
                "data\\sound\\voices\\%s\\%s%02u%04u%s.wav",
            ],
            "takeScan": {
                "address": "0x0041b2fe", "startInclusive": 1, "endExclusive": 100,
                "signature": "4383fb640f8c",
            },
            "zeroMatch": {
                "result": "ABSENT_NO_COMMAND_NODE",
                "nodeDecisionAddress": "0x0043d24c",
                "signature": "83ff01755b33ff",
            },
        })
        native_mygghanget = contract["sources"]["nativeMygghanget"]
        self.assertEqual(native_mygghanget["claim"], "STATIC_CODE_EXACT")
        self.assertEqual(
            set(native_mygghanget["claimLimit"]),
            {"RUNTIME_EXECUTION_UNPROVEN", "FRAMEBUFFER_PARITY_UNPROVEN"},
        )
        self.assertEqual(native_mygghanget["source"]["sha256"], probe["source"]["executable_sha256"])
        native_generator = ROOT / native_mygghanget["generator"]["path"]
        self.assertEqual(
            hashlib.sha256(native_generator.read_bytes()).hexdigest(),
            native_mygghanget["generator"]["sha256"],
        )
        self.assertEqual(native_mygghanget["assets"]["sky"], {
            "condition": "nice",
            "bank": "b",
            "discoveryPolicy": "contiguous-rectangular-grid",
        })
        self.assertEqual(
            native_mygghanget["assets"]["presentationBoundary"]["loaderReceipt"],
            {
                "address": "0x004051c8",
                "size": 164,
                "sha256": "e65833986c2b60314c9876499346ef6a981fbaf9dbd7abdb013d9cd875cdefce",
            },
        )
        self.assertEqual(
            [item["assetName"] for item in
             native_mygghanget["assets"]["presentationBoundary"]["resources"]],
            [
                "loading_mygghanget_general",
                "startengine_mygghanget",
                "land_mygghanget",
            ],
        )
        self.assertEqual(native_mygghanget["voice"]["takeDomain"], [1, 2, 3, 4, 5])
        self.assertEqual(native_mygghanget["stateMachine"]["stateZeroOffscreenAddress"], "0x00425c29")
        self.assertEqual(contract["counts"], {
            "locationDomains": 18,
            "characterDomains": 26,
            "images": len(contract["images"]),
            "logicalMedia": len(contract["media"]),
            "audioVariants": len(contract["audio"]),
            "unresolvedMedia": len(contract["unresolvedReferencedMedia"]),
        })
        self.assertEqual(contract["counts"]["images"], 1197)
        self.assertEqual(contract["counts"]["logicalMedia"], 312)
        self.assertEqual(contract["counts"]["audioVariants"], 349)
        self.assertEqual(contract["counts"]["unresolvedMedia"], 18)
        sections = contract["packSections"]
        self.assertEqual(len(sections), 20)
        self.assertEqual(sections[0]["key"], "flight_scene_shared")
        self.assertEqual(
            [item["domainId"] for item in sections if item["kind"] == "location"],
            contract["domains"]["locations"],
        )
        self.assertEqual(sections[-1]["key"], "flight_scene_barn")
        inventory_keys = {
            item["key"] for item in contract["images"] + contract["audio"]
        }
        assigned_keys = [key for section in sections for key in section["assetKeys"]]
        self.assertEqual(len(assigned_keys), len(set(assigned_keys)))
        self.assertEqual(set(assigned_keys), inventory_keys)
        mygghanget = next(
            item for item in sections if item.get("domainId") == "mygghanget"
        )
        self.assertEqual(
            mygghanget["dependencyState"], "PROVEN_NATIVE_BESPOKE_STATIC_CLOSURE"
        )
        self.assertEqual(mygghanget["characters"], [])
        self.assertEqual(mygghanget["characterScripts"], [])
        self.assertEqual(len(mygghanget["requiredSharedAssetKeys"]), 11)
        self.assertEqual(
            len([
                key
                for key in mygghanget["requiredSharedAssetKeys"]
                if key.startswith("flight-scene-shared-sky-nice-b")
            ]),
            8,
        )
        self.assertTrue(
            any(
                key.startswith("flight-scene-shared-sky-nice-b")
                for key in mygghanget["requiredSharedAssetKeys"]
            )
        )
        self.assertEqual(mygghanget["counts"], {"assets": 52, "images": 47, "audio": 5})
        self.assertEqual(mygghanget["closureCounts"], {"assets": 63, "images": 58, "audio": 5})
        self.assertEqual(
            set(mygghanget["claimLimit"]),
            {"RUNTIME_EXECUTION_UNPROVEN", "FRAMEBUFFER_PARITY_UNPROVEN"},
        )
        mygghanget_voice = next(
            item for item in contract["media"]
            if item["opcode"] == "NATIVE_MYGGHANGET_VOICE"
        )
        self.assertEqual(
            [variant["take"] for variant in mygghanget_voice["variants"]],
            [1, 2, 3, 4, 5],
        )
        alerts = {
            item["scriptNumber"]: item
            for item in contract["media"]
            if item["opcode"] == "NATIVE_RADIO_ALERT"
        }
        self.assertEqual(set(alerts), {43, 44})
        expected_alert_assets = {
            "flight-voice-mm-01-0043-b": (
                "data/Sound/Voices/b/MM010043B.WAV",
                "a6885143feb328a3757f79c55f6f3ca4a8216e2f09a636c14d7b8687ba20cd47",
            ),
            "flight-voice-mm-02-0043-b": (
                "data/Sound/Voices/b/MM020043B.WAV",
                "4c8c8cac84215aff11a2047422ee92019c37a9222f3ef941aa86978804f7eaa5",
            ),
            "flight-voice-mm-01-0044-b": (
                "data/Sound/Voices/b/MM010044B.WAV",
                "09ee2d6053362b349700ecacac35ade4d8ed2846f07e70b4dcef81d94c2eb98b",
            ),
            "flight-voice-mm-02-0044-b": (
                "data/Sound/Voices/b/MM020044B.WAV",
                "2adbd30fa6a5cc176e0957121ec867024b3a435127ad961267e0f47e371fd2fa",
            ),
        }
        audio_by_key = {item["key"]: item for item in contract["audio"]}
        for clip, alert in alerts.items():
            self.assertEqual(alert["resolvedPrefix"], contract["resolution"]["ownerPrefixes"]["mulle"])
            self.assertEqual(alert["bank"], "b")
            self.assertEqual([variant["take"] for variant in alert["variants"]], [1, 2])
            self.assertEqual(
                {reference["domainId"] for reference in alert["references"]},
                {"barn", "doris_digital"},
            )
        for key, (source, digest) in expected_alert_assets.items():
            self.assertEqual(audio_by_key[key]["source"], source)
            self.assertEqual(audio_by_key[key]["sourceSha256"], digest)
            variant = next(
                variant for alert in alerts.values() for variant in alert["variants"]
                if variant["key"] == key
            )
            self.assertEqual(variant["sourceSha256"], digest)
        alert_keys = set(expected_alert_assets)
        shared = sections[0]
        self.assertTrue(alert_keys.issubset(set(shared["assetKeys"])))
        for domain in ("barn", "doris_digital"):
            section = next(item for item in sections if item.get("domainId") == domain)
            self.assertEqual(section["dependencies"], ["flight_scene_shared"])
            self.assertTrue(alert_keys.issubset(set(section["requiredSharedAssetKeys"])))

        native_udsp_source = contract["sources"]["nativeUdspCommands"]
        self.assertEqual(
            native_udsp_source["executableSha256"],
            contract["sources"]["nativeVoice"]["source"]["sha256"],
        )
        judge = [
            item for item in contract["media"]
            if item["opcode"] == "NATIVE_JUDGE_AIRPLANE_AUDIO"
        ]
        awards = [
            item for item in contract["media"]
            if item["opcode"] == "NATIVE_AWARD_DIPLOMA_AUDIO"
        ]
        manager = [
            item for item in contract["media"]
            if item["opcode"] == "NATIVE_DIPLOMA_MANAGER_AUDIO"
        ]
        self.assertEqual([item["scriptNumber"] for item in judge], [4, 5, 6, 7, 8])
        self.assertEqual(
            {item["scriptNumber"] for item in awards},
            {451, 452, 453, 456, 454, 455},
        )
        implicit_keys = set()
        audit = {
            path.casefold(): digest
            for path, digest in native_udsp_scene_commands.NL_SERVICE_MEDIA_SHA256.items()
        }
        for item in judge + awards + manager:
            self.assertEqual(item["status"], "RESOLVED")
            self.assertEqual(item["nativeImplicit"]["requiredTake"], 1)
            self.assertEqual(item["nativeImplicit"]["semanticStatus"], "UNPROVEN")
            self.assertFalse(item["nativeImplicit"]["parityEligible"])
            expected_domains = (
                {"varldsutstallning"}
                if item["opcode"] == "NATIVE_JUDGE_AIRPLANE_AUDIO"
                else {"roy_mccoy", "varldsutstallning"}
            )
            self.assertEqual(
                {reference["domainId"] for reference in item["references"]},
                expected_domains,
            )
            self.assertEqual([variant["take"] for variant in item["variants"]], [1])
            variant = item["variants"][0]
            asset = audio_by_key[variant["key"]]
            self.assertEqual(asset["sourceSha256"], audit[asset["source"].casefold()])
            self.assertEqual(variant["sourceSha256"], asset["sourceSha256"])
            implicit_keys.add(variant["key"])
        self.assertEqual(len(manager), 1)
        self.assertEqual(manager[0]["scriptNumber"], 38)
        self.assertEqual(manager[0]["resolvedPrefix"], "dd")
        self.assertEqual(manager[0]["bank"], "x")
        self.assertTrue(implicit_keys.issubset(set(shared["assetKeys"])))
        for domain in ("roy_mccoy", "varldsutstallning"):
            section = next(item for item in sections if item.get("domainId") == domain)
            expected_keys = {
                variant["key"]
                for item in judge + awards
                if domain in {reference["domainId"] for reference in item["references"]}
                for variant in item["variants"]
            }
            self.assertTrue(expected_keys.issubset(set(section["requiredSharedAssetKeys"])))
        for section in sections[1:]:
            self.assertEqual(
                section["closureAssetKeys"],
                sorted(section["assetKeys"] + section["requiredSharedAssetKeys"]),
            )
            self.assertEqual(
                section["dependencies"],
                ["flight_scene_shared"] if section["requiredSharedAssetKeys"] else [],
            )
        self.assertIn(
            ("grotte", 6, "n"),
            {
                (item["owner"], item["scriptNumber"], item["bank"])
                for item in contract["unresolvedReferencedMedia"]
            },
        )
        audio_keys = {item["key"] for item in contract["audio"]}
        referenced_audio = {
            variant["key"]
            for media in contract["media"]
            for variant in media["variants"]
        }
        self.assertEqual(audio_keys, referenced_audio)
        self.assertEqual(
            {item["status"] for item in contract["media"]},
            {"RESOLVED", "ABSENT_NO_COMMAND_NODE"},
        )
        serialized = path.read_text(encoding="utf-8")
        self.assertNotIn("data:audio", serialized)
        self.assertNotIn("data:image", serialized)
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--",
             "content/miel_vliegt/flight_scene_assets.json",
             "content/miel_vliegt/miel-vliegt/scenes"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        self.assertEqual(tracked, [])
        ignored = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "--quiet", "--",
             "content/miel_vliegt/flight_scene_assets.json"],
            check=False,
        )
        self.assertEqual(ignored.returncode, 0)

    def test_private_payload_generation_is_wired_into_both_build_paths(self):
        generator = "tools/miel_vliegt/flight_scene_assets.py"
        for relative in (
            "tools/miel_vliegt/regenerate_flight_content.sh",
            "deployment/hydrate-proven-flight-payloads.sh",
        ):
            script = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn(generator, script)
            self.assertIn('--data-archive "$ISO_ROOT/data.up"', script)
            self.assertIn('--sounds-archive "$ISO_ROOT/sounds.up"', script)
            self.assertIn('--executable "$SYS/MulleMeck.exe"', script)
            self.assertIn('--output "$ROOT/content/miel_vliegt"', script)

        dockerfile = (ROOT / "deployment/docker/Dockerfile.boten").read_text(encoding="utf-8")
        self.assertIn(
            "COPY ./content/miel_vliegt/flight_scene_assets.json "
            "./assets/flight_scene_assets.json",
            dockerfile,
        )
        hydrator = (ROOT / "deployment/hydrate-proven-flight-payloads.sh").read_text(
            encoding="utf-8"
        )
        payload_array = hydrator.split("PAYLOAD_PATHS=(", 1)[1].split(")", 1)[0]
        self.assertIn("content/miel_vliegt/flight_scene_assets.json", payload_array)
        self.assertIn(
            "COPY ./content/miel_vliegt/flight_scene_asset_contract.json "
            "./assets/flight_scene_asset_contract.json",
            dockerfile,
        )


@unittest.skipUnless(
    os.environ.get("MIEL_VLIEGT_VALIDATE_ISO") == "1"
    and bool(os.environ.get("MIEL_VLIEGT_NATIVE_EXE"))
    and Path(os.environ.get("MIEL_VLIEGT_NATIVE_EXE", "/missing")).is_file()
    and Path("/Volumes/Mielvliegt/data.up").is_file()
    and Path("/Volumes/Mielvliegt/sounds.up").is_file(),
    "set MIEL_VLIEGT_VALIDATE_ISO=1 with the Dutch ISO mounted",
)
class FlightSceneAssetsMountedIsoTest(unittest.TestCase):
    def test_canonical_dutch_archives_resolve_every_scene_asset(self):
        contract, _ = build_scene_asset_contract(
            ROOT / "content/miel_vliegt/scene_dispatch_contract.json",
            ROOT / "content/miel_vliegt/uds_scene_scripts.json",
            ArchiveSource(Path("/Volumes/Mielvliegt/data.up")),
            ArchiveSource(Path("/Volumes/Mielvliegt/sounds.up")),
            extract_native_voice_contract(
                Path(os.environ["MIEL_VLIEGT_NATIVE_EXE"]),
                json.loads((ROOT / "content/miel_vliegt/uds_scene_scripts.json").read_text())[
                    "referenced_character_ids"
                ],
            ),
            extract_native_mygghanget_contract(Path(os.environ["MIEL_VLIEGT_NATIVE_EXE"])),
        )
        self.assertEqual(contract["counts"]["locationDomains"], 18)
        self.assertEqual(contract["counts"]["characterDomains"], 26)
        self.assertGreater(contract["counts"]["images"], 1000)
        self.assertGreater(contract["counts"]["audioVariants"], 250)
        self.assertGreater(contract["counts"]["unresolvedMedia"], 0)
        self.assertEqual(len(contract["packSections"]), 20)
        self.assertEqual(
            sum(section["counts"]["assets"] for section in contract["packSections"]),
            contract["counts"]["images"] + contract["counts"]["audioVariants"],
        )
        self.assertEqual(
            next(
                section for section in contract["packSections"]
                if section.get("domainId") == "mygghanget"
            )["dependencyState"],
            "PROVEN_NATIVE_BESPOKE_STATIC_CLOSURE",
        )


if __name__ == "__main__":
    unittest.main()
