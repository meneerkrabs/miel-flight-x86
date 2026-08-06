#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.miel_vliegt import native_scene_navigator as navigator


ROOT = Path(__file__).resolve().parents[2]


class FakeImage:
    image_base = 0x00400000

    def __init__(self, manifest):
        self.values = {}
        for record in manifest["engine"].values():
            self.values[int(record["address"], 16)] = bytes.fromhex(record["signature"])
        for call in manifest["engine"]["scene_registry"]["registration_calls"]:
            self.values[int(call["address"], 16)] = bytes.fromhex(call["signature"])
        for scene in manifest["scenes"]:
            self.values[int(scene["constructor"], 16)] = bytes.fromhex(scene["constructor_signature"])
            self.values[int(scene["loader"], 16)] = bytes.fromhex(scene["loader_signature"])
            self.values[int(scene["mode_address"], 16)] = scene["mode"].encode("ascii") + b"\0"
        for target in manifest["startup_targets"]:
            self.values[int(target["mode_address"], 16)] = target["mode"].encode("ascii") + b"\0"
        marker = manifest["engine"]["scene_probe_marker"]
        self.values[int(marker["create_directory_iat"], 16)] = bytes.fromhex(marker["create_directory_iat_signature"])
        self.sections = [{
            "virtual_address": self.image_base,
            "raw_size": 0x70000,
            "raw_offset": 0,
        }]
        self.data = bytearray(self.sections[0]["raw_size"])
        for address, value in self.values.items():
            offset = address - self.image_base
            self.data[offset:offset + len(value)] = value

    def bytes_at(self, address, size):
        offset = address - self.image_base
        return bytes(self.data[offset:offset + size])


class NativeSceneNavigatorTests(unittest.TestCase):
    def setUp(self):
        self.manifest = navigator.load_manifest()

    def test_contract_covers_every_locationinfo_scene_once(self):
        scenes = self.manifest["scenes"]
        self.assertEqual(len(scenes), 18)
        self.assertEqual(
            {scene["location_id"] for scene in scenes},
            {2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22},
        )
        self.assertEqual(len({scene["mode"] for scene in scenes}), 18)
        self.assertEqual(len(self.manifest["engine"]["scene_registry"]["registration_calls"]), 18)
        self.assertEqual(navigator.scene_by_id(self.manifest, "mygghanget")["mode"], "mode_mygghanget")

    def test_flight_is_a_reviewed_startup_target_not_a_fake_location(self):
        target = navigator.startup_target_by_id(self.manifest, "flight")
        self.assertEqual(target, {
            "id": "flight",
            "kind": "runtime_mode",
            "mode": "mode_fly",
            "mode_address": "0x00454f0c",
        })
        self.assertNotIn("flight", {scene["id"] for scene in self.manifest["scenes"]})

    def test_contract_uses_the_native_mode_registry_not_a_guessed_state_offset(self):
        self.assertEqual(self.manifest["engine"]["mode_change"]["address"], "0x0041e450")
        self.assertEqual(self.manifest["engine"]["mode_change"]["manager"], "ecx")
        self.assertEqual(self.manifest["engine"]["mode_change"]["mode_name_pointer"], "[esp+4]")
        self.assertEqual(self.manifest["engine"]["startup_mode_transition"]["original_mode"], "mode_login")
        self.assertEqual(
            self.manifest["navigation"]["confirmation"],
            "target-location-loader-entry",
        )

    def test_unknown_scene_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unknown native scene"):
            navigator.scene_by_id(self.manifest, "made_up_location")

        with self.assertRaisesRegex(ValueError, "unknown native startup target"):
            navigator.startup_target_by_id(self.manifest, "made_up_location")

    def test_executable_preflight_checks_every_hook_mode_and_scene_signature(self):
        fake = FakeImage(self.manifest)
        with patch.object(navigator, "sha256_file", return_value=self.manifest["source"]["executable_sha256"]), \
             patch.object(navigator, "PeImage", return_value=fake):
            self.assertIs(navigator.verify_executable(Path("MulleMeck.exe"), self.manifest), fake)
        broken = copy.deepcopy(self.manifest)
        broken["scenes"][0]["loader_signature"] = "00" * 12
        with patch.object(navigator, "sha256_file", return_value=broken["source"]["executable_sha256"]), \
             patch.object(navigator, "PeImage", return_value=fake):
            with self.assertRaisesRegex(ValueError, "atle_artillerist.loader"):
                navigator.verify_executable(Path("MulleMeck.exe"), broken)

    def test_generated_header_is_deterministic_and_contains_the_reviewed_catalog(self):
        first = navigator.emit_c_header(self.manifest)
        second = navigator.emit_c_header(copy.deepcopy(self.manifest))
        self.assertEqual(first, second)
        self.assertIn("#define MIEL_SCENE_COUNT 18u", first)
        self.assertIn('"mode_roymccoy"', first)
        self.assertIn("0x0041e450u", first)
        self.assertIn("#define MIEL_ENTRYPOINT_ADDRESS 0x00448852u", first)
        self.assertIn("0x55, 0x8b, 0xec", first)
        self.assertTrue(first.endswith("\n"))

    def test_manifest_rejects_locationinfo_drift_and_duplicates(self):
        broken = copy.deepcopy(self.manifest)
        broken["scenes"][0]["location_id"] = broken["scenes"][1]["location_id"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe.json"
            path.write_text(json.dumps(broken), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate scene identity"):
                navigator.load_manifest(path)

    def test_rejected_diagnostic_helper_still_uses_original_setmode(self):
        source = (ROOT / "tools/miel_vliegt/hangover/native_scene_debugger.c").read_text(encoding="utf-8")
        for token in ("DEBUG_ONLY_THIS_PROCESS", "WaitForDebugEvent", "WriteProcessMemory"):
            self.assertIn(token, source)
        self.assertIn("MIEL_MODE_CHANGE_ADDRESS", source)
        self.assertNotIn("MIEL_MODE_TICK_ADDRESS", source)
        self.assertNotIn("current_location_offset", source)

    def test_playable_start_patch_changes_only_the_reviewed_setmode_argument(self):
        fake = FakeImage(self.manifest)
        scene = navigator.scene_by_id(self.manifest, "roy_mccoy")
        transition = self.manifest["engine"]["startup_mode_transition"]
        address = int(transition["address"], 16) + transition["argument_offset"]
        loader = int(scene["loader"], 16)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "MulleMeck.exe"
            output = Path(directory) / "MulleMeck-roy.exe"
            source.write_bytes(fake.data)
            expected_hash = self.manifest["source"]["executable_sha256"]

            def digest(path):
                if path == source:
                    return expected_hash
                return hashlib.sha256(path.read_bytes()).hexdigest()

            with patch.object(navigator, "sha256_file", side_effect=digest), \
                 patch.object(navigator, "PeImage", return_value=fake):
                receipt = navigator.patch_executable(source, output, self.manifest, scene)

            patched = output.read_bytes()
            offset = address - fake.image_base
            self.assertEqual(patched[offset:offset + 4], int(scene["mode_address"], 16).to_bytes(4, "little"))
            loader_offset = loader - fake.image_base
            self.assertEqual(patched[loader_offset:loader_offset + 13], fake.bytes_at(loader, 13))
            self.assertEqual(receipt["strategy"], "startup-mode-argument")
            self.assertIsNone(receipt["marker_directory"])

    def test_flight_start_patch_uses_the_native_mode_fly_string(self):
        fake = FakeImage(self.manifest)
        target = navigator.startup_target_by_id(self.manifest, "flight")
        transition = self.manifest["engine"]["startup_mode_transition"]
        address = int(transition["address"], 16) + transition["argument_offset"]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "MulleMeck.exe"
            output = Path(directory) / "MulleMeck-flight.exe"
            source.write_bytes(fake.data)

            def digest(path):
                if path == source:
                    return self.manifest["source"]["executable_sha256"]
                return hashlib.sha256(path.read_bytes()).hexdigest()

            with patch.object(navigator, "sha256_file", side_effect=digest), \
                 patch.object(navigator, "PeImage", return_value=fake):
                receipt = navigator.patch_executable(
                    source, output, self.manifest, target,
                )
            patched = output.read_bytes()

        offset = address - fake.image_base
        self.assertEqual(
            patched[offset:offset + 4],
            int(target["mode_address"], 16).to_bytes(4, "little"),
        )
        self.assertEqual(receipt["scene"], {
            "id": "flight", "location_id": None,
            "mode": "mode_fly", "kind": "runtime_mode",
        })

    def test_probe_patch_confirms_only_the_requested_loader_with_a_marker(self):
        fake = FakeImage(self.manifest)
        scene = navigator.scene_by_id(self.manifest, "mygghanget")
        marker = self.manifest["engine"]["scene_probe_marker"]
        marker_directory = r"Z:\receipt\scene-hit-box64-mygghanget"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "MulleMeck.exe"
            output = Path(directory) / "MulleMeck-probe.exe"
            source.write_bytes(fake.data)
            expected_hash = self.manifest["source"]["executable_sha256"]

            def digest(path):
                if path == source:
                    return expected_hash
                return hashlib.sha256(path.read_bytes()).hexdigest()

            with patch.object(navigator, "sha256_file", side_effect=digest), \
                 patch.object(navigator, "PeImage", return_value=fake):
                receipt = navigator.patch_executable(
                    source, output, self.manifest, scene,
                    marker_directory=marker_directory,
                )

            patched = output.read_bytes()
            marker_offset = int(marker["address"], 16) - fake.image_base
            self.assertEqual(
                patched[marker_offset:marker_offset + len(marker_directory) + 1],
                marker_directory.encode("ascii") + b"\0",
            )
            loader_offset = int(scene["loader"], 16) - fake.image_base
            self.assertEqual(patched[loader_offset], 0x68)
            self.assertEqual(patched[loader_offset + 11:loader_offset + 13], b"\xeb\xfe")
            self.assertEqual(receipt["strategy"], "startup-mode-argument+probe-loader-marker")
            self.assertEqual([change["kind"] for change in receipt["changes"]], [
                "startup-mode-argument", "probe-marker-directory", "probe-loader-marker",
            ])


if __name__ == "__main__":
    unittest.main()
