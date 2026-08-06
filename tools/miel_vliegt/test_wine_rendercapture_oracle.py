#!/usr/bin/env python3
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt import wine_rendercapture_oracle as oracle


def scenario(**changes):
    value = {
        "schema": 1,
        "id": "smoke",
        "description": "unit fixture, never native evidence",
        "target": "launcher",
        "renderer": "gdi",
        "duration_seconds": 2,
        "window_rect": {"x": 0, "y": 0, "width": 640, "height": 480},
        "frame_times_seconds": [0, 2],
        "inputs": [],
    }
    value.update(changes)
    return value


def write_bmp(path: Path) -> None:
    width, height = 640, 480
    pixels = bytearray(width * height * 4)
    for index in range(width * height):
        pixels[index * 4:index * 4 + 4] = b"\x10\x20\x30\x00"
    pixels[-4:] = b"\x40\x50\x60\x00"
    offset = 14 + 40
    header = struct.pack("<2sIHHI", b"BM", offset + len(pixels), 0, 0, offset)
    dib = struct.pack("<IiiHHIIiiII", 40, width, -height, 1, 32, 0, len(pixels), 0, 0, 0, 0)
    path.write_bytes(header + dib + pixels)


class WineRendercaptureOracleTests(unittest.TestCase):
    def test_scenario_pins_launcher_only_gdi_policy(self):
        self.assertEqual(oracle.validate_scenario(scenario())["renderer"], "gdi")
        tracked = json.loads(
            (oracle.ROOT / "tools/miel_vliegt/scenarios/wine_render_smoke.json").read_text(encoding="utf-8")
        )
        self.assertEqual(oracle.validate_scenario(tracked)["renderer"], "gdi")
        with self.assertRaisesRegex(ValueError, "restricted to the 2D launcher"):
            oracle.validate_scenario(scenario(target="game"))
        self.assertEqual(
            oracle.validate_scenario(scenario(target="game", renderer="default"))["renderer"],
            "default",
        )

    def test_scenario_rejects_timing_and_unknown_fields(self):
        with self.assertRaisesRegex(ValueError, "unique, ordered"):
            oracle.validate_scenario(scenario(frame_times_seconds=[2, 1]))
        invalid = scenario()
        invalid["unreviewed"] = True
        with self.assertRaisesRegex(ValueError, "invalid Wine capture scenario"):
            oracle.validate_scenario(invalid)

    def test_bmp_is_canonicalized_to_rgba_and_deterministic_png(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bmp, rgba, png = root / "frame.bmp", root / "frame.rgba", root / "frame.png"
            write_bmp(bmp)
            width, height, digest = oracle._canonicalize_bmp(bmp, rgba, png)
            self.assertEqual((width, height), (640, 480))
            self.assertEqual(rgba.stat().st_size, 640 * 480 * 4)
            self.assertEqual(digest, oracle.sha256_file(rgba))
            self.assertEqual(oracle._image_size(png), (640, 480))

    def test_capture_lock_rejects_a_second_oracle(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "capture.lock"
            with mock.patch.dict(os.environ, {"MIEL_WINE_CAPTURE_LOCK": str(lock)}):
                with oracle._capture_lock(Path(temporary) / "first"):
                    with self.assertRaisesRegex(ValueError, "another Wine rendercapture is active"):
                        with oracle._capture_lock(Path(temporary) / "second"):
                            pass

    def test_failed_capture_reaps_only_its_private_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preflight = root / "preflight.json"
            scenario_path = root / "scenario.json"
            output = root / "capture"
            wine = root / "bin/wine"
            wine.parent.mkdir()
            wine.write_bytes(b"wine")
            preflight.write_text(json.dumps({"tools": {"wine": {"path": str(wine)}}}), encoding="utf-8")
            scenario_path.write_text(json.dumps(scenario()), encoding="utf-8")

            def fail(*_args, **_kwargs):
                (output / "wine-prefix").mkdir(parents=True)
                (output / "game").mkdir()
                raise ValueError("deliberate failure")

            with mock.patch.object(oracle, "_capture_unlocked", side_effect=fail), \
                    mock.patch.object(oracle, "_kill_wine_prefix") as cleanup, \
                    mock.patch.dict(os.environ, {"MIEL_WINE_CAPTURE_LOCK": str(root / "lock")}):
                with self.assertRaisesRegex(ValueError, "deliberate failure"):
                    oracle.capture(preflight, scenario_path, output)
            cleanup.assert_called_once_with(str(wine), output / "wine-prefix")
            self.assertFalse((output / "wine-prefix").exists())
            self.assertFalse((output / "game").exists())

    def test_blocker_receipt_never_claims_render_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preflight, scenario_path = root / "preflight.json", root / "scenario.json"
            preflight.write_text("{}", encoding="utf-8")
            scenario_path.write_text(json.dumps(scenario()), encoding="utf-8")
            output = root / "capture"
            output.mkdir()
            (output / "wine.log").write_text("original process failed\n", encoding="utf-8")
            path = oracle.write_capture_blocker(preflight, scenario_path, output, ValueError("flat framebuffer"))
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(value["status"], "BLOCKED")
            self.assertFalse(value["evidence_policy"]["render_evidence_produced"])
            self.assertEqual(value["error"]["detail"], "flat framebuffer")
            self.assertFalse((output / "capture-receipt.json").exists())

    @unittest.skipUnless(oracle._tool("zig"), "Zig is required for helper reproducibility")
    def test_capture_helper_build_is_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, first_provenance = oracle.build_capture_helper(Path(temporary) / "first")
            second, second_provenance = oracle.build_capture_helper(Path(temporary) / "second")
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertEqual(oracle.sha256_file(first), oracle.sha256_file(second))
            self.assertEqual(first_provenance["source_sha256"], second_provenance["source_sha256"])
            self.assertEqual(first_provenance["binary_sha256"], second_provenance["binary_sha256"])


if __name__ == "__main__":
    unittest.main()
