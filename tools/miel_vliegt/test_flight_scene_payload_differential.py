import copy
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import flight_scene_payload_differential as differential


ROOT = Path(__file__).resolve().parents[2]


def png(red: int, green: int, blue: int) -> bytes:
    import zlib

    signature = b"\x89PNG\r\n\x1a\n"

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    raw = bytes((0, red, green, blue, 255))
    return signature + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def wav(marker: bytes) -> bytes:
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    body = b"fmt " + struct.pack("<I", len(fmt)) + fmt
    body += b"data" + struct.pack("<I", len(marker)) + marker
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WAVE" + body


class FlightScenePayloadDifferentialTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.asset_root = self.root / "miel-vliegt"
        image = png(1, 2, 3)
        audio = wav(b"A")
        image_path = self.asset_root / "scenes/location/background.png"
        audio_path = self.asset_root / "scenes/audio/voice.wav"
        image_path.parent.mkdir(parents=True)
        audio_path.parent.mkdir(parents=True)
        image_path.write_bytes(image)
        audio_path.write_bytes(audio)
        self.contract = {
            "schema": 1,
            "contract": "miel-vliegt-flight-scene-assets",
            "counts": {"images": 1, "audioVariants": 1},
            "images": [{
                "type": "image",
                "key": "background",
                "url": "assets/miel-vliegt/scenes/location/background.png",
                "outputSha256": hashlib.sha256(image).hexdigest(),
                "width": 1,
                "height": 1,
            }],
            "audio": [{
                "type": "audio",
                "key": "voice",
                "urls": ["assets/miel-vliegt/scenes/audio/voice.wav"],
                "sourceSha256": hashlib.sha256(audio).hexdigest(),
            }],
            "packSections": [{
                "key": "flight_scene",
                "assetKeys": ["background", "voice"],
            }],
        }
        self.contract_path = self.root / "contract.json"
        self.pack_path = self.root / "pack.json"
        self.contract_path.write_text(json.dumps(self.contract) + "\n")
        self.pack_path.write_text(json.dumps({
            "flight_scene": [
                {"type": "image", "key": "background",
                 "url": "assets/miel-vliegt/scenes/location/background.png"},
                {"type": "audio", "key": "voice",
                 "urls": ["assets/miel-vliegt/scenes/audio/voice.wav"]},
            ]
        }) + "\n")

    def tearDown(self):
        self.temp.cleanup()

    def build(self):
        return differential.build_receipt(
            self.contract_path,
            self.pack_path,
            self.asset_root,
            differential.DEFAULT_SCHEMA,
        )

    def test_builds_exact_three_class_receipt_without_pixel_claim(self):
        receipt = self.build()
        self.assertEqual(receipt["claim"], "EXACT_EXPORTED_SCENE_PAYLOAD")
        self.assertEqual(
            set(receipt["classes"]),
            {"sceneImages", "sceneAudio", "phaserPack"},
        )
        self.assertEqual(receipt["summary"]["files"], 2)
        self.assertEqual(receipt["summary"]["assetClasses"], 3)
        self.assertFalse(receipt["summary"]["framebufferParityClaimed"])
        differential.validate_receipt(receipt)

    def test_rejects_missing_corrupt_and_unlisted_payloads(self):
        mutations = [
            ("missing exported scene image", lambda: (
                self.asset_root / "scenes/location/background.png"
            ).unlink()),
            ("scene audio hash drifted", lambda: (
                self.asset_root / "scenes/audio/voice.wav"
            ).write_bytes(wav(b"B"))),
            ("unlisted=", lambda: (
                self.asset_root / "scenes/extra.bin"
            ).write_bytes(b"extra")),
        ]
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                self.tearDown()
                self.setUp()
                mutate()
                with self.assertRaisesRegex(
                    differential.PayloadDifferentialError, expected
                ):
                    self.build()

    def test_rejects_pack_drift_and_receipt_promotion(self):
        pack = json.loads(self.pack_path.read_text())
        pack["flight_scene"].reverse()
        self.pack_path.write_text(json.dumps(pack))
        with self.assertRaisesRegex(
            differential.PayloadDifferentialError, "Phaser scene pack differs"
        ):
            self.build()

        self.pack_path.write_text(json.dumps({
            "flight_scene": [
                {"type": "image", "key": "background",
                 "url": "assets/miel-vliegt/scenes/location/background.png"},
                {"type": "audio", "key": "voice",
                 "urls": ["assets/miel-vliegt/scenes/audio/voice.wav"]},
            ]
        }))
        receipt = self.build()
        forged = copy.deepcopy(receipt)
        forged["summary"]["framebufferParityClaimed"] = True
        unsigned = dict(forged)
        unsigned.pop("subjectSha256")
        forged["subjectSha256"] = hashlib.sha256(
            differential._canonical(unsigned)
        ).hexdigest()
        with self.assertRaisesRegex(
            differential.PayloadDifferentialError, "cannot claim exact closure"
        ):
            differential.validate_receipt(forged)

    def test_schema_guard_is_fail_closed(self):
        schema = json.loads(differential.DEFAULT_SCHEMA.read_text())
        differential.validate_schema_guard(schema)
        schema["additionalProperties"] = True
        with self.assertRaisesRegex(
            differential.PayloadDifferentialError, "schema guard"
        ):
            differential.validate_schema_guard(schema)


class CheckedInFlightScenePayloadDifferentialTest(unittest.TestCase):
    def test_receipt_is_bound_to_current_contract_generator_and_schema(self):
        receipt = json.loads(differential.DEFAULT_RECEIPT.read_text(encoding="utf-8"))
        differential.validate_receipt(receipt)
        for name, identity in receipt["inputs"].items():
            path = ROOT / identity["path"]
            self.assertTrue(path.is_file(), name)
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(),
                identity["sha256"],
                name,
            )
        contract = json.loads(differential.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(
            hashlib.sha256(differential._canonical(contract)).hexdigest(),
            receipt["inputs"]["contract"]["canonicalSha256"],
        )

    def test_private_payload_matches_receipt_when_hydrated(self):
        if not differential.DEFAULT_ASSET_ROOT.is_dir() \
                or not differential.DEFAULT_PACK.is_file():
            self.skipTest("gitignored flight scene payload is not hydrated")
        self.assertEqual(
            differential.build_receipt(),
            json.loads(differential.DEFAULT_RECEIPT.read_text(encoding="utf-8")),
        )


if __name__ == "__main__":
    unittest.main()
