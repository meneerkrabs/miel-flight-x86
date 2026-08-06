from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import subprocess
import unittest

from tools.miel_vliegt.kaitai_adapters import parse_cca_kaitai, parse_user_save_kaitai
from tools.miel_vliegt.parse_cca import FRAME, HEADER, NAME_SIZE, parse_cca
from tools.miel_vliegt.parse_user_save import UserSaveFormatError, parse_user_save
from tools.miel_vliegt.verify_kaitai_parity import _raw_user_save, _user_fixture_receipt


ROOT = Path(__file__).resolve().parents[2]


def cca_fixture(*, animations=("body", "wing"), frame_count=2, frame_rate=25.0):
    payload = bytearray(HEADER.pack(b"CCA\0", 1, len(animations), frame_count, frame_rate))
    for animation_index, name in enumerate(animations):
        payload.extend((name.encode("ascii") + b"\0").ljust(NAME_SIZE, b"\0"))
        for frame_index in range(frame_count):
            base = float(animation_index * 10 + frame_index)
            payload.extend(FRAME.pack(base, base + 1, base + 2, 1.0, 0.0, 0.0, 0.0))
    return bytes(payload)


class KaitaiParityTest(unittest.TestCase):
    def test_checked_in_generated_sources_match_pinned_compiler(self) -> None:
        result = subprocess.run(
            ["node", "tools/miel_vliegt/kaitai/generate_kaitai.cjs", "--check"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = json.loads(
            (ROOT / "tools/miel_vliegt/kaitai/generated/python/manifest.json").read_text()
        )
        self.assertEqual(manifest["compiler"]["version"], "0.11.0")
        self.assertEqual(manifest["runtime"]["version"], "0.11")

    def test_cca_generated_parser_matches_independent_ir(self) -> None:
        for kwargs in (
            {},
            {"animations": ("one",), "frame_count": 0, "frame_rate": 30.0},
            {"animations": ("a", "b", "c"), "frame_count": 5, "frame_rate": 25.0},
        ):
            with self.subTest(kwargs=kwargs):
                payload = cca_fixture(**kwargs)
                self.assertEqual(parse_cca_kaitai(payload), parse_cca(payload))

    def test_cca_domain_validation_is_not_weakened_by_generated_parser(self) -> None:
        malformed = []
        base = cca_fixture(animations=("body",), frame_count=1)
        malformed.extend((base[:-1], base + b"x", b"NOPE" + base[4:]))
        bad_name = bytearray(base)
        bad_name[HEADER.size : HEADER.size + NAME_SIZE] = b"x" * NAME_SIZE
        malformed.append(bytes(bad_name))
        bad_padding = bytearray(base)
        bad_padding[HEADER.size + 5] = 1
        malformed.append(bytes(bad_padding))
        bad_float = bytearray(base)
        struct.pack_into("<f", bad_float, HEADER.size + NAME_SIZE, math.nan)
        malformed.append(bytes(bad_float))
        for payload in malformed:
            with self.subTest(size=len(payload)):
                with self.assertRaises(ValueError):
                    parse_cca(payload)
                with self.assertRaises(ValueError):
                    parse_cca_kaitai(payload)

    def test_user_container_generated_parser_matches_independent_ir(self) -> None:
        payload = _raw_user_save(
            b"Sander",
            ((b"MISS", b"first"), (b"INVI", b"propeller\0"), (b"MISS", b"second")),
        )
        self.assertEqual(parse_user_save_kaitai(payload), parse_user_save(payload))
        receipt = _user_fixture_receipt()
        self.assertEqual(receipt["native_samples"], 0)
        self.assertEqual(receipt["claim"], "SYNTHETIC_DIFFERENTIAL_EXACT")

    def test_user_container_still_fails_closed(self) -> None:
        valid = _raw_user_save(b"Miel", ())
        malformed = (
            b"RIFF" + valid[4:],
            valid[:4] + struct.pack(">I", len(valid)) + valid[8:],
            _raw_user_save(b"Miel", ((b"FUTR", b"x"),)),
        )
        for payload in malformed:
            with self.subTest(payload=payload[:20]):
                with self.assertRaises(UserSaveFormatError):
                    parse_user_save(payload)
                with self.assertRaises(UserSaveFormatError):
                    parse_user_save_kaitai(payload)


if __name__ == "__main__":
    unittest.main()
