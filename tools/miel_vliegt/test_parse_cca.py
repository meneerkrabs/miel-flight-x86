import math
import struct
import unittest

from tools.miel_vliegt.parse_cca import FRAME, HEADER, NAME_SIZE, parse_cca


def cca_fixture(*, animations=("body", "wing"), frame_count=2, frame_rate=25.0):
    payload = bytearray(HEADER.pack(b"CCA\0", 1, len(animations), frame_count, frame_rate))
    for animation_index, name in enumerate(animations):
        encoded = name.encode("ascii") + b"\0"
        payload.extend(encoded.ljust(NAME_SIZE, b"\0"))
        for frame_index in range(frame_count):
            base = float(animation_index * 10 + frame_index)
            payload.extend(FRAME.pack(base, base + 1, base + 2, 1.0, 0.0, 0.0, 0.0))
    return bytes(payload)


class CcaParserTest(unittest.TestCase):
    def test_parses_all_blueprint_frames_in_wxyz_order(self):
        parsed = parse_cca(cca_fixture())
        self.assertEqual((parsed.looping, parsed.animation_count, parsed.frame_count), (1, 2, 2))
        self.assertEqual(parsed.frame_rate, 25.0)
        self.assertEqual([item.blueprint_name for item in parsed.animations], ["body", "wing"])
        frame = parsed.animations[1].frames[1]
        self.assertEqual((frame.position.x, frame.position.y, frame.position.z), (11.0, 12.0, 13.0))
        self.assertEqual(
            (frame.orientation.w, frame.orientation.x, frame.orientation.y, frame.orientation.z),
            (1.0, 0.0, 0.0, 0.0),
        )
        self.assertEqual(len(parsed.animations[0].frame_payload_sha256), 64)

    def test_rejects_bad_magic_and_size_drift(self):
        payload = cca_fixture()
        with self.assertRaisesRegex(ValueError, "expected CCA magic"):
            parse_cca(b"NOPE" + payload[4:])
        with self.assertRaisesRegex(ValueError, "truncated"):
            parse_cca(payload[:-1])
        with self.assertRaisesRegex(ValueError, "trailing bytes"):
            parse_cca(payload + b"x")

    def test_rejects_ambiguous_blueprint_names(self):
        payload = bytearray(cca_fixture(animations=("body",), frame_count=1))
        payload[HEADER.size : HEADER.size + NAME_SIZE] = b"x" * NAME_SIZE
        with self.assertRaisesRegex(ValueError, "no NUL-terminated"):
            parse_cca(bytes(payload))
        payload = bytearray(cca_fixture(animations=("body",), frame_count=1))
        payload[HEADER.size + 5] = 1
        with self.assertRaisesRegex(ValueError, "non-zero blueprint-name padding"):
            parse_cca(bytes(payload))

    def test_rejects_invalid_timing_and_non_finite_transforms(self):
        payload = bytearray(cca_fixture(animations=("body",), frame_count=1))
        struct.pack_into("<f", payload, 16, 0.0)
        with self.assertRaisesRegex(ValueError, "invalid frame rate"):
            parse_cca(bytes(payload))
        payload = bytearray(cca_fixture(animations=("body",), frame_count=1))
        struct.pack_into("<f", payload, HEADER.size + NAME_SIZE, math.nan)
        with self.assertRaisesRegex(ValueError, "non-finite transform"):
            parse_cca(bytes(payload))


if __name__ == "__main__":
    unittest.main()
