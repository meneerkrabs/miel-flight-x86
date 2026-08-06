from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import tempfile
import unittest

from tools.miel_vliegt.parse_user_save import (
    ROOT_ID,
    UserSave,
    UserSaveChunk,
)
from tools.miel_vliegt.user_save_payloads import (
    AirplanePart,
    AirplanePartsPayload,
    BarnPart,
    BarnPayload,
    CStringPayload,
    DiplomaPayload,
    ExportedAirplanePayload,
    MissionPayload,
    MissionStateChange,
    PhotoPayload,
    STRUCTURAL_ORACLE,
    SavedAirplanePayload,
    UserSavePayloadError,
    load_mission_shapes,
    parse_typed_chunk,
    parse_typed_payload,
    parse_typed_user_save,
    serialize_typed_payload,
)


def mission_payload(
    mission_id: int = 1,
    state: int = 2,
    is_random: int = 0,
    dependencies: tuple[int, ...] = (1, 0, 1, 0),
    changes: tuple[tuple[int, int], ...] = ((0, 0), (1, 0), (1, 1), (0, 1)),
) -> bytes:
    return (
        struct.pack("<III", mission_id, state, is_random)
        + struct.pack(f"<{len(dependencies)}I", *dependencies)
        + b"".join(struct.pack("<II", *change) for change in changes)
    )


class UserSavePayloadTests(unittest.TestCase):
    def assert_lossless(self, chunk_id: bytes, payload: bytes) -> object:
        value = parse_typed_payload(chunk_id, payload)
        self.assertEqual(serialize_typed_payload(chunk_id, value), payload)
        return value

    def test_name_and_inventory_are_strict_ascii_cstrings(self) -> None:
        self.assertEqual(self.assert_lossless(b"NAME", b"Sander\0"), CStringPayload("Sander"))
        self.assertEqual(self.assert_lossless(b"INVI", b"propeller\0"), CStringPayload("propeller"))

        for payload, message in (
            (b"unterminated", "not NUL-terminated"),
            (b"first\0trailing", "bytes after"),
            (b"Miel\xff\0", "not ASCII"),
        ):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(UserSavePayloadError, message):
                    parse_typed_payload(b"NAME", payload)

    def test_photo_payload_is_exact_and_validates_every_status(self) -> None:
        statuses = tuple(tuple((x + y) % 3 for x in range(10)) for y in range(10))
        raw = struct.pack(
            "<102I",
            1,
            0,
            *(status for row in statuses for status in row),
        )
        self.assertEqual(self.assert_lossless(b"PHOT", raw), PhotoPayload(1, 0, statuses))

        with self.assertRaisesRegex(UserSavePayloadError, "exactly 408 bytes"):
            parse_typed_payload(b"PHOT", raw[:-4])
        invalid = bytearray(raw)
        struct.pack_into("<I", invalid, 2 * 4 + 37 * 4, 3)
        with self.assertRaisesRegex(UserSavePayloadError, r"status\[3\]\[7\].*0, 1, or 2"):
            parse_typed_payload(b"PHOT", bytes(invalid))
        for enabled in (2, 0xFFFFFFFF):
            invalid = struct.pack("<I", enabled) + raw[4:]
            with self.assertRaisesRegex(UserSavePayloadError, "enabled.*0 or 1"):
                parse_typed_payload(b"PHOT", invalid)

    def test_diploma_contains_exactly_six_little_endian_u32_values(self) -> None:
        raw = struct.pack("<6I", 0, 1, 2, 3, 0x12345678, 0xFFFFFFFF)
        self.assertEqual(
            self.assert_lossless(b"DIPL", raw),
            DiplomaPayload((0, 1, 2, 3, 0x12345678, 0xFFFFFFFF)),
        )
        with self.assertRaisesRegex(UserSavePayloadError, "exactly 24 bytes"):
            parse_typed_payload(b"DIPL", raw + b"\0")

    def test_barn_records_accept_finite_or_all_nan_positions_losslessly(self) -> None:
        finite = struct.pack("<IIfff", 8, 42, 1.25, -2.5, 0.0)
        nan_bits = bytes.fromhex("0100c07f 0200c07f 0300c07f")
        all_nan = struct.pack("<II", 0, 99) + nan_bits
        value = self.assert_lossless(b"BARN", finite + all_nan)
        self.assertIsInstance(value, BarnPayload)
        assert isinstance(value, BarnPayload)
        self.assertEqual(value.parts[0], BarnPart(8, 42, 1.25, -2.5, 0.0))
        self.assertTrue(all(math.isnan(v) for v in (value.parts[1].x, value.parts[1].y, value.parts[1].z)))

        with self.assertRaisesRegex(UserSavePayloadError, "location must be in 0..8"):
            parse_typed_payload(b"BARN", struct.pack("<IIfff", 9, 1, 0, 0, 0))
        with self.assertRaisesRegex(UserSavePayloadError, "finite floats or three NaNs"):
            parse_typed_payload(b"BARN", struct.pack("<IIfff", 0, 1, math.nan, 0, math.nan))
        with self.assertRaisesRegex(UserSavePayloadError, "multiple of 20"):
            parse_typed_payload(b"BARN", finite + b"x")

    def test_airp_airb_and_aira_are_nested_and_lossless(self) -> None:
        parts = struct.pack("<IHHIHH", 4, 2, 0xFFFF, 0x12345678, 5, 1)
        airp = self.assert_lossless(b"AIRP", parts)
        self.assertEqual(
            airp,
            AirplanePartsPayload((AirplanePart(4, 2, 0xFFFF), AirplanePart(0x12345678, 5, 1))),
        )

        airb = self.assert_lossless(b"AIRB", b"Miels vliegtuig\0" + parts)
        self.assertEqual(airb, ExportedAirplanePayload("Miels vliegtuig", airp))

        aira = self.assert_lossless(b"AIRA", struct.pack("<I", 17) + b"Miels vliegtuig\0" + parts)
        self.assertEqual(aira, SavedAirplanePayload(17, airb))

        with self.assertRaisesRegex(UserSavePayloadError, "multiple of 8"):
            parse_typed_payload(b"AIRB", b"plane\0" + parts + b"x")
        with self.assertRaisesRegex(UserSavePayloadError, "too short"):
            parse_typed_payload(b"AIRA", struct.pack("<I", 1))

    def test_mission_shape_is_derived_from_first_party_contract(self) -> None:
        value = self.assert_lossless(b"MISS", mission_payload())
        self.assertEqual(
            value,
            MissionPayload(
                1,
                2,
                0,
                (1, 0, 1, 0),
                (
                    MissionStateChange(0, 0),
                    MissionStateChange(1, 0),
                    MissionStateChange(1, 1),
                    MissionStateChange(0, 1),
                ),
            ),
        )
        shapes = load_mission_shapes()
        self.assertEqual(shapes[1], (4, 4))
        self.assertEqual(shapes[30], (4, 5))
        self.assertNotIn(28, shapes)
        self.assertNotIn(29, shapes)

    def test_mission_rejects_unknown_ambiguous_bad_size_and_bad_flags(self) -> None:
        with self.assertRaisesRegex(UserSavePayloadError, "id 28 is structurally ambiguous"):
            parse_typed_payload(
                b"MISS",
                mission_payload(28, dependencies=(1, 0, 1), changes=((0, 0), (1, 1))),
            )
        with self.assertRaisesRegex(UserSavePayloadError, "id 29 is structurally ambiguous"):
            parse_typed_payload(
                b"MISS",
                mission_payload(29, dependencies=(1, 0, 1, 0), changes=((0, 0),) * 3),
            )
        with self.assertRaisesRegex(UserSavePayloadError, "id 0.*absent"):
            parse_typed_payload(b"MISS", mission_payload(0))
        with self.assertRaisesRegex(UserSavePayloadError, "exactly 60 bytes"):
            parse_typed_payload(b"MISS", mission_payload() + b"\0")
        with self.assertRaisesRegex(UserSavePayloadError, "state must be in 0..3"):
            parse_typed_payload(b"MISS", mission_payload(state=4))
        with self.assertRaisesRegex(UserSavePayloadError, "is_random.*0 or 1"):
            parse_typed_payload(b"MISS", mission_payload(is_random=2))
        with self.assertRaisesRegex(UserSavePayloadError, r"dependency\[2\].*0 or 1"):
            parse_typed_payload(b"MISS", mission_payload(dependencies=(1, 0, 2, 0)))
        with self.assertRaisesRegex(UserSavePayloadError, "success_processed.*0 or 1"):
            parse_typed_payload(
                b"MISS",
                mission_payload(changes=((0, 0), (1, 0), (1, 2), (0, 1))),
            )

    def test_mission_contract_ambiguity_is_computed_not_hardcoded(self) -> None:
        contract = {
            "missions": [
                {"id": 7, "dependencies": [{}], "actions": [{}, {}]},
                {"id": 7, "dependencies": [{}, {}], "actions": [{}, {}]},
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "missions.json")
            path.write_text(json.dumps(contract), encoding="utf-8")
            self.assertEqual(load_mission_shapes(path), {})
            with self.assertRaisesRegex(UserSavePayloadError, "structurally ambiguous"):
                parse_typed_payload(
                    b"MISS",
                    mission_payload(7, dependencies=(1,), changes=((0, 0), (0, 0))),
                    mission_contract=path,
                )

    def test_typed_layer_consumes_structural_models_without_mutating_them(self) -> None:
        save = UserSave(
            ROOT_ID,
            (
                UserSaveChunk(b"NAME", b"Miel\0"),
                UserSaveChunk(b"INVI", b"camera\0"),
                UserSaveChunk(b"AIRP", struct.pack("<IHH", 9, 2, 1)),
            ),
        )
        typed = parse_typed_user_save(save)
        self.assertEqual(
            typed.chunks,
            (
                parse_typed_chunk(save.chunks[0]),
                parse_typed_chunk(save.chunks[1]),
                parse_typed_chunk(save.chunks[2]),
            ),
        )
        self.assertEqual(save.chunks[0].payload, b"Miel\0")

    def test_wrong_value_pair_and_unknown_payload_fail_closed(self) -> None:
        with self.assertRaisesRegex(UserSavePayloadError, "does not match"):
            serialize_typed_payload(b"AIRP", CStringPayload("wrong"))
        with self.assertRaisesRegex(UserSavePayloadError, "exactly 60 bytes"):
            serialize_typed_payload(
                b"MISS",
                MissionPayload(1, 0, 0, (0,), (MissionStateChange(0, 0),)),
            )
        with self.assertRaisesRegex(UserSavePayloadError, "unsupported typed payload"):
            parse_typed_payload(b"NOPE", b"")

    def test_secondary_oracle_is_explicitly_not_runtime_proof(self) -> None:
        self.assertEqual(STRUCTURAL_ORACLE["role"], "SECONDARY_STRUCTURAL_ORACLE")
        self.assertFalse(STRUCTURAL_ORACLE["native_roundtrip_proven"])
        self.assertEqual(
            STRUCTURAL_ORACLE["commit"],
            "e34efcd858ec4475fa03d3f8668fa4e26f9e780e",
        )


if __name__ == "__main__":
    unittest.main()
