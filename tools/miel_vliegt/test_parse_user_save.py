from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from tools.miel_vliegt.parse_user_save import (
    CHUNK_ORDER,
    FORMAT_EVIDENCE_STATUS,
    NAME_ID,
    ROOT_ID,
    SERIALIZER_STATUS,
    UserSave,
    UserSaveChunk,
    UserSaveFormatError,
    load_user_save,
    parse_user_save,
    serialize_user_save,
)


def source_fixture(
    username: bytes = b"Sander",
    chunks: tuple[tuple[bytes, bytes], ...] = (
        (b"MISS", b"\x01\x00\x00\x00"),
        (b"INVI", b"propeller\x00"),
        (b"PHOT", b"\x00\x00\x00\x00"),
        (b"DIPL", b"\x01\x00\x00\x00" * 6),
        (b"BARN", b"hangar-state"),
        (b"AIRP", b"\x06\x00\x00\x00"),
    ),
) -> bytes:
    """Build bytes independently of the production serializer."""

    body = ROOT_ID + NAME_ID + struct.pack(">I", len(username)) + username
    for chunk_id, payload in chunks:
        body += chunk_id + struct.pack(">I", len(payload)) + payload
    return b"FORM" + struct.pack(">I", len(body)) + body


def raw_form(body: bytes) -> bytes:
    return b"FORM" + struct.pack(">I", len(body)) + body


class ParseUserSaveTests(unittest.TestCase):
    def test_parses_special_username_and_all_known_chunks(self) -> None:
        save = parse_user_save(source_fixture())

        self.assertEqual(save.root_id, b"USER")
        self.assertEqual(save.username, b"Sander")
        self.assertEqual(tuple(chunk.chunk_id for chunk in save.chunks), CHUNK_ORDER[:-1])
        self.assertEqual(save.chunks_named(b"NAME")[0].payload, b"Sander")
        self.assertEqual(save.chunks_named(b"INVI")[0].payload, b"propeller\x00")

    def test_repeated_chunks_are_preserved_in_source_order(self) -> None:
        raw = source_fixture(
            chunks=((b"MISS", b"first"), (b"INVI", b"part"), (b"MISS", b"second"))
        )

        save = parse_user_save(raw)

        self.assertEqual(
            [chunk.payload for chunk in save.chunks_named(b"MISS")],
            [b"first", b"second"],
        )
        self.assertEqual(
            [chunk.chunk_id for chunk in save.chunks],
            [b"NAME", b"MISS", b"INVI", b"MISS"],
        )

    def test_empty_username_and_no_gameplay_chunks_remain_structurally_valid(self) -> None:
        self.assertEqual(
            parse_user_save(source_fixture(b"", ())),
            UserSave(ROOT_ID, (UserSaveChunk(NAME_ID, b""),)),
        )

    def test_load_reads_path_without_keeping_original_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "user0.dat")
            path.write_bytes(source_fixture(b"Miel", ()))

            self.assertEqual(load_user_save(path).username, b"Miel")

    def test_rejects_wrong_form_id(self) -> None:
        raw = bytearray(source_fixture())
        raw[0:4] = b"RIFF"
        with self.assertRaisesRegex(UserSaveFormatError, "expected FORM"):
            parse_user_save(bytes(raw))

    def test_rejects_outer_size_mismatch_in_both_directions(self) -> None:
        raw = source_fixture()
        for declared_size in (len(raw) - 9, len(raw) - 7):
            damaged = raw[:4] + struct.pack(">I", declared_size) + raw[8:]
            with self.subTest(declared_size=declared_size):
                with self.assertRaisesRegex(UserSaveFormatError, "FORM size mismatch"):
                    parse_user_save(damaged)

    def test_rejects_wrong_root_id(self) -> None:
        raw = bytearray(source_fixture())
        raw[8:12] = b"GAME"
        with self.assertRaisesRegex(UserSaveFormatError, "expected USER root id"):
            parse_user_save(bytes(raw))

    def test_rejects_name_payload_overrun(self) -> None:
        raw = bytearray(source_fixture(b"Miel", ()))
        raw[16:20] = struct.pack(">I", 5)
        with self.assertRaisesRegex(UserSaveFormatError, "NAME payload overruns"):
            parse_user_save(bytes(raw))

    def test_rejects_missing_misplaced_or_duplicate_name_chunk(self) -> None:
        missing_name = raw_form(ROOT_ID + b"MISS" + struct.pack(">I", 1) + b"x")
        with self.assertRaisesRegex(UserSaveFormatError, "NAME chunk.*first"):
            parse_user_save(missing_name)

        misplaced_name = raw_form(
            ROOT_ID
            + b"MISS"
            + struct.pack(">I", 1)
            + b"x"
            + NAME_ID
            + struct.pack(">I", 4)
            + b"Miel"
        )
        with self.assertRaisesRegex(UserSaveFormatError, "NAME chunk.*first"):
            parse_user_save(misplaced_name)

        duplicate_name = source_fixture(chunks=((NAME_ID, b"second-name"),))
        with self.assertRaisesRegex(UserSaveFormatError, "NAME chunk.*first"):
            parse_user_save(duplicate_name)

    def test_aira_extension_chunk_is_structurally_supported(self) -> None:
        save = parse_user_save(source_fixture(chunks=((b"AIRA", b"aircraft-state"),)))
        self.assertEqual(save.chunks_named(b"AIRA")[0].payload, b"aircraft-state")

    def test_rejects_unknown_chunk_instead_of_preserving_it(self) -> None:
        with self.assertRaisesRegex(UserSaveFormatError, "unsupported user-save chunk id"):
            parse_user_save(source_fixture(chunks=((b"FUTR", b"data"),)))

    def test_rejects_truncated_chunk_header_and_payload(self) -> None:
        header_tail = source_fixture(chunks=())
        header_tail = (
            header_tail[:4]
            + struct.pack(">I", len(header_tail) - 8 + 3)
            + header_tail[8:]
            + b"MIS"
        )
        with self.assertRaisesRegex(UserSaveFormatError, "truncated chunk header"):
            parse_user_save(header_tail)

        payload_overrun = source_fixture(chunks=((b"MISS", b"x"),))
        chunk_size_offset = payload_overrun.index(b"MISS") + 4
        payload_overrun = (
            payload_overrun[:chunk_size_offset]
            + struct.pack(">I", 2)
            + payload_overrun[chunk_size_offset + 4 :]
        )
        with self.assertRaisesRegex(UserSaveFormatError, "MISS payload overruns"):
            parse_user_save(payload_overrun)

    def test_canonical_serializer_groups_native_save_call_order_stably(self) -> None:
        save = UserSave(
            ROOT_ID,
            (
                UserSaveChunk(NAME_ID, b"Miel"),
                UserSaveChunk(b"AIRP", b"plane"),
                UserSaveChunk(b"MISS", b"mission-1"),
                UserSaveChunk(b"BARN", b"barn"),
                UserSaveChunk(b"MISS", b"mission-2"),
            ),
        )

        reparsed = parse_user_save(serialize_user_save(save))

        self.assertEqual(
            [(chunk.chunk_id, chunk.payload) for chunk in reparsed.chunks],
            [
                (b"NAME", b"Miel"),
                (b"MISS", b"mission-1"),
                (b"MISS", b"mission-2"),
                (b"BARN", b"barn"),
                (b"AIRP", b"plane"),
            ],
        )

    def test_canonical_fixture_roundtrips_byte_for_byte(self) -> None:
        raw = source_fixture()
        self.assertEqual(serialize_user_save(parse_user_save(raw)), raw)
        self.assertEqual(FORMAT_EVIDENCE_STATUS, "SOURCE_CORROBORATED_NO_NATIVE_SAMPLE")
        self.assertEqual(SERIALIZER_STATUS, "UNVERIFIED_ORIGINAL_ROUNDTRIP")

    def test_public_models_reject_non_bytes_and_unknown_ids(self) -> None:
        with self.assertRaisesRegex(TypeError, "root id must be bytes"):
            UserSave("USER", ())  # type: ignore[arg-type]
        with self.assertRaisesRegex(UserSaveFormatError, "NAME chunk.*first"):
            UserSave(ROOT_ID, ())
        with self.assertRaisesRegex(TypeError, "payload must be bytes"):
            UserSaveChunk(b"MISS", bytearray())  # type: ignore[arg-type]
        with self.assertRaisesRegex(UserSaveFormatError, "unsupported"):
            UserSaveChunk(b"NOPE", b"")
        with self.assertRaisesRegex(TypeError, "save data must be bytes"):
            parse_user_save(bytearray(source_fixture()))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
