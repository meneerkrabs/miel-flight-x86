#!/usr/bin/env python3
"""Inspect and extract the UDSP archives used by Miel Vliegt.

The archive keeps directory records, file records, and NUL-terminated names in
three tables at the end of the file. File payloads are stored before those
tables. Encoding 1 is the original engine's small command stream: ``e`` repeats
a four-byte word, while ``f`` and ``g`` copy literal bytes.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path, PureWindowsPath


HEADER = struct.Struct("<4sBBH6I")
RECORD = struct.Struct("<6I")


@dataclass(frozen=True)
class ArchiveHeader:
    version_major: int
    version_minor: int
    directory_table_size: int
    directory_table_offset: int
    string_table_size: int
    string_table_offset: int
    file_table_size: int
    file_table_offset: int


@dataclass(frozen=True)
class FileEntry:
    path: str
    name_hash: int
    name_offset: int
    encoding: int
    logical_size: int
    stored_size: int
    data_offset: int


def normalize_archive_path(path: str) -> tuple[str, ...]:
    """Return a safe relative UDSP path without changing source case.

    Runtime lookup is case-insensitive, so extraction rejects traversal and
    absolute/drive-qualified names before applying the same lowercase collision
    key used by the immutable JavaScript resource catalog.
    """

    source = PureWindowsPath(path)
    if source.anchor or source.drive or source.root \
            or not source.parts or any(part == ".." for part in source.parts):
        raise ValueError(f"unsafe archive path: {path}")
    parts = tuple(part for part in source.parts if part not in ("", "."))
    if not parts:
        raise ValueError(f"unsafe archive path: {path}")
    return parts


class UdspArchive:
    def __init__(self, path: Path):
        self.path = path
        self._data = path.read_bytes()
        self.header = self._read_header()
        self.directories, self.files = self._read_index()

    def _read_header(self) -> ArchiveHeader:
        if len(self._data) < HEADER.size:
            raise ValueError(f"{self.path}: truncated UDSP header")
        magic, major, minor, reserved, *fields = HEADER.unpack_from(self._data)
        if magic != b"UDSP":
            raise ValueError(f"{self.path}: expected UDSP magic, got {magic!r}")
        if reserved != 0:
            raise ValueError(f"{self.path}: unsupported header flags {reserved:#x}")
        header = ArchiveHeader(major, minor, *fields)
        for label, size in (
            ("directory", header.directory_table_size),
            ("file", header.file_table_size),
        ):
            if size % RECORD.size:
                raise ValueError(f"{self.path}: {label} table is not record-aligned")
        for label, offset, size in (
            ("directory", header.directory_table_offset, header.directory_table_size),
            ("file", header.file_table_offset, header.file_table_size),
            ("string", header.string_table_offset, header.string_table_size),
        ):
            if offset < HEADER.size or offset + size > len(self._data):
                raise ValueError(f"{self.path}: {label} table is outside the archive")
        return header

    def _records(self, offset: int, size: int) -> list[tuple[int, ...]]:
        return [RECORD.unpack_from(self._data, pos) for pos in range(offset, offset + size, RECORD.size)]

    def _read_index(self) -> tuple[list[str], list[FileEntry]]:
        h = self.header
        raw_names = self._data[h.string_table_offset : h.string_table_offset + h.string_table_size]
        if not raw_names.endswith(b"\0"):
            raise ValueError(f"{self.path}: unterminated string table")
        directory_records = self._records(h.directory_table_offset, h.directory_table_size)
        file_records = self._records(h.file_table_offset, h.file_table_size)
        def name_at(offset: int) -> str:
            if offset < 0 or offset >= len(raw_names):
                raise ValueError(f"{self.path}: name offset {offset} is outside the string table")
            end = raw_names.find(b"\0", offset)
            if end < 0:
                raise ValueError(f"{self.path}: unterminated name at offset {offset}")
            return raw_names[offset:end].decode("latin-1")

        # UpPackage relocates field 1 of every 24-byte directory and file
        # record against the string-table base (UdsPack.dll 0x1000150a and
        # 0x10001535). Directory-record order is hash-table order, not string
        # order, so pairing it with the first N strings silently misfiles most
        # assets while leaving their basenames looking plausible.
        directories = [name_at(record[1]) for record in directory_records]
        parents: list[str | None] = [None] * len(file_records)
        for directory, record in zip(directories, directory_records):
            file_count, relative_offset = record[4], record[5]
            if relative_offset % RECORD.size:
                raise ValueError(f"{self.path}: unaligned file range for {directory}")
            start = relative_offset // RECORD.size
            end = start + file_count
            if end > len(file_records):
                raise ValueError(f"{self.path}: file range outside table for {directory}")
            for index in range(start, end):
                if parents[index] is not None:
                    raise ValueError(f"{self.path}: overlapping file ranges at index {index}")
                parents[index] = directory

        entries = []
        payload_limit = min(h.directory_table_offset, h.file_table_offset, h.string_table_offset)

        for index, (record, parent) in enumerate(zip(file_records, parents)):
            if parent is None:
                raise ValueError(f"{self.path}: file {index} has no directory")
            name_hash, name_offset, encoding, logical_size, stored_size, data_offset = record
            name = name_at(name_offset)
            if not name or "\\" in name or "/" in name:
                raise ValueError(f"{self.path}: invalid file name {name!r} at offset {name_offset}")
            if data_offset < HEADER.size or data_offset + stored_size > payload_limit:
                raise ValueError(f"{self.path}: payload outside data region for {name}")
            path = str(PureWindowsPath(parent) / name)
            entries.append(
                FileEntry(path, name_hash, name_offset, encoding, logical_size, stored_size, data_offset)
            )
        return directories, entries

    @staticmethod
    def decode_payload(payload: bytes, logical_size: int) -> bytes:
        source_offset = 0
        decoded = bytearray()
        while source_offset < len(payload):
            if source_offset + 2 > len(payload):
                raise ValueError("truncated encoding command")
            command, count = payload[source_offset : source_offset + 2]
            source_offset += 2
            if command == ord("e"):
                pattern = payload[source_offset : source_offset + 4]
                if len(pattern) != 4:
                    raise ValueError("truncated repeat command")
                source_offset += 4
                decoded.extend(pattern * ((count + 3) // 4))
            elif command in (ord("f"), ord("g")):
                literal = payload[source_offset : source_offset + count]
                if len(literal) != count:
                    raise ValueError("truncated literal command")
                source_offset += count
                decoded.extend(literal)
            else:
                raise ValueError(f"unknown encoding command {command:#x}")
        if len(decoded) != logical_size:
            raise ValueError(f"decoded {len(decoded)} bytes, expected {logical_size}")
        return bytes(decoded)

    def payload(self, entry: FileEntry, *, decode: bool = True) -> bytes:
        payload = self._data[entry.data_offset : entry.data_offset + entry.stored_size]
        if entry.encoding == 0 or not decode:
            return payload
        if entry.encoding == 1:
            return self.decode_payload(payload, entry.logical_size)
        raise ValueError(f"unsupported encoding {entry.encoding} for {entry.path}")

    def extract(self, destination: Path, *, decode: bool = True) -> None:
        root = destination.resolve()
        planned: list[tuple[FileEntry, tuple[str, ...]]] = []
        case_keys: set[str] = set()
        for entry in self.files:
            parts = normalize_archive_path(entry.path)
            case_key = "/".join(parts).lower()
            if case_key in case_keys:
                raise ValueError(
                    f"case-insensitive archive path collision: {entry.path}"
                )
            case_keys.add(case_key)
            planned.append((entry, parts))

        for entry, parts in planned:
            relative = Path(*parts)
            output = (root / relative).resolve()
            if root not in output.parents:
                raise ValueError(f"unsafe archive path: {entry.path}")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(self.payload(entry, decode=decode))

    def manifest(self) -> dict[str, object]:
        return {
            "archive": self.path.name,
            "version": f"{self.header.version_major}.{self.header.version_minor}",
            "directories": self.directories,
            "files": [asdict(entry) for entry in self.files],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, help="extract stored payloads below this directory")
    parser.add_argument("--manifest", type=Path, help="write archive metadata as JSON")
    parser.add_argument("--stored", action="store_true", help="preserve encoded payload bytes")
    args = parser.parse_args()

    archive = UdspArchive(args.archive)
    if args.output:
        archive.extract(args.output, decode=not args.stored)
    manifest = archive.manifest()
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if not args.output and not args.manifest:
        print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
