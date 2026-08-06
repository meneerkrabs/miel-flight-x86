#!/usr/bin/env python3
"""Parse the CcFf scene graph used by Miel vliegt de wereld rond.

CcFf is a little-endian chunk container.  A chunk length includes its six-byte
header.  Scene records mix chunks with fixed-size legacy fields, so this parser
only interprets structures whose boundaries are proven and retains the other
bytes as hexadecimal evidence.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator


FILE_HEADER = struct.Struct("<4s6sI")
CHUNK_HEADER = struct.Struct("<HI")
VECTOR = struct.Struct("<3f")
TRIANGLE = struct.Struct("<4I")

TOP_LEVEL_IDS = (0x1000, 0x2000, 0x3000, 0x4000)
RECORD_IDS = {0x2100, 0x3100, 0x4100, 0x4200, 0x4300}


@dataclass(frozen=True)
class Chunk:
    identifier: int
    offset: int
    size: int

    @property
    def data_offset(self) -> int:
        return self.offset + CHUNK_HEADER.size

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class SceneRecord:
    kind: str
    chunk_id: str
    name: str | None
    group: str | None
    position: tuple[float, float, float] | None
    scale: float
    orientation: tuple[tuple[float, float, float], ...] | None
    prefix_hex: str
    metadata_chunks: tuple[dict[str, object], ...]
    offset: int
    size: int


@dataclass(frozen=True)
class MeshVertex:
    position: tuple[float, float, float]
    field: int


@dataclass(frozen=True)
class MeshTriangle:
    indices: tuple[int, int, int]
    material_reference: int
    uv: tuple[tuple[float, float], ...] | None


@dataclass(frozen=True)
class MeshGeometry:
    reference: int
    vertices: tuple[MeshVertex, ...]
    triangles: tuple[MeshTriangle, ...]


@dataclass(frozen=True)
class MaterialDefinition:
    reference: int
    texture: str | None


class CcfScene:
    def __init__(self, path: Path):
        self.path = path
        self._data = path.read_bytes()
        self.version, self.top_chunks = self._read_header()
        self.records = tuple(self._read_records())

    def _read_header(self) -> tuple[str, tuple[Chunk, ...]]:
        if len(self._data) < FILE_HEADER.size:
            raise ValueError(f"{self.path}: truncated CcFf header")
        magic, raw_version, declared_size = FILE_HEADER.unpack_from(self._data)
        if magic != b"CcFf":
            raise ValueError(f"{self.path}: expected CcFf magic, got {magic!r}")
        if declared_size != len(self._data) - 8:
            raise ValueError(
                f"{self.path}: declared size {declared_size} does not match {len(self._data) - 8}"
            )
        chunks = tuple(self._chunks(FILE_HEADER.size, len(self._data)))
        identifiers = tuple(chunk.identifier for chunk in chunks)
        if identifiers != TOP_LEVEL_IDS:
            formatted = ", ".join(f"{identifier:#06x}" for identifier in identifiers)
            raise ValueError(f"{self.path}: unexpected top-level chunks: {formatted}")
        version = ".".join(str(value) for value in raw_version)
        return version, chunks

    def _chunk_at(self, offset: int, limit: int) -> Chunk:
        if offset < 0 or offset + CHUNK_HEADER.size > limit:
            raise ValueError(f"{self.path}: truncated chunk header at {offset}")
        identifier, size = CHUNK_HEADER.unpack_from(self._data, offset)
        if size < CHUNK_HEADER.size:
            raise ValueError(f"{self.path}: invalid chunk size {size} at {offset}")
        chunk = Chunk(identifier, offset, size)
        if chunk.end > limit:
            raise ValueError(f"{self.path}: chunk {identifier:#06x} at {offset} exceeds its parent")
        return chunk

    def _chunks(self, start: int, limit: int) -> Iterator[Chunk]:
        offset = start
        while offset < limit:
            chunk = self._chunk_at(offset, limit)
            yield chunk
            offset = chunk.end
        if offset != limit:
            raise ValueError(f"{self.path}: child chunks do not fill parent ending at {limit}")

    def _read_records(self) -> Iterator[SceneRecord]:
        for top_chunk in self.top_chunks[1:]:
            for chunk in self._chunks(top_chunk.data_offset, top_chunk.end):
                if chunk.identifier not in RECORD_IDS:
                    raise ValueError(
                        f"{self.path}: unexpected record {chunk.identifier:#06x} at {chunk.offset}"
                    )
                yield self._parse_record(chunk)

    def _parse_record(self, record: Chunk) -> SceneRecord:
        name_chunk = self._chunk_at(record.data_offset, record.end)
        if name_chunk.identifier != 0xF010:
            raise ValueError(f"{self.path}: record at {record.offset} has no name chunk")
        strings = [self._parse_string(chunk) for chunk in self._chunks(name_chunk.data_offset, name_chunk.end)]
        if len(strings) != 2:
            raise ValueError(f"{self.path}: record at {record.offset} has {len(strings)} names")

        position_chunk = self._find_chunk(0xF040, name_chunk.end, record.end, size=18)
        orientation_chunk = None
        if position_chunk is not None:
            orientation_chunk = self._find_chunk(0xF070, position_chunk.end, record.end, size=66)

        position = self._vector(position_chunk) if position_chunk else None
        orientation = self._orientation(orientation_chunk) if orientation_chunk else None
        scale = 1.0
        if position_chunk is not None and orientation_chunk is not None:
            scale_bytes = orientation_chunk.offset - position_chunk.end
            if scale_bytes not in (0, 4):
                raise ValueError(f"{self.path}: unexpected transform gap at {record.offset}")
            if scale_bytes == 4:
                scale = struct.unpack_from("<f", self._data, position_chunk.end)[0]
                if not math.isfinite(scale):
                    raise ValueError(f"{self.path}: non-finite scale at {record.offset}")
        prefix_end = position_chunk.offset if position_chunk else record.end
        prefix = self._data[name_chunk.end:prefix_end]
        metadata_start = orientation_chunk.end if orientation_chunk else (
            position_chunk.end if position_chunk else record.end
        )
        metadata = tuple(self._metadata_chunks(metadata_start, record.end))
        return SceneRecord(
            kind={
                0x2100: "material",
                0x3100: "mesh",
                0x4100: "object",
                0x4200: "node",
                0x4300: "light",
            }[record.identifier],
            chunk_id=f"0x{record.identifier:04x}",
            name=strings[0],
            group=strings[1],
            position=position,
            scale=scale,
            orientation=orientation,
            prefix_hex=prefix.hex(),
            metadata_chunks=metadata,
            offset=record.offset,
            size=record.size,
        )

    def _parse_string(self, chunk: Chunk) -> str:
        if chunk.identifier != 0xF020 or chunk.size < 11:
            raise ValueError(f"{self.path}: malformed string chunk at {chunk.offset}")
        length = struct.unpack_from("<I", self._data, chunk.data_offset)[0]
        start = chunk.data_offset + 4
        end = start + length
        if end != chunk.end or length < 1 or self._data[end - 1] != 0:
            raise ValueError(f"{self.path}: invalid string length at {chunk.offset}")
        return self._data[start : end - 1].decode("latin-1")

    def _find_chunk(
        self, identifier: int, start: int, limit: int, *, size: int | None = None
    ) -> Chunk | None:
        signature = struct.pack("<H", identifier)
        offset = start
        while True:
            offset = self._data.find(signature, offset, limit)
            if offset < 0 or offset + CHUNK_HEADER.size > limit:
                return None
            chunk_size = struct.unpack_from("<I", self._data, offset + 2)[0]
            if chunk_size >= CHUNK_HEADER.size and offset + chunk_size <= limit:
                if size is None or chunk_size == size:
                    return Chunk(identifier, offset, chunk_size)
            offset += 1

    def _vector(self, chunk: Chunk) -> tuple[float, float, float]:
        values = VECTOR.unpack_from(self._data, chunk.data_offset)
        if not all(math.isfinite(value) for value in values):
            raise ValueError(f"{self.path}: non-finite vector at {chunk.offset}")
        return values

    def _orientation(self, chunk: Chunk) -> tuple[tuple[float, float, float], ...]:
        matrix = self._chunk_at(chunk.data_offset, chunk.end)
        if matrix.identifier != 0xF050 or matrix.end != chunk.end:
            raise ValueError(f"{self.path}: malformed orientation at {chunk.offset}")
        rows = tuple(self._chunks(matrix.data_offset, matrix.end))
        if len(rows) != 3 or any(row.identifier != 0xF040 or row.size != 18 for row in rows):
            raise ValueError(f"{self.path}: malformed orientation matrix at {matrix.offset}")
        return tuple(self._vector(row) for row in rows)

    def _metadata_chunks(self, start: int, limit: int) -> Iterator[dict[str, object]]:
        offset = start
        while offset < limit:
            chunk = self._chunk_at(offset, limit)
            payload = self._data[chunk.data_offset : chunk.end]
            yield {
                "id": f"0x{chunk.identifier:04x}",
                "size": chunk.size,
                "payload_hex": payload.hex(),
            }
            offset = chunk.end

    def material(self, record: SceneRecord) -> MaterialDefinition:
        if record.kind != "material":
            raise ValueError(f"{self.path}: {record.name!r} is not a material")
        payload = bytes.fromhex(record.prefix_hex)
        if len(payload) < 4:
            raise ValueError(f"{self.path}: material {record.name!r} has no reference")
        reference = struct.unpack_from("<I", payload)[0]
        texture = None
        offset = 4
        if offset + CHUNK_HEADER.size <= len(payload):
            identifier, size = CHUNK_HEADER.unpack_from(payload, offset)
            if identifier == 0x2110:
                end = offset + size
                if size < CHUNK_HEADER.size or end > len(payload):
                    raise ValueError(f"{self.path}: malformed material texture chunk")
                nested_id, nested_size = CHUNK_HEADER.unpack_from(payload, offset + CHUNK_HEADER.size)
                if nested_id != 0xF020 or offset + CHUNK_HEADER.size + nested_size != end:
                    raise ValueError(f"{self.path}: malformed material texture name")
                string_offset = offset + CHUNK_HEADER.size * 2
                length = struct.unpack_from("<I", payload, string_offset)[0]
                start = string_offset + 4
                if length < 1 or start + length != end or payload[end - 1] != 0:
                    raise ValueError(f"{self.path}: invalid material texture string")
                texture = payload[start : end - 1].decode("latin-1")
        return MaterialDefinition(reference, texture)

    def mesh(self, record: SceneRecord) -> MeshGeometry:
        if record.kind != "mesh":
            raise ValueError(f"{self.path}: {record.name!r} is not a mesh")
        prefix = bytes.fromhex(record.prefix_hex)
        if len(prefix) < 4:
            raise ValueError(f"{self.path}: mesh {record.name!r} has no reference")
        reference = struct.unpack_from("<I", prefix)[0]
        vertices = []
        triangles = []
        for metadata in record.metadata_chunks:
            payload = bytes.fromhex(str(metadata["payload_hex"]))
            if metadata["id"] == "0x3110":
                if len(payload) != 28:
                    raise ValueError(f"{self.path}: malformed vertex in {record.name!r}")
                position_chunk = self._memory_chunk(payload, 0)
                field_chunk = self._memory_chunk(payload, position_chunk.end)
                if (
                    position_chunk.identifier != 0xF040
                    or position_chunk.size != 18
                    or field_chunk.identifier != 0x4500
                    or field_chunk.size != 10
                    or field_chunk.end != len(payload)
                ):
                    raise ValueError(f"{self.path}: malformed vertex fields in {record.name!r}")
                position = VECTOR.unpack_from(payload, position_chunk.data_offset)
                field = struct.unpack_from("<I", payload, field_chunk.data_offset)[0]
                vertices.append(MeshVertex(position, field))
            elif metadata["id"] == "0x3120":
                if len(payload) not in (16, 46):
                    raise ValueError(f"{self.path}: malformed triangle in {record.name!r}")
                index_0, index_1, index_2, material_reference = TRIANGLE.unpack_from(payload)
                uv = None
                if len(payload) == 46:
                    uv_chunk = self._memory_chunk(payload, TRIANGLE.size)
                    if uv_chunk.identifier != 0xF060 or uv_chunk.size != 30:
                        raise ValueError(f"{self.path}: malformed triangle UVs in {record.name!r}")
                    values = struct.unpack_from("<6f", payload, uv_chunk.data_offset)
                    uv = ((values[0], values[1]), (values[2], values[3]), (values[4], values[5]))
                triangles.append(
                    MeshTriangle((index_0, index_1, index_2), material_reference, uv)
                )
        if any(index >= len(vertices) for triangle in triangles for index in triangle.indices):
            raise ValueError(f"{self.path}: triangle index outside mesh {record.name!r}")
        return MeshGeometry(reference, tuple(vertices), tuple(triangles))

    @staticmethod
    def _memory_chunk(data: bytes, offset: int) -> Chunk:
        if offset + CHUNK_HEADER.size > len(data):
            raise ValueError("truncated nested CCF chunk")
        identifier, size = CHUNK_HEADER.unpack_from(data, offset)
        chunk = Chunk(identifier, offset, size)
        if size < CHUNK_HEADER.size or chunk.end > len(data):
            raise ValueError("nested CCF chunk exceeds payload")
        return chunk

    def manifest(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for record in self.records:
            counts[record.kind] = counts.get(record.kind, 0) + 1
        return {
            "source": self.path.name,
            "version": self.version,
            "counts": counts,
            "records": [asdict(record) for record in self.records],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scene", type=Path)
    parser.add_argument("--output", type=Path, help="write scene graph JSON")
    args = parser.parse_args()

    manifest = CcfScene(args.scene).manifest()
    encoded = json.dumps(manifest, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
