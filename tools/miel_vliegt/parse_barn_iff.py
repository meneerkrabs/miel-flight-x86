#!/usr/bin/env python3
"""Parse the IFF contracts used by the Miel Vliegt hangar.

The container is big-endian IFF (FORM and chunk lengths). Record payloads are
little-endian native structs. Field names stay deliberately neutral where the
original executable proves layout and use, but not yet the higher-level name.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from pathlib import Path


FORM_HEADER = struct.Struct(">4sI4s")
CHUNK_HEADER = struct.Struct(">4sI")
AIRPLANE_LINK = struct.Struct("<IHH")
BARN_PLACEMENT = struct.Struct("<IIfff")
MISSION_RECORD = struct.Struct("<III")


@dataclass(frozen=True)
class IffChunk:
    identifier: str
    payload: bytes
    offset: int


@dataclass(frozen=True)
class PartDefinition:
    part_id: int
    model_path: str


@dataclass(frozen=True)
class AirplaneLink:
    part_id: int
    link_slot: int
    linked_part_id: int


@dataclass(frozen=True)
class BarnPlacement:
    group_id: int
    part_id: int
    position: tuple[float, float, float] | None


@dataclass(frozen=True)
class MissionRecord:
    mission_id: int
    field_1: int
    field_2: int


class IffForm:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.form_type, self.chunks = self._parse()

    def _parse(self) -> tuple[bytes, tuple[IffChunk, ...]]:
        if len(self.data) < FORM_HEADER.size:
            raise ValueError(f"{self.path}: truncated FORM header")
        magic, declared_size, form_type = FORM_HEADER.unpack_from(self.data)
        if magic != b"FORM":
            raise ValueError(f"{self.path}: expected FORM magic, got {magic!r}")
        if declared_size != len(self.data) - 8:
            raise ValueError(
                f"{self.path}: declared size {declared_size} does not match {len(self.data) - 8}"
            )
        chunks = []
        offset = FORM_HEADER.size
        while offset < len(self.data):
            if offset + CHUNK_HEADER.size > len(self.data):
                raise ValueError(f"{self.path}: truncated chunk header at {offset}")
            identifier, size = CHUNK_HEADER.unpack_from(self.data, offset)
            end = offset + CHUNK_HEADER.size + size
            if end > len(self.data):
                raise ValueError(f"{self.path}: chunk at {offset} exceeds FORM boundary")
            try:
                name = identifier.decode("ascii")
            except UnicodeDecodeError as error:
                raise ValueError(f"{self.path}: non-ASCII chunk id at {offset}") from error
            chunks.append(IffChunk(name, self.data[offset + CHUNK_HEADER.size : end], offset))
            # This UDS dialect does not add the conventional even-byte pad.
            offset = end
        return form_type, tuple(chunks)


def parse_part_catalog(path: Path) -> tuple[PartDefinition, ...]:
    form = IffForm(path)
    if form.form_type != b"PRTS" or any(chunk.identifier != "PART" for chunk in form.chunks):
        raise ValueError(f"{path}: expected a PRTS form containing PART chunks")
    parts = []
    for chunk in form.chunks:
        if len(chunk.payload) < 6 or not chunk.payload.endswith(b"\0"):
            raise ValueError(f"{path}: malformed PART chunk at {chunk.offset}")
        part_id = struct.unpack_from("<I", chunk.payload)[0]
        model_path = chunk.payload[4:-1].decode("latin-1")
        if not model_path or not model_path.lower().endswith(".ccf"):
            raise ValueError(f"{path}: invalid model path for part {part_id}")
        parts.append(PartDefinition(part_id, model_path.replace("\\", "/")))
    if len({part.part_id for part in parts}) != len(parts):
        raise ValueError(f"{path}: duplicate part ids")
    return tuple(parts)


def _single_chunk(path: Path, identifier: str, record: struct.Struct) -> bytes:
    form = IffForm(path)
    if form.form_type != b"\0\0\0\0" or len(form.chunks) != 1:
        raise ValueError(f"{path}: expected a single-chunk neutral FORM")
    chunk = form.chunks[0]
    if chunk.identifier != identifier:
        raise ValueError(f"{path}: expected {identifier}, got {chunk.identifier}")
    if len(chunk.payload) % record.size:
        raise ValueError(f"{path}: {identifier} payload is not {record.size}-byte aligned")
    return chunk.payload


def parse_airplane(path: Path) -> tuple[AirplaneLink, ...]:
    payload = _single_chunk(path, "AIRP", AIRPLANE_LINK)
    return tuple(AirplaneLink(*values) for values in AIRPLANE_LINK.iter_unpack(payload))


def parse_barn(path: Path) -> tuple[BarnPlacement, ...]:
    payload = _single_chunk(path, "BARN", BARN_PLACEMENT)
    placements = []
    for group_id, part_id, x, y, z in BARN_PLACEMENT.iter_unpack(payload):
        values = (x, y, z)
        position = values if all(math.isfinite(value) for value in values) else None
        if position is None and not all(math.isnan(value) for value in values):
            raise ValueError(f"{path}: mixed finite/non-finite BARN position")
        placements.append(BarnPlacement(group_id, part_id, position))
    return tuple(placements)


def parse_missions(path: Path) -> tuple[MissionRecord, ...]:
    form = IffForm(path)
    if form.form_type != b"\0\0\0\0" or any(
        chunk.identifier != "MISS" or len(chunk.payload) != MISSION_RECORD.size
        for chunk in form.chunks
    ):
        raise ValueError(f"{path}: expected 12-byte MISS chunks")
    return tuple(MissionRecord(*MISSION_RECORD.unpack(chunk.payload)) for chunk in form.chunks)
