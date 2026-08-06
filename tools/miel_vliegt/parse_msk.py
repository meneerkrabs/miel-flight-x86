#!/usr/bin/env python3
"""Parse the 640x480 byte masks used by the native UDS hangar."""

from __future__ import annotations

import base64
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


MASK_WIDTH = 640
MASK_HEIGHT = 480
MASK_SIZE = MASK_WIDTH * MASK_HEIGHT
RUN = struct.Struct("<BH")


@dataclass(frozen=True)
class MaskRegion:
    value: int
    pixels: int
    bounds: tuple[int, int, int, int]


@dataclass(frozen=True)
class HangarMask:
    width: int
    height: int
    regions: tuple[MaskRegion, ...]
    rle_base64: str

    def value_at(self, x: int, y: int) -> int | None:
        if x < 0 or y < 0 or x >= self.width or y >= self.height:
            return None
        offset = y * self.width + x
        cursor = 0
        for value, length in decode_runs(self.rle_base64):
            cursor += length
            if offset < cursor:
                return value
        raise ValueError("mask RLE ended before requested pixel")


def _runs(data: bytes) -> tuple[tuple[int, int], ...]:
    runs = []
    value = data[0]
    length = 1
    for candidate in data[1:]:
        if candidate == value and length < 0xFFFF:
            length += 1
            continue
        runs.append((value, length))
        value = candidate
        length = 1
    runs.append((value, length))
    return tuple(runs)


def decode_runs(encoded: str) -> tuple[tuple[int, int], ...]:
    payload = base64.b64decode(encoded, validate=True)
    if len(payload) % RUN.size:
        raise ValueError("mask RLE payload is not three-byte aligned")
    return tuple(RUN.iter_unpack(payload))


def parse_mask(path: Path) -> HangarMask:
    data = path.read_bytes()
    if len(data) != MASK_SIZE:
        raise ValueError(f"{path}: expected {MASK_SIZE} bytes, got {len(data)}")

    counts = Counter(data)
    regions = []
    for value in sorted(counts):
        offsets = [offset for offset, candidate in enumerate(data) if candidate == value]
        xs = [offset % MASK_WIDTH for offset in offsets]
        ys = [offset // MASK_WIDTH for offset in offsets]
        regions.append(
            MaskRegion(value, counts[value], (min(xs), min(ys), max(xs), max(ys)))
        )

    encoded = b"".join(RUN.pack(value, length) for value, length in _runs(data))
    return HangarMask(
        MASK_WIDTH,
        MASK_HEIGHT,
        tuple(regions),
        base64.b64encode(encoded).decode("ascii"),
    )
