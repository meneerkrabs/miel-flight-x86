#!/usr/bin/env python3
"""Parse the CC engine's compact blueprint-animation (CCA) format.

The binary layout is independently enforced here with the pinned cc-tools
``cc_anim.ksy`` schema as a secondary structural oracle.  Parsing the records
does not establish how the original executable interpolates, schedules, or
applies the transforms at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from dataclasses import asdict, dataclass
from pathlib import Path


HEADER = struct.Struct("<4sIIIf")
FRAME = struct.Struct("<7f")
NAME_SIZE = 0x40
MAGIC = b"CCA\0"


@dataclass(frozen=True)
class Coordinate3d:
    x: float
    y: float
    z: float


@dataclass(frozen=True)
class Quaternion:
    w: float
    x: float
    y: float
    z: float


@dataclass(frozen=True)
class AnimationFrame:
    position: Coordinate3d
    orientation: Quaternion


@dataclass(frozen=True)
class BlueprintAnimation:
    blueprint_name: str
    frames: tuple[AnimationFrame, ...]
    frame_payload_sha256: str


@dataclass(frozen=True)
class CcaAnimation:
    looping: int
    animation_count: int
    frame_count: int
    frame_rate: float
    animations: tuple[BlueprintAnimation, ...]


def _blueprint_name(raw: bytes, source: str, index: int) -> str:
    try:
        terminator = raw.index(0)
    except ValueError as error:
        raise ValueError(f"{source}: animation {index} has no NUL-terminated blueprint name") from error
    if any(raw[terminator + 1 :]):
        raise ValueError(f"{source}: animation {index} has non-zero blueprint-name padding")
    try:
        name = raw[:terminator].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{source}: animation {index} blueprint name is not ASCII") from error
    if not name:
        raise ValueError(f"{source}: animation {index} has an empty blueprint name")
    return name


def parse_cca(data: bytes, *, source: str = "<bytes>") -> CcaAnimation:
    """Parse one complete CCA payload and reject structural ambiguity."""

    if len(data) < HEADER.size:
        raise ValueError(f"{source}: truncated CCA header")
    magic, looping, animation_count, frame_count, frame_rate = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ValueError(f"{source}: expected CCA magic {MAGIC!r}, got {magic!r}")
    expected_size = HEADER.size + animation_count * (NAME_SIZE + frame_count * FRAME.size)
    if len(data) != expected_size:
        relation = "truncated" if len(data) < expected_size else "has trailing bytes"
        raise ValueError(
            f"{source}: CCA payload {relation}: got {len(data)} bytes, expected {expected_size}"
        )
    if not math.isfinite(frame_rate) or frame_rate <= 0:
        raise ValueError(f"{source}: invalid frame rate {frame_rate!r}")

    animations = []
    offset = HEADER.size
    for animation_index in range(animation_count):
        name = _blueprint_name(data[offset : offset + NAME_SIZE], source, animation_index)
        offset += NAME_SIZE
        payload_start = offset
        frames = []
        for frame_index in range(frame_count):
            values = FRAME.unpack_from(data, offset)
            offset += FRAME.size
            if not all(math.isfinite(value) for value in values):
                raise ValueError(
                    f"{source}: animation {animation_index} frame {frame_index} contains a non-finite transform"
                )
            frames.append(
                AnimationFrame(
                    Coordinate3d(*values[:3]),
                    Quaternion(*values[3:]),
                )
            )
        payload = data[payload_start:offset]
        animations.append(
            BlueprintAnimation(name, tuple(frames), hashlib.sha256(payload).hexdigest())
        )
    return CcaAnimation(looping, animation_count, frame_count, frame_rate, tuple(animations))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    parsed = parse_cca(args.input.read_bytes(), source=str(args.input))
    print(json.dumps(asdict(parsed), indent=2))


if __name__ == "__main__":
    main()
