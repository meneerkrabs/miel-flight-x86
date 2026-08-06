#!/usr/bin/env python3
"""Adapt generated Kaitai models to the repository's normalized flight IR.

The generated classes own binary decoding.  This module owns domain
validation and stable models, keeping Kaitai compiler details out of callers.
The handwritten parsers remain independent differential oracles; this module
must never call them to decide whether its own result is correct.
"""

from __future__ import annotations

import hashlib
import math
import struct

from kaitaistruct import KaitaiStructError

try:
    from tools.miel_vliegt.kaitai.generated.python.miel_cca import MielCca
    from tools.miel_vliegt.kaitai.generated.python.miel_user_save import MielUserSave
    from tools.miel_vliegt.parse_cca import (
        AnimationFrame,
        BlueprintAnimation,
        CcaAnimation,
        Coordinate3d,
        FRAME,
        HEADER,
        MAGIC,
        NAME_SIZE,
        Quaternion,
    )
    from tools.miel_vliegt.parse_user_save import (
        ALLOWED_CHUNK_IDS,
        FORM_ID,
        NAME_ID,
        ROOT_ID,
        UserSave,
        UserSaveChunk,
        UserSaveFormatError,
    )
except ModuleNotFoundError:  # Direct script/import from tools/miel_vliegt.
    from kaitai.generated.python.miel_cca import MielCca
    from kaitai.generated.python.miel_user_save import MielUserSave
    from parse_cca import (
    AnimationFrame,
    BlueprintAnimation,
    CcaAnimation,
    Coordinate3d,
    FRAME,
    HEADER,
    MAGIC,
    NAME_SIZE,
    Quaternion,
    )
    from parse_user_save import (
        ALLOWED_CHUNK_IDS,
        FORM_ID,
        NAME_ID,
        ROOT_ID,
        UserSave,
        UserSaveChunk,
        UserSaveFormatError,
    )


def _blueprint_name(raw: bytes, source: str, index: int) -> str:
    try:
        terminator = raw.index(0)
    except ValueError as error:
        raise ValueError(
            f"{source}: animation {index} has no NUL-terminated blueprint name"
        ) from error
    if any(raw[terminator + 1 :]):
        raise ValueError(
            f"{source}: animation {index} has non-zero blueprint-name padding"
        )
    try:
        name = raw[:terminator].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(
            f"{source}: animation {index} blueprint name is not ASCII"
        ) from error
    if not name:
        raise ValueError(f"{source}: animation {index} has an empty blueprint name")
    return name


def parse_cca_kaitai(data: bytes, *, source: str = "<bytes>") -> CcaAnimation:
    """Parse CCA through generated code and return the existing immutable IR."""

    if not isinstance(data, bytes):
        raise TypeError(f"CCA data must be bytes, got {type(data).__name__}")
    if len(data) < HEADER.size:
        raise ValueError(f"{source}: truncated CCA header")

    # Bound counts before the generated parser allocates arrays.  This is a
    # resource-safety guard, not an alternate payload decoder.
    magic, _looping, animation_count, frame_count, _frame_rate = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ValueError(f"{source}: expected CCA magic {MAGIC!r}, got {magic!r}")
    expected_size = HEADER.size + animation_count * (NAME_SIZE + frame_count * FRAME.size)
    if len(data) != expected_size:
        relation = "truncated" if len(data) < expected_size else "has trailing bytes"
        raise ValueError(
            f"{source}: CCA payload {relation}: got {len(data)} bytes, expected {expected_size}"
        )

    try:
        parsed = MielCca.from_bytes(data)
    except KaitaiStructError as error:
        raise ValueError(f"{source}: Kaitai CCA decode failed: {error}") from error
    if not math.isfinite(parsed.frame_rate) or parsed.frame_rate <= 0:
        raise ValueError(f"{source}: invalid frame rate {parsed.frame_rate!r}")

    animations: list[BlueprintAnimation] = []
    payload_stride = NAME_SIZE + parsed.frame_count * FRAME.size
    for animation_index, animation in enumerate(parsed.animations):
        name = _blueprint_name(animation.blueprint_name_raw, source, animation_index)
        frames: list[AnimationFrame] = []
        for frame_index, frame in enumerate(animation.frames):
            values = (
                frame.position.x,
                frame.position.y,
                frame.position.z,
                frame.orientation.w,
                frame.orientation.x,
                frame.orientation.y,
                frame.orientation.z,
            )
            if not all(math.isfinite(value) for value in values):
                raise ValueError(
                    f"{source}: animation {animation_index} frame {frame_index} "
                    "contains a non-finite transform"
                )
            frames.append(
                AnimationFrame(
                    Coordinate3d(*values[:3]),
                    Quaternion(*values[3:]),
                )
            )
        record_start = HEADER.size + animation_index * payload_stride
        payload_start = record_start + NAME_SIZE
        payload_end = payload_start + parsed.frame_count * FRAME.size
        animations.append(
            BlueprintAnimation(
                name,
                tuple(frames),
                hashlib.sha256(data[payload_start:payload_end]).hexdigest(),
            )
        )

    return CcaAnimation(
        parsed.looping,
        parsed.animation_count,
        parsed.frame_count,
        parsed.frame_rate,
        tuple(animations),
    )


def parse_user_save_kaitai(data: bytes) -> UserSave:
    """Parse FORM/USER through generated code into the existing container IR."""

    if not isinstance(data, bytes):
        raise TypeError(f"save data must be bytes, got {type(data).__name__}")
    minimum_size = 20
    if len(data) < minimum_size:
        raise UserSaveFormatError(
            f"user save is too short: {len(data)} bytes; need at least {minimum_size}"
        )
    if data[:4] != FORM_ID:
        raise UserSaveFormatError(f"expected FORM header, got {data[:4]!r}")
    form_size = struct.unpack_from(">I", data, 4)[0]
    actual_form_size = len(data) - 8
    if form_size != actual_form_size:
        raise UserSaveFormatError(
            f"FORM size mismatch: header says {form_size}, file contains {actual_form_size}"
        )
    if data[8:12] != ROOT_ID:
        raise UserSaveFormatError(f"expected USER root id, got {data[8:12]!r}")

    try:
        parsed = MielUserSave.from_bytes(data)
    except KaitaiStructError as error:
        raise UserSaveFormatError(f"Kaitai USER decode failed: {error}") from error

    chunks: list[UserSaveChunk] = []
    for chunk in parsed.body.chunks:
        if chunk.chunk_id not in ALLOWED_CHUNK_IDS:
            raise UserSaveFormatError(
                f"unsupported user-save chunk id: {chunk.chunk_id!r}"
            )
        chunks.append(UserSaveChunk(chunk.chunk_id, chunk.payload))

    name_positions = [index for index, chunk in enumerate(chunks) if chunk.chunk_id == NAME_ID]
    if name_positions != [0]:
        raise UserSaveFormatError(
            "user save must contain exactly one NAME chunk and it must be first"
        )
    return UserSave(ROOT_ID, tuple(chunks))


__all__ = ["parse_cca_kaitai", "parse_user_save_kaitai"]
