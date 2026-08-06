#!/usr/bin/env python3
"""Strict structural parser for original Miel Vliegt ``user*.dat`` saves.

The on-disk framing is an IFF-like dialect without alignment padding::

    FORM <be32 form-size>
      USER
      NAME <be32 username-size> <username bytes>
      MISS <be32 size> <opaque bytes>
      ...

The adjacent ``USER`` root id and first ``NAME`` chunk spell ``USERNAME`` on
disk, but they remain two ordinary four-byte structural fields.  The old
``willywerkel/savefile.py`` comment calling this an eight-byte chunk id is
therefore misleading: its ``seek(8)`` skips the root id *and* the NAME id.
The split is corroborated by CC0 ``cc-tools``
``ksy/mm_chunk_container.ksy`` at commit ``e34efcd`` and by the native generic
IFF reader/writer control flow.

Chunk payload semantics are intentionally out of scope here.  This module
only proves and preserves the container boundary.  In particular, it neither
guesses record layouts nor silently accepts future/unknown chunks.

The serializer is useful for canonical synthetic fixtures.  Until a native
``user0.dat`` has been captured and compared byte-for-byte, it must not be
treated as proof that the game accepts newly generated saves.

No captured original ``user0.dat`` is checked into this repository.  The
structural contract is source-corroborated, not a native round-trip receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Final, Iterable


FORM_ID: Final = b"FORM"
ROOT_ID: Final = b"USER"
NAME_ID: Final = b"NAME"
CHUNK_ORDER: Final = (
    NAME_ID,
    b"MISS",
    b"INVI",
    b"PHOT",
    b"DIPL",
    b"BARN",
    b"AIRP",
    b"AIRA",
)
ALLOWED_CHUNK_IDS: Final = frozenset(CHUNK_ORDER)
FORMAT_EVIDENCE_STATUS: Final = "SOURCE_CORROBORATED_NO_NATIVE_SAMPLE"
SERIALIZER_STATUS: Final = "UNVERIFIED_ORIGINAL_ROUNDTRIP"

_FORM_HEADER = struct.Struct(">4sI")
_CHUNK_HEADER = struct.Struct(">4sI")
_ROOT_SIZE = len(ROOT_ID)


class UserSaveFormatError(ValueError):
    """Raised when bytes are not exactly the supported original save dialect."""


@dataclass(frozen=True, slots=True)
class UserSaveChunk:
    """One supported 4CC chunk with an intentionally opaque payload."""

    chunk_id: bytes
    payload: bytes

    def __post_init__(self) -> None:
        chunk_id = _require_bytes(self.chunk_id, "chunk id")
        payload = _require_bytes(self.payload, f"{chunk_id!r} payload")
        if chunk_id not in ALLOWED_CHUNK_IDS:
            raise UserSaveFormatError(f"unsupported user-save chunk id: {chunk_id!r}")
        object.__setattr__(self, "chunk_id", chunk_id)
        object.__setattr__(self, "payload", payload)


@dataclass(frozen=True, slots=True)
class UserSave:
    """Parsed root id plus source-ordered supported chunks."""

    root_id: bytes
    chunks: tuple[UserSaveChunk, ...]

    def __post_init__(self) -> None:
        root_id = _require_bytes(self.root_id, "root id")
        if root_id != ROOT_ID:
            raise UserSaveFormatError(f"unsupported user-save root id: {root_id!r}")
        chunks = tuple(self.chunks)
        for index, chunk in enumerate(chunks):
            if not isinstance(chunk, UserSaveChunk):
                raise TypeError(f"chunks[{index}] must be UserSaveChunk")
        name_positions = [index for index, chunk in enumerate(chunks) if chunk.chunk_id == NAME_ID]
        if name_positions != [0]:
            raise UserSaveFormatError(
                "user save must contain exactly one NAME chunk and it must be first"
            )
        object.__setattr__(self, "root_id", root_id)
        object.__setattr__(self, "chunks", chunks)

    @property
    def username(self) -> bytes:
        """Return the payload of the required first NAME chunk."""

        return self.chunks[0].payload

    def chunks_named(self, chunk_id: bytes) -> tuple[UserSaveChunk, ...]:
        """Return every repeated occurrence of a supported chunk in source order."""

        chunk_id = _require_bytes(chunk_id, "chunk id")
        if chunk_id not in ALLOWED_CHUNK_IDS:
            raise UserSaveFormatError(f"unsupported user-save chunk id: {chunk_id!r}")
        return tuple(chunk for chunk in self.chunks if chunk.chunk_id == chunk_id)


def parse_user_save(data: bytes) -> UserSave:
    """Parse one complete save, rejecting unknown, padded, or truncated bytes."""

    data = _require_bytes(data, "save data")
    minimum_size = _FORM_HEADER.size + _ROOT_SIZE + _CHUNK_HEADER.size
    if len(data) < minimum_size:
        raise UserSaveFormatError(
            f"user save is too short: {len(data)} bytes; need at least {minimum_size}"
        )

    form_id, form_size = _FORM_HEADER.unpack_from(data)
    if form_id != FORM_ID:
        raise UserSaveFormatError(f"expected FORM header, got {form_id!r}")
    actual_form_size = len(data) - _FORM_HEADER.size
    if form_size != actual_form_size:
        raise UserSaveFormatError(
            f"FORM size mismatch: header says {form_size}, file contains {actual_form_size}"
        )

    cursor = _FORM_HEADER.size
    root_id = data[cursor : cursor + _ROOT_SIZE]
    if root_id != ROOT_ID:
        raise UserSaveFormatError(f"expected USER root id, got {root_id!r}")
    cursor += _ROOT_SIZE

    chunks: list[UserSaveChunk] = []
    while cursor < len(data):
        remaining = len(data) - cursor
        if remaining < _CHUNK_HEADER.size:
            raise UserSaveFormatError(
                f"truncated chunk header at offset {cursor}: {remaining} bytes remain"
            )
        chunk_id, payload_size = _CHUNK_HEADER.unpack_from(data, cursor)
        cursor += _CHUNK_HEADER.size
        if chunk_id not in ALLOWED_CHUNK_IDS:
            raise UserSaveFormatError(
                f"unsupported user-save chunk id {chunk_id!r} at offset "
                f"{cursor - _CHUNK_HEADER.size}"
            )
        payload_end = cursor + payload_size
        if payload_end > len(data):
            raise UserSaveFormatError(
                f"{chunk_id.decode('ascii')} payload overruns FORM: need "
                f"{payload_size} bytes, only {len(data) - cursor} remain"
            )
        chunks.append(UserSaveChunk(chunk_id, data[cursor:payload_end]))
        cursor = payload_end

    return UserSave(root_id, tuple(chunks))


def load_user_save(path: str | Path) -> UserSave:
    """Read and strictly parse one user save from disk."""

    return parse_user_save(Path(path).read_bytes())


def serialize_user_save(save: UserSave) -> bytes:
    """Serialize a deterministic fixture in native save-call chunk order.

    Repeated chunks retain their relative order within each 4CC group.  This
    is a canonical test/data interchange contract, not yet a claim of native
    write compatibility; see :data:`SERIALIZER_STATUS`.
    """

    if not isinstance(save, UserSave):
        raise TypeError("save must be UserSave")

    grouped: dict[bytes, list[UserSaveChunk]] = {chunk_id: [] for chunk_id in CHUNK_ORDER}
    for chunk in save.chunks:
        grouped[chunk.chunk_id].append(chunk)
    canonical_chunks: Iterable[UserSaveChunk] = (
        chunk for chunk_id in CHUNK_ORDER for chunk in grouped[chunk_id]
    )

    body = bytearray(save.root_id)
    for chunk in canonical_chunks:
        body += _CHUNK_HEADER.pack(chunk.chunk_id, _checked_u32(len(chunk.payload), "payload"))
        body += chunk.payload

    return _FORM_HEADER.pack(FORM_ID, _checked_u32(len(body), "FORM body")) + body


def _require_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label} must be bytes, got {type(value).__name__}")
    return value


def _checked_u32(value: int, label: str) -> int:
    if not 0 <= value <= 0xFFFFFFFF:
        raise UserSaveFormatError(f"{label} is too large for a big-endian u32: {value}")
    return value


__all__ = [
    "ALLOWED_CHUNK_IDS",
    "CHUNK_ORDER",
    "FORMAT_EVIDENCE_STATUS",
    "FORM_ID",
    "NAME_ID",
    "ROOT_ID",
    "SERIALIZER_STATUS",
    "UserSave",
    "UserSaveChunk",
    "UserSaveFormatError",
    "load_user_save",
    "parse_user_save",
    "serialize_user_save",
]
