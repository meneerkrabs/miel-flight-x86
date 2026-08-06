#!/usr/bin/env python3
"""Typed, lossless decoders for Miel Vliegt save-chunk payloads.

The outer ``FORM/USER`` framing remains owned by :mod:`parse_user_save`.
This module deliberately adds a separate semantic layer: it accepts an
already bounded :class:`~parse_user_save.UserSaveChunk`, validates the entire
payload, and produces an immutable value that serializes back to the same
bytes.

Record shapes are corroborated by ``cc-tools`` commit ``e34efcd``.  That
project is a secondary structural oracle only; these codecs do not claim a
native-game round trip until an original save has been captured and compared.
Mission record cardinalities come from this repository's first-party UDS
mission extraction, never from the secondary table.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
import struct
from typing import Final, Iterable, TypeAlias

try:
    from .parse_user_save import UserSave, UserSaveChunk, UserSaveFormatError
except ImportError:  # pragma: no cover - direct script/import fallback
    from parse_user_save import UserSave, UserSaveChunk, UserSaveFormatError


STRUCTURAL_ORACLE: Final = {
    "repository": "https://github.com/RonnyReverse/cc-tools",
    "commit": "e34efcd858ec4475fa03d3f8668fa4e26f9e780e",
    "role": "SECONDARY_STRUCTURAL_ORACLE",
    "native_roundtrip_proven": False,
}
DEFAULT_MISSION_CONTRACT: Final = (
    Path(__file__).resolve().parents[2]
    / "content"
    / "miel_vliegt"
    / "uds_flight_contracts.json"
)

_U32 = struct.Struct("<I")
_MISSION_HEADER = struct.Struct("<III")
_STATE_CHANGE = struct.Struct("<II")
_BARN_PART = struct.Struct("<IIfff")
_AIRPLANE_PART = struct.Struct("<IHH")
_DIPLOMA = struct.Struct("<6I")
_PHOTO = struct.Struct("<102I")


class UserSavePayloadError(UserSaveFormatError):
    """Raised when a bounded chunk has an invalid typed payload."""


@dataclass(frozen=True, slots=True)
class CStringPayload:
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise TypeError("text must be str")
        _encode_ascii_cstring(self.text, "string")


@dataclass(frozen=True, slots=True)
class PhotoPayload:
    enabled: int
    completed: int
    statuses: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        _require_bool_u32(self.enabled, "PHOT enabled")
        _require_bool_u32(self.completed, "PHOT completed")
        rows = tuple(tuple(row) for row in self.statuses)
        if len(rows) != 10 or any(len(row) != 10 for row in rows):
            raise UserSavePayloadError("PHOT must contain exactly a 10x10 status grid")
        for y, row in enumerate(rows):
            for x, status in enumerate(row):
                if status not in (0, 1, 2):
                    raise UserSavePayloadError(
                        f"PHOT status[{y}][{x}] must be 0, 1, or 2; got {status!r}"
                    )
        object.__setattr__(self, "statuses", rows)


@dataclass(frozen=True, slots=True)
class DiplomaPayload:
    values: tuple[int, int, int, int, int, int]

    def __post_init__(self) -> None:
        values = tuple(self.values)
        if len(values) != 6:
            raise UserSavePayloadError("DIPL must contain exactly six u32 values")
        for index, value in enumerate(values):
            _require_u32(value, f"DIPL value[{index}]")
        object.__setattr__(self, "values", values)


@dataclass(frozen=True, slots=True)
class BarnPart:
    location: int
    part_id: int
    x: float
    y: float
    z: float

    def __post_init__(self) -> None:
        if self.location not in range(9):
            raise UserSavePayloadError(
                f"BARN location must be in 0..8; got {self.location!r}"
            )
        _require_u32(self.part_id, "BARN part id")
        coordinates = (self.x, self.y, self.z)
        if all(math.isnan(value) for value in coordinates):
            return
        if not all(math.isfinite(value) for value in coordinates):
            raise UserSavePayloadError(
                "BARN position must be three finite floats or three NaNs"
            )


@dataclass(frozen=True, slots=True)
class BarnPayload:
    parts: tuple[BarnPart, ...]

    def __post_init__(self) -> None:
        parts = tuple(self.parts)
        if any(not isinstance(part, BarnPart) for part in parts):
            raise TypeError("BARN parts must be BarnPart values")
        object.__setattr__(self, "parts", parts)


@dataclass(frozen=True, slots=True)
class AirplanePart:
    part_id: int
    slot: int
    parent: int

    def __post_init__(self) -> None:
        _require_u32(self.part_id, "AIRP part id")
        _require_u16(self.slot, "AIRP slot")
        _require_u16(self.parent, "AIRP parent")


@dataclass(frozen=True, slots=True)
class AirplanePartsPayload:
    parts: tuple[AirplanePart, ...]

    def __post_init__(self) -> None:
        parts = tuple(self.parts)
        if any(not isinstance(part, AirplanePart) for part in parts):
            raise TypeError("AIRP parts must be AirplanePart values")
        object.__setattr__(self, "parts", parts)


@dataclass(frozen=True, slots=True)
class ExportedAirplanePayload:
    name: str
    airplane: AirplanePartsPayload

    def __post_init__(self) -> None:
        _encode_ascii_cstring(self.name, "AIRB name")
        if not isinstance(self.airplane, AirplanePartsPayload):
            raise TypeError("AIRB airplane must be AirplanePartsPayload")


@dataclass(frozen=True, slots=True)
class SavedAirplanePayload:
    airplane_id: int
    exported: ExportedAirplanePayload

    def __post_init__(self) -> None:
        _require_u32(self.airplane_id, "AIRA airplane id")
        if not isinstance(self.exported, ExportedAirplanePayload):
            raise TypeError("AIRA exported must be ExportedAirplanePayload")


@dataclass(frozen=True, slots=True)
class MissionStateChange:
    unknown_bool: int
    success_processed: int

    def __post_init__(self) -> None:
        _require_bool_u32(self.unknown_bool, "MISS state-change unknown_bool")
        _require_bool_u32(self.success_processed, "MISS state-change success_processed")


@dataclass(frozen=True, slots=True)
class MissionPayload:
    mission_id: int
    state: int
    is_random: int
    dependencies: tuple[int, ...]
    state_changes: tuple[MissionStateChange, ...]

    def __post_init__(self) -> None:
        _require_u32(self.mission_id, "MISS id")
        if self.state not in range(4):
            raise UserSavePayloadError(f"MISS state must be in 0..3; got {self.state!r}")
        _require_bool_u32(self.is_random, "MISS is_random")
        dependencies = tuple(self.dependencies)
        for index, dependency in enumerate(dependencies):
            _require_bool_u32(dependency, f"MISS dependency[{index}]")
        state_changes = tuple(self.state_changes)
        if any(not isinstance(change, MissionStateChange) for change in state_changes):
            raise TypeError("MISS state_changes must be MissionStateChange values")
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "state_changes", state_changes)


TypedPayload: TypeAlias = (
    CStringPayload
    | PhotoPayload
    | DiplomaPayload
    | BarnPayload
    | AirplanePartsPayload
    | ExportedAirplanePayload
    | SavedAirplanePayload
    | MissionPayload
)


@dataclass(frozen=True, slots=True)
class TypedUserSaveChunk:
    chunk_id: bytes
    value: TypedPayload


@dataclass(frozen=True, slots=True)
class TypedUserSave:
    chunks: tuple[TypedUserSaveChunk, ...]


def load_mission_shapes(
    path: str | Path = DEFAULT_MISSION_CONTRACT,
) -> dict[int, tuple[int, int]]:
    """Return unambiguous ``mission id -> (dependencies, actions)`` shapes.

    Duplicate declarations are accepted only when their structural shape is
    identical.  Consequently IDs 28 and 29 remain explicitly ambiguous while
    duplicate IDs 30 and 31 are safe for payload-boundary decoding.
    """

    document = json.loads(Path(path).read_text(encoding="utf-8"))
    missions = document.get("missions")
    if not isinstance(missions, list):
        raise UserSavePayloadError("mission contract has no missions list")

    candidates: dict[int, set[tuple[int, int]]] = {}
    for index, mission in enumerate(missions):
        if not isinstance(mission, dict):
            raise UserSavePayloadError(f"mission contract entry {index} is not an object")
        mission_id = mission.get("id")
        dependencies = mission.get("dependencies")
        actions = mission.get("actions")
        _require_u32(mission_id, f"mission contract entry {index} id")
        if not isinstance(dependencies, list) or not isinstance(actions, list):
            raise UserSavePayloadError(
                f"mission contract entry {index} lacks dependency/action arrays"
            )
        candidates.setdefault(mission_id, set()).add((len(dependencies), len(actions)))

    return {
        mission_id: next(iter(shapes))
        for mission_id, shapes in candidates.items()
        if len(shapes) == 1
    }


def parse_typed_chunk(
    chunk: UserSaveChunk,
    *,
    mission_contract: str | Path = DEFAULT_MISSION_CONTRACT,
) -> TypedUserSaveChunk:
    """Decode one structurally parsed save chunk and consume it completely."""

    if not isinstance(chunk, UserSaveChunk):
        raise TypeError("chunk must be UserSaveChunk")
    value = parse_typed_payload(
        chunk.chunk_id,
        chunk.payload,
        mission_contract=mission_contract,
    )
    return TypedUserSaveChunk(chunk.chunk_id, value)


def parse_typed_user_save(
    save: UserSave,
    *,
    mission_contract: str | Path = DEFAULT_MISSION_CONTRACT,
) -> TypedUserSave:
    """Decode all payloads of a structurally parsed ``FORM/USER`` save."""

    if not isinstance(save, UserSave):
        raise TypeError("save must be UserSave")
    return TypedUserSave(
        tuple(
            parse_typed_chunk(chunk, mission_contract=mission_contract)
            for chunk in save.chunks
        )
    )


def parse_typed_payload(
    chunk_id: bytes,
    payload: bytes,
    *,
    mission_contract: str | Path = DEFAULT_MISSION_CONTRACT,
) -> TypedPayload:
    """Decode a known payload, rejecting unknown IDs and trailing bytes."""

    if not isinstance(chunk_id, bytes) or not isinstance(payload, bytes):
        raise TypeError("chunk_id and payload must be bytes")
    if chunk_id in (b"NAME", b"INVI"):
        return CStringPayload(_decode_ascii_cstring(payload, chunk_id.decode("ascii")))
    if chunk_id == b"PHOT":
        if len(payload) != _PHOTO.size:
            raise _size_error("PHOT", _PHOTO.size, len(payload))
        values = _PHOTO.unpack(payload)
        rows = tuple(tuple(values[2 + y * 10 : 2 + (y + 1) * 10]) for y in range(10))
        return PhotoPayload(values[0], values[1], rows)
    if chunk_id == b"DIPL":
        if len(payload) != _DIPLOMA.size:
            raise _size_error("DIPL", _DIPLOMA.size, len(payload))
        return DiplomaPayload(_DIPLOMA.unpack(payload))
    if chunk_id == b"BARN":
        return BarnPayload(
            tuple(BarnPart(*values) for values in _iter_records(payload, _BARN_PART, "BARN"))
        )
    if chunk_id == b"AIRP":
        return _parse_airplane_parts(payload, "AIRP")
    if chunk_id == b"AIRB":
        name, rest = _split_ascii_cstring(payload, "AIRB name")
        return ExportedAirplanePayload(name, _parse_airplane_parts(rest, "AIRB/AIRP"))
    if chunk_id == b"AIRA":
        if len(payload) < _U32.size + 1:
            raise UserSavePayloadError("AIRA is too short for airplane id and AIRB name")
        airplane_id = _U32.unpack_from(payload)[0]
        exported = parse_typed_payload(b"AIRB", payload[_U32.size :])
        assert isinstance(exported, ExportedAirplanePayload)
        return SavedAirplanePayload(airplane_id, exported)
    if chunk_id == b"MISS":
        return _parse_mission(payload, Path(mission_contract))
    raise UserSavePayloadError(f"unsupported typed payload id: {chunk_id!r}")


def serialize_typed_payload(
    chunk_id: bytes,
    value: TypedPayload,
    *,
    mission_contract: str | Path = DEFAULT_MISSION_CONTRACT,
) -> bytes:
    """Encode one typed value using the exact little-endian payload shape."""

    if chunk_id in (b"NAME", b"INVI") and isinstance(value, CStringPayload):
        return _encode_ascii_cstring(value.text, chunk_id.decode("ascii"))
    if chunk_id == b"PHOT" and isinstance(value, PhotoPayload):
        flat = (value.enabled, value.completed, *(status for row in value.statuses for status in row))
        return _PHOTO.pack(*flat)
    if chunk_id == b"DIPL" and isinstance(value, DiplomaPayload):
        return _DIPLOMA.pack(*value.values)
    if chunk_id == b"BARN" and isinstance(value, BarnPayload):
        return b"".join(
            _BARN_PART.pack(part.location, part.part_id, part.x, part.y, part.z)
            for part in value.parts
        )
    if chunk_id == b"AIRP" and isinstance(value, AirplanePartsPayload):
        return _serialize_airplane_parts(value.parts)
    if chunk_id == b"AIRB" and isinstance(value, ExportedAirplanePayload):
        return _encode_ascii_cstring(value.name, "AIRB name") + _serialize_airplane_parts(
            value.airplane.parts
        )
    if chunk_id == b"AIRA" and isinstance(value, SavedAirplanePayload):
        return _U32.pack(value.airplane_id) + serialize_typed_payload(b"AIRB", value.exported)
    if chunk_id == b"MISS" and isinstance(value, MissionPayload):
        payload = (
            _MISSION_HEADER.pack(value.mission_id, value.state, value.is_random)
            + b"".join(_U32.pack(flag) for flag in value.dependencies)
            + b"".join(
                _STATE_CHANGE.pack(change.unknown_bool, change.success_processed)
                for change in value.state_changes
            )
        )
        # Serialization is fail-closed too: callers cannot construct a typed
        # value with invented cardinalities and turn it into plausible bytes.
        _parse_mission(payload, Path(mission_contract))
        return payload
    raise UserSavePayloadError(
        f"value {type(value).__name__} does not match typed payload id {chunk_id!r}"
    )


def _parse_airplane_parts(payload: bytes, label: str) -> AirplanePartsPayload:
    return AirplanePartsPayload(
        tuple(AirplanePart(*values) for values in _iter_records(payload, _AIRPLANE_PART, label))
    )


def _serialize_airplane_parts(parts: Iterable[AirplanePart]) -> bytes:
    return b"".join(
        _AIRPLANE_PART.pack(part.part_id, part.slot, part.parent) for part in parts
    )


def _parse_mission(payload: bytes, mission_contract: Path) -> MissionPayload:
    if len(payload) < _MISSION_HEADER.size:
        raise UserSavePayloadError("MISS is too short for id/state/is_random")
    mission_id, state, is_random = _MISSION_HEADER.unpack_from(payload)

    shapes = load_mission_shapes(mission_contract)
    if mission_id not in shapes:
        candidates = _mission_shape_candidates(mission_contract, mission_id)
        if candidates:
            raise UserSavePayloadError(
                f"MISS id {mission_id} is structurally ambiguous in the first-party "
                f"contract: {sorted(candidates)!r}"
            )
        raise UserSavePayloadError(
            f"MISS id {mission_id} is absent from the first-party mission contract"
        )
    dependency_count, state_change_count = shapes[mission_id]
    expected_size = _MISSION_HEADER.size + dependency_count * _U32.size + state_change_count * _STATE_CHANGE.size
    if len(payload) != expected_size:
        raise _size_error(f"MISS id {mission_id}", expected_size, len(payload))

    cursor = _MISSION_HEADER.size
    dependencies = tuple(
        _U32.unpack_from(payload, cursor + index * _U32.size)[0]
        for index in range(dependency_count)
    )
    cursor += dependency_count * _U32.size
    changes = tuple(
        MissionStateChange(*_STATE_CHANGE.unpack_from(payload, cursor + index * _STATE_CHANGE.size))
        for index in range(state_change_count)
    )
    return MissionPayload(mission_id, state, is_random, dependencies, changes)


def _mission_shape_candidates(path: Path, mission_id: int) -> set[tuple[int, int]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {
        (len(mission["dependencies"]), len(mission["actions"]))
        for mission in document.get("missions", [])
        if isinstance(mission, dict) and mission.get("id") == mission_id
    }


def _iter_records(payload: bytes, record: struct.Struct, label: str):
    if len(payload) % record.size:
        raise UserSavePayloadError(
            f"{label} payload size {len(payload)} is not a multiple of {record.size}"
        )
    for offset in range(0, len(payload), record.size):
        yield record.unpack_from(payload, offset)


def _split_ascii_cstring(payload: bytes, label: str) -> tuple[str, bytes]:
    nul = payload.find(b"\0")
    if nul < 0:
        raise UserSavePayloadError(f"{label} is not NUL-terminated")
    try:
        text = payload[:nul].decode("ascii")
    except UnicodeDecodeError as error:
        raise UserSavePayloadError(f"{label} is not ASCII") from error
    return text, payload[nul + 1 :]


def _decode_ascii_cstring(payload: bytes, label: str) -> str:
    text, trailing = _split_ascii_cstring(payload, label)
    if trailing:
        raise UserSavePayloadError(f"{label} has bytes after its NUL terminator")
    return text


def _encode_ascii_cstring(text: str, label: str) -> bytes:
    if "\0" in text:
        raise UserSavePayloadError(f"{label} contains an embedded NUL")
    try:
        return text.encode("ascii") + b"\0"
    except UnicodeEncodeError as error:
        raise UserSavePayloadError(f"{label} is not ASCII") from error


def _require_u32(value: object, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise UserSavePayloadError(f"{label} must be a u32; got {value!r}")


def _require_u16(value: object, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF:
        raise UserSavePayloadError(f"{label} must be a u16; got {value!r}")


def _require_bool_u32(value: object, label: str) -> None:
    if value not in (0, 1) or isinstance(value, bool):
        raise UserSavePayloadError(f"{label} must be encoded as u32 0 or 1; got {value!r}")


def _size_error(label: str, expected: int, actual: int) -> UserSavePayloadError:
    return UserSavePayloadError(
        f"{label} payload must be exactly {expected} bytes; got {actual}"
    )


__all__ = [
    "AirplanePart",
    "AirplanePartsPayload",
    "BarnPart",
    "BarnPayload",
    "CStringPayload",
    "DEFAULT_MISSION_CONTRACT",
    "DiplomaPayload",
    "ExportedAirplanePayload",
    "MissionPayload",
    "MissionStateChange",
    "PhotoPayload",
    "STRUCTURAL_ORACLE",
    "SavedAirplanePayload",
    "TypedUserSave",
    "TypedUserSaveChunk",
    "UserSavePayloadError",
    "load_mission_shapes",
    "parse_typed_chunk",
    "parse_typed_payload",
    "parse_typed_user_save",
    "serialize_typed_payload",
]
