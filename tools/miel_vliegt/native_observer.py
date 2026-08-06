#!/usr/bin/env python3
"""Fail-closed binary capture and receipt core for native whole-game observation.

This module deliberately does not capture a process.  A native probe may write the
format defined here; this code linearizes/reads its ring-buffer snapshot and binds
it to the pinned executable, coverage map and scenario.  Protocol fixtures can be
encoded for tests, but can never satisfy a production-evidence verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "miel-vliegt-native-observer"
RECEIPT_SCHEMA = 2
VERSION = 1
MAGIC = b"MVOBSV1\0"
PRODUCTION_CAPTURE_ENABLED = False

FLAG_NATIVE = 1 << 0
FLAG_COMPLETE = 1 << 1
FLAG_WRAPPED = 1 << 2
KNOWN_FLAGS = FLAG_NATIVE | FLAG_COMPLETE | FLAG_WRAPPED

# magic, version, header size, flags, ring capacity/used/count, bitmap sizes,
# reserved, first/next sequence, executable/map/scenario SHA-256.
HEADER = struct.Struct("<8sHHIIIIIIIIQQ32s32s32s")
# type, flags (reserved), payload length, monotonically increasing sequence, CRC.
RECORD = struct.Struct("<BBHQI")
RECORD_CRC_PREFIX = struct.Struct("<BBHQ")

FUNCTION_HIT = 1
BLOCK_HIT = 2
EDGE_HIT = 3
FLIGHT_STEP = 4
DEEP_BEGIN = 5
DEEP_INSTRUCTION = 6
DEEP_MEMORY = 7
DEEP_END = 8
KNOWN_RECORD_TYPES = {
    FUNCTION_HIT, BLOCK_HIT, EDGE_HIT, FLIGHT_STEP, DEEP_BEGIN,
    DEEP_INSTRUCTION, DEEP_MEMORY, DEEP_END,
}

U32 = struct.Struct("<I")
EDGE = struct.Struct("<II")
STEP = struct.Struct("<QB3xI")
DEEP_MARKER = struct.Struct("<IQI")
DEEP_REGISTERS = struct.Struct("<12I")
DEEP_MEMORY_PREFIX = struct.Struct("<IIIBBH")
REGISTER_NAMES = ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERNS = {
    "function": re.compile(r"^fn_([0-9a-f]{8})$"),
    "block": re.compile(r"^bb_([0-9a-f]{8})$"),
    "edge": re.compile(r"^edge_([0-9a-f]{8})_([0-9a-f]{8})$"),
}


class ObserverError(ValueError):
    """The capture is malformed, stale, incomplete, or over-claims evidence."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_bytes(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ObserverError(f"{field} must be a lowercase SHA-256")
    return bytes.fromhex(value)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_json_strict(raw: bytes, context: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ObserverError(f"{context} contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ObserverError(f"{context} contains non-finite number {value}")

    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ObserverError(f"invalid {context} JSON: {error}") from error


def _strict_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ObserverError(
            f"{context} fields differ: missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


@dataclass(frozen=True)
class CoverageIndex:
    """Validated stable-ID lookup plus the exact source-map identity."""

    sha256: str
    executable_sha256: str
    functions: tuple[str, ...]
    blocks: tuple[str, ...]
    edges: tuple[str, ...]
    function_address: Mapping[int, int]
    block_address: Mapping[int, int]
    edge_address: Mapping[tuple[int, int], int]

    @classmethod
    def from_path(cls, path: Path) -> "CoverageIndex":
        raw = path.read_bytes()
        value = _load_json_strict(raw, "coverage map")
        return cls.from_value(value, sha256=sha256_bytes(raw))

    @classmethod
    def from_value(cls, value: Any, *, sha256: str | None = None) -> "CoverageIndex":
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise ObserverError("unsupported coverage map schema")
        source_identity = value.get("source")
        if not isinstance(source_identity, dict):
            raise ObserverError("coverage map source must be an object")
        executable = source_identity.get("executable_sha256")
        _hash_bytes(executable, "coverage map executable_sha256")

        def rows(kind: str, field: str, address_field: str) -> tuple[tuple[str, ...], dict[int, int]]:
            source = value.get(field)
            if not isinstance(source, list):
                raise ObserverError(f"coverage map {field} must be a list")
            identifiers: list[str] = []
            identifier_set: set[str] = set()
            addresses: dict[int, int] = {}
            pattern = ID_PATTERNS[kind]
            for ordinal, row in enumerate(source):
                if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                    raise ObserverError(f"coverage map {field}[{ordinal}] has no ID")
                match = pattern.fullmatch(row["id"])
                if match is None:
                    raise ObserverError(f"invalid {kind} ID: {row['id']!r}")
                try:
                    address = int(row[address_field], 16)
                except (KeyError, TypeError, ValueError) as error:
                    raise ObserverError(f"invalid address for {row['id']}") from error
                if address != int(match.group(1), 16):
                    raise ObserverError(f"ID/address mismatch for {row['id']}")
                if row["id"] in identifier_set or address in addresses:
                    raise ObserverError(f"duplicate {kind} coverage identity: {row['id']}")
                identifiers.append(row["id"])
                identifier_set.add(row["id"])
                addresses[address] = ordinal
            return tuple(identifiers), addresses

        functions, function_address = rows("function", "functions", "address")
        blocks, block_address = rows("block", "basic_blocks", "start")
        edge_rows = value.get("edges")
        if not isinstance(edge_rows, list):
            raise ObserverError("coverage map edges must be a list")
        edges: list[str] = []
        edge_set: set[str] = set()
        edge_address: dict[tuple[int, int], int] = {}
        for ordinal, row in enumerate(edge_rows):
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise ObserverError(f"coverage map edges[{ordinal}] has no ID")
            match = ID_PATTERNS["edge"].fullmatch(row["id"])
            if match is None:
                raise ObserverError(f"invalid edge ID: {row['id']!r}")
            pair = (int(match.group(1), 16), int(match.group(2), 16))
            if row.get("source") != f"bb_{pair[0]:08x}" or row.get("target") != f"bb_{pair[1]:08x}":
                raise ObserverError(f"ID/endpoints mismatch for {row['id']}")
            if row["id"] in edge_set or pair in edge_address:
                raise ObserverError(f"duplicate edge coverage identity: {row['id']}")
            if pair[0] not in block_address or pair[1] not in block_address:
                raise ObserverError(f"edge references an unknown block: {row['id']}")
            edges.append(row["id"])
            edge_set.add(row["id"])
            edge_address[pair] = ordinal
        map_hash = sha256 or sha256_bytes(_canonical_json(value))
        _hash_bytes(map_hash, "coverage map SHA-256")
        return cls(
            map_hash, executable, functions, blocks, tuple(edges),
            function_address, block_address, edge_address,
        )


@dataclass(frozen=True)
class Capture:
    capture_kind: str
    complete: bool
    wrapped: bool
    event_capacity: int
    first_sequence: int
    next_sequence: int
    executable_sha256: str
    coverage_map_sha256: str
    scenario_sha256: str
    events: tuple[dict[str, Any], ...]
    coverage: Mapping[str, tuple[str, ...]]


def _bitmap_size(count: int) -> int:
    return (count + 7) // 8


def _set_bit(bitmap: bytearray, ordinal: int) -> None:
    bitmap[ordinal // 8] |= 1 << (ordinal % 8)


def _bitmap_ids(bitmap: bytes, identifiers: Sequence[str]) -> tuple[str, ...]:
    expected = _bitmap_size(len(identifiers))
    if len(bitmap) != expected:
        raise ObserverError("coverage bitmap length mismatch")
    if identifiers and len(identifiers) % 8:
        unused_mask = 0xFF << (len(identifiers) % 8) & 0xFF
        if bitmap[-1] & unused_mask:
            raise ObserverError("coverage bitmap has non-zero unused bits")
    return tuple(identifier for ordinal, identifier in enumerate(identifiers)
                 if bitmap[ordinal // 8] & (1 << (ordinal % 8)))


def _event_payload(event: Mapping[str, Any], coverage: CoverageIndex) -> tuple[int, bytes, tuple[str, int] | None]:
    kind = event.get("type")
    if kind == "function":
        _strict_keys(event, {"type", "id"}, "function event")
        match = ID_PATTERNS["function"].fullmatch(str(event["id"]))
        address = int(match.group(1), 16) if match else -1
        if address not in coverage.function_address:
            raise ObserverError(f"unknown function ID: {event['id']!r}")
        return FUNCTION_HIT, U32.pack(address), ("function", coverage.function_address[address])
    if kind == "block":
        _strict_keys(event, {"type", "id"}, "block event")
        match = ID_PATTERNS["block"].fullmatch(str(event["id"]))
        address = int(match.group(1), 16) if match else -1
        if address not in coverage.block_address:
            raise ObserverError(f"unknown block ID: {event['id']!r}")
        return BLOCK_HIT, U32.pack(address), ("block", coverage.block_address[address])
    if kind == "edge":
        _strict_keys(event, {"type", "id"}, "edge event")
        match = ID_PATTERNS["edge"].fullmatch(str(event["id"]))
        pair = (int(match.group(1), 16), int(match.group(2), 16)) if match else (-1, -1)
        if pair not in coverage.edge_address:
            raise ObserverError(f"unknown edge ID: {event['id']!r}")
        return EDGE_HIT, EDGE.pack(*pair), ("edge", coverage.edge_address[pair])
    if kind == "flight.step":
        _strict_keys(event, {"type", "tick", "phase", "dt_f32_bits"}, "flight.step event")
        phase = {"enter": 1, "leave": 2}.get(event["phase"])
        if phase is None:
            raise ObserverError("flight.step phase must be enter or leave")
        tick = _unsigned(event["tick"], 64, "flight.step tick")
        dt_bits = _unsigned(event["dt_f32_bits"], 32, "flight.step dt_f32_bits")
        return FLIGHT_STEP, STEP.pack(tick, phase, dt_bits), None
    if kind in {"deep.begin", "deep.end"}:
        _strict_keys(event, {"type", "window_id", "tick", "reason_code"}, f"{kind} event")
        record_type = DEEP_BEGIN if kind == "deep.begin" else DEEP_END
        return record_type, DEEP_MARKER.pack(
            _unsigned(event["window_id"], 32, "window_id"),
            _unsigned(event["tick"], 64, "deep tick"),
            _unsigned(event["reason_code"], 32, "reason_code"),
        ), None
    if kind == "deep.instruction":
        _strict_keys(event, {"type", "window_id", "thread_id", "ip", "eflags", "registers"}, "deep.instruction event")
        registers = event["registers"]
        if not isinstance(registers, Mapping):
            raise ObserverError("deep.instruction registers must be an object")
        _strict_keys(registers, set(REGISTER_NAMES), "deep.instruction registers")
        values = [
            _unsigned(event["window_id"], 32, "window_id"),
            _unsigned(event["thread_id"], 32, "thread_id"),
            _unsigned(event["ip"], 32, "instruction pointer"),
            _unsigned(event["eflags"], 32, "eflags"),
            *(_unsigned(registers[name], 32, name) for name in REGISTER_NAMES),
        ]
        return DEEP_INSTRUCTION, DEEP_REGISTERS.pack(*values), None
    if kind == "deep.memory":
        _strict_keys(event, {"type", "window_id", "thread_id", "address", "access", "data"}, "deep.memory event")
        access = {"read": 1, "write": 2}.get(event["access"])
        data = event["data"]
        if access is None or not isinstance(data, bytes) or not 1 <= len(data) <= 255:
            raise ObserverError("deep.memory requires read/write and 1..255 data bytes")
        prefix = DEEP_MEMORY_PREFIX.pack(
            _unsigned(event["window_id"], 32, "window_id"),
            _unsigned(event["thread_id"], 32, "thread_id"),
            _unsigned(event["address"], 32, "memory address"),
            access, len(data), 0,
        )
        return DEEP_MEMORY, prefix + data, None
    raise ObserverError(f"unknown observer event: {kind!r}")


def _unsigned(value: Any, bits: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << bits:
        raise ObserverError(f"{field} must be an unsigned {bits}-bit integer")
    return value


def _frame(record_type: int, sequence: int, payload: bytes) -> bytes:
    if record_type not in KNOWN_RECORD_TYPES or len(payload) > 4096:
        raise ObserverError("invalid observer record")
    prefix = RECORD_CRC_PREFIX.pack(record_type, 0, len(payload), sequence)
    return RECORD.pack(record_type, 0, len(payload), sequence, zlib.crc32(prefix + payload)) + payload


def encode_artifact(
    events: Iterable[Mapping[str, Any]], coverage: CoverageIndex, *,
    scenario_sha256: str, native_capture: bool = False, complete: bool = True,
    event_capacity: int | None = None,
) -> bytes:
    """Encode a capture snapshot; non-native is the safe default for fixtures."""

    scenario_hash = _hash_bytes(scenario_sha256, "scenario_sha256")
    frames: list[bytes] = []
    bitmaps = {
        "function": bytearray(_bitmap_size(len(coverage.functions))),
        "block": bytearray(_bitmap_size(len(coverage.blocks))),
        "edge": bytearray(_bitmap_size(len(coverage.edges))),
    }
    normalized = []
    for sequence, event in enumerate(events):
        record_type, payload, coverage_bit = _event_payload(event, coverage)
        frames.append(_frame(record_type, sequence, payload))
        normalized.append(dict(event))
        if coverage_bit:
            _set_bit(bitmaps[coverage_bit[0]], coverage_bit[1])
    _validate_event_semantics(normalized)

    total = sum(map(len, frames))
    capacity = total if event_capacity is None else event_capacity
    if not isinstance(capacity, int) or capacity < 0:
        raise ObserverError("event_capacity must be non-negative")
    if frames and capacity < max(map(len, frames)):
        raise ObserverError("event_capacity cannot hold one complete event")
    first = 0
    while total > capacity:
        total -= len(frames.pop(0))
        first += 1
    retained_events = normalized[first:]
    _validate_event_semantics(retained_events)
    wrapped = first > 0
    flags = (FLAG_NATIVE if native_capture else 0) | (FLAG_COMPLETE if complete else 0) | (FLAG_WRAPPED if wrapped else 0)
    body = b"".join(frames)
    header = HEADER.pack(
        MAGIC, VERSION, HEADER.size, flags, capacity, len(body), len(frames),
        len(bitmaps["function"]), len(bitmaps["block"]), len(bitmaps["edge"]), 0,
        first, first + len(frames), bytes.fromhex(coverage.executable_sha256),
        bytes.fromhex(coverage.sha256), scenario_hash,
    )
    return header + bytes(bitmaps["function"]) + bytes(bitmaps["block"]) + bytes(bitmaps["edge"]) + body


def _parse_event(record_type: int, payload: bytes, coverage: CoverageIndex) -> tuple[dict[str, Any], tuple[str, int] | None]:
    def fixed(parser: struct.Struct, name: str) -> tuple[Any, ...]:
        if len(payload) != parser.size:
            raise ObserverError(f"invalid {name} payload length")
        return parser.unpack(payload)

    if record_type == FUNCTION_HIT:
        address, = fixed(U32, "function")
        ordinal = coverage.function_address.get(address)
        if ordinal is None:
            raise ObserverError(f"unknown function address: 0x{address:08x}")
        return {"type": "function", "id": coverage.functions[ordinal]}, ("function", ordinal)
    if record_type == BLOCK_HIT:
        address, = fixed(U32, "block")
        ordinal = coverage.block_address.get(address)
        if ordinal is None:
            raise ObserverError(f"unknown block address: 0x{address:08x}")
        return {"type": "block", "id": coverage.blocks[ordinal]}, ("block", ordinal)
    if record_type == EDGE_HIT:
        pair = fixed(EDGE, "edge")
        ordinal = coverage.edge_address.get(pair)
        if ordinal is None:
            raise ObserverError(f"unknown edge address: 0x{pair[0]:08x}->0x{pair[1]:08x}")
        return {"type": "edge", "id": coverage.edges[ordinal]}, ("edge", ordinal)
    if record_type == FLIGHT_STEP:
        tick, phase, dt_bits = fixed(STEP, "flight.step")
        if phase not in {1, 2}:
            raise ObserverError("unknown flight.step phase")
        return {"type": "flight.step", "tick": tick, "phase": "enter" if phase == 1 else "leave", "dt_f32_bits": dt_bits}, None
    if record_type in {DEEP_BEGIN, DEEP_END}:
        window_id, tick, reason = fixed(DEEP_MARKER, "deep marker")
        return {"type": "deep.begin" if record_type == DEEP_BEGIN else "deep.end", "window_id": window_id, "tick": tick, "reason_code": reason}, None
    if record_type == DEEP_INSTRUCTION:
        values = fixed(DEEP_REGISTERS, "deep.instruction")
        return {
            "type": "deep.instruction", "window_id": values[0], "thread_id": values[1],
            "ip": values[2], "eflags": values[3],
            "registers": dict(zip(REGISTER_NAMES, values[4:])),
        }, None
    if record_type == DEEP_MEMORY:
        if len(payload) < DEEP_MEMORY_PREFIX.size:
            raise ObserverError("invalid deep.memory payload length")
        window, thread, address, access, size, reserved = DEEP_MEMORY_PREFIX.unpack_from(payload)
        data = payload[DEEP_MEMORY_PREFIX.size:]
        if reserved or access not in {1, 2} or size == 0 or len(data) != size:
            raise ObserverError("invalid deep.memory payload")
        return {
            "type": "deep.memory", "window_id": window, "thread_id": thread,
            "address": address, "access": "read" if access == 1 else "write", "data": data,
        }, None
    raise ObserverError(f"unknown observer record type: {record_type}")


def _validate_event_semantics(events: Sequence[Mapping[str, Any]]) -> None:
    active_tick: int | None = None
    last_tick: int | None = None
    windows: dict[int, tuple[int, int]] = {}
    for event in events:
        kind = event["type"]
        if kind == "flight.step":
            tick = event["tick"]
            if event["phase"] == "enter":
                if active_tick is not None or (last_tick is not None and tick != last_tick + 1):
                    raise ObserverError("flight.step ticks are overlapping or non-contiguous")
                active_tick = tick
            elif active_tick != tick:
                raise ObserverError("flight.step leave has no matching enter")
            else:
                active_tick = None
                last_tick = tick
        elif kind == "deep.begin":
            window = event["window_id"]
            if window in windows:
                raise ObserverError(f"deep-trace window {window} opened twice")
            windows[window] = (event["tick"], event["reason_code"])
        elif kind in {"deep.instruction", "deep.memory"}:
            if event["window_id"] not in windows:
                raise ObserverError("deep-trace event is outside its window")
        elif kind == "deep.end":
            opened = windows.pop(event["window_id"], None)
            if opened is None or event["tick"] < opened[0] or event["reason_code"] != opened[1]:
                raise ObserverError("deep-trace window close does not match its open")
    if active_tick is not None:
        raise ObserverError("flight.step tick is incomplete")
    if windows:
        raise ObserverError(f"deep-trace windows are incomplete: {sorted(windows)}")


def parse_artifact(source: bytes | Path, coverage: CoverageIndex) -> Capture:
    data = source.read_bytes() if isinstance(source, Path) else source
    if len(data) < HEADER.size:
        raise ObserverError("observer artifact is truncated before its header")
    values = HEADER.unpack_from(data)
    (magic, version, header_size, flags, capacity, event_bytes, event_count,
     function_bytes, block_bytes, edge_bytes, reserved, first, next_sequence,
     executable_hash, map_hash, scenario_hash) = values
    if magic != MAGIC or version != VERSION or header_size != HEADER.size:
        raise ObserverError("unsupported observer artifact header")
    if flags & ~KNOWN_FLAGS or reserved:
        raise ObserverError("observer artifact has unknown flags or reserved data")
    if map_hash.hex() != coverage.sha256 or executable_hash.hex() != coverage.executable_sha256:
        raise ObserverError("observer artifact provenance does not match the coverage map")
    expected_bitmap_sizes = (
        _bitmap_size(len(coverage.functions)), _bitmap_size(len(coverage.blocks)),
        _bitmap_size(len(coverage.edges)),
    )
    if (function_bytes, block_bytes, edge_bytes) != expected_bitmap_sizes:
        raise ObserverError("observer artifact coverage layout does not match the map")
    if event_bytes > capacity or next_sequence != first + event_count:
        raise ObserverError("observer ring metadata is inconsistent")
    wrapped = bool(flags & FLAG_WRAPPED)
    if wrapped != (first > 0):
        raise ObserverError("observer ring wrap flag is inconsistent")
    end = HEADER.size + function_bytes + block_bytes + edge_bytes + event_bytes
    if len(data) != end:
        raise ObserverError("observer artifact length does not match its header")
    offset = HEADER.size
    function_bitmap = data[offset:offset + function_bytes]
    offset += function_bytes
    block_bitmap = data[offset:offset + block_bytes]
    offset += block_bytes
    edge_bitmap = data[offset:offset + edge_bytes]
    offset += edge_bytes
    coverage_ids = {
        "function": _bitmap_ids(function_bitmap, coverage.functions),
        "block": _bitmap_ids(block_bitmap, coverage.blocks),
        "edge": _bitmap_ids(edge_bitmap, coverage.edges),
    }
    observed = {key: set() for key in coverage_ids}
    events: list[dict[str, Any]] = []
    sequence = first
    for _ in range(event_count):
        if offset + RECORD.size > len(data):
            raise ObserverError("observer event header is truncated")
        record_type, record_flags, payload_size, actual_sequence, checksum = RECORD.unpack_from(data, offset)
        offset += RECORD.size
        if record_type not in KNOWN_RECORD_TYPES:
            raise ObserverError(f"unknown observer record type: {record_type}")
        if record_flags or payload_size > 4096 or offset + payload_size > len(data):
            raise ObserverError("invalid or truncated observer event")
        payload = data[offset:offset + payload_size]
        offset += payload_size
        prefix = RECORD_CRC_PREFIX.pack(record_type, record_flags, payload_size, actual_sequence)
        if zlib.crc32(prefix + payload) != checksum:
            raise ObserverError("observer event CRC mismatch")
        if actual_sequence != sequence:
            raise ObserverError("observer event sequence is missing or out of order")
        event, coverage_bit = _parse_event(record_type, payload, coverage)
        event["sequence"] = sequence
        events.append(event)
        if coverage_bit:
            observed[coverage_bit[0]].add(coverage_bit[1])
        sequence += 1
    if offset != len(data):
        raise ObserverError("observer event count does not consume the artifact")
    for kind, bitmap_ids in coverage_ids.items():
        event_ids = {getattr(coverage, f"{kind}s")[ordinal] for ordinal in observed[kind]}
        if not event_ids.issubset(bitmap_ids):
            raise ObserverError(f"{kind} event is absent from its coverage bitmap")
        if not wrapped and event_ids != set(bitmap_ids):
            raise ObserverError(f"{kind} bitmap contains coverage without an event")
    semantic_events = [{key: value for key, value in event.items() if key != "sequence"} for event in events]
    _validate_event_semantics(semantic_events)
    return Capture(
        "native" if flags & FLAG_NATIVE else "protocol_fixture",
        bool(flags & FLAG_COMPLETE), wrapped, capacity, first, next_sequence,
        executable_hash.hex(), map_hash.hex(), scenario_hash.hex(), tuple(events), coverage_ids,
    )


def import_hook_log(
    log_path: Path, coverage: CoverageIndex, *, scenario_sha256: str,
) -> bytes:
    """Convert the in-process MVT stream to MVOBSV1 without inventing frames.

    Recursive flight.step calls are collapsed to their outermost entry/leave
    pair.  They are native integration steps, not rendered-frame observations;
    trajectory promotion still requires the separate reviewed state layout.
    """
    loaded = False
    raw_sequence = 0
    depth = 0
    tick = 0
    active_dt: int | None = None
    thread_id: int | None = None
    events: list[dict[str, Any]] = []
    function_id = "fn_0040e610"
    if function_id not in coverage.functions:
        raise ObserverError("coverage map has no flight.step function")
    for line_number, line in enumerate(
        log_path.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if line.startswith("MVO "):
            marker = _load_json_strict(line[4:].encode(), f"hook marker line {line_number}")
            if isinstance(marker, dict) and marker == {
                "schema": 1, "protocol": "miel-vliegt-native-observer-hook",
                "status": "LOADED", "thread_id": marker.get("thread_id"),
            } and isinstance(marker.get("thread_id"), int) \
                    and not isinstance(marker.get("thread_id"), bool):
                loaded = True
            continue
        if not line.startswith("MVT "):
            continue
        value = _load_json_strict(line[4:].encode(), f"hook event line {line_number}")
        if not isinstance(value, dict) or value.get("record") != "behavior" \
                or isinstance(value.get("sequence"), bool) \
                or value.get("sequence") != raw_sequence:
            raise ObserverError("hook event sequence is missing or invalid")
        raw_sequence += 1
        diagnostics = value.get("diagnostics")
        current_thread = diagnostics.get("thread_id") if isinstance(diagnostics, dict) else None
        if isinstance(current_thread, bool) or not isinstance(current_thread, int):
            raise ObserverError("hook event has no thread identity")
        if thread_id is None:
            thread_id = current_thread
        elif thread_id != current_thread:
            raise ObserverError("flight.step hook crossed game threads")
        channel = value.get("channel")
        if channel == "flight.step.enter":
            bits = value.get("values", {}).get("dt_f32_bits")
            if not isinstance(bits, str) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", bits):
                raise ObserverError("flight.step hook has invalid dt bits")
            if depth == 0:
                active_dt = int(bits, 16)
                events.extend([
                    {"type": "function", "id": function_id},
                    {"type": "flight.step", "tick": tick, "phase": "enter",
                     "dt_f32_bits": active_dt},
                ])
            depth += 1
        elif channel == "flight.step.leave":
            if value.get("values") != {} or depth == 0:
                raise ObserverError("flight.step hook leave is unmatched")
            depth -= 1
            if depth == 0:
                assert active_dt is not None
                events.append({
                    "type": "flight.step", "tick": tick, "phase": "leave",
                    "dt_f32_bits": active_dt,
                })
                tick += 1
                active_dt = None
        else:
            raise ObserverError(f"unknown in-process hook channel: {channel!r}")
    if not loaded:
        raise ObserverError("hook log has no LOADED marker")
    if depth or not tick:
        raise ObserverError("hook log has no complete outer flight.step")
    return encode_artifact(
        events, coverage, scenario_sha256=scenario_sha256,
        native_capture=False, complete=True,
    )


RECEIPT_FIELDS = {
    "schema", "protocol", "capture_kind", "evidence_status", "production_claim",
    "capture_complete", "artifact", "artifact_sha256", "executable", "executable_sha256",
    "coverage_map", "coverage_map_sha256", "scenario", "scenario_sha256",
    "capture_tool", "capture_tool_sha256", "capture_command", "capture_host",
    "capture_controller", "capture_controller_sha256",
    "capture_contract", "capture_contract_sha256",
    "patched_executable", "patched_executable_sha256",
    "patch_receipt", "patch_receipt_sha256",
    "launch_receipt", "launch_receipt_sha256",
}

LAUNCH_RECEIPT_FIELDS = {
    "schema", "protocol", "status", "phase", "detail", "scene",
    "original_executable_sha256", "patched_executable_sha256",
    "observer_dll_sha256", "patch_receipt_sha256", "checks",
}


def _inside(root: Path, relative: Any, field: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ObserverError(f"{field} must be a non-empty relative path")
    root = root.resolve()
    result = (root / relative).resolve()
    if result != root and root not in result.parents:
        raise ObserverError(f"{field} escapes the receipt root")
    if not result.is_file():
        raise ObserverError(f"{field} does not exist: {relative}")
    return result


def verify_receipt(path: Path, *, root: Path = ROOT, require_production: bool = False) -> tuple[dict[str, Any], Capture]:
    receipt = _load_json_strict(path.read_bytes(), "observer receipt")
    if not isinstance(receipt, dict):
        raise ObserverError("observer receipt must be an object")
    _strict_keys(receipt, RECEIPT_FIELDS, "observer receipt")
    if receipt["schema"] != RECEIPT_SCHEMA or receipt["protocol"] != PROTOCOL:
        raise ObserverError("unsupported observer receipt")
    if receipt["capture_kind"] not in {"native", "protocol_fixture"}:
        raise ObserverError("unknown receipt capture_kind")
    for field in ("production_claim", "capture_complete"):
        if not isinstance(receipt[field], bool):
            raise ObserverError(f"{field} must be boolean")
    if receipt["evidence_status"] not in {"native-capture", "fixture-only"}:
        raise ObserverError("unknown observer evidence_status")
    command = receipt["capture_command"]
    host = receipt["capture_host"]
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise ObserverError("capture_command must be a non-empty string array")
    if not isinstance(host, dict):
        raise ObserverError("capture_host must be an object")
    _strict_keys(host, {"os", "architecture", "backend"}, "capture_host")
    if not all(isinstance(host[field], str) and host[field] for field in host):
        raise ObserverError("capture_host values must be non-empty strings")

    files = {}
    for field in (
        "artifact", "executable", "coverage_map", "scenario", "capture_tool",
        "capture_controller", "capture_contract",
    ):
        files[field] = _inside(root, receipt[field], field)
        claimed = receipt[f"{field}_sha256"]
        _hash_bytes(claimed, f"{field}_sha256")
        if sha256_file(files[field]) != claimed:
            raise ObserverError(f"{field} SHA-256 drifted")
    provenance_fields = ("patched_executable", "patch_receipt", "launch_receipt")
    if receipt["capture_kind"] == "protocol_fixture":
        if any(receipt[field] is not None or receipt[f"{field}_sha256"] is not None
               for field in provenance_fields):
            raise ObserverError("protocol fixtures cannot carry native launch provenance")
    else:
        for field in provenance_fields:
            files[field] = _inside(root, receipt[field], field)
            claimed = receipt[f"{field}_sha256"]
            _hash_bytes(claimed, f"{field}_sha256")
            if sha256_file(files[field]) != claimed:
                raise ObserverError(f"{field} SHA-256 drifted")
    coverage = CoverageIndex.from_path(files["coverage_map"])
    capture = parse_artifact(files["artifact"], coverage)
    if receipt["executable_sha256"] != coverage.executable_sha256:
        raise ObserverError("receipt executable does not match the coverage map")
    if receipt["scenario_sha256"] != capture.scenario_sha256:
        raise ObserverError("receipt scenario does not match the artifact")
    if receipt["capture_kind"] != capture.capture_kind or receipt["capture_complete"] != capture.complete:
        raise ObserverError("receipt capture state does not match the artifact")

    if receipt["capture_kind"] == "native":
        try:
            scenario = _load_json_strict(files["scenario"].read_bytes(), "observer scenario")
            patch_receipt = _load_json_strict(
                files["patch_receipt"].read_bytes(), "scene patch receipt",
            )
            launch = _load_json_strict(
                files["launch_receipt"].read_bytes(), "observer launch receipt",
            )
            host_contract = _load_json_strict(
                files["capture_contract"].read_bytes(), "capture-host contract",
            )
        except (KeyError, TypeError, ModuleNotFoundError) as error:
            raise ObserverError("native observer provenance is incomplete") from error
        if not isinstance(scenario, dict) or not isinstance(scenario.get("id"), str) \
                or not isinstance(scenario.get("native_scene"), str):
            raise ObserverError("native observer scenario needs id and native_scene")
        if not isinstance(host_contract, dict) \
                or host_contract.get("schema") != 1 \
                or host_contract.get("host_role") != "EXPERIMENTAL_CAPTURE_HOST" \
                or host_contract.get("source", {}).get("project") != "AndreRH/hangover" \
                or host_contract.get("source", {}).get("release") != "hangover-11.9" \
                or host_contract.get("target", {}).get("executable_sha256") \
                    != receipt["executable_sha256"] \
                or host_contract.get("probe_backends") != [
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    {"id": "fex", "hodll": "libwow64fex.dll"},
                ] \
                or host_contract.get("observer_strategy", {}).get("selected") \
                    != "startup-mode-patch+suspended-process-game-thread-hook":
            raise ObserverError("native capture-host contract failed closed")
        patch_scene = patch_receipt.get("scene") if isinstance(patch_receipt, dict) else None
        patch_changes = patch_receipt.get("changes") if isinstance(patch_receipt, dict) else None
        if not isinstance(patch_receipt, dict) \
                or patch_receipt.get("schema") != 1 \
                or patch_receipt.get("protocol") != "miel-vliegt-native-scene-start-patch" \
                or patch_receipt.get("status") != "PREPARED" \
                or patch_receipt.get("strategy") != "startup-mode-argument" \
                or patch_receipt.get("marker_directory") is not None \
                or patch_receipt.get("source_executable_sha256") != receipt["executable_sha256"] \
                or patch_receipt.get("patched_executable_sha256") \
                    != receipt["patched_executable_sha256"] \
                or not isinstance(patch_scene, dict) \
                or patch_scene.get("id") != scenario["native_scene"] \
                or not isinstance(patch_changes, list) \
                or len(patch_changes) != 1 \
                or not isinstance(patch_changes[0], dict) \
                or patch_changes[0].get("kind") != "startup-mode-argument":
            raise ObserverError("native scene patch receipt failed closed")
        required_checks = {
            "created_suspended", "entrypoint_signature_verified",
            "entrypoint_barrier_installed", "loader_initialization_completed",
            "entrypoint_barrier_reached", "entrypoint_bytes_restored",
            "observer_loaded", "observer_initialized", "main_thread_resumed",
            "projector_input_idle", "scenario_completion_event",
            "observer_failure_event_clear", "observation_window_completed",
            "target_terminated",
        }
        if not isinstance(launch, dict) or set(launch) != LAUNCH_RECEIPT_FIELDS \
                or launch.get("schema") != 1 \
                or launch.get("protocol") != "miel-vliegt-native-observer-launch" \
                or launch.get("status") != "PASS" or launch.get("phase") != "cleanup" \
                or launch.get("original_executable_sha256") != receipt["executable_sha256"] \
                or launch.get("patched_executable_sha256") \
                    != receipt["patched_executable_sha256"] \
                or launch.get("observer_dll_sha256") != receipt["capture_tool_sha256"] \
                or launch.get("patch_receipt_sha256") != receipt["patch_receipt_sha256"] \
                or launch.get("scene") != scenario["native_scene"] \
                or not isinstance(launch.get("checks"), dict) \
                or set(launch["checks"]) != required_checks \
                or not all(value is True for value in launch["checks"].values()):
            raise ObserverError("native observer launch receipt failed closed")
        allowed_backends = {
            f"hangover-{item['id']}-suspended-process-hook"
            for item in host_contract.get("probe_backends", [])
            if isinstance(item, dict) and item.get("id") in {"box64", "fex"}
        }
        if receipt["capture_host"].get("os") != "Linux" \
                or receipt["capture_host"].get("architecture") != "aarch64" \
                or receipt["capture_host"].get("backend") not in allowed_backends:
            raise ObserverError("native observer host is not the reviewed capture route")
        expected_command = [
            "native-observer-launcher.exe", "--source", "MulleMeck.exe",
            "--target", "MulleMeck-scene.exe",
            "--observer", "native-observer-hook.dll",
            "--patch-receipt", "native-scene-patch.json",
            "--receipt", "native-observer-launch.json", "--cwd", ".",
            "--scene", scenario["native_scene"],
            "--observe-ms", "10000",
        ]
        if receipt["capture_command"] != expected_command:
            raise ObserverError("native observer capture command is not the reviewed persistent route")

    is_native_evidence = (
        PRODUCTION_CAPTURE_ENABLED
        and capture.capture_kind == "native" and capture.complete and not capture.wrapped
        and receipt["evidence_status"] == "native-capture"
    )
    if receipt["production_claim"] and not PRODUCTION_CAPTURE_ENABLED:
        raise ObserverError(
            "native production capture is disabled until runner attestation and frame correlation exist"
        )
    if receipt["production_claim"] and not is_native_evidence:
        raise ObserverError("production evidence requires a complete, unwrapped native capture")
    if not receipt["production_claim"] and receipt["evidence_status"] == "native-capture":
        raise ObserverError("native-capture evidence_status requires production_claim")
    if receipt["capture_kind"] == "protocol_fixture" and receipt["evidence_status"] != "fixture-only":
        raise ObserverError("protocol fixtures must remain fixture-only")
    if require_production and not receipt["production_claim"]:
        raise ObserverError("receipt does not contain production native evidence")
    return receipt, capture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    artifact = subcommands.add_parser("verify-artifact")
    artifact.add_argument("artifact", type=Path)
    artifact.add_argument("coverage_map", type=Path)
    receipt = subcommands.add_parser("verify-receipt")
    receipt.add_argument("receipt", type=Path)
    receipt.add_argument("--root", type=Path, default=ROOT)
    receipt.add_argument("--require-production", action="store_true")
    importer = subcommands.add_parser("import-hook-log")
    importer.add_argument("log", type=Path)
    importer.add_argument("coverage_map", type=Path)
    importer.add_argument("scenario", type=Path)
    importer.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "import-hook-log":
        coverage = CoverageIndex.from_path(args.coverage_map)
        args.output.write_bytes(import_hook_log(
            args.log, coverage, scenario_sha256=sha256_file(args.scenario),
        ))
        result = parse_artifact(args.output, coverage)
    elif args.command == "verify-artifact":
        result = parse_artifact(args.artifact, CoverageIndex.from_path(args.coverage_map))
    else:
        _, result = verify_receipt(args.receipt, root=args.root, require_production=args.require_production)
    print(json.dumps({
        "capture_kind": result.capture_kind, "complete": result.complete,
        "wrapped": result.wrapped, "event_count": len(result.events),
        "coverage_counts": {key: len(value) for key, value in result.coverage.items()},
    }, sort_keys=True))


if __name__ == "__main__":
    main()
