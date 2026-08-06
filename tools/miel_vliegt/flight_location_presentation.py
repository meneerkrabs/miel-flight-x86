#!/usr/bin/env python3
"""Generate the edition-local static presentation contract for flight locations.

Domain identity is joined from the dispatch, native-scene and mode-body
contracts.  Layout constants are decoded from each joined PE loader, while
tile coordinates and dimensions come from the checked asset inventory.  The
module deliberately emits typed ``UNPROVEN`` subsets instead of guessing a
background selector or custom attachment renderer.
"""

from __future__ import annotations

import argparse
import collections
import functools
import hashlib
import importlib.metadata
import json
import math
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from tools.miel_vliegt.decode_gti import decode_gti
    from tools.miel_vliegt.export_web_assets import encode_png
    from tools.miel_vliegt.extract_udsp import UdspArchive
    from tools.miel_vliegt.native_mygghanget_contract import PeImage
except ModuleNotFoundError:  # Direct script execution.
    from decode_gti import decode_gti
    from export_web_assets import encode_png
    from extract_udsp import UdspArchive
    from native_mygghanget_contract import PeImage


ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "content/miel_vliegt"
TILE_RE = re.compile(r"(?:^|/)layer(?P<layer>\d+)_(?P<row>\d+)_(?P<column>\d+)\.gti$", re.I)
PINNED_CAPSTONE_VERSION = "5.0.9"
SOURCE_FINGERPRINT_DOMAIN = b"miel-vliegt-location-source-v1\0"


@dataclass(frozen=True)
class NativeInstruction:
    address: int
    offset: int
    data: bytes
    decoded: bool


@functools.lru_cache(maxsize=2048)
def _disassemble(executable: str, address: int, payload: bytes) -> tuple[NativeInstruction, ...]:
    """Decode one indexed function and require complete instruction coverage."""
    del executable  # Cache identity only; decoded bytes remain the source of truth.
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
    except ModuleNotFoundError as error:
        raise ValueError(
            "pinned capstone decoder is required for native layout extraction"
        ) from error
    if importlib.metadata.version("capstone") != PINNED_CAPSTONE_VERSION:
        raise ValueError("native layout extraction requires pinned capstone 5.0.9")
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.skipdata = True
    instructions = [
        NativeInstruction(row.address, row.address - address, bytes(row.bytes), row.id != 0)
        for row in decoder.disasm(payload, address)
    ]
    if not instructions or instructions[0].address != address:
        raise ValueError(f"native function has no decoded entry instruction at {address:#x}")
    cursor = address
    for instruction in instructions:
        if instruction.address != cursor or not instruction.data:
            raise ValueError(f"native function instruction coverage drift at {cursor:#x}")
        cursor += len(instruction.data)
    if cursor != address + len(payload) or b"".join(row.data for row in instructions) != payload:
        raise ValueError(f"native function instruction coverage is incomplete at {address:#x}")
    return tuple(instructions)


def native_decoder_available() -> bool:
    try:
        import capstone  # noqa: F401
        return importlib.metadata.version("capstone") == PINNED_CAPSTONE_VERSION
    except (ModuleNotFoundError, importlib.metadata.PackageNotFoundError):
        return False


def _instructions(
    image: PeImage, row: dict[str, object]
) -> tuple[NativeInstruction, ...]:
    payload = _function_bytes(image, row)
    return _disassemble(str(image.path.resolve()), int(row["address"], 16), payload)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _address(value: int) -> str:
    return f"0x{value:08x}"


def _function_map(functions: dict[str, object]) -> dict[int, dict[str, object]]:
    result = {}
    for row in functions["functions"]:
        address = int(row["address"], 16)
        if address in result:
            raise ValueError(f"duplicate native function address {address:#x}")
        result[address] = row
    return result


def _function_bytes(image: PeImage, row: dict[str, object]) -> bytes:
    address = int(row["address"], 16)
    size = int(row["size"])
    if int(row["end"], 16) - address != size:
        raise ValueError(f"native function extent drift at {address:#x}")
    offset = image.address_to_offset(address)
    payload = image.data[offset:offset + size]
    if len(payload) != size or _sha256(payload) != row["sha256"]:
        raise ValueError(f"native function receipt drift at {address:#x}")
    return payload


def _receipt(image: PeImage, row: dict[str, object]) -> dict[str, object]:
    _function_bytes(image, row)
    return {
        "address": row["address"],
        "size": row["size"],
        "sha256": row["sha256"],
    }


def _direct_calls(
    instructions: Iterable[NativeInstruction], base: int
) -> list[tuple[int, int]]:
    calls = []
    for instruction in instructions:
        if not instruction.decoded or len(instruction.data) != 5 or instruction.data[0] != 0xE8:
            continue
        displacement = struct.unpack_from("<i", instruction.data, 1)[0]
        calls.append((
            instruction.offset,
            base + instruction.offset + len(instruction.data) + displacement,
        ))
    return calls


def _strings(
    image: PeImage, instructions: Iterable[NativeInstruction]
) -> set[str]:
    """Resolve only native strings reached by decoded immediate operands."""
    values = set()
    for instruction in instructions:
        if not instruction.decoded:
            continue
        data = instruction.data
        if len(data) != 5 or data[0] not in (0x68, *range(0xB8, 0xC0)):
            continue
        address = struct.unpack_from("<I", data, 1)[0]
        try:
            value = image.c_string(address)
        except ValueError:
            continue
        if value:
            values.add(value)
    return values


def _mov_immediates(
    instructions: Iterable[NativeInstruction],
) -> list[tuple[int, int, int]]:
    values = []
    for instruction in instructions:
        if not instruction.decoded:
            continue
        data = instruction.data
        if len(data) == 5 and 0xB8 <= data[0] <= 0xBF:
            values.append((
                instruction.offset,
                data[0] - 0xB8,
                struct.unpack_from("<I", data, 1)[0],
            ))
    return values


def _discover_engine(
    image: PeImage,
    probe: dict[str, object],
    bodies: dict[str, object],
    function_rows: dict[int, dict[str, object]],
) -> dict[str, object]:
    base_address = int(probe["engine"]["location_base_loader"]["address"], 16)
    try:
        base_row = function_rows[base_address]
    except KeyError as error:
        raise ValueError("location base loader is absent from native function index") from error
    base_instructions = _instructions(image, base_row)

    grid_candidates = []
    for target in {target for _, target in _direct_calls(base_instructions, base_address)}:
        row = function_rows.get(target)
        if row is None:
            continue
        instructions = _instructions(image, row)
        formats = {
            value for value in _strings(image, instructions)
            if "layer" in value.lower() and value.count("%1u") == 3
        }
        if any(value.lower().endswith(".gti") for value in formats) and any(
            not value.lower().endswith(".gti") for value in formats
        ):
            grid_candidates.append((row, formats))
    if len(grid_candidates) != 1:
        raise ValueError(f"native grid-loader instruction shape is ambiguous ({len(grid_candidates)})")
    grid_row, grid_formats = grid_candidates[0]
    grid_instructions = _instructions(image, grid_row)
    grid_strings = _strings(image, grid_instructions)
    suffixes = {value.lower() for value in grid_strings if value.startswith("\\")}
    if not any("background" in value for value in suffixes) or not any(
        "attachment" in value for value in suffixes
    ):
        raise ValueError("native grid-loader resource suffixes drifted")
    capacity_values = {
        value for _, register, value in _mov_immediates(grid_instructions)
        if register == 7 and 1 < value <= 32
    }
    coordinate_bases = {
        value for _, register, value in _mov_immediates(grid_instructions)
        if register == 6 and 0 < value <= 8
    }
    if len(capacity_values) != 1 or len(coordinate_bases) != 1:
        raise ValueError("native grid record capacity/coordinate base is ambiguous")
    layer_capacity = capacity_values.pop()
    coordinate_base = coordinate_bases.pop()

    location_renders = [
        int(row["lifecycle"]["render"], 16)
        for row in bodies["modes"]
        if row["mode_type"] == "location"
    ]
    common_render, _ = collections.Counter(location_renders).most_common(1)[0]
    common_render_row = function_rows.get(common_render)
    if common_render_row is None:
        raise ValueError("common location render is absent from native function index")
    common_render_instructions = _instructions(image, common_render_row)
    renderer_candidates = []
    for target in {
        target for _, target in _direct_calls(common_render_instructions, common_render)
    }:
        row = function_rows.get(target)
        if row is None:
            continue
        instructions = _instructions(image, row)
        repeated_steps = {
            value for value, count in collections.Counter(
                value for _, _, value in _mov_immediates(instructions)
            ).items()
            if count >= 2 and 64 <= value <= 4096 and value & (value - 1) == 0
        }
        if len(repeated_steps) == 1:
            renderer_candidates.append((row, repeated_steps.pop()))
    if len(renderer_candidates) != 1:
        raise ValueError(f"native grid-renderer instruction shape is ambiguous ({len(renderer_candidates)})")
    renderer_row, tile_step = renderer_candidates[0]

    attachment_candidates = []
    for row in function_rows.values():
        payload = _function_bytes(image, row)
        if not payload.startswith(bytes.fromhex("8b44240453565733ff8bf1")):
            continue
        instructions = _instructions(image, row)
        if any(
            instruction.decoded and instruction.data == b"\xc2\x10\x00"
            for instruction in instructions
        ):
            attachment_candidates.append(row)
    if len(attachment_candidates) != 1:
        raise ValueError(
            f"native static-attachment helper shape is ambiguous ({len(attachment_candidates)})"
        )

    return {
        "commonLocationLoader": {
            **_receipt(image, base_row),
            "evidenceStatus": "FUNCTION_BYTES_EXACT_CALL_TARGET_JOIN_EXACT",
        },
        "gridLoader": {
            **_receipt(image, grid_row),
            "evidenceStatus": "HEURISTIC_CANDIDATE_SEMANTICS_UNPROVEN",
            "candidateLayerRecordCapacity": layer_capacity,
            "candidateCoordinateBase": coordinate_base,
            "candidateTileStepPixels": tile_step,
            "formats": sorted(grid_formats),
        },
        "gridRenderer": {
            **_receipt(image, renderer_row),
            "evidenceStatus": "HEURISTIC_CANDIDATE_SEMANTICS_UNPROVEN",
            "traversal": None,
            "candidateTileStepPixels": tile_step,
        },
        "staticAttachmentHelper": {
            **_receipt(image, attachment_candidates[0]),
            "evidenceStatus": "HEURISTIC_CANDIDATE_SEMANTICS_UNPROVEN",
        },
        "_addresses": {
            "base": base_address,
            "attachment": int(attachment_candidates[0]["address"], 16),
        },
    }


def _constant_before(
    instructions: Iterable[NativeInstruction], end: int, register: int, start: int
) -> int | None:
    events: list[tuple[int, int]] = []
    lower = max(start, end - 120)
    for instruction in instructions:
        offset = instruction.offset
        data = instruction.data
        if not instruction.decoded or not lower <= offset < end:
            continue
        if len(data) == 5 and data[0] == 0xB8 + register and offset + 5 <= end:
            events.append((offset, struct.unpack_from("<I", data, 1)[0]))
        if len(data) == 2 and data[0] in (0x31, 0x33):
            self_modrm = 0xC0 | (register << 3) | register
            if data[1] == self_modrm:
                events.append((offset, 0))
    return events[-1][1] if events else None


def _constant_memory_writes(
    instructions: Iterable[NativeInstruction], start: int, end: int
) -> list[tuple[int, int, int]]:
    """Return (instruction offset, displacement, constant) for the setup block."""
    writes = []
    instruction_rows = tuple(instructions)
    for instruction in instruction_rows:
        cursor = instruction.offset
        data = instruction.data
        if not instruction.decoded or not start <= cursor < end:
            continue
        opcode = data[0]
        if opcode == 0xC7 and len(data) >= 7:
            modrm = data[1]
            mode = modrm >> 6
            if (modrm >> 3) & 7 == 0 and mode in (1, 2):
                if mode == 1 and len(data) == 7 and cursor + len(data) <= end:
                    displacement = data[2]
                    value = struct.unpack_from("<I", data, 3)[0]
                    writes.append((cursor, displacement, value))
                elif mode == 2 and len(data) == 10 and cursor + len(data) <= end:
                    displacement = struct.unpack_from("<I", data, 2)[0]
                    value = struct.unpack_from("<I", data, 6)[0]
                    writes.append((cursor, displacement, value))
        elif opcode == 0x89 and len(data) in (3, 6):
            modrm = data[1]
            mode = modrm >> 6
            source_register = (modrm >> 3) & 7
            if mode == 1 and len(data) == 3:
                displacement = data[2]
            elif mode == 2 and len(data) == 6:
                displacement = struct.unpack_from("<I", data, 2)[0]
            else:
                continue
            value = _constant_before(
                instruction_rows, cursor, source_register, start
            )
            if value is not None and cursor + len(data) <= end:
                writes.append((cursor, displacement, value))
    return writes


def _camera_pair(
    instructions: Iterable[NativeInstruction], start: int, end: int
) -> tuple[list[tuple[int, int, float]], int]:
    writes = []
    for instruction in instructions:
        data = instruction.data
        if not instruction.decoded or not start <= instruction.offset < end \
                or len(data) != 10 or data[:2] != b"\xc7\x86":
            continue
        field = struct.unpack_from("<I", data, 2)[0]
        value = struct.unpack_from("<f", data, 6)[0]
        if math.isfinite(value) and 1e-6 <= abs(value) <= 4096:
            writes.append((field, instruction.offset, value))
    negative = [write for write in writes if write[2] < 0]
    positive = [write for write in writes if write[2] > 0]
    pairs = [
        (left, right)
        for left in negative
        for right in positive
        if abs(left[1] - right[1]) <= 32
    ]
    if pairs:
        widest = max(abs(left[1] - right[1]) for left, right in pairs)
        pairs = [pair for pair in pairs if abs(pair[0][1] - pair[1][1]) == widest]
    if len(pairs) != 1:
        raise ValueError(f"native camera-bound instruction shape is ambiguous ({len(pairs)})")
    pair = sorted(pairs[0], key=lambda write: write[2])
    return pair, min(write[1] for write in pair)


def _push_value(groups: tuple[bytes | None, bytes | None]) -> int:
    short, long = groups
    if short is not None:
        return struct.unpack("<b", short)[0]
    assert long is not None
    return struct.unpack("<I", long)[0]


PUSH = rb"(?:\x6a(.)|\x68(.{4}))"
ANCHOR_RE = re.compile(
    PUSH + PUSH + rb"\x8b\xce(?:\xc7\x80\xbc\x01\x00\x00\x00\x00\x80\x3f)?\xe8(.{4})",
    re.S,
)


def _anchor(
    image: PeImage,
    function_rows: dict[int, dict[str, object]],
    payload: bytes,
    instructions: Iterable[NativeInstruction],
    base: int,
    after: int,
    layer_capacity: int,
) -> tuple[dict[str, int], int, int]:
    matches = []
    boundaries = {
        instruction.offset for instruction in instructions if instruction.decoded
    }
    boundaries.add(len(payload))
    for match in ANCHOR_RE.finditer(payload, after):
        if match.start() not in boundaries or match.end() not in boundaries \
                or match.end() - 5 not in boundaries:
            continue
        screen_y = _push_value((match.group(1), match.group(2)))
        layer = _push_value((match.group(3), match.group(4)))
        if 1 <= layer <= layer_capacity and -4096 <= screen_y <= 4096:
            displacement = struct.unpack("<i", match.group(5))[0]
            target = base + match.end() + displacement
            target_row = function_rows.get(target)
            if target_row is None:
                continue
            target_instructions = _instructions(image, target_row)
            returns = {
                instruction.data for instruction in target_instructions
                if instruction.decoded and instruction.data[:1] == b"\xc2"
            }
            if b"\xc2\x08\x00" in returns and b"\xc2\x0c\x00" not in returns:
                matches.append(({"nativeLayerOrdinal": layer, "screenY": screen_y}, target, match.start()))
    if len(matches) != 1:
        raise ValueError(f"native render anchor shape is ambiguous ({len(matches)})")
    return matches[0]


def _decode_push(
    instructions: dict[int, NativeInstruction], offset: int
) -> tuple[int, int] | None:
    instruction = instructions.get(offset)
    if instruction is None or not instruction.decoded:
        return None
    data = instruction.data
    if len(data) == 2 and data[0] == 0x6A:
        return struct.unpack_from("<b", data, 1)[0], offset + len(data)
    if len(data) == 5 and data[0] == 0x68:
        return struct.unpack_from("<I", data, 1)[0], offset + len(data)
    return None


def _static_attachment_placements(
    image: PeImage,
    instructions: Iterable[NativeInstruction],
    base: int,
    helper: int,
) -> list[dict[str, object]]:
    placements = []
    by_offset = {instruction.offset: instruction for instruction in instructions}

    def skip_state_writes(cursor: int, limit: int) -> int:
        while cursor < limit:
            instruction = by_offset.get(cursor)
            if instruction is None or not instruction.decoded:
                break
            data = instruction.data
            if data[:2] == b"\xc6\x86" and len(data) == 7 and cursor + 7 <= limit:
                cursor += len(data)
                continue
            if data[:2] == b"\x89\x86" and len(data) == 6 and cursor + 6 <= limit:
                cursor += len(data)
                continue
            if data[:2] == b"\xd9\x9e" and len(data) == 6 and cursor + 6 <= limit:
                cursor += len(data)
                continue
            break
        return cursor

    for call_offset, target in _direct_calls(by_offset.values(), base):
        if target != helper:
            continue
        decoded = None
        for start in sorted(
            offset for offset in by_offset if max(0, call_offset - 40) <= offset < call_offset
        ):
            cursor = start
            values = []
            for _ in range(4):
                item = _decode_push(by_offset, cursor)
                if item is None:
                    break
                value, cursor = item
                values.append(value)
                cursor = skip_state_writes(cursor, call_offset)
            if len(values) == 4 and cursor == call_offset:
                decoded = values
                break
        if decoded is None:
            raise ValueError(f"static attachment placement arguments are ambiguous at {base + call_offset:#x}")
        y, x, layer, name_address = decoded
        try:
            name = image.c_string(name_address)
        except ValueError as error:
            raise ValueError("static attachment selector is not a native string") from error
        placements.append({
            "name": name,
            "nativeLayerOrdinal": layer,
            "x": x,
            "y": y,
            "callAddress": _address(base + call_offset),
        })
    return placements


def _tile_topology(tiles: list[dict[str, object]]) -> str:
    rows: dict[int, list[int]] = collections.defaultdict(list)
    for tile in tiles:
        rows[tile["row"]].append(tile["column"])
    if sorted(rows) != list(range(1, max(rows) + 1)):
        return "SPARSE_EXACT"
    if any(sorted(columns) != list(range(min(columns), max(columns) + 1)) for columns in rows.values()):
        return "SPARSE_EXACT"
    if any(min(columns) != 1 for columns in rows.values()):
        return "SPARSE_EXACT"
    maxima = {max(columns) for columns in rows.values()}
    return "RECTANGULAR_CONTIGUOUS" if len(maxima) == 1 else "ROW_CONTIGUOUS_EXACT"


def _compact_asset(image: dict[str, object]) -> dict[str, object]:
    return {
        key: image[key]
        for key in ("key", "url", "source", "sourceSha256", "outputSha256", "width", "height", "format")
    }


def _path_key(value: str) -> str:
    return value.replace("\\", "/").strip("/").lower()


def _png_dimensions(payload: bytes) -> tuple[int, int]:
    if len(payload) < 24 or payload[:8] != b"\x89PNG\r\n\x1a\n" \
            or payload[12:16] != b"IHDR":
        raise ValueError("exported location image is not a PNG with an IHDR")
    return struct.unpack_from(">II", payload, 16)


def _validate_asset_payload(
    image: dict[str, object], source_payload: bytes, output_payload: bytes
) -> None:
    if _sha256(source_payload) != image.get("sourceSha256"):
        raise ValueError(f"location source asset receipt drift: {image.get('source')}")
    decoded = decode_gti(source_payload)
    if (
        type(image.get("width")) is not int
        or type(image.get("height")) is not int
        or type(image.get("format")) is not str
    ):
        raise ValueError(f"location source asset metadata type drift: {image.get('source')}")
    expected = (image.get("width"), image.get("height"), image.get("format"))
    actual = (decoded.width, decoded.height, decoded.format_name)
    if actual != expected:
        raise ValueError(f"location source asset dimensions/format drift: {image.get('source')}")
    if _sha256(output_payload) != image.get("outputSha256"):
        raise ValueError(f"location output asset receipt drift: {image.get('url')}")
    if _png_dimensions(output_payload) != (decoded.width, decoded.height):
        raise ValueError(f"location output asset dimensions drift: {image.get('url')}")
    if output_payload != encode_png(decoded):
        raise ValueError(f"location output asset pixel content drift: {image.get('url')}")


@functools.lru_cache(maxsize=8)
def _archive(path: str) -> UdspArchive:
    return UdspArchive(Path(path))


@functools.lru_cache(maxsize=8)
def _file_sha(path: str) -> str:
    return _sha256(Path(path).read_bytes())


def _source_fingerprint(executable_sha256: str, data_archive_sha256: str) -> str:
    """Return the authoritative edition identity derived only from supplied bytes."""
    for label, value in (
        ("executable", executable_sha256),
        ("data archive", data_archive_sha256),
    ):
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"invalid {label} source hash")
    return _sha256(
        SOURCE_FINGERPRINT_DOMAIN
        + bytes.fromhex(executable_sha256)
        + bytes.fromhex(data_archive_sha256)
    )


class LocationAssetEvidence:
    """Actual edition archive and exported PNG evidence for location assets."""

    def __init__(self, archive_path: Path, output_root: Path, assets: dict[str, object]):
        self.archive_path = Path(archive_path).resolve()
        self.output_root = Path(output_root).resolve()
        if not self.archive_path.is_file() or not self.output_root.is_dir():
            raise ValueError("location asset evidence paths are unavailable")
        source = assets.get("sources", {}).get("data", {})
        if (
            source.get("kind") != "udsp-archive"
            or source.get("archive") != self.archive_path.name
            or source.get("sha256") != _file_sha(str(self.archive_path))
        ):
            raise ValueError("location asset archive source identity drift")
        archive = _archive(str(self.archive_path))
        if source.get("file_count") != len(archive.files):
            raise ValueError("location asset archive file-count drift")
        self.entries = {}
        for entry in archive.files:
            key = _path_key(entry.path)
            if key in self.entries:
                raise ValueError(f"duplicate case-insensitive archive path: {entry.path}")
            self.entries[key] = entry

    def location_sources(self, domain: str) -> set[str]:
        prefix = f"data/graphics/locations/{domain}/"
        return {
            path for path in self.entries
            if path.startswith(prefix) and path.endswith(".gti")
        }

    def validate(self, image: dict[str, object]) -> None:
        source = _path_key(image["source"])
        entry = self.entries.get(source)
        if entry is None:
            raise ValueError(f"location source asset is absent from archive: {source}")
        url = Path(image["url"])
        if url.is_absolute() or ".." in url.parts or not url.parts or url.parts[0] != "assets":
            raise ValueError(f"unsafe location output asset URL: {image['url']}")
        output = (self.output_root.joinpath(*url.parts[1:])).resolve()
        if self.output_root not in output.parents or not output.is_file():
            raise ValueError(f"location output asset is unavailable: {image['url']}")
        _validate_asset_payload(
            image,
            _archive(str(self.archive_path)).payload(entry),
            output.read_bytes(),
        )


def _validate_location_asset_closure(
    assets: dict[str, object],
    domains: set[str],
    pack_rows: dict[str, dict[str, object]],
    evidence: LocationAssetEvidence,
) -> None:
    all_records = [*assets.get("images", []), *assets.get("audio", [])]
    keys = [row.get("key") for row in all_records]
    if any(type(key) is not str or not key for key in keys) or len(keys) != len(set(keys)):
        raise ValueError("asset inventory has invalid or duplicate keys")
    known_keys = set(keys)
    records_by_key = {row["key"]: row for row in all_records}
    location_images = collections.defaultdict(list)
    for image in assets.get("images", []):
        if image.get("domainKind") == "location" and image.get("domainId") in domains:
            location_images[image["domainId"]].append(image)
    for domain in sorted(domains):
        rows = location_images.get(domain, [])
        row_keys = {row["key"] for row in rows}
        pack_keys = pack_rows[domain].get("assetKeys")
        owned_location_keys = set()
        foreign_location_keys = set()
        if isinstance(pack_keys, list):
            for key in pack_keys:
                record = records_by_key.get(key)
                if record is None or record.get("domainKind") != "location":
                    continue
                if record.get("domainId") == domain:
                    owned_location_keys.add(key)
                else:
                    foreign_location_keys.add(key)
        if (
            not isinstance(pack_keys, list)
            or any(type(key) is not str for key in pack_keys)
            or len(pack_keys) != len(set(pack_keys))
            or not set(pack_keys) <= known_keys
            or owned_location_keys != row_keys
            or foreign_location_keys
        ):
            raise ValueError(f"location asset pack closure drift for {domain}")
        sources = {_path_key(row["source"]) for row in rows}
        if len(sources) != len(rows) or sources != evidence.location_sources(domain):
            raise ValueError(f"location archive asset closure drift for {domain}")
        for image in rows:
            evidence.validate(image)


def _domain_assets(
    assets: dict[str, object],
    domain: str,
    closure_keys: set[str],
) -> dict[str, object]:
    tiles: dict[tuple[int, int, int], dict[str, object]] = {}
    backgrounds = []
    attachments = []
    for image in assets["images"]:
        if image.get("domainKind") != "location" or image.get("domainId") != domain:
            continue
        if image["key"] not in closure_keys:
            raise ValueError(f"location asset is outside checked closure: {domain} {image['key']}")
        source = image["source"].replace("\\", "/")
        tile_match = TILE_RE.search(source)
        if tile_match:
            coordinate = tuple(int(tile_match.group(name)) for name in ("layer", "row", "column"))
            if coordinate in tiles:
                raise ValueError(f"duplicate tile coordinate {domain} {coordinate}")
            if not all(value >= 1 for value in coordinate):
                raise ValueError(f"tile coordinate is invalid: {domain} {coordinate}")
            if not (0 < image["width"] and 0 < image["height"]):
                raise ValueError(f"tile dimensions are invalid: {source}")
            tiles[coordinate] = image
        elif "/background/" in source.lower():
            backgrounds.append(image)
        elif "/attachments/" in source.lower():
            attachments.append(image)
    if not tiles:
        raise ValueError(f"location {domain} has no native grid tiles")
    return {"tiles": tiles, "backgrounds": backgrounds, "attachments": attachments}


def _validate_identity(
    executable: Path,
    dispatch: dict[str, object],
    assets: dict[str, object],
    probe: dict[str, object],
    bodies: dict[str, object],
    functions: dict[str, object],
    identity: dict[str, object],
) -> str:
    executable_sha = _sha256(executable.read_bytes())
    identity_executable = identity.get("executable", {})
    if (
        identity.get("schema") != 1
        or type(identity.get("edition")) is not str
        or not identity.get("edition")
        or set(identity_executable) != {"filename", "sha256"}
    ):
        raise ValueError("edition label/executable manifest is malformed")
    if identity["executable"]["filename"] != executable.name:
        raise ValueError("edition executable filename differs from source manifest")
    expected_hashes = {
        identity["executable"]["sha256"],
        probe["source"]["executable_sha256"],
        bodies["source"]["executable_sha256"],
        functions["source"]["sha256"],
        assets["sources"]["nativeVoice"]["source"]["sha256"],
    }
    if expected_hashes != {executable_sha}:
        raise ValueError("edition executable source identity drift")
    editions = {
        identity["edition"], dispatch["edition"], assets["edition"], probe["source"]["edition"]
    }
    if len(editions) != 1:
        raise ValueError(f"edition label drift: {sorted(editions)}")
    return editions.pop()


def _unique_rows(
    rows: Iterable[dict[str, object]], key: str, label: str
) -> dict[object, dict[str, object]]:
    result = {}
    for row in rows:
        value = row.get(key)
        if value in result:
            raise ValueError(f"duplicate {label} row: {value!r}")
        result[value] = row
    return result


def build_flight_location_presentation_contract(
    executable: Path,
    *,
    data_archive: Path,
    asset_output_root: Path,
    dispatch: dict[str, object],
    assets: dict[str, object],
    probe: dict[str, object],
    bodies: dict[str, object],
    functions: dict[str, object],
    identity: dict[str, object],
    source_receipts: dict[str, object] | None = None,
) -> dict[str, object]:
    executable = Path(executable)
    edition_label = _validate_identity(
        executable, dispatch, assets, probe, bodies, functions, identity
    )
    data_archive = Path(data_archive).resolve()
    executable_sha256 = _sha256(executable.read_bytes())
    data_archive_sha256 = _file_sha(str(data_archive))
    source_fingerprint = _source_fingerprint(executable_sha256, data_archive_sha256)
    image = PeImage(executable)
    function_rows = _function_map(functions)
    engine = _discover_engine(image, probe, bodies, function_rows)
    private_addresses = engine.pop("_addresses")
    layer_capacity = engine["gridLoader"]["candidateLayerRecordCapacity"]

    bespoke = {
        row["domainId"]
        for row in dispatch["expectedAbsences"]
        if row["kind"] == "LOCATION_SCRIPT_DOMAIN"
        and row["reason"] == "BESPOKE_NATIVE_STATE_MACHINE"
    }
    if len(bespoke) != 1:
        raise ValueError("dispatch must identify exactly one bespoke native location domain")
    dispatch_rows = _unique_rows(
        (row for row in dispatch["locations"] if row["domainId"] not in bespoke),
        "domainId", "dispatch location",
    )
    probe_rows = _unique_rows(
        (row for row in probe["scenes"] if row["id"] not in bespoke),
        "id", "native-scene location",
    )
    body_rows = _unique_rows(
        (
            row for row in bodies["modes"]
            if row["mode_type"] == "location" and row["id"] not in bespoke
        ),
        "id", "mode-body location",
    )
    asset_location_domains = assets["domains"]["locations"]
    if len(asset_location_domains) != len(set(asset_location_domains)):
        raise ValueError("duplicate location domain in asset inventory")
    asset_domains = set(asset_location_domains) - bespoke
    pack_rows = {}
    for row in assets["packSections"]:
        if row["kind"] != "location" or row["domainId"] in bespoke:
            continue
        if row["domainId"] in pack_rows:
            raise ValueError(f"duplicate location pack closure for {row['domainId']}")
        pack_rows[row["domainId"]] = row
    domain_sets = [set(dispatch_rows), set(probe_rows), set(body_rows), asset_domains]
    domain_sets.append(set(pack_rows))
    if any(domains != domain_sets[0] for domains in domain_sets[1:]):
        raise ValueError(
            "non-bespoke location domain join drift: "
            + " | ".join(",".join(sorted(domains)) for domains in domain_sets)
        )
    location_ids = [row["locationId"] for row in dispatch_rows.values()]
    modes = [row["mode"] for row in dispatch_rows.values()]
    if len(location_ids) != len(set(location_ids)) or len(modes) != len(set(modes)):
        raise ValueError("duplicate location id or mode in dispatch domain join")
    evidence = LocationAssetEvidence(data_archive, asset_output_root, assets)
    _validate_location_asset_closure(
        assets, set(dispatch_rows), pack_rows, evidence
    )

    anchor_function = None
    locations = []
    for domain, dispatch_row in sorted(dispatch_rows.items(), key=lambda item: item[1]["locationId"]):
        probe_row = probe_rows[domain]
        body_row = body_rows[domain]
        if not (
            dispatch_row["locationId"] == probe_row["location_id"] == body_row["location_id"]
            and dispatch_row["mode"] == probe_row["mode"] == body_row["mode"]
        ):
            raise ValueError(f"location identity domain join drift for {domain}")
        loader_address = int(probe_row["loader"], 16)
        loader_row = function_rows.get(loader_address)
        if loader_row is None:
            raise ValueError(f"loader missing from native function index for {domain}")
        lifecycle_load = int(body_row["lifecycle"]["load"], 16)
        if not loader_address <= lifecycle_load < int(loader_row["end"], 16):
            raise ValueError(f"location loader domain join drift for {domain}")
        payload = _function_bytes(image, loader_row)
        loader_instructions = _instructions(image, loader_row)
        base_calls = [
            offset for offset, target in _direct_calls(loader_instructions, loader_address)
            if target == private_addresses["base"]
        ]
        if len(base_calls) != 1:
            raise ValueError(f"common location loader call count drift for {domain}")
        anchor, target, anchor_at = _anchor(
            image,
            function_rows,
            payload,
            loader_instructions,
            loader_address,
            base_calls[0] + 5,
            layer_capacity,
        )
        camera_writes, camera_at = _camera_pair(
            loader_instructions, base_calls[0] + 5, anchor_at
        )
        layout_writes = _constant_memory_writes(
            loader_instructions, base_calls[0] + 5, camera_at
        )
        if not layout_writes or len({field for _, field, _ in layout_writes}) != len(
            layout_writes
        ):
            raise ValueError(
                f"native candidate offset field shape is ambiguous for {domain} "
                f"({len(layout_writes)} writes)"
            )
        if [field for _, field, _ in layout_writes] != sorted(
            field for _, field, _ in layout_writes
        ):
            raise ValueError(f"native vertical-offset field order drift for {domain}")
        if anchor_function is None:
            anchor_function = target
        elif anchor_function != target:
            raise ValueError("native render-anchor helper differs between location loaders")

        domain_assets = _domain_assets(
            assets,
            domain,
            set(pack_rows[domain]["assetKeys"]),
        )
        layer_rows = []
        for ordinal in sorted({coordinate[0] for coordinate in domain_assets["tiles"]}):
            layer_tiles = []
            for (layer, row, column), asset in sorted(domain_assets["tiles"].items()):
                if layer != ordinal:
                    continue
                layer_tiles.append({
                    "row": row,
                    "column": column,
                    **_compact_asset(asset),
                })
            layer_rows.append({
                "nativeRenderOrdinal": ordinal,
                "topology": _tile_topology(layer_tiles),
                "tiles": layer_tiles,
            })

        backgrounds = sorted(domain_assets["backgrounds"], key=lambda row: row["source"].lower())
        if len(backgrounds) == 1:
            background = {
                "selectorStatus": "SINGLE_ASSET_CANDIDATE_NATIVE_SELECTOR_UNPROVEN",
                "selectedKey": None,
                "candidateKey": backgrounds[0]["key"],
                "assets": [_compact_asset(backgrounds[0])],
            }
        else:
            background = {
                "selectorStatus": "UNPROVEN_MULTI_ASSET_NATIVE_SELECTOR",
                "selectedKey": None,
                "candidateKey": None,
                "assets": [_compact_asset(row) for row in backgrounds],
            }

        placements = _static_attachment_placements(
            image, loader_instructions, loader_address, private_addresses["attachment"]
        )
        attachments = sorted(domain_assets["attachments"], key=lambda row: row["source"].lower())
        by_stem = {Path(row["source"]).stem.lower(): row for row in attachments}
        if len(by_stem) != len(attachments):
            raise ValueError(f"duplicate attachment selector stem for {domain}")
        if placements:
            names = [placement["name"].lower() for placement in placements]
            if len(names) != len(set(names)) or set(names) != set(by_stem):
                raise ValueError(f"static attachment selector/placement ambiguity for {domain}")
            attachment_contract = {
                "status": "CALLSITE_ARGUMENT_CANDIDATES_HELPER_SEMANTICS_UNPROVEN",
                "candidatePlacements": [
                    {**placement, "asset": _compact_asset(by_stem[placement["name"].lower()])}
                    for placement in placements
                ],
                "placements": [],
                "unplacedAssets": [],
            }
        elif attachments:
            attachment_contract = {
                "status": "UNPROVEN_CUSTOM_RUNTIME",
                "candidatePlacements": [],
                "placements": [],
                "unplacedAssets": [_compact_asset(row) for row in attachments],
            }
        else:
            attachment_contract = {
                "status": "ABSENT_FROM_EDITION_ASSET_CLOSURE",
                "candidatePlacements": [],
                "placements": [],
                "unplacedAssets": [],
            }

        locations.append({
            "locationId": dispatch_row["locationId"],
            "domainId": domain,
            "mode": dispatch_row["mode"],
            "layoutStatus": "NATIVE_LAYOUT_SEMANTICS_UNPROVEN",
            "loader": _receipt(image, loader_row),
            "lifecycleLoadEntry": body_row["lifecycle"]["load"],
            "candidateVerticalOffsetWrites": [
                {
                    "instructionAddress": _address(loader_address + instruction_offset),
                    "nativeField": f"0x{field:x}",
                    "candidateValueU32": value,
                }
                for instruction_offset, field, value in layout_writes
            ],
            "candidateCameraBounds": {
                "minimumF32": camera_writes[0][2],
                "maximumF32": camera_writes[1][2],
                "nativeFields": [f"0x{camera_writes[0][0]:x}", f"0x{camera_writes[1][0]:x}"],
                "status": "PROXIMITY_AND_SIGN_HEURISTIC_UNPROVEN",
            },
            "candidateRenderAnchor": {
                **anchor,
                "status": "CALLSITE_ARGUMENTS_EXACT_HELPER_SEMANTICS_UNPROVEN",
            },
            "layers": layer_rows,
            "background": background,
            "attachments": attachment_contract,
            "claimLimits": [
                "NATIVE_LAYER_OFFSET_MAPPING_UNPROVEN",
                "NATIVE_CAMERA_BOUND_SEMANTICS_UNPROVEN",
                "NATIVE_RENDER_TRAVERSAL_UNPROVEN",
                "NATIVE_BACKGROUND_SELECTION_UNPROVEN",
                "NATIVE_ATTACHMENT_HELPER_SEMANTICS_UNPROVEN",
                "PHASER_PAINTER_ORDER_UNPROVEN",
                "FRAMEBUFFER_PARITY_UNPROVEN",
            ],
        })

    if anchor_function is None or anchor_function not in function_rows:
        raise ValueError("native render-anchor helper is absent from native function index")
    engine["renderAnchor"] = {
        **_receipt(image, function_rows[anchor_function]),
        "evidenceStatus": "HEURISTIC_CANDIDATE_SEMANTICS_UNPROVEN",
    }

    return {
        "schema": 1,
        "contract": "miel-vliegt-flight-location-presentation",
        "editionLabel": edition_label,
        "editionLabelStatus": "INFORMATIONAL_METADATA_NOT_SOURCE_IDENTITY",
        "sourceFingerprint": {
            "scheme": "sha256(executable-bytes,data-archive-bytes)-v1",
            "sha256": source_fingerprint,
            "executableSha256": executable_sha256,
            "dataArchiveSha256": data_archive_sha256,
        },
        "claim": "SOURCE_FINGERPRINTED_LOCATION_ASSET_TOPOLOGY_EXACT",
        "claimLimits": [
            "INSTALL_MEDIA_ISO_AND_CAB_PROVENANCE_UNPROVEN",
            "NATIVE_LAYOUT_SEMANTICS_UNPROVEN",
            "NATIVE_RENDER_TRAVERSAL_UNPROVEN",
            "BACKGROUND_SELECTOR_UNPROVEN",
            "CUSTOM_ATTACHMENT_RUNTIME_UNPROVEN",
            "PHASER_PAINTER_ORDER_UNPROVEN",
            "FRAMEBUFFER_PARITY_UNPROVEN",
        ],
        "sources": source_receipts or {
            "executable": {
                "filename": executable.name,
                "sha256": _sha256(executable.read_bytes()),
            }
        },
        "engine": engine,
        "counts": {
            "locations": len(locations),
            "layers": sum(len(row["layers"]) for row in locations),
            "tiles": sum(len(layer["tiles"]) for row in locations for layer in row["layers"]),
        },
        "locations": locations,
    }


def generate_flight_location_presentation_contract(
    *,
    executable: Path,
    data_archive: Path,
    asset_output_root: Path,
    dispatch_path: Path,
    assets_path: Path,
    probe_path: Path,
    bodies_path: Path,
    functions_path: Path,
    identity_path: Path,
) -> dict[str, object]:
    paths = {
        "dispatch": Path(dispatch_path),
        "assets": Path(assets_path),
        "probe": Path(probe_path),
        "bodies": Path(bodies_path),
        "functions": Path(functions_path),
        "identity": Path(identity_path),
    }
    documents = {name: _load(path) for name, path in paths.items()}
    if documents["assets"]["sources"]["dispatch"]["sha256"] != _sha256(paths["dispatch"].read_bytes()):
        raise ValueError("asset contract dispatch source receipt drift")
    if documents["dispatch"]["sources"]["locations"]["sha256"] != _sha256(paths["probe"].read_bytes()):
        raise ValueError("dispatch native-scene source receipt drift")
    body_function_receipt = documents["bodies"]["source"]["artifacts"]["native_function_index"]
    if body_function_receipt["sha256"] != _sha256(paths["functions"].read_bytes()):
        raise ValueError("mode-body native-function source receipt drift")
    body_probe_receipt = documents["bodies"]["source"]["artifacts"]["native_scene_probe"]
    if body_probe_receipt["sha256"] != _sha256(paths["probe"].read_bytes()):
        raise ValueError("mode-body native-scene source receipt drift")
    receipts = {
        name: {"path": path.resolve().relative_to(ROOT).as_posix(), "sha256": _sha256(path.read_bytes())}
        for name, path in paths.items()
    }
    executable = Path(executable)
    receipts["executable"] = {"filename": executable.name, "sha256": _sha256(executable.read_bytes())}
    data_archive = Path(data_archive)
    receipts["dataArchive"] = {
        "filename": data_archive.name,
        "sha256": _file_sha(str(data_archive.resolve())),
    }
    generator = Path(__file__)
    receipts["generator"] = {
        "path": generator.resolve().relative_to(ROOT).as_posix(),
        "sha256": _sha256(generator.read_bytes()),
    }
    decoder_requirements = ROOT / "tools/parity/requirements.txt"
    if f"capstone=={PINNED_CAPSTONE_VERSION}" not in decoder_requirements.read_text(
        encoding="utf-8"
    ).splitlines():
        raise ValueError("pinned capstone requirement drift")
    receipts["decoderRequirements"] = {
        "path": decoder_requirements.relative_to(ROOT).as_posix(),
        "sha256": _sha256(decoder_requirements.read_bytes()),
    }
    return build_flight_location_presentation_contract(
        executable,
        data_archive=data_archive,
        asset_output_root=asset_output_root,
        **documents,
        source_receipts=receipts,
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--data-archive", type=Path, required=True)
    parser.add_argument("--asset-output-root", type=Path, required=True)
    parser.add_argument("--dispatch", type=Path, default=CONTENT / "scene_dispatch_contract.json")
    parser.add_argument("--assets", type=Path, default=CONTENT / "flight_scene_asset_contract.json")
    parser.add_argument("--probe", type=Path, default=CONTENT / "native_scene_probe.json")
    parser.add_argument("--bodies", type=Path, default=CONTENT / "native_mode_bodies.json")
    parser.add_argument("--functions", type=Path, default=CONTENT / "native_function_index.json")
    parser.add_argument("--identity", type=Path, default=CONTENT / "source_identity.json")
    parser.add_argument("--output", type=Path, default=CONTENT / "flight_location_presentation_contract.json")
    args = parser.parse_args(list(argv) if argv is not None else None)
    contract = generate_flight_location_presentation_contract(
        executable=args.executable,
        data_archive=args.data_archive,
        asset_output_root=args.asset_output_root,
        dispatch_path=args.dispatch,
        assets_path=args.assets,
        probe_path=args.probe,
        bodies_path=args.bodies,
        functions_path=args.functions,
        identity_path=args.identity,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
