#!/usr/bin/env python3
"""Minimal fail-closed PE32 loader for pinned first-party micro-oracles."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from unicorn import UC_PROT_ALL, Uc

try:
    from tools.miel_vliegt.analyze_native import PeImage
except ModuleNotFoundError:
    from analyze_native import PeImage


PAGE = 0x1000


def align(value: int) -> int:
    return (value + PAGE - 1) & ~(PAGE - 1)


@dataclass(frozen=True)
class LoadedPe32:
    image: PeImage
    base: int
    size: int
    exports: dict[str, int]
    imports: dict[int, str]
    relocation_count: int

    @property
    def executable_ranges(self) -> tuple[tuple[int, int], ...]:
        return tuple(
            (
                self.base + section.virtual_address - self.image.image_base,
                self.base + section.virtual_address - self.image.image_base
                + max(section.virtual_size, section.raw_size),
            )
            for section in self.image.sections if section.executable
        )


def _optional_header(image: PeImage) -> int:
    pe_offset = struct.unpack_from("<I", image.data, 0x3C)[0]
    return pe_offset + 4 + 20


def image_size(image: PeImage) -> int:
    return struct.unpack_from("<I", image.data, _optional_header(image) + 56)[0]


def size_of_headers(image: PeImage) -> int:
    return struct.unpack_from("<I", image.data, _optional_header(image) + 60)[0]


def _u32_array(image: PeImage, address: int, count: int) -> tuple[int, ...]:
    return struct.unpack(f"<{count}I", image.bytes_at(address, count * 4)) if count else ()


def highlow_relocation_count(image: PeImage) -> int:
    """Count supported relocations without requiring the image to be rebased."""
    if len(image._directories) <= 5 or not image._directories[5][0]:
        return 0
    rva, size = image._directories[5]
    cursor = image.image_base + rva
    end = cursor + size
    count = 0
    while cursor < end:
        page_rva, block_size = struct.unpack("<II", image.bytes_at(cursor, 8))
        if block_size < 8 or block_size % 2 or cursor + block_size > end:
            raise ValueError("invalid PE relocation block")
        entries = struct.unpack(
            f"<{(block_size - 8) // 2}H", image.bytes_at(cursor + 8, block_size - 8)
        )
        for entry in entries:
            kind = entry >> 12
            if kind == 0:
                continue
            if kind != 3:
                raise ValueError(f"unsupported PE relocation type {kind}")
            count += 1
        cursor += block_size
    if cursor != end:
        raise ValueError("PE relocation directory has trailing bytes")
    return count


def exports(image: PeImage, actual_base: int) -> dict[str, int]:
    if not image._directories or not image._directories[0][0]:
        return {}
    rva, size = image._directories[0]
    fields = struct.unpack("<IIHHIIIIIII", image.bytes_at(image.image_base + rva, 40))
    ordinal_base, function_count, name_count = fields[5], fields[6], fields[7]
    functions_rva, names_rva, ordinals_rva = fields[8], fields[9], fields[10]
    functions = _u32_array(image, image.image_base + functions_rva, function_count)
    names = _u32_array(image, image.image_base + names_rva, name_count)
    ordinals = struct.unpack(
        f"<{name_count}H", image.bytes_at(image.image_base + ordinals_rva, name_count * 2)
    ) if name_count else ()
    result = {}
    for name_rva, ordinal_index in zip(names, ordinals):
        if ordinal_index >= len(functions):
            raise ValueError("PE export ordinal is outside the function table")
        function_rva = functions[ordinal_index]
        if rva <= function_rva < rva + size:
            raise ValueError("forwarded PE exports are not allowed in the micro-loader")
        name = image.cstring(image.image_base + name_rva)
        if name in result:
            raise ValueError(f"duplicate PE export {name}")
        result[name] = actual_base + function_rva
    _ = ordinal_base
    return result


def _relocate(machine: Uc, image: PeImage, actual_base: int) -> int:
    delta = actual_base - image.image_base
    if len(image._directories) <= 5 or not image._directories[5][0]:
        if delta:
            raise ValueError("rebased PE32 image has no relocation directory")
        return 0
    rva, size = image._directories[5]
    cursor = image.image_base + rva
    end = cursor + size
    count = 0
    while cursor < end:
        page_rva, block_size = struct.unpack("<II", image.bytes_at(cursor, 8))
        if block_size < 8 or block_size % 2 or cursor + block_size > end:
            raise ValueError("invalid PE relocation block")
        entries = struct.unpack(
            f"<{(block_size - 8) // 2}H", image.bytes_at(cursor + 8, block_size - 8)
        )
        for entry in entries:
            kind, offset = entry >> 12, entry & 0xFFF
            if kind == 0:
                continue
            if kind != 3:
                raise ValueError(f"unsupported PE relocation type {kind}")
            if delta:
                address = actual_base + page_rva + offset
                value = struct.unpack("<I", bytes(machine.mem_read(address, 4)))[0]
                machine.mem_write(address, struct.pack("<I", (value + delta) & 0xFFFFFFFF))
            count += 1
        cursor += block_size
    if cursor != end:
        raise ValueError("PE relocation directory has trailing bytes")
    return count


def map_pe32(machine: Uc, path: Path, actual_base: int, expected_sha256: str) -> LoadedPe32:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError(f"{path.name}: first-party DLL identity drifted")
    image = PeImage(path)
    size = image_size(image)
    machine.mem_map(actual_base, align(size), UC_PROT_ALL)
    machine.mem_write(actual_base, b"\0" * align(size))
    header_size = min(size_of_headers(image), len(data))
    machine.mem_write(actual_base, data[:header_size])
    for section in image.sections:
        destination = actual_base + section.virtual_address - image.image_base
        machine.mem_write(destination, data[section.raw_offset:section.raw_offset + section.raw_size])
    relocation_count = _relocate(machine, image, actual_base)
    imports = {
        actual_base + address - image.image_base: symbol
        for address, symbol in image.imports().items()
    }
    return LoadedPe32(
        image=image,
        base=actual_base,
        size=size,
        exports=exports(image, actual_base),
        imports=imports,
        relocation_count=relocation_count,
    )


def link_imports(
    machine: Uc,
    module: LoadedPe32,
    providers: dict[str, LoadedPe32],
    traps: dict[str, int],
) -> None:
    for iat, symbol in module.imports.items():
        dll, separator, name = symbol.partition("!")
        provider = providers.get(dll.lower())
        target = provider.exports.get(name) if provider is not None else None
        if target is None:
            target = traps.get(symbol)
        if target is None:
            raise ValueError(f"unresolved PE import lacks a unique trap: {symbol}")
        machine.mem_write(iat, struct.pack("<I", target))
