#!/usr/bin/env python3
"""Extract the source-exact Miel Vliegt BARN camera/render contract.

The output contains no executable bytes.  It records reviewed constants and
short instruction hashes from a separately supplied, pinned Dutch executable
and Cc.dll so a binary drift fails closed instead of silently changing the web
renderer.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


EXE_SHA256 = "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"
CC_SHA256 = "c7b0599de35db339c4a3acc56987e36c7b07ebf3553fb7511bc31d18d667c70e"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


class PeImage:
    def __init__(self, path: Path, expected_sha256: str):
        self.path = path
        self.data = path.read_bytes()
        actual = _sha256(self.data)
        if actual != expected_sha256:
            raise ValueError(f"{path}: SHA-256 {actual} != pinned {expected_sha256}")
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise ValueError(f"{path}: not a PE image")
        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError(f"{path}: missing PE signature")
        section_count, optional_size = struct.unpack_from("<H12xH", self.data, pe_offset + 6)
        optional = pe_offset + 24
        if struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise ValueError(f"{path}: expected PE32 optional header")
        self.image_base = struct.unpack_from("<I", self.data, optional + 28)[0]
        table = optional + optional_size
        sections = []
        for index in range(section_count):
            offset = table + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, offset + 8
            )
            sections.append(Section(virtual_address, virtual_size, raw_offset, raw_size))
        self.sections = tuple(sections)

    def read(self, address: int, size: int) -> bytes:
        rva = address - self.image_base
        for section in self.sections:
            extent = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva and rva + size <= section.virtual_address + extent:
                offset = section.raw_offset + rva - section.virtual_address
                value = self.data[offset : offset + size]
                if len(value) != size:
                    break
                return value
        raise ValueError(f"{self.path}: address {address:#010x}+{size} is not file-backed")

    def f32(self, address: int) -> float:
        return struct.unpack("<f", self.read(address, 4))[0]

    def signature(self, address: int, size: int) -> dict[str, object]:
        return {
            "address": f"0x{address:08x}",
            "size": size,
            "sha256": _sha256(self.read(address, size)),
        }


def harvest(executable: Path, cc_dll: Path) -> dict[str, object]:
    exe = PeImage(executable, EXE_SHA256)
    cc = PeImage(cc_dll, CC_SHA256)
    table = [exe.f32(0x00455028 + index * 4) for index in range(18)]
    views = []
    for index, name in enumerate(("outside", "inside", "shelf")):
        row = table[index * 6 : index * 6 + 6]
        views.append({"id": index, "name": name, "position": row[:3], "axis_rotation": row[3:]})

    return {
        "schema": 1,
        "status": "REVIEWED_STATIC_NATIVE_CONTRACT",
        "source": {"executable_sha256": EXE_SHA256, "cc_dll_sha256": CC_SHA256},
        "camera": {
            "centre": [320.0, 240.0],
            "clipping_distance": {"near": 0.20000000298023224, "far": 100.0},
            "window_endpoints": [0.0, 0.0, 639.0, 479.0],
            "horizontal_fov_degrees": 40.0,
            "axis_rotation_order_flag": 0,
            "axis_rotation_order": ["z", "x", "y"],
            "forward_axis": "+z",
            "views": views,
        },
        "barn": {
            "record_layout": ["group_id:u32", "part_id:u32", "x:f32", "y:f32", "z:f32"],
            "record_size": 20,
            "group_normalization": {
                "outside": {"view": 0, "shelf": 0, "group": 0},
                "inside": {"view": 1, "shelf": 0, "group": 1},
                "shelf_rule": "group > 2 becomes view 2 and shelf group - 2",
            },
            "placement_semantics": "catalog lookup; skip misses; set BARN position on the part root",
            "native_catalog_misses": [0, 533, 1060, 1061, 5322, 6411, 6422, 10170],
            "all_nan_position_sentinels": [192],
        },
        "evidence": {
            "mode_barn_camera_setup": exe.signature(0x00415260, 0x63),
            "mode_barn_camera_rows": exe.signature(0x00415CCB, 0x4D),
            "mode_barn_render": exe.signature(0x00416370, 0x3D0),
            "barn_record_loader": exe.signature(0x00419C95, 0xB5),
            "barn_group_normalizer": exe.signature(0x004186D0, 0x48),
            "cc_axis_rot_constructor": cc.signature(0x1002DCF0, 0x0A),
            "cc_axis_rot_matrix": cc.signature(0x1002CF30, 0xDB),
            "cc_camera_projection": cc.signature(0x1001D7C9, 0x5A),
        },
        "policy": {
            "static_contract_is_not_pixel_evidence": True,
            "promotion_requires_native_framebuffer_differential": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("cc_dll", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(harvest(args.executable, args.cc_dll), indent=2) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True), encoded.splitlines(keepends=True),
                fromfile=str(args.output), tofile="fresh native BARN render contract",
            ))
            raise SystemExit(f"native BARN render contract drifted:\n{diff[:12000]}")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
