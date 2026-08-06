#!/usr/bin/env python3
"""Harvest the exact CCA transform-record corpus from Dutch Miel Vliegt."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import math
from pathlib import Path, PureWindowsPath
from typing import Iterable

try:
    from tools.miel_vliegt.extract_udsp import UdspArchive
    from tools.miel_vliegt.parse_cca import CcaAnimation, parse_cca
except ModuleNotFoundError:  # Direct script execution.
    from extract_udsp import UdspArchive
    from parse_cca import CcaAnimation, parse_cca


CC_TOOLS_ORACLE = {
    "repository": "https://github.com/RonnyReverse/cc-tools",
    "commit": "e34efcd858ec4475fa03d3f8668fa4e26f9e780e",
    "schema": "ksy/cc_anim.ksy",
    "schema_sha256": "22f5d78399d9164fae92bfbbfeba109caa497b1c03b7f7a071efc3fc2a7b021d",
    "role": "SECONDARY_STRUCTURAL_ORACLE",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _frame(frame) -> dict[str, list[float]]:
    return {
        "position": [frame.position.x, frame.position.y, frame.position.z],
        "orientation_wxyz": [
            frame.orientation.w,
            frame.orientation.x,
            frame.orientation.y,
            frame.orientation.z,
        ],
    }


def _animation_record(animation) -> dict[str, object]:
    positions = [[frame.position.x, frame.position.y, frame.position.z] for frame in animation.frames]
    orientations = [
        [frame.orientation.w, frame.orientation.x, frame.orientation.y, frame.orientation.z]
        for frame in animation.frames
    ]
    record: dict[str, object] = {
        "blueprint_name": animation.blueprint_name,
        "frame_payload_sha256": animation.frame_payload_sha256,
    }
    if animation.frames:
        # ``sum`` changed its floating-point accumulation algorithm between
        # supported Python versions.  ``fsum`` is deliberately used so this
        # source receipt stays byte-identical across regeneration hosts.
        norms = [math.fsum(component * component for component in orientation) for orientation in orientations]
        record["position_bounds"] = {
            "minimum": [min(position[axis] for position in positions) for axis in range(3)],
            "maximum": [max(position[axis] for position in positions) for axis in range(3)],
        }
        record["orientation_norm_squared"] = {"minimum": min(norms), "maximum": max(norms)}
        record["first_frame"] = _frame(animation.frames[0])
        record["last_frame"] = _frame(animation.frames[-1])
    return record


def _file_record(path: str, payload: bytes, parsed: CcaAnimation) -> dict[str, object]:
    if parsed.animation_count != len(parsed.animations):
        raise ValueError(f"{path}: parsed animation count disagrees with header")
    if any(len(animation.frames) != parsed.frame_count for animation in parsed.animations):
        raise ValueError(f"{path}: parsed frame count disagrees with header")
    return {
        "path": path.replace("\\", "/"),
        "sha256": _sha256(payload),
        "size": len(payload),
        "looping": parsed.looping,
        "animation_count": parsed.animation_count,
        "frame_count": parsed.frame_count,
        "frame_rate": parsed.frame_rate,
        "transform_records": parsed.animation_count * parsed.frame_count,
        "animations": [_animation_record(animation) for animation in parsed.animations],
    }


def _build_contract(
    sources: Iterable[tuple[str, bytes]], *, transport: dict[str, object]
) -> dict[str, object]:
    files = []
    for path, payload in sorted(sources, key=lambda item: item[0].casefold()):
        parsed = parse_cca(payload, source=path)
        files.append(_file_record(path, payload, parsed))
    counts = {
        "files": len(files),
        "blueprint_animations": sum(item["animation_count"] for item in files),
        "transform_records": sum(item["transform_records"] for item in files),
    }
    return {
        "schema": 1,
        "claim": "SOURCE_STRUCTURE_EXACT",
        "claim_limit": (
            "CCA header, blueprint names and stored transform records only; interpolation, "
            "coordinate application, scheduling and runtime rendering remain unproven"
        ),
        "structural_oracle": CC_TOOLS_ORACLE,
        "transport": transport,
        "counts": counts,
        "files": files,
    }


def harvest_directory(source_root: Path) -> dict[str, object]:
    paths = sorted(
        (path for path in source_root.rglob("*") if path.is_file() and path.suffix.casefold() == ".cca"),
        key=lambda path: path.relative_to(source_root).as_posix().casefold(),
    )
    sources = [(path.relative_to(source_root).as_posix(), path.read_bytes()) for path in paths]
    return _build_contract(sources, transport={"kind": "decoded_directory"})


def harvest_archive(archive_path: Path) -> dict[str, object]:
    archive = UdspArchive(archive_path)
    entries = [entry for entry in archive.files if PureWindowsPath(entry.path).suffix.casefold() == ".cca"]
    sources = [(entry.path, archive.payload(entry)) for entry in entries]
    return _build_contract(
        sources,
        transport={
            "kind": "UDSP_ARCHIVE",
            "archive": archive_path.name,
            "archive_sha256": _sha256(archive_path.read_bytes()),
            "archive_version": f"{archive.header.version_major}.{archive.header.version_minor}",
        },
    )


def harvest(source: Path) -> dict[str, object]:
    if source.is_dir():
        return harvest_directory(source)
    return harvest_archive(source)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="decoded source root or the original data.up")
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(harvest(args.source), indent=2) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    encoded.splitlines(keepends=True),
                    fromfile=str(args.output),
                    tofile="fresh CCA source harvest",
                )
            )
            raise SystemExit(f"CCA source contract drifted:\n{diff[:12000]}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
