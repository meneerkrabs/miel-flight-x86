#!/usr/bin/env python3
"""Generate stable, source-hashed UDS hangar parity contracts."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

try:
    from tools.miel_vliegt.parse_barn_iff import (
        parse_airplane,
        parse_barn,
        parse_missions,
        parse_part_catalog,
    )
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from parse_barn_iff import parse_airplane, parse_barn, parse_missions, parse_part_catalog


BARN_PATH = Path("data/Default")
SOURCE_FILES = ("Parts.dat", "airplane.dat", "barn.dat", "missions.dat")


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def harvest(source_root: Path) -> dict[str, object]:
    root = source_root / BARN_PATH
    paths = {name: root / name for name in SOURCE_FILES}
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise ValueError(f"missing UDS hangar sources: {', '.join(missing)}")

    parts = parse_part_catalog(paths["Parts.dat"])
    airplane = parse_airplane(paths["airplane.dat"])
    placements = parse_barn(paths["barn.dat"])
    missions = parse_missions(paths["missions.dat"])
    part_ids = {part.part_id for part in parts}
    unresolved_barn_ids = sorted({
        placement.part_id for placement in placements if placement.part_id not in part_ids
    })
    return {
        "schema": 1,
        "sources": {name: {"sha256": _hash(path)} for name, path in paths.items()},
        "counts": {
            "parts": len(parts),
            "airplane_links": len(airplane),
            "barn_placements": len(placements),
            "missions": len(missions),
        },
        "coverage": {
            "barn_catalog_resolved": sum(
                placement.part_id in part_ids for placement in placements
            ),
            "barn_external_or_encoded_ids": unresolved_barn_ids,
            "airplane_catalog_resolved": sum(link.part_id in part_ids for link in airplane),
        },
        "parts": [asdict(part) for part in parts],
        "default_airplane": [asdict(link) for link in airplane],
        "barn": [asdict(placement) for placement in placements],
        "missions": [asdict(mission) for mission in missions],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="root containing extracted data/")
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--check", action="store_true", help="fail when output differs from freshly harvested data"
    )
    args = parser.parse_args()
    contract = harvest(args.source)
    encoded = json.dumps(contract, indent=2) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    encoded.splitlines(keepends=True),
                    fromfile=str(args.output),
                    tofile="fresh UDS harvest",
                )
            )
            raise SystemExit(f"UDS parity contract drifted:\n{diff}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
