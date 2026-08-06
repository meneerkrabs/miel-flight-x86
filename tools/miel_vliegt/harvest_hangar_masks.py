#!/usr/bin/env python3
"""Generate exact, source-hashed contracts for the UDS hangar masks."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

try:
    from tools.miel_vliegt.parse_msk import parse_mask
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from parse_msk import parse_mask


HANGAR_PATH = Path("data/Graphics/Barn")
MASKS = ("hangar_inside.msk", "hangar_outside.msk", "hangar_shelf.msk")
# Native MulleMeck.exe registers these names against the mask values at
# 0x41586b..0x415a84. Shelf rendering at 0x4164b0..0x4164e5 independently
# proves the 0..6 shelf index and the clamped up/down controls.
MASK_ACTIONS = {
    "inside": {
        0: "door",
        1: "shelf1",
        2: "shelf2",
        3: "shelf3",
        4: "shelf4",
        5: "shelf5",
        6: "shelf6",
        7: "shelf7",
        8: "camera",
        9: "background",
    },
    "outside": {
        0: "door",
        1: "camera",
        2: "album",
        3: "map",
        4: "flyaway",
        5: "radio",
        6: "background",
    },
    "shelf": {0: "door", 1: "up", 2: "down", 3: "inside", 4: "background"},
}


def harvest(source_root: Path) -> dict[str, object]:
    root = source_root / HANGAR_PATH
    paths = {name: root / name for name in MASKS}
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise ValueError(f"missing UDS hangar masks: {', '.join(missing)}")

    masks = {}
    for name, path in paths.items():
        mask = parse_mask(path)
        mask_name = name.removesuffix(".msk").removeprefix("hangar_")
        present_values = {region.value for region in mask.regions}
        if set(MASK_ACTIONS[mask_name]) != present_values:
            raise ValueError(f"{path}: executable action map does not cover mask values")
        masks[mask_name] = {
            "source": {
                "path": str(HANGAR_PATH / name),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            },
            "width": mask.width,
            "height": mask.height,
            "regions": [asdict(region) for region in mask.regions],
            "actions": {str(value): action for value, action in MASK_ACTIONS[mask_name].items()},
            "rle_base64": mask.rle_base64,
        }
    return {"schema": 1, "masks": masks}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="root containing extracted data/")
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--check", action="store_true", help="fail when the tracked contract has drifted"
    )
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
                    tofile="fresh UDS mask harvest",
                )
            )
            raise SystemExit(f"UDS hangar mask contract drifted:\n{diff}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
