#!/usr/bin/env python3
"""Harvest source-backed aircraft component classes for Miel Vliegt."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

try:
    from tools.miel_vliegt.harvest_ccf_parts import harvest as harvest_parts
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from harvest_ccf_parts import harvest as harvest_parts


DEFAULT_PATH = Path("data/Default")
REQUIRED_SLOTS = (
    "engine",
    "fuel_tank",
    "fuselage",
    "left_wing",
    "right_wing",
    "nose",
    "propeller",
    "tail",
    "landing_gear",
)
MASK_SLOT_ORDER = (
    "left_wing",
    "right_wing",
    "propeller",
    "fuselage",
    "fuel_tank",
    "engine",
    "landing_gear",
    "tail",
    "nose",
)
LABEL_COMPONENTS = {
    "nose": "nose",
    "tail": "tail",
    "left wing": "left_wing",
    "right wing": "right_wing",
    "propeller": "propeller",
    "landinggear": "landing_gear",
    "fuselage": "fuselage",
    "engine": "engine",
    "fueltank": "fuel_tank",
}
TYPE_SLOTS = {
    0: ("left_wing",),
    1: ("right_wing",),
    2: ("propeller",),
    3: ("fuselage",),
    4: ("fuel_tank",),
    5: ("engine",),
    6: ("landing_gear",),
    7: ("tail",),
    8: ("nose",),
    9: ("left_wing", "right_wing"),
    13: ("propeller",),
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parse_exemplars(path: Path) -> list[dict[str, object]]:
    exemplars = []
    for line_number, line in enumerate(path.read_text(encoding="latin-1").splitlines(), 1):
        match = re.fullmatch(r"\s*(\d+)\s+#(.+?)\s*", line)
        if not match:
            raise ValueError(f"{path}:{line_number}: malformed component exemplar")
        label = match.group(2).strip()
        component = LABEL_COMPONENTS.get(label.lower())
        if component is None:
            raise ValueError(f"{path}:{line_number}: unknown component label {label!r}")
        exemplars.append({
            "part_id": int(match.group(1)),
            "source_label": label,
            "component": component,
        })
    if len(exemplars) != 9:
        raise ValueError(f"{path}: expected 9 component exemplars, found {len(exemplars)}")
    return exemplars


def classify_part(part: dict[str, object]) -> tuple[str, ...]:
    """Map the native ATCH type to the slots used by the 0x1ff gate."""
    component_type = int(part["native_properties"]["component_type"])
    slots = TYPE_SLOTS.get(component_type, ())
    if component_type == 3 and int(part["part_id"]) == 96:
        return (*slots, "nose")
    return slots


def harvest(source_root: Path, parts_contract: dict[str, object] | None = None) -> dict[str, object]:
    defaults = source_root / DEFAULT_PATH
    exemplar_path = defaults / "parts.txt"
    if not exemplar_path.is_file():
        raise ValueError(f"missing native component exemplars: {exemplar_path}")
    parts_contract = parts_contract or harvest_parts(source_root)
    exemplars = _parse_exemplars(exemplar_path)
    parts = [
        {
            "part_id": part["part_id"],
            "component_type": part["native_properties"]["component_type"],
            "slots": list(classify_part(part)),
            "fields": part["native_properties"]["fields"],
            "object": part["object"],
            "model": part["model"],
        }
        for part in parts_contract["parts"]
    ]
    by_id = {part["part_id"]: part for part in parts}
    for exemplar in exemplars:
        actual = by_id.get(exemplar["part_id"])
        if actual is None or exemplar["component"] not in actual["slots"]:
            raise ValueError(
                f"component classifier disagrees with parts.txt for {exemplar['part_id']}: "
                f"{actual and actual['slots']} does not contain {exemplar['component']}"
            )
    counts = Counter(
        slot for part in parts for slot in (part["slots"] or ["unclassified"])
    )
    return {
        "schema": 1,
        "sources": {
            "parts.txt": {"sha256": _sha256(exemplar_path)},
            "Parts.dat": parts_contract["sources"]["Parts.dat"],
            "models": parts_contract["sources"]["models"],
        },
        "policy": {
            "required_slots": list(REQUIRED_SLOTS),
            "mask_slot_order": list(MASK_SLOT_ORDER),
            "complete_mask": "0x1ff",
            "missing_report_order": [
                "engine", "fuel_tank", "fuselage", "left_wing", "right_wing",
                "nose", "propeller", "tail", "landing_gear",
            ],
            "limit": "Presence is exact; ATCH field physics are retained but not yet all named.",
        },
        "counts": dict(sorted(counts.items())),
        "exemplars": exemplars,
        "parts": parts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="root containing extracted data/")
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(harvest(args.source), indent=2) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True), encoded.splitlines(keepends=True),
                fromfile=str(args.output), tofile="fresh component harvest",
            ))
            raise SystemExit(f"flight component parity contract drifted:\n{diff[:12000]}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
