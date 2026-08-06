#!/usr/bin/env python3
"""Generate the compact runtime EXT0 attachment contract from flight CCFs."""

from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path

try:
    from tools.miel_vliegt.harvest_ccf_parts import harvest
except ModuleNotFoundError:
    from harvest_ccf_parts import harvest


def project_attachments(parts: dict[str, object]) -> dict[str, object]:
    """Project the runtime target contract from one authoritative CCF harvest."""
    return {
        "schema": 1,
        "sources": parts["sources"],
        "counts": {
            "parts": parts["counts"]["parts"],
            "attachment_targets": parts["counts"]["attachment_targets"],
            "parts_with_attachment_targets": parts["counts"]["parts_with_attachment_targets"],
        },
        "parts": [
            {
                "part_id": part["part_id"],
                "attachment_targets": part["attachment_targets"],
            }
            for part in parts["parts"]
        ],
    }


def harvest_attachments(source_root: Path) -> dict[str, object]:
    return project_attachments(harvest(source_root))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(harvest_attachments(args.source), separators=(",", ":")) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True),
                encoded.splitlines(keepends=True),
                fromfile=str(args.output),
                tofile="fresh CCF attachment harvest",
            ))
            raise SystemExit(f"CCF attachment parity contract drifted:\n{diff[:12000]}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
