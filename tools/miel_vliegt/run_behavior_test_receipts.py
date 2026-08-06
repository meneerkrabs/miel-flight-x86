#!/usr/bin/env python3
"""Execute flight parity suites and write deterministic evidence receipts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from tools.miel_vliegt.behavior_evidence import build_receipts, load_json_strict
except ModuleNotFoundError:
    from behavior_evidence import build_receipts, load_json_strict


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--suites", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    suites_path = args.suites or root / "content/miel_vliegt/flight_behavior_test_suites.json"
    output = args.output or root / "content/miel_vliegt/flight_behavior_test_receipts.json"
    receipts = build_receipts(root, load_json_strict(suites_path), execute=True)
    encoded = json.dumps(receipts, indent=2) + "\n"
    if args.check:
        current = output.read_text(encoding="utf-8") if output.is_file() else ""
        if current != encoded:
            raise SystemExit("flight behavior receipts are stale; regenerate after executing their suites")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    print(f"flight behavior receipts OK: {len(receipts['receipts'])} executable suites")


if __name__ == "__main__":
    main()
