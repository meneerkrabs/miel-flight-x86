#!/usr/bin/env python3
"""Verify the tracked Cc API contract against the pinned Dutch DLL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from tools.miel_vliegt.harvest_cc_api_contract import (
        read_cc_exports,
        sha256_file,
        verify_primary_contract,
    )
except ModuleNotFoundError:
    from harvest_cc_api_contract import (
        read_cc_exports,
        sha256_file,
        verify_primary_contract,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cc_dll", type=Path)
    parser.add_argument(
        "contract", type=Path,
        default=Path("content/miel_vliegt/cc_api_contract.json"), nargs="?",
    )
    parser.add_argument(
        "--source-identity", type=Path,
        default=Path("content/miel_vliegt/source_identity.json"),
    )
    args = parser.parse_args()

    identity = json.loads(args.source_identity.read_text(encoding="utf-8"))
    expected = identity.get("cc_dll", {}).get("sha256")
    actual = sha256_file(args.cc_dll)
    if actual != expected:
        raise SystemExit("Cc.dll does not match the pinned Dutch source identity")
    image_base, export_map = read_cc_exports(args.cc_dll)
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    verify_primary_contract(
        contract, export_map, image_base=image_base, cc_sha256=actual,
    )
    print(
        f"Cc API contract: {len(export_map)} exports verified against "
        f"{actual[:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
