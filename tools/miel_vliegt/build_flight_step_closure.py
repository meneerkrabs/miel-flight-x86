#!/usr/bin/env python3
"""Derive the executable and blocked boundaries around native flight.step."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.analyze_native import PeImage
except ModuleNotFoundError:
    from analyze_native import PeImage


ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "content/miel_vliegt/native_function_index.json"
IDENTITY = ROOT / "content/miel_vliegt/source_identity.json"
OUTPUT = ROOT / "content/miel_vliegt/flight_step_closure.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(index: dict[str, Any], executable: Path) -> dict[str, Any]:
    functions = {item["address"]: item for item in index["functions"]}
    step = next(item for item in index["functions"] if item.get("name") == "flight.step")
    closure_addresses: set[str] = set()
    pending = [step["address"]]
    while pending:
        address = pending.pop()
        if address in closure_addresses or address not in functions:
            continue
        closure_addresses.add(address)
        pending.extend(functions[address].get("calls", []))
    closure = [functions[address] for address in sorted(closure_addresses)]

    def closed_from(address: str, visiting: set[str] | None = None) -> bool:
        visiting = set() if visiting is None else visiting
        if address in visiting:
            return True
        function = functions[address]
        if function.get("imports") or function.get("unresolved_indirect_calls") \
                or function.get("unresolved_direct_calls"):
            return False
        return all(
            target in functions and closed_from(target, {*visiting, address})
            for target in function.get("calls", [])
        )

    closed_islands = [
        {
            "id": f"fn_{int(item['address'], 16):08x}",
            "address": item["address"],
            "end": item["end"],
            "sha256": item["sha256"],
            "relation": "direct_leaf" if item["address"] in step.get("calls", []) else "transitive_behind_boundary",
            "status": "ABI_UNREVIEWED",
        }
        for item in closure if item["address"] != step["address"] and closed_from(item["address"])
    ]
    imports = sorted({symbol for item in closure for symbol in item.get("imports", [])})

    def import_class(symbol: str) -> tuple[str, str]:
        dll, _, name = symbol.partition("!")
        if dll.lower() == "cc.dll":
            return "first_party_engine", "NATIVE_REQUIRED"
        if dll.lower() == "udspack.dll":
            return "first_party_package", "INITIALIZATION_REQUIRED"
        if name == "QueryPerformanceCounter":
            return "platform", "DETERMINISTIC_INJECTION_REQUIRED"
        if name == "rand":
            return "crt", "SEEDED_TRANSCRIPT_REQUIRED"
        return ("platform" if dll.lower().startswith(("kernel", "user", "winmm")) else "crt", "UNRESOLVED")

    image = PeImage(executable)
    max_step = struct.unpack("<f", image.bytes_at(0x0044C950, 4))[0]
    globals_rows = [
        {
            "address": address,
            "type": "f32" if address == "0x0044c950" else None,
            "role": "max_step_seconds" if address == "0x0044c950" else None,
            "value": max_step if address == "0x0044c950" else None,
            "status": "RESOLVED" if address == "0x0044c950" else "UNKNOWN",
        }
        for address in step.get("data_references", [])
    ]
    indirect = [
        {
            "site": item["address"],
            "kind": item["kind"],
            "operand": "[this.vtable+4]" if item["address"] == "0x0040e618" else None,
            "target": None,
            "abi": None,
            "state_effect": None,
        }
        for item in step["unresolved_indirect_calls"]
    ]
    return {
        "schema": 1,
        "target": {
            "id": "flight.step",
            "address": step["address"],
            "end": step["end"],
            "sha256": step["sha256"],
            "native_function_index_sha256": _sha256(INDEX),
        },
        "status": "BLOCKED_CLOSURE",
        "entry_abi": {
            "calling_convention": "thiscall",
            "arguments": ["dt_f32"],
            "this_min_size": 384,
        },
        "known_fields": [
            {"offset": 0, "type": "pointer", "role": "vtable"},
            {"offset": 376, "type": "f32", "role": "left_lift_scalar"},
            {"offset": 380, "type": "f32", "role": "right_lift_scalar"},
        ],
        "fixed_step": {
            "slice": {"address": "0x0040e631", "end": "0x0040e669"},
            "max_step_seconds": max_step,
            "max_step_bits": "0x3d23d70a",
            "status": "STATIC_ONLY",
        },
        "indirect_calls": indirect,
        "imports": [
            {"symbol": symbol, "class": import_class(symbol)[0], "policy": import_class(symbol)[1]}
            for symbol in imports
        ],
        "globals": globals_rows,
        "direct_closure": [
            {
                "id": f"fn_{int(item['address'], 16):08x}",
                "address": item["address"],
                "end": item["end"],
                "sha256": item["sha256"],
            }
            for item in closure
        ],
        "closed_islands": closed_islands,
        "blockers": {
            "unresolved_step_indirect_calls": len(indirect),
            "closure_functions": len(closure),
            "closure_import_symbols": len(imports),
            "closure_functions_with_imports": sum(bool(item.get("imports")) for item in closure),
            "closure_functions_with_indirect_calls": sum(bool(item.get("unresolved_indirect_calls")) for item in closure),
            "unknown_globals": sum(item["status"] == "UNKNOWN" for item in globals_rows),
        },
        "promotion_requirements": [
            "Resolve every reached indirect target, ABI and memory write-set",
            "Bind QueryPerformanceCounter to an explicit counter/frequency transcript",
            "Bind rand to an explicit seed and draw-order transcript",
            "Execute Cc physics through the hash-pinned first-party DLL",
            "Prove the complete flight object layout and reject unexpected reads/writes",
            "Capture taxi, takeoff, turn, landing and crash native trajectories"
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    identity = json.loads(IDENTITY.read_text())
    if _sha256(args.executable) != identity["executable"]["sha256"]:
        raise SystemExit("flight.step closure requires the pinned Dutch executable")
    document = build(json.loads(INDEX.read_text()), args.executable)
    encoded = json.dumps(document, indent=2) + "\n"
    if args.check:
        if not args.output.is_file() or args.output.read_text() != encoded:
            raise SystemExit("flight.step closure artifact drifted")
    else:
        args.output.write_text(encoded)
    print(
        "flight.step closure: "
        f"{document['blockers']['closure_functions']} functions, "
        f"{document['blockers']['unresolved_step_indirect_calls']} direct indirect sites, "
        f"status={document['status']}"
    )


if __name__ == "__main__":
    main()
