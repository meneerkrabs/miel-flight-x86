#!/usr/bin/env python3
"""Derive stable native trace coverage IDs from the pinned function index."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INDEX = ROOT / "content/miel_vliegt/native_function_index.json"
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/native_trace_coverage_map.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _address_id(prefix: str, address: str) -> str:
    return f"{prefix}_{int(address, 16):08x}"


def build_map(index_path: Path) -> dict[str, Any]:
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index.get("schema") != 1:
        raise ValueError("unsupported native function index schema")
    executable_hash = index.get("source", {}).get("sha256")
    if not isinstance(executable_hash, str) or len(executable_hash) != 64:
        raise ValueError("native function index has no executable identity")

    functions = []
    blocks = []
    block_by_start: dict[int, dict[str, Any]] = {}
    function_by_address: dict[int, str] = {}
    source_functions = sorted(index.get("functions", []), key=lambda item: int(item["address"], 16))
    for function in source_functions:
        function_id = _address_id("fn", function["address"])
        function_by_address[int(function["address"], 16)] = function_id
        functions.append({
            "id": function_id,
            "address": function["address"],
            "end": function["end"],
            "name": function.get("name"),
            "sha256": function["sha256"],
        })
        for block in function.get("basic_blocks", []):
            block_id = block["id"]
            record = {
                "id": block_id,
                "function_id": function_id,
                "start": block["start"],
                "end": block["end"],
                "size": block["size"],
                "unknown_skipdata_bytes": block["unknown_skipdata_bytes"],
            }
            blocks.append(record)
            block_by_start[int(block["start"], 16)] = record

    edges_by_id: dict[str, dict[str, Any]] = {}
    unresolved_sites = []
    for function in source_functions:
        function_id = _address_id("fn", function["address"])
        function_blocks = [
            block for block in blocks if block["function_id"] == function_id
        ]
        for site in function.get("branch_sites", []):
            site_address = int(site["address"], 16)
            source = next((
                block for block in function_blocks
                if int(block["start"], 16) <= site_address < int(block["end"], 16)
            ), None)
            if source is None:
                raise ValueError(f"branch site outside mapped blocks: {site['address']}")
            if site["kind"] == "unresolved_switch_or_indirect_jump":
                unresolved_sites.append({
                    "id": _address_id("unknown_branch", site["address"]),
                    "function_id": function_id,
                    "block_id": source["id"],
                    "address": site["address"],
                })
                continue
            targets = [(site["kind"], int(site["target"], 16))]
            if site["kind"] == "direct_conditional":
                targets.append(("conditional_fallthrough", int(source["end"], 16)))
            for kind, target_address in targets:
                target = block_by_start.get(target_address)
                if target is None:
                    # A jump outside the recovered function map remains explicit.
                    unresolved_sites.append({
                        "id": _address_id("unknown_target", site["address"]),
                        "function_id": function_id,
                        "block_id": source["id"],
                        "address": site["address"],
                        "target": f"0x{target_address:08x}",
                    })
                    continue
                edge_id = f"edge_{source['id'][3:]}_{target['id'][3:]}"
                edge = edges_by_id.setdefault(edge_id, {
                    "id": edge_id,
                    "source": source["id"],
                    "target": target["id"],
                    "kinds": [],
                })
                if kind not in edge["kinds"]:
                    edge["kinds"].append(kind)

    call_edges = []
    for function in source_functions:
        source_id = _address_id("fn", function["address"])
        for target in function.get("calls", []):
            target_id = function_by_address.get(int(target, 16))
            if target_id:
                call_edges.append({
                    "id": f"call_{source_id[3:]}_{target_id[3:]}",
                    "source": source_id,
                    "target": target_id,
                })

    result = {
        "schema": 1,
        "source": {
            "executable_sha256": executable_hash,
            "function_index": str(index_path.relative_to(ROOT)),
            "function_index_sha256": _sha256(index_path),
            "image_base": index["source"]["image_base"],
        },
        "id_contract": {
            "function": "fn_<8 lowercase hex VA>",
            "basic_block": "bb_<8 lowercase hex VA>",
            "edge": "edge_<source VA>_<target VA>",
            "call": "call_<source function VA>_<target function VA>",
        },
        "counts": {
            "functions": len(functions),
            "basic_blocks": len(blocks),
            "edges": len(edges_by_id),
            "call_edges": len(call_edges),
            "unresolved_branch_sites": len(unresolved_sites),
        },
        "functions": functions,
        "basic_blocks": sorted(blocks, key=lambda item: item["id"]),
        "edges": sorted(edges_by_id.values(), key=lambda item: item["id"]),
        "call_edges": sorted(call_edges, key=lambda item: item["id"]),
        "unresolved_branch_sites": sorted(unresolved_sites, key=lambda item: item["id"]),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=DEFAULT_INDEX)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = build_map(args.index.resolve())
    encoded = json.dumps(result, indent=2, sort_keys=False) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            raise SystemExit("native trace coverage map drifted")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
