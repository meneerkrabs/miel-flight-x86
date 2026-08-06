#!/usr/bin/env python3
"""Build a distributable identity receipt from private native analysis output."""

from __future__ import annotations

from typing import Any


def build(index: dict[str, Any], code_map: dict[str, Any]) -> dict[str, Any]:
    mapped = {row["address"]: row for row in code_map["functions"]}
    functions = []
    indirect_calls: list[str] = []
    indirect_branches: list[str] = []
    for function in sorted(index["functions"], key=lambda row: row["address"]):
        address = function["address"]
        owner = mapped[address]["ownership"]
        functions.append({
            "address": address,
            "end": function["end"],
            "sha256": function["sha256"],
            "ownership_status": owner["status"],
            "ownership_disposition": owner["disposition"],
        })
        indirect_calls.extend(
            site["address"] for site in function.get("unresolved_indirect_calls", [])
        )
        indirect_branches.extend(
            site["address"] for site in function.get("branch_sites", [])
            if site.get("kind") == "unresolved_switch_or_indirect_jump"
        )
    source = index.get("source", {})
    return {
        "schema": 1,
        "source_sha256": source.get("sha256"),
        "functions": functions,
        "unresolved_indirect_calls": sorted(set(indirect_calls)),
        "unresolved_indirect_branches": sorted(set(indirect_branches)),
    }
