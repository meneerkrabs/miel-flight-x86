#!/usr/bin/env python3
"""Map the native executable onto clean-room UDS/Cc engine subsystems."""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any


SUBSYSTEMS = {
    "package_io": "UDS package/file access and package registration",
    "scenegraph": "worlds, rooms, blueprints, nodes, meshes and hierarchy",
    "transform_math": "coordinates, matrices, quaternions and transforms",
    "rendering": "device, textures, images, camera, sprites, lights and fonts",
    "physics_collision": "rigid bodies, integration, constraints and collision",
    "input": "keyboard, mouse and DirectInput acquisition",
    "media": "AVI, drawing, printing and COM-backed media services",
    "platform": "Win32 process, filesystem, timing and window services",
    "compiler_runtime": "C/C++ runtime and compiler-generated support",
    "engine_core": "Cc callbacks and engine services not owned by another boundary",
}


def classify_import(symbol: str) -> str:
    dll, _, member = symbol.partition("!")
    dll_lower = dll.lower()
    if dll_lower == "udspack.dll" or "CcSetPackageList" in member:
        return "package_io"
    if dll_lower == "msvcrt.dll":
        return "compiler_runtime"
    if dll_lower == "dinput.dll":
        return "input"
    if dll_lower in {"avifil32.dll", "gdi32.dll", "winspool.drv", "ole32.dll"}:
        return "media"
    if dll_lower == "user32.dll":
        input_tokens = ("Cursor", "Key", "Mouse", "Capture", "GetAsyncKeyState")
        return "input" if any(token in member for token in input_tokens) else "platform"
    if dll_lower == "kernel32.dll":
        return "platform"
    if dll_lower != "cc.dll":
        raise ValueError(f"unclassified native import DLL: {symbol}")

    if any(token in member for token in (
        "CcRigidBody", "CcODE", "CcConstraint", "PhOBB", "PhLine",
        "PhCollidedPolyList",
    )):
        return "physics_collision"
    if any(token in member for token in (
        "CcCoord3d", "CcMatrixRot", "CcQuaternion", "CcAxisRot", "CcSRT",
        "CcPosition", "CcPosNode",
    )):
        return "transform_math"
    if any(token in member for token in (
        "Gt", "CcCamera", "CcSprite", "CcProjector", "CcShadow", "CcLight",
        "CcColor",
    )):
        return "rendering"
    if any(token in member for token in (
        "CcWorld", "CcRoom", "CcLoadedScene", "CcBlueprint", "CcSrtNode",
        "CcNull", "CcNamedSrtNode", "CcName", "CcObjPolygon", "CcMesh",
        "CcPolygon", "CcPolyVertex", "CcVertex",
    )):
        return "scenegraph"
    return "engine_core"


def _function_id(address: str) -> str:
    return f"fn_{int(address, 16):08x}"


def build(index: dict[str, Any], code_map: dict[str, Any]) -> dict[str, Any]:
    if index.get("schema") != 1 or code_map.get("schema") != 1:
        raise ValueError("unsupported native index/code-map schema")
    if index["source"]["sha256"] != code_map["source"]["sha256"]:
        raise ValueError("native index and code map target different executables")

    imports = sorted(item["symbol"] for item in index["imports"])
    import_subsystem = {symbol: classify_import(symbol) for symbol in imports}
    if set(import_subsystem.values()) - set(SUBSYSTEMS):
        raise ValueError("import classifier emitted an unknown subsystem")

    indexed_functions = {_function_id(item["address"]): item for item in index["functions"]}
    mapped_functions = {item["id"]: item for item in code_map["functions"]}
    if set(indexed_functions) != set(mapped_functions):
        raise ValueError("native function index/code-map inventories differ")

    direct: dict[str, set[str]] = {}
    calls: dict[str, tuple[str, ...]] = {}
    for function_id, function in indexed_functions.items():
        unknown = set(function["imports"]) - set(import_subsystem)
        if unknown:
            raise ValueError(f"{function_id}: imports absent from PE inventory: {sorted(unknown)}")
        direct[function_id] = {import_subsystem[symbol] for symbol in function["imports"]}
        calls[function_id] = tuple(_function_id(address) for address in function["calls"])

    # Least fixed point over direct-call edges. This is deliberately not an
    # ownership claim: it describes which engine boundaries a native function
    # can reach through the recovered direct graph.
    reachable = {function_id: set(values) for function_id, values in direct.items()}
    changed = True
    while changed:
        changed = False
        for function_id in sorted(reachable):
            expanded = set(reachable[function_id])
            for target in calls[function_id]:
                expanded.update(reachable[target])
            if expanded != reachable[function_id]:
                reachable[function_id] = expanded
                changed = True

    subsystem_rows = []
    for subsystem_id, description in SUBSYSTEMS.items():
        subsystem_rows.append({
            "id": subsystem_id,
            "description": description,
            "native_imports": [
                symbol for symbol in imports if import_subsystem[symbol] == subsystem_id
            ],
            "direct_functions": sorted(
                function_id for function_id, values in direct.items() if subsystem_id in values
            ),
            "transitive_functions": sorted(
                function_id for function_id, values in reachable.items() if subsystem_id in values
            ),
        })

    rows = []
    evidence_counts: collections.Counter[str] = collections.Counter()
    for function_id in sorted(indexed_functions):
        ownership = mapped_functions[function_id]["ownership"]["status"]
        if direct[function_id]:
            evidence = "direct_import"
        elif reachable[function_id]:
            evidence = "direct_call_closure"
        else:
            evidence = "none"
        evidence_counts[evidence] += 1
        rows.append({
            "id": function_id,
            "ownership": ownership,
            "engine_evidence": evidence,
            "direct_subsystems": sorted(direct[function_id]),
            "reachable_subsystems": sorted(reachable[function_id]),
        })

    return {
        "schema": 1,
        "source": index["source"],
        "policy": {
            "implementation_unit": "Clean-room engine subsystem, never a one-to-one machine function port.",
            "direct_call_limit": "Transitive subsystem evidence excludes unresolved virtual, callback and indirect edges.",
            "ownership_limit": "Subsystem reachability is structural evidence and does not prove gameplay ownership or equivalence.",
        },
        "summary": {
            "imports": len(imports),
            "classified_imports": len(import_subsystem),
            "subsystems": len(SUBSYSTEMS),
            "functions": len(rows),
            "function_engine_evidence": dict(sorted(evidence_counts.items())),
            "functions_without_engine_evidence": evidence_counts["none"],
            "semantic_coverage_claimed": False,
        },
        "subsystems": subsystem_rows,
        "functions": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    parser.add_argument("code_map", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = build(
        json.loads(args.index.read_text(encoding="utf-8")),
        json.loads(args.code_map.read_text(encoding="utf-8")),
    )
    encoded = json.dumps(result, separators=(",", ":")) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            raise SystemExit("native engine subsystem map drifted")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
