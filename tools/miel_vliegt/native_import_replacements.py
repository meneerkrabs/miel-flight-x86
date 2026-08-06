#!/usr/bin/env python3
"""Audit native import thunks against release-reachable web replacements.

An import name is discovery evidence, not equivalence.  A COMPLETE decision is
therefore accepted only when a policy entry binds the exact native function,
the replacement module/export and a fresh executable release receipt.  The
checked-in policy currently promotes no thunk: browser-adjacent AVI, printer,
input, texture conversion and CRT code is not an exact replacement by itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
INDEX = "content/miel_vliegt/native_function_index.json"
CODE_MAP = "content/miel_vliegt/native_code_map.json"
POLICY = "tools/miel_vliegt/native_import_replacements.json"
RELEASE_BUILD = "webpack.common.js"
OUTPUT = "content/miel_vliegt/native_import_thunk_audit.json"
BOUNDARY_OUTPUT = "content/miel_vliegt/native_function_import_boundary.json"
PROTOCOL = "miel-vliegt-native-import-thunk-audit"
EXECUTION_PROTOCOL = "miel-vliegt-native-import-replacement-execution"
BOUNDARY_PROTOCOL = "miel-vliegt-native-function-boundary-evidence"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def function_id(address: str) -> str:
    return f"fn_{int(address, 16):08x}"


def native_interfaces(identifier: str, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "imports": sorted(source.get("imports") or []),
        "fallback": f"native-function:{identifier}",
    }


def _reason(native_import: str) -> tuple[str, str]:
    library = native_import.split("!", 1)[0].upper()
    if library == "AVIFIL32.DLL":
        return "media", "NO_EXACT_RELEASE_REACHABLE_AVI_SERVICE"
    if library == "WINSPOOL.DRV":
        return "printing", "NO_RELEASE_PRINTER_SERVICE"
    if library == "DINPUT.DLL":
        return "input", "WEB_INPUT_IS_NOT_DIRECTINPUT_FACTORY_EQUIVALENCE"
    if library == "CC.DLL":
        return "rendering", "OFFLINE_TEXTURE_DECODE_IS_NOT_RUNTIME_GTCONVERT_EQUIVALENCE"
    return "compiler_runtime", "NO_EXACT_RELEASE_REACHABLE_CRT_SERVICE"


def _safe_file(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} path is absent")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the repository") from error
    if not path.is_file():
        raise ValueError(f"{label} is absent: {relative}")
    return path


def _exports(source: str, name: str) -> bool:
    escaped = re.escape(name)
    patterns = (
        rf"\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+{escaped}\b",
        rf"\bexport\s*\{{[^}}]*\b{escaped}\b[^}}]*\}}",
    )
    return any(re.search(pattern, source, re.MULTILINE) for pattern in patterns)


def _entrypoint_imports(
    entrypoint: Path, module: Path, export_name: str,
) -> bool:
    source = entrypoint.read_text(encoding="utf-8")
    for clause, specifier in re.findall(
        r"\bimport\s+(.+?)\s+from\s+['\"]([^'\"]+)['\"]", source,
        re.MULTILINE,
    ):
        if not specifier.startswith(".") or not re.search(
            rf"\b{re.escape(export_name)}\b", clause,
        ):
            continue
        candidate = (entrypoint.parent / specifier).resolve()
        if candidate == module or candidate.with_suffix(".js") == module:
            return True
    return False


def _release_entrypoint(root: Path) -> str:
    build = _safe_file(root, RELEASE_BUILD, "release build configuration")
    source = build.read_text(encoding="utf-8")
    match = re.search(r"\bentry\s*:\s*['\"]([^'\"]+)['\"]", source)
    if match is None:
        raise ValueError("release build entrypoint is not a static path")
    return match.group(1).removeprefix("./")


def _complete_replacement(
    identifier: str, interfaces: dict[str, Any], spec: Any, root: Path,
) -> dict[str, Any]:
    required = {
        "nativeInterfaces", "replacementOwner", "replacementModule",
        "replacementExport", "productionEntrypoint", "executionReceipt",
    }
    if not isinstance(spec, dict) or set(spec) != required:
        raise ValueError(f"{identifier}: replacement policy fields differ")
    if spec["nativeInterfaces"] != interfaces:
        raise ValueError(f"{identifier}: replacement native interface drifted")
    for field in ("replacementOwner", "replacementExport"):
        if not isinstance(spec[field], str) or not spec[field]:
            raise ValueError(f"{identifier}: {field} is absent")

    module = _safe_file(root, spec["replacementModule"], "replacement module")
    if spec["productionEntrypoint"] != _release_entrypoint(root):
        raise ValueError(f"{identifier}: production entrypoint is not the release build entry")
    entrypoint = _safe_file(root, spec["productionEntrypoint"], "production entrypoint")
    receipt_path = _safe_file(root, spec["executionReceipt"], "execution receipt")
    module_source = module.read_text(encoding="utf-8")
    if not _exports(module_source, spec["replacementExport"]):
        raise ValueError(f"{identifier}: replacement export is absent")
    if not _entrypoint_imports(entrypoint, module, spec["replacementExport"]):
        raise ValueError(f"{identifier}: production entrypoint does not import replacement export")

    receipt = load_json(receipt_path)
    expected = {
        "schema", "protocol", "status", "functionId", "nativeInterfaces",
        "replacementModule", "replacementExport", "replacementSourceSha256",
        "productionEntrypoint", "productionEntrypointSha256",
    }
    if set(receipt) != expected or receipt.get("schema") != 1 \
            or receipt.get("protocol") != EXECUTION_PROTOCOL \
            or receipt.get("status") != "PASS" \
            or receipt.get("functionId") != identifier \
            or receipt.get("nativeInterfaces") != interfaces \
            or receipt.get("replacementModule") != spec["replacementModule"] \
            or receipt.get("replacementExport") != spec["replacementExport"] \
            or receipt.get("replacementSourceSha256") != sha256_file(module) \
            or receipt.get("productionEntrypoint") != spec["productionEntrypoint"] \
            or receipt.get("productionEntrypointSha256") != sha256_file(entrypoint):
        raise ValueError(f"{identifier}: executable release receipt differs")

    return {
        "replacementOwner": spec["replacementOwner"],
        "replacementModule": spec["replacementModule"],
        "replacementExport": spec["replacementExport"],
        "replacementSourceSha256": sha256_file(module),
        "productionEntrypoint": spec["productionEntrypoint"],
        "productionEntrypointSha256": sha256_file(entrypoint),
        "executionReceipt": {
            "path": spec["executionReceipt"],
            "sha256": sha256_file(receipt_path),
        },
    }


def build(
    index: dict[str, Any], code_map: dict[str, Any], policy: dict[str, Any],
    root: Path = ROOT,
) -> dict[str, Any]:
    if index.get("schema") != 1 or code_map.get("schema") != 1 \
            or index.get("source") != code_map.get("source"):
        raise ValueError("native import audit inventories differ")
    if policy.get("schema") != 1 \
            or policy.get("protocol") != "miel-vliegt-native-import-replacement-policy" \
            or set(policy) != {"schema", "protocol", "replacements"} \
            or not isinstance(policy["replacements"], dict):
        raise ValueError("native import replacement policy is invalid")

    indexed = {function_id(row["address"]): row for row in index["functions"]}
    mapped = {row["id"]: row for row in code_map["functions"]}
    candidates = {
        identifier: row for identifier, row in mapped.items()
        if row.get("kind", {}).get("value") == "import_thunk"
        and row.get("kind", {}).get("confidence") == "high"
    }
    if not candidates or set(policy["replacements"]) - set(candidates):
        raise ValueError("replacement policy names a non-audited import thunk")

    decisions = []
    for identifier in sorted(candidates):
        source = indexed.get(identifier)
        mapped_row = candidates[identifier]
        if source is None or source.get("sha256") != mapped_row.get("sha256") \
                or source.get("address") != mapped_row.get("address") \
                or len(source.get("imports") or []) != 1:
            raise ValueError(f"{identifier}: import thunk identity is not exact")
        interfaces = native_interfaces(identifier, source)
        native_import = interfaces["imports"][0]
        identity = {
            "functionId": identifier,
            "nativeFunctionSha256": source["sha256"],
            "nativeInterfaces": interfaces,
        }
        spec = policy["replacements"].get(identifier)
        if spec is None:
            subsystem, reason = _reason(native_import)
            decision = {
                **identity,
                "status": "UNKNOWN",
                "disposition": "UNKNOWN",
                "subsystem": subsystem,
                "reason": reason,
                "replacement": None,
            }
        else:
            replacement = _complete_replacement(identifier, interfaces, spec, root)
            decision = {
                **identity,
                "status": "COMPLETE",
                "disposition": "IMPORT_BOUNDARY",
                "subsystem": _reason(native_import)[0],
                "reason": "HASH_BOUND_RELEASE_REPLACEMENT_EXECUTED",
                "replacement": replacement,
            }
        decisions.append({**decision, "decisionSha256": hashlib.sha256(canonical(decision)).hexdigest()})

    counts = Counter(row["status"] for row in decisions)
    result = {
        "schema": 1,
        "protocol": PROTOCOL,
        "source": index["source"],
        "inputHashes": {
            INDEX: sha256_file(root / INDEX),
            CODE_MAP: sha256_file(root / CODE_MAP),
            POLICY: sha256_file(root / POLICY),
            RELEASE_BUILD: sha256_file(root / RELEASE_BUILD),
        },
        "policy": {
            "candidate": "HIGH_CONFIDENCE_IMPORT_THUNK_WITH_ONE_EXACT_IMPORT",
            "promotion": "EXACT_NATIVE_INTERFACE_AND_HASH_BOUND_EXECUTED_RELEASE_EXPORT",
            "similarBrowserConcept": "INSUFFICIENT",
            "missingReplacement": "UNKNOWN",
        },
        "summary": {
            "audited": len(decisions),
            "complete": counts["COMPLETE"],
            "unknown": counts["UNKNOWN"],
        },
        "decisions": decisions,
    }
    return {**result, "receiptSha256": hashlib.sha256(canonical(result)).hexdigest()}


def build_from_root(root: Path = ROOT) -> dict[str, Any]:
    return build(
        load_json(root / INDEX), load_json(root / CODE_MAP),
        load_json(root / POLICY), root,
    )


def validate(audit: dict[str, Any], root: Path = ROOT) -> dict[str, dict[str, Any]]:
    expected = build_from_root(root)
    if audit != expected:
        raise ValueError("native import thunk audit drifted")
    return {row["functionId"]: row for row in audit["decisions"]}


def build_boundary(audit: dict[str, Any]) -> dict[str, Any]:
    """Project COMPLETE audit decisions into the generic completion receipt."""
    boundary_id = "boundary:import-boundary:release-reachable-web-replacements"
    complete = [row for row in audit["decisions"] if row["status"] == "COMPLETE"]
    claims = []
    mappings = []
    for row in complete:
        identity = {
            "boundaryId": boundary_id,
            "disposition": "IMPORT_BOUNDARY",
            "functionId": row["functionId"],
            "nativeFunctionSha256": row["nativeFunctionSha256"],
        }
        claims.append({
            **identity,
            "membershipSha256": hashlib.sha256(canonical(identity)).hexdigest(),
        })
        replacement = row["replacement"]
        mappings.append({
            "functionId": row["functionId"],
            "nativeInterfaces": row["nativeInterfaces"]["imports"] or [
                row["nativeInterfaces"]["fallback"]
            ],
            "replacementOwner": replacement["replacementOwner"],
            "replacementModule": replacement["replacementModule"],
            "replacementExport": replacement["replacementExport"],
            "replacementSourceSha256": replacement["replacementSourceSha256"],
        })
    value = {
        "schema": 1,
        "protocol": BOUNDARY_PROTOCOL,
        "reviewStatus": "REVIEWED",
        "boundaryId": boundary_id,
        "disposition": "IMPORT_BOUNDARY",
        "claims": claims,
        "apiImportMapping": mappings,
    }
    return {**value, "boundarySha256": hashlib.sha256(canonical(value)).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output or root / OUTPUT
    result = build_from_root(root)
    boundary = build_boundary(result)
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    boundary_encoded = json.dumps(boundary, sort_keys=True, separators=(",", ":")) + "\n"
    boundary_path = root / BOUNDARY_OUTPUT
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != encoded:
            raise SystemExit("native import thunk audit drifted")
        if not boundary_path.is_file() \
                or boundary_path.read_text(encoding="utf-8") != boundary_encoded:
            raise SystemExit("native import boundary receipt drifted")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
        boundary_path.parent.mkdir(parents=True, exist_ok=True)
        boundary_path.write_text(boundary_encoded, encoding="utf-8")
    print(
        f"native import thunk audit OK: audited={result['summary']['audited']}, "
        f"complete={result['summary']['complete']}, unknown={result['summary']['unknown']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
