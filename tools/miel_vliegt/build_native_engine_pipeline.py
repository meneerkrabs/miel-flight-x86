#!/usr/bin/env python3
"""Build the compact, fail-closed native flight-engine implementation ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
INDEX = "content/miel_vliegt/native_function_index.json"
CODE_MAP = "content/miel_vliegt/native_code_map.json"
SUBSYSTEMS = "content/miel_vliegt/native_engine_subsystems.json"
ABI_CONTRACTS = "content/miel_vliegt/native_abi_contracts.json"
IMPORT_AUDIT = "content/miel_vliegt/native_import_thunk_audit.json"
IMPORT_BOUNDARY_OUTPUT = "content/miel_vliegt/native_function_import_boundary.json"
OUTPUT = "content/miel_vliegt/native_engine_pipeline_contract.json"
BOUNDARY_OUTPUT = "content/miel_vliegt/native_function_game_behavior_boundary.json"
STAGES = ("discovered", "classified", "contract", "implemented", "differential")
GAME_BEHAVIOR_IDS = (
    "fn_0040fe30", "fn_004102d0", "fn_004102f0",
)
BOUNDARY_PROTOCOL = "miel-vliegt-native-function-boundary-evidence"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def function_id(address: str) -> str:
    return f"fn_{int(address, 16):08x}"


def _differential_passes(root: Path, row: dict[str, Any]) -> bool:
    differential = row.get("differential")
    if not isinstance(differential, dict) or set(differential) != {"contract", "receipt"}:
        return False
    contract_path = root / differential["contract"]
    receipt_path = root / differential["receipt"]
    if not contract_path.is_file() or not receipt_path.is_file():
        return False
    receipt = load_json(receipt_path)
    units = receipt.get("native_units", {})
    covered_units = {
        unit for values in units.values() if isinstance(values, list) for unit in values
    } if isinstance(units, dict) else set()
    return receipt.get("differential_result") == "PASS" \
        and receipt.get("native_parity_evidence") is True \
        and row["id"] in covered_units


def _hashed_sources(root: Path, row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError(f"{row.get('id')}: native game behavior evidence is missing")
    abi_path = evidence.get("abi_contract")
    differential = evidence.get("differential")
    implementation = evidence.get("implementation")
    tests = evidence.get("tests")
    if not isinstance(abi_path, str) or not isinstance(differential, dict) \
            or set(differential) != {"contract", "receipt"} \
            or not isinstance(implementation, list) or not implementation \
            or not isinstance(tests, list) or not tests:
        raise ValueError(f"{row['id']}: native game behavior sources are incomplete")

    def source_hash(path: Any) -> str:
        if not isinstance(path, str) or not path or not (root / path).is_file():
            raise ValueError(f"{row['id']}: native game behavior source is absent")
        return sha256_file(root / path)

    value = {
        "functionId": row["id"],
        "nativeFunctionSha256": row["pe"]["sha256"],
        "pipelineEvidenceSha256": sha256_json(evidence),
        "abiContractSha256": source_hash(abi_path),
        "differentialContractSha256": source_hash(differential["contract"]),
        "differentialReceiptSha256": source_hash(differential["receipt"]),
        "implementationHashes": {
            path: source_hash(path) for path in implementation
        },
        "testHashes": {path: source_hash(path) for path in tests},
    }
    return {**value, "sourceEvidenceSha256": sha256_json(value)}


def build_boundary_receipt(
    rows: list[dict[str, Any]], code_map: dict[str, Any], root: Path = ROOT,
) -> dict[str, Any]:
    by_id = {row["id"]: row for row in rows}
    mapped = {row["id"]: row for row in code_map.get("functions", [])}
    if set(GAME_BEHAVIOR_IDS) - set(by_id) or set(GAME_BEHAVIOR_IDS) - set(mapped):
        raise ValueError("native game behavior boundary inventory is incomplete")
    selected = [by_id[identifier] for identifier in GAME_BEHAVIOR_IDS]
    for row in selected:
        code_row = mapped[row["id"]]
        if row.get("classification", {}).get("effect_class") != "FUNCTIONAL_PURE" \
                or row.get("classification", {}).get("ownership") != "reviewed" \
                or code_row.get("ownership", {}).get("status") != "reviewed" \
                or code_row.get("ownership", {}).get("modules") != ["airplane"] \
                or row.get("stages") != {stage: "PASS" for stage in STAGES} \
                or row.get("pe", {}).get("sha256") != code_row.get("sha256"):
            raise ValueError(f"{row['id']}: native game behavior proof prerequisites differ")
    boundary_id = "boundary:game-behavior:x86-pure-airplane-core"
    claims = []
    for row in selected:
        identity = {
            "boundaryId": boundary_id,
            "disposition": "GAME_BEHAVIOR",
            "functionId": row["id"],
            "nativeFunctionSha256": row["pe"]["sha256"],
        }
        claims.append({**identity, "membershipSha256": sha256_json(identity)})
    claim_identity = [
        {"functionId": row["functionId"],
         "nativeFunctionSha256": row["nativeFunctionSha256"]}
        for row in claims
    ]
    ownership_identity = {"owner": "airplane", "claims": claim_identity}
    effect_identity = {
        "effects": ["FUNCTIONAL_PURE"],
        "claims": [
            {"functionId": row["id"], "effectClass": "FUNCTIONAL_PURE"}
            for row in selected
        ],
    }
    receipt = {
        "schema": 1,
        "protocol": BOUNDARY_PROTOCOL,
        "reviewStatus": "REVIEWED",
        "boundaryId": boundary_id,
        "disposition": "GAME_BEHAVIOR",
        "claims": claims,
        "ownershipBoundary": {
            "reviewed": True,
            "owner": "airplane",
            "boundarySha256": sha256_json(ownership_identity),
        },
        "effectBoundary": {
            "reviewed": True,
            "effects": ["FUNCTIONAL_PURE"],
            "boundarySha256": sha256_json(effect_identity),
        },
        "sourceEvidence": [_hashed_sources(root, row) for row in selected],
    }
    return {**receipt, "boundarySha256": sha256_json(receipt)}


def _encoded(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def build(
    index: dict[str, Any], code_map: dict[str, Any], subsystems: dict[str, Any],
    abi_contracts: dict[str, Any], root: Path = ROOT,
    import_audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        from tools.miel_vliegt import native_import_replacements
    except ModuleNotFoundError:  # direct script execution adds this directory only
        import native_import_replacements

    sources = {
        document["source"]["sha256"]
        for document in (index, code_map, subsystems)
    }
    if any(document.get("schema") != 1 for document in (index, code_map, subsystems)) \
            or len(sources) != 1 \
            or abi_contracts.get("schema") != 1 \
            or abi_contracts.get("source_sha256") not in sources:
        raise ValueError("native pipeline inputs target different or unsupported inventories")
    if abi_contracts.get("policy") != {
        "unknown_effects": "CONSERVATIVE_STATEFUL",
        "pure_requires": "reviewed ABI plus a fail-closed native differential receipt",
        "machine_bytes": "FORBIDDEN",
    }:
        raise ValueError("native ABI policy was weakened")

    if import_audit is None:
        import_audit = load_json(root / IMPORT_AUDIT)
    import_decisions = native_import_replacements.validate(import_audit, root)
    import_boundary = native_import_replacements.build_boundary(import_audit)
    boundary_path = root / IMPORT_BOUNDARY_OUTPUT
    if not boundary_path.is_file() or load_json(boundary_path) != import_boundary:
        raise ValueError("native import boundary receipt drifted")

    indexed = {function_id(row["address"]): row for row in index["functions"]}
    mapped = {row["id"]: row for row in code_map["functions"]}
    subsystem_rows = {row["id"]: row for row in subsystems["functions"]}
    known_subsystems = {row["id"] for row in subsystems["subsystems"]}
    if set(indexed) != set(mapped) or set(indexed) != set(subsystem_rows):
        raise ValueError("native pipeline inventories differ")

    overrides = {row.get("id"): row for row in abi_contracts.get("functions", [])}
    if None in overrides or len(overrides) != len(abi_contracts.get("functions", [])) \
            or not set(overrides).issubset(indexed):
        raise ValueError("native ABI overrides are invalid")

    rows = []
    stage_counts: Counter[str] = Counter()
    effect_counts: Counter[str] = Counter()
    for native_id in sorted(indexed):
        source = indexed[native_id]
        mapped_row = mapped[native_id]
        subsystem_row = subsystem_rows[native_id]
        override = overrides.get(native_id)
        if override is not None:
            for field in ("address", "end", "sha256"):
                if override.get(field) != source[field]:
                    raise ValueError(f"{native_id}: reviewed ABI identity drifted at {field}")
            if override.get("subsystem") not in known_subsystems:
                raise ValueError(f"{native_id}: reviewed subsystem is unknown")
            implementation = override.get("implementation")
            tests = override.get("tests")
            implemented = isinstance(implementation, list) and bool(implementation) \
                and all((root / path).is_file() for path in implementation) \
                and isinstance(tests, list) and bool(tests) \
                and all((root / path).is_file() for path in tests)
            differential = implemented and _differential_passes(root, override)
            if override.get("effect_class") == "FUNCTIONAL_PURE" and not differential:
                raise ValueError(
                    f"{native_id}: functional purity requires a passing native differential"
                )
            effect_class = override["effect_class"]
            abi = {"status": "REVIEWED", **override["abi"]}
            evidence = {
                "abi_contract": ABI_CONTRACTS,
                "implementation": implementation,
                "tests": tests,
                "differential": override["differential"],
                "effect_limit": override["effect_limit"],
            }
        else:
            implemented = differential = False
            effect_class = "CONSERVATIVE_STATEFUL"
            abi = {
                "status": "UNKNOWN",
                "calling_convention": "UNKNOWN",
                "arguments": "UNKNOWN",
                "return": "UNKNOWN",
                "stack_cleanup": "UNKNOWN",
            }
            evidence = {
                "effect_limit": "No reviewed ABI/effect contract; fail closed as stateful."
            }

        cfg_source = {
            "entry": source["address"],
            "blocks": source["basic_blocks"],
            "branches": source["branch_sites"],
        }
        stages = {
            "discovered": "PASS",
            "classified": "PASS",
            "contract": "PASS" if override else "MISSING",
            "implemented": "PASS" if implemented else "MISSING",
            "differential": "PASS" if differential else "MISSING",
        }
        seen_missing = False
        for stage in STAGES:
            if stages[stage] == "MISSING":
                seen_missing = True
            elif seen_missing:
                raise ValueError(f"{native_id}: non-monotonic native pipeline stages")
            if stages[stage] == "PASS":
                stage_counts[stage] += 1
        effect_counts[effect_class] += 1
        reachable = subsystem_row.get("reachable_subsystems") or []
        direct = subsystem_row.get("direct_subsystems") or []
        reviewed = [override["subsystem"]] if override is not None else []
        classified_subsystems = sorted(set(direct) | set(reachable) | set(reviewed)) \
            or ["unclassified"]
        rows.append({
            "id": native_id,
            "pe": {
                "address": source["address"], "end": source["end"],
                "size": source["size"], "sha256": source["sha256"],
            },
            "native_interfaces": {
                "imports": sorted(source.get("imports") or []),
                "fallback": f"native-function:{native_id}",
            },
            "cfg": {
                "basic_blocks": len(source["basic_blocks"]),
                "branch_sites": len(source["branch_sites"]),
                "unresolved_indirect_calls": len(source["unresolved_indirect_calls"]),
                "unresolved_direct_calls": len(source["unresolved_direct_calls"]),
                "sha256": sha256_json(cfg_source),
            },
            "classification": {
                "function_kind": mapped_row["kind"]["value"],
                "ownership": mapped_row["ownership"]["status"],
                "subsystems": classified_subsystems,
                "effect_class": effect_class,
            },
            "abi_ir": abi,
            "stages": stages,
            "evidence": evidence,
            "disposition": "UNKNOWN",
        })

    boundary = build_boundary_receipt(rows, code_map, root)
    boundary_reference = {
        "path": BOUNDARY_OUTPUT,
        "sha256": hashlib.sha256(_encoded(boundary)).hexdigest(),
    }
    for row in rows:
        if row["id"] in GAME_BEHAVIOR_IDS:
            row["disposition"] = "GAME_BEHAVIOR"
            row["boundary_evidence_receipt"] = boundary_reference
        import_decision = import_decisions.get(row["id"])
        if import_decision is not None:
            row["evidence"]["import_thunk_audit"] = {
                "path": IMPORT_AUDIT,
                "sha256": sha256_file(root / IMPORT_AUDIT),
                "decisionSha256": import_decision["decisionSha256"],
                "status": import_decision["status"],
                "reason": import_decision["reason"],
            }
            if import_decision["status"] == "COMPLETE":
                row["disposition"] = "IMPORT_BOUNDARY"
                row["boundary_evidence_receipt"] = {
                    "path": IMPORT_BOUNDARY_OUTPUT,
                    "sha256": sha256_file(boundary_path),
                }

    return {
        "schema": 1,
        "protocol": "miel-vliegt-native-engine-pipeline",
        "source": index["source"],
        "input_hashes": {
            path: sha256_file(root / path)
            for path in (INDEX, CODE_MAP, SUBSYSTEMS, ABI_CONTRACTS, IMPORT_AUDIT,
                         IMPORT_BOUNDARY_OUTPUT)
        },
        "policy": {
            "stage_order": list(STAGES),
            "stage_transition": "A later PASS requires every earlier stage to PASS.",
            "unknown_effects": "CONSERVATIVE_STATEFUL",
            "semantic_claims": "Only REVIEWED ABI rows with passing native differential evidence.",
            "machine_bytes": "FORBIDDEN",
            "import_thunks": "UNKNOWN unless exact import identity and a hash-bound executed release export agree.",
        },
        "summary": {
            "functions": len(rows),
            "stage_pass": {stage: stage_counts[stage] for stage in STAGES},
            "stage_debt": {stage: len(rows) - stage_counts[stage] for stage in STAGES},
            "effect_classes": dict(sorted(effect_counts.items())),
            "release_ready": stage_counts["differential"] == len(rows),
        },
        "functions": rows,
    }


def build_from_root(root: Path = ROOT) -> dict[str, Any]:
    return build(
        load_json(root / INDEX), load_json(root / CODE_MAP),
        load_json(root / SUBSYSTEMS), load_json(root / ABI_CONTRACTS), root,
        load_json(root / IMPORT_AUDIT),
    )


def build_boundary_from_root(root: Path = ROOT) -> dict[str, Any]:
    pipeline = build_from_root(root)
    return build_boundary_receipt(
        pipeline["functions"], load_json(root / CODE_MAP), root,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output or root / OUTPUT
    result = build_from_root(root)
    boundary = build_boundary_from_root(root)
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    boundary_path = root / BOUNDARY_OUTPUT
    boundary_encoded = _encoded(boundary).decode()
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != encoded:
            raise SystemExit("native engine pipeline contract drifted")
        if not boundary_path.is_file() \
                or boundary_path.read_text(encoding="utf-8") != boundary_encoded:
            raise SystemExit("native game behavior boundary receipt drifted")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
        boundary_path.parent.mkdir(parents=True, exist_ok=True)
        boundary_path.write_text(boundary_encoded, encoding="utf-8")
    print(
        "native engine pipeline OK: "
        + ", ".join(f"{stage}={result['summary']['stage_pass'][stage]}" for stage in STAGES)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
