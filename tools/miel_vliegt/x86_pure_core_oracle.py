#!/usr/bin/env python3
"""Run a compact, first-divergence native/JS aircraft-property differential."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from unicorn import __version__ as unicorn_version

try:
    from tools.miel_vliegt.x86_micro_oracle import ROOT, load_json, sha256_file
    from tools.miel_vliegt.x86_property_oracle import (
        PropertyFoldOracle, case_definitions, validate_contract as validate_fold_contract,
    )
except ModuleNotFoundError:
    from x86_micro_oracle import ROOT, load_json, sha256_file
    from x86_property_oracle import (
        PropertyFoldOracle, case_definitions, validate_contract as validate_fold_contract,
    )


CONTRACT = ROOT / "content/miel_vliegt/x86_pure_core_contract.json"
RESULT_FIELDS = ("component_mask", "counted_parts", "float_bits")


class PureCoreOracleError(RuntimeError):
    pass


def sha256_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def validate_contract(root: Path = ROOT) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    contract = load_json(root / CONTRACT.relative_to(ROOT))
    fold, identity, index = validate_fold_contract(root)
    if contract.get("schema") != 1 \
            or contract.get("protocol") != "miel-vliegt-x86-pure-property-core" \
            or contract.get("source_identity") != fold["source_identity"] \
            or contract.get("native_function_index") != fold["native_function_index"] \
            or contract.get("property_fold_contract") != str(
                Path("content/miel_vliegt/x86_property_fold_contract.json")
            ):
        raise ValueError("unsupported pure-core oracle contract")
    expected_policy = {
        "emulator": "unicorn", "fixed_image_base": "0x00400000",
        "fpu_control_word": "0x027f", "unexpected_code": "FAIL",
        "unexpected_read": "FAIL", "unexpected_write": "FAIL",
        "compare": "bit_exact_float32_and_integer", "stop": "FIRST_DIVERGENCE",
    }
    if contract.get("policy") != expected_policy:
        raise ValueError("pure-core oracle policy was weakened")
    function = contract.get("function", {})
    indexed = next(
        (row for row in index["functions"] if row["address"] == function.get("address")), None
    )
    fold_function = fold["function"]
    if indexed is None or any(
        function.get(field) != indexed.get(field) for field in ("address", "end", "sha256")
    ) or function.get("native_unit") != fold_function["native_unit"] \
            or function.get("id") != fold_function["id"] \
            or function.get("effect_class") != "FUNCTIONAL_PURE" \
            or not isinstance(function.get("purity_boundary"), str):
        raise ValueError("pure-core native identity or purity boundary drifted")
    case_ids = contract.get("case_ids")
    if not isinstance(case_ids, list) or not case_ids \
            or len(case_ids) != len(set(case_ids)):
        raise ValueError("pure-core case ids must be a non-empty unique array")
    available, by_id = case_definitions(fold, root)
    by_case = {row["id"]: row for row in available}
    if not set(case_ids).issubset(by_case):
        raise ValueError("pure-core case matrix references unknown cases")
    return contract, identity, index, {
        "definitions": [by_case[case_id] for case_id in case_ids],
        "parts": by_id,
        "fold_contract": fold,
    }


def web_cases(contract: dict[str, Any], root: Path = ROOT) -> tuple[list[dict[str, Any]], dict[str, str]]:
    runner = root / contract["web"]["runner"]
    process = subprocess.run(
        ["node", str(runner)], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if process.returncode:
        raise PureCoreOracleError(f"web pure-core runner failed: {process.stderr.strip()}")
    document = json.loads(process.stdout)
    rows = document.get("cases") if document.get("schema") == 1 else None
    if not isinstance(rows, list) or [row.get("id") for row in rows] != contract["case_ids"]:
        raise PureCoreOracleError("web pure-core case coverage drifted")
    for row in rows:
        if set(row) != {"id", "part_ids", *RESULT_FIELDS} \
                or not isinstance(row["part_ids"], list) \
                or not isinstance(row["component_mask"], int) \
                or not isinstance(row["counted_parts"], int) \
                or not isinstance(row["float_bits"], list) \
                or len(row["float_bits"]) != 11:
            raise PureCoreOracleError(f"invalid web pure-core row for {row.get('id')}")
    paths = [contract["web"]["runner"], *contract["web"]["runtime_paths"]]
    return rows, {path: sha256_file(root / path) for path in paths}


def first_difference(native: dict[str, Any], web: dict[str, Any]) -> dict[str, Any] | None:
    for field in RESULT_FIELDS:
        if native[field] == web[field]:
            continue
        if field == "float_bits":
            for index, (native_bits, web_bits) in enumerate(zip(native[field], web[field])):
                if native_bits != web_bits:
                    return {
                        "field": field, "index": index,
                        "native": native_bits, "web": web_bits,
                    }
        return {"field": field, "native": native[field], "web": web[field]}
    return None


def build_receipt(executable: Path, root: Path = ROOT) -> dict[str, Any]:
    contract, identity, index, matrix = validate_contract(root)
    web, runtime_hashes = web_cases(contract, root)
    oracle = PropertyFoldOracle(executable, matrix["fold_contract"], identity, index)
    rows = []
    traces: dict[str, dict[str, Any]] = {}
    divergence = None
    for definition, candidate in zip(matrix["definitions"], web):
        native, trace = oracle.execute(definition, matrix["parts"])
        trace_id = sha256_json(trace)
        traces[trace_id] = trace
        difference = first_difference(native, candidate)
        rows.append({
            "id": definition["id"],
            "part_ids": definition["part_ids"],
            **native,
            "trace": trace_id,
            "native_proof_sha256": sha256_json({
                "input": definition, "native_result": native, "trace": trace_id,
            }),
        })
        if difference is not None:
            divergence = {
                "case_id": definition["id"],
                "part_ids": definition["part_ids"],
                **difference,
                "trace": trace_id,
            }
            break
    return {
        "schema": 1,
        "protocol": contract["protocol"],
        "executable_sha256": identity["executable"]["sha256"],
        "contract_sha256": sha256_file(root / CONTRACT.relative_to(ROOT)),
        "native_function_index_sha256": sha256_file(root / contract["native_function_index"]),
        "web_runtime_hashes": runtime_hashes,
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "differential_result": "PASS" if divergence is None else "FAIL",
        "native_parity_evidence": divergence is None,
        "first_divergence": divergence,
        "case_count": len(rows),
        "expected_case_count": len(matrix["definitions"]),
        "cases": rows,
        "trace_catalog": traces,
        "evidence_scope": [contract["function"]["id"]],
        "native_units": {contract["function"]["id"]: [contract["function"]["native_unit"]]},
    }


def verify_artifact(path: Path, root: Path = ROOT) -> dict[str, Any]:
    contract, identity, _, matrix = validate_contract(root)
    receipt = load_json(path)
    web, runtime_hashes = web_cases(contract, root)
    required = {
        "schema": 1,
        "protocol": contract["protocol"],
        "executable_sha256": identity["executable"]["sha256"],
        "contract_sha256": sha256_file(root / CONTRACT.relative_to(ROOT)),
        "native_function_index_sha256": sha256_file(root / contract["native_function_index"]),
        "web_runtime_hashes": runtime_hashes,
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "differential_result": "PASS",
        "native_parity_evidence": True,
        "first_divergence": None,
        "case_count": len(matrix["definitions"]),
        "expected_case_count": len(matrix["definitions"]),
        "evidence_scope": [contract["function"]["id"]],
        "native_units": {contract["function"]["id"]: [contract["function"]["native_unit"]]},
    }
    for key, expected in required.items():
        if receipt.get(key) != expected:
            raise ValueError(f"pure-core receipt drifted at {key}")
    rows = receipt.get("cases")
    traces = receipt.get("trace_catalog")
    if not isinstance(rows, list) or not isinstance(traces, dict) \
            or [row.get("id") for row in rows] != contract["case_ids"]:
        raise ValueError("pure-core receipt case or trace inventory drifted")
    used = set()
    for definition, row, candidate in zip(matrix["definitions"], rows, web):
        native = {field: row.get(field) for field in RESULT_FIELDS}
        if row.get("part_ids") != definition["part_ids"] \
                or any(native[field] != candidate[field] for field in RESULT_FIELDS):
            raise ValueError(f"pure-core stored differential drifted for {definition['id']}")
        trace_id = row.get("trace")
        trace = traces.get(trace_id)
        if not isinstance(trace, dict) or trace_id != sha256_json(trace) \
                or trace.get("instruction_count", 0) <= 0 \
                or row.get("native_proof_sha256") != sha256_json({
                    "input": definition, "native_result": native, "trace": trace_id,
                }):
            raise ValueError(f"pure-core native proof is incomplete for {definition['id']}")
        used.add(trace_id)
    if used != set(traces):
        raise ValueError("pure-core receipt contains unused traces")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--executable", type=Path, required=True)
    capture.add_argument("--output", type=Path, default=ROOT / "content/miel_vliegt/x86_pure_core_receipt.json")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--executable", type=Path, required=True)
    verify.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_pure_core_receipt.json")
    artifact = subparsers.add_parser("verify-artifact")
    artifact.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_pure_core_receipt.json")
    args = parser.parse_args()
    if args.command == "capture":
        receipt = build_receipt(args.executable.resolve())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
        if receipt["differential_result"] != "PASS":
            raise SystemExit(f"native/web divergence: {receipt['first_divergence']}")
    elif args.command == "verify":
        expected = verify_artifact(args.artifact.resolve())
        actual = build_receipt(args.executable.resolve())
        if actual != expected:
            raise SystemExit("pure-core native receipt drifted")
    else:
        verify_artifact(args.artifact.resolve())
    print("x86 pure property core differential OK")


if __name__ == "__main__":
    main()
