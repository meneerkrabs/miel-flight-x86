#!/usr/bin/env python3
"""Validate behavior contracts, derived evidence and executable receipts."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.behavior_evidence import build_receipts, load_json_strict
    from tools.miel_vliegt.x86_micro_oracle import verify_artifact as verify_x86_micro_oracle
    from tools.miel_vliegt.x86_property_oracle import verify_artifact as verify_x86_property_oracle
    from tools.miel_vliegt.x86_drop_oracle import verify_artifact as verify_x86_drop_oracle
except ModuleNotFoundError:
    from behavior_evidence import build_receipts, load_json_strict
    from x86_micro_oracle import verify_artifact as verify_x86_micro_oracle
    from x86_property_oracle import verify_artifact as verify_x86_property_oracle
    from x86_drop_oracle import verify_artifact as verify_x86_drop_oracle


DISPOSITIONS = {"REQUIRED", "PLATFORM_SUBSTITUTION", "DESCOPED"}
BEHAVIOR_CLASSES = {"pure", "state_transition", "integrator", "render", "audio"}
EVIDENCE_VALUES = {
    "source": {"UNMAPPED", "PINNED"},
    "native_behavior": {"UNMAPPED", "PINNED", "CONTRACTED"},
    "reachability": {"UNPROVEN", "STATIC", "DYNAMIC"},
    "runtime": {"MISSING", "IMPLEMENTED", "SUBSTITUTED"},
    "replay": {"NONE", "PASS"},
    "differential": {"NONE", "PASS"},
}
DYNAMIC_CLASSES = {"state_transition", "integrator", "render", "audio"}
PROOF_LEVELS = {
    "STATIC_EQUIVALENT", "EMULATED_EQUIVALENT", "NATIVE_DIFFERENTIAL",
    "BLOCKED_NATIVE_OBSERVATION", "MISSING", "PLATFORM_SUBSTITUTION", "DESCOPED",
}


def resolve_pointer(document: Any, pointer: str, label: str) -> Any:
    if not pointer:
        return document
    if not pointer.startswith("/"):
        raise ValueError(f"{label}: invalid JSON pointer #{pointer}")
    value = document
    for raw in pointer[1:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            try:
                value = value[int(part)]
            except (ValueError, IndexError) as error:
                raise ValueError(f"{label}: missing pointer segment {part!r}") from error
        elif isinstance(value, dict) and part in value:
            value = value[part]
        else:
            raise ValueError(f"{label}: missing pointer segment {part!r}")
    return value


def validate_reference(root: Path, reference: str, label: str) -> Any:
    relative, separator, pointer = reference.partition("#")
    path = root / relative
    if not path.is_file():
        raise ValueError(f"{label}: evidence file does not exist: {relative}")
    document = load_json_strict(path)
    return resolve_pointer(document, pointer, label) if separator else document


def derived_status(record: dict[str, Any], behavior: dict[str, Any]) -> str:
    disposition = record["disposition"]
    if disposition != "REQUIRED":
        return disposition
    evidence = record["evidence"]
    base = (
        evidence["source"] == "PINNED"
        and evidence["native_behavior"] == "CONTRACTED"
        and evidence["runtime"] == "IMPLEMENTED"
    )
    if not base:
        return "MISSING"
    if behavior["class"] in DYNAMIC_CLASSES:
        return "EQUIVALENT" if evidence["differential"] == "PASS" else "MISSING"
    return "EQUIVALENT" if evidence["replay"] == "PASS" else "MISSING"


def derived_proof_level(
    record: dict[str, Any], behavior: dict[str, Any], trace_documents: list[Any]
) -> str:
    status = derived_status(record, behavior)
    if status != "EQUIVALENT":
        if status == "MISSING" and record["evidence"]["runtime"] == "IMPLEMENTED" \
                and behavior["class"] in DYNAMIC_CLASSES:
            return "BLOCKED_NATIVE_OBSERVATION"
        return status
    if record["evidence"]["differential"] == "PASS":
        protocols = {
            document.get("protocol") for document in trace_documents if isinstance(document, dict)
        }
        if protocols & {
            "miel-vliegt-x86-micro-oracle",
            "miel-vliegt-x86-property-fold-oracle",
            "miel-vliegt-x86-drop-oracle",
        }:
            return "EMULATED_EQUIVALENT"
        return "NATIVE_DIFFERENTIAL"
    return "STATIC_EQUIVALENT"


def _receipt_map(receipts: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if receipts.get("schema") != 1 or not isinstance(receipts.get("receipts"), list):
        raise ValueError("unsupported behavior receipt schema")
    result = {}
    for receipt in receipts["receipts"]:
        suite_id = receipt.get("suite_id")
        if not isinstance(suite_id, str) or suite_id in result:
            raise ValueError(f"invalid or duplicate receipt suite id {suite_id!r}")
        result[suite_id] = receipt
    return result


def validate(
    root: Path,
    contracts_path: Path,
    ledger_path: Path,
    code_map_path: Path,
    suites_path: Path,
    receipts_path: Path,
    *,
    execute_receipts: bool = False,
    require_release_ready: bool = False,
) -> Counter[str]:
    contracts = load_json_strict(contracts_path)
    ledger = load_json_strict(ledger_path)
    code_map = load_json_strict(code_map_path)
    suites = load_json_strict(suites_path)
    tracked_receipts = load_json_strict(receipts_path)
    if contracts.get("schema") != 1 or ledger.get("schema") != 2:
        raise ValueError("unsupported behavior contract or ledger schema")
    if code_map.get("schema") != 1:
        raise ValueError("unsupported native code-map schema")
    behaviors = contracts.get("behaviors")
    records = ledger.get("records")
    if not isinstance(behaviors, list) or not isinstance(records, list):
        raise ValueError("behavior contracts and ledger records must be arrays")
    behavior_by_id = {item.get("id"): item for item in behaviors}
    if None in behavior_by_id or len(behavior_by_id) != len(behaviors):
        raise ValueError("behavior contracts need unique non-empty ids")
    if list(behavior_by_id) != sorted(behavior_by_id):
        raise ValueError("behavior contracts must be sorted by id")
    record_by_id = {item.get("id"): item for item in records}
    if None in record_by_id or len(record_by_id) != len(records):
        raise ValueError("ledger v2 records need unique non-empty ids")
    if list(record_by_id) != sorted(record_by_id):
        raise ValueError("ledger v2 records must be sorted by id")
    if set(record_by_id) != set(behavior_by_id):
        raise ValueError("ledger v2 must cover every behavior contract exactly once")

    functions = code_map.get("functions")
    sccs = code_map.get("sccs")
    if not isinstance(functions, list) or not isinstance(sccs, list):
        raise ValueError("native code-map functions and SCCs must be arrays")
    function_by_id = {item.get("id"): item for item in functions}
    scc_ids = {item.get("id") for item in sccs}
    if None in function_by_id or len(function_by_id) != len(functions) or None in scc_ids:
        raise ValueError("native code-map has invalid or duplicate function/SCC ids")
    behavior_coverage: dict[str, set[str]] = {}
    for behavior_id, behavior in behavior_by_id.items():
        for unit_id in behavior["native_units"]:
            if unit_id not in function_by_id:
                raise ValueError(f"{behavior_id}: native function {unit_id} is absent from code-map")
            behavior_coverage.setdefault(unit_id, set()).add(behavior_id)
    reviewed = []
    reviewed_game_owned = []
    unknown = []
    covered_sccs: dict[str, set[str]] = {}
    covered_blocks: dict[str, set[str]] = {}
    for function_id, function in function_by_id.items():
        ownership = function.get("ownership", {}).get("status")
        disposition = function.get("ownership", {}).get("disposition")
        if disposition not in {
            "GAME_OWNED", "ENGINE_OWNED", "PLATFORM_OWNED", "COMPILER_RUNTIME", "UNKNOWN"
        }:
            raise ValueError(f"{function_id}: invalid ownership disposition {disposition!r}")
        if ownership == "reviewed":
            reviewed.append(function_id)
            if not function.get("sha256") or not function["ownership"].get("evidence"):
                raise ValueError(f"{function_id}: reviewed ownership lacks pinned evidence")
            if disposition == "GAME_OWNED":
                reviewed_game_owned.append(function_id)
                if function_id not in behavior_coverage:
                    raise ValueError(f"{function_id}: uncovered GAME_OWNED reviewed function")
                if function.get("scc") not in scc_ids:
                    raise ValueError(f"{function_id}: missing SCC id {function.get('scc')}")
                for behavior_id in behavior_coverage[function_id]:
                    covered_sccs.setdefault(function["scc"], set()).add(behavior_id)
                    for block_id in function.get("basic_blocks", []):
                        covered_blocks.setdefault(block_id, set()).add(behavior_id)
                if not function.get("basic_blocks"):
                    raise ValueError(f"{function_id}: reviewed function has no basic-block ids")
            elif function_id in behavior_coverage:
                raise ValueError(f"{function_id}: non-game ownership cannot cover gameplay behavior")
        elif ownership in ("candidate", "unassigned"):
            if disposition != "UNKNOWN":
                raise ValueError(f"{function_id}: unreviewed ownership cannot claim a disposition")
            unknown.append(function_id)
        else:
            raise ValueError(f"{function_id}: unknown ownership classifier state {ownership!r}")
    # Every game-owned function, its SCC, and all its basic blocks now resolve
    # to at least one behavior contract. Candidate/unassigned functions remain
    # explicitly UNKNOWN and do not count as coverage.
    if not covered_sccs or not covered_blocks:
        raise ValueError("reviewed game-owned SCC/basic-block coverage is empty")
    summary = code_map.get("summary", {})
    ownership_counts = summary.get("ownership", {})
    if summary.get("functions") != len(functions) \
            or ownership_counts.get("reviewed") != len(reviewed) \
            or ownership_counts.get("candidate", 0) + ownership_counts.get("unassigned", 0) != len(unknown):
        raise ValueError("native code-map reviewed/UNKNOWN frontier counts drifted")

    native_coverage = ledger.get("native_coverage")
    if not isinstance(native_coverage, dict):
        raise ValueError("ledger v2 must expose native coverage debt")
    expected_native_coverage = {
        "functions_total": len(functions),
        "reviewed_game_owned": len(reviewed_game_owned),
        "candidate_game_owned": ownership_counts.get("candidate", 0),
        "unassigned": ownership_counts.get("unassigned", 0),
        "unknown_function_ownership": len(unknown),
        "basic_blocks_total": summary.get("basic_blocks"),
        "unresolved_indirect_call_sites": summary.get("unresolved_indirect_call_sites"),
        "unresolved_indirect_branch_sites": summary.get("unresolved_switch_or_indirect_branches"),
        "semantic_coverage_complete": summary.get("executable_byte_coverage", {}).get(
            "semantic_coverage_claimed"
        ) is True,
    }
    for field, expected in expected_native_coverage.items():
        if native_coverage.get(field) != expected:
            raise ValueError(
                f"native coverage debt {field} drifted: "
                f"stored={native_coverage.get(field)!r} actual={expected!r}"
            )

    suite_by_id = {suite.get("id"): suite for suite in suites.get("suites", [])}
    if None in suite_by_id or len(suite_by_id) != len(suites.get("suites", [])):
        raise ValueError("test suites need unique non-empty ids")
    receipt_by_id = _receipt_map(tracked_receipts)
    if set(receipt_by_id) != set(suite_by_id):
        raise ValueError("tracked receipt suites do not match executable suite declarations")

    fresh = build_receipts(root, suites, execute=execute_receipts)
    fresh_by_id = _receipt_map(fresh)
    for suite_id, suite in suite_by_id.items():
        receipt = receipt_by_id[suite_id]
        expected = fresh_by_id[suite_id]
        for field in ("contract_ids", "mode", "command", "runtime_hashes"):
            if receipt.get(field) != expected[field]:
                raise ValueError(f"{suite_id}: stale executable receipt field {field}")
        if receipt.get("result") != "PASS" or receipt.get("exit_code") != 0:
            raise ValueError(f"{suite_id}: tracked executable receipt is not PASS")
        if execute_receipts and expected["result"] != "PASS":
            raise ValueError(f"{suite_id}: executable receipt did not pass")
        for contract_id in suite["contract_ids"]:
            if contract_id not in behavior_by_id:
                raise ValueError(f"{suite_id}: unknown contract id {contract_id}")

    counts: Counter[str] = Counter()
    for behavior_id, behavior in behavior_by_id.items():
        if behavior.get("class") not in BEHAVIOR_CLASSES:
            raise ValueError(f"{behavior_id}: invalid behavior class")
        expected_minimum = "DIFFERENTIAL" if behavior["class"] in DYNAMIC_CLASSES else "REPLAY"
        if behavior.get("minimum_evidence") != expected_minimum:
            raise ValueError(f"{behavior_id}: behavior class requires {expected_minimum} evidence")
        for reference in behavior.get("sources", []):
            validate_reference(root, reference, f"{behavior_id}.sources")
        record = record_by_id[behavior_id]
        if record.get("disposition") not in DISPOSITIONS:
            raise ValueError(f"{behavior_id}: invalid disposition")
        evidence = record.get("evidence")
        if not isinstance(evidence, dict) or set(evidence) != set(EVIDENCE_VALUES):
            raise ValueError(f"{behavior_id}: evidence vector is incomplete")
        for facet, allowed in EVIDENCE_VALUES.items():
            if evidence[facet] not in allowed:
                raise ValueError(f"{behavior_id}: invalid {facet} evidence {evidence[facet]!r}")
        suite_ids = record.get("test_suites", [])
        if evidence["replay"] == "PASS" and not suite_ids:
            raise ValueError(f"{behavior_id}: replay PASS requires an executable test receipt")
        if evidence["differential"] == "PASS" and not suite_ids:
            raise ValueError(f"{behavior_id}: differential PASS requires an executable test receipt")
        for suite_id in suite_ids:
            receipt = receipt_by_id.get(suite_id)
            if receipt is None or behavior_id not in receipt["contract_ids"]:
                raise ValueError(f"{behavior_id}: suite {suite_id!r} does not receipt this contract")
            if evidence["replay"] == "PASS" and receipt["mode"] not in ("replay", "differential"):
                raise ValueError(f"{behavior_id}: replay evidence requires replay-capable suite")
            if evidence["differential"] == "PASS" and receipt["mode"] != "differential":
                raise ValueError(f"{behavior_id}: differential evidence requires differential receipt")
        trace_artifacts = record.get("trace_artifacts", [])
        if evidence["differential"] == "PASS" and not trace_artifacts:
            raise ValueError(f"{behavior_id}: differential PASS requires a native trace artifact")
        trace_documents = []
        for reference in trace_artifacts:
            document = validate_reference(root, reference, f"{behavior_id}.trace_artifacts")
            if isinstance(document, dict) \
                    and document.get("protocol") in {
                        "miel-vliegt-x86-micro-oracle",
                        "miel-vliegt-x86-property-fold-oracle",
                        "miel-vliegt-x86-drop-oracle",
                    }:
                relative, separator, _ = reference.partition("#")
                if separator:
                    raise ValueError(f"{behavior_id}: micro-oracle evidence must reference its full receipt")
                verifier = {
                    "miel-vliegt-x86-micro-oracle": verify_x86_micro_oracle,
                    "miel-vliegt-x86-property-fold-oracle": verify_x86_property_oracle,
                    "miel-vliegt-x86-drop-oracle": verify_x86_drop_oracle,
                }[document["protocol"]]
                document = verifier(root / relative, root)
                if behavior_id not in document.get("evidence_scope", []):
                    raise ValueError(f"{behavior_id}: micro-oracle receipt does not cover this behavior")
                covered_units = document.get("native_units", {}).get(behavior_id, [])
                if set(covered_units) != set(behavior["native_units"]):
                    raise ValueError(
                        f"{behavior_id}: micro-oracle receipt does not cover the behavior native units"
                    )
            trace_documents.append(document)
        status = derived_status(record, behavior)
        if record.get("derived_status") != status:
            raise ValueError(
                f"{behavior_id}: derived status drifted: stored={record.get('derived_status')} actual={status}"
            )
        proof_level = derived_proof_level(record, behavior, trace_documents)
        if proof_level not in PROOF_LEVELS or record.get("proof_level") != proof_level:
            raise ValueError(
                f"{behavior_id}: proof level drifted: "
                f"stored={record.get('proof_level')} actual={proof_level}"
            )
        if behavior["class"] in DYNAMIC_CLASSES and status == "EQUIVALENT" \
                and evidence["differential"] != "PASS":
            raise ValueError(f"{behavior_id}: dynamic EQUIVALENT requires differential evidence")
        counts[status] += 1
    release_ready = (
        native_coverage["unknown_function_ownership"] == 0
        and native_coverage["unresolved_indirect_call_sites"] == 0
        and native_coverage["unresolved_indirect_branch_sites"] == 0
        and native_coverage["semantic_coverage_complete"]
        and counts["MISSING"] == 0
    )
    if native_coverage.get("release_ready") is not release_ready:
        raise ValueError("stored native release readiness does not match derived evidence")
    if require_release_ready and not release_ready:
        raise ValueError(
            "native-flight release blocked by unresolved ownership, control-flow or behavior evidence"
        )
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--no-execute-receipts", action="store_true")
    parser.add_argument("--require-release-ready", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    counts = validate(
        root,
        root / "content/miel_vliegt/native_behavior_contracts.json",
        root / "content/miel_vliegt/flight_parity_ledger_v2.json",
        root / "content/miel_vliegt/native_code_map.json",
        root / "content/miel_vliegt/flight_behavior_test_suites.json",
        root / "content/miel_vliegt/flight_behavior_test_receipts.json",
        execute_receipts=not args.no_execute_receipts,
        require_release_ready=args.require_release_ready,
    )
    ledger = load_json_strict(root / "content/miel_vliegt/flight_parity_ledger_v2.json")
    native_coverage = ledger["native_coverage"]
    print("flight behavior evidence OK: " + ", ".join(
        f"{status}={count}" for status, count in sorted(counts.items())
    ) + ", " + ", ".join((
        f"unknown_functions={native_coverage['unknown_function_ownership']}",
        f"indirect_calls={native_coverage['unresolved_indirect_call_sites']}",
        f"indirect_branches={native_coverage['unresolved_indirect_branch_sites']}",
        f"release_ready={str(native_coverage['release_ready']).lower()}",
    )))


if __name__ == "__main__":
    main()
