#!/usr/bin/env python3
"""Audit native boundary candidates without promoting heuristic classifications.

The native code map contains useful bulk candidates, but three very different
claims must stay separate:

* direct-graph unreachable candidates are not proven unreachable until roots,
  callbacks, vtables and indirect targets are all reviewed and closed;
* import thunks are not import substitutions until the existing import audit
  binds an exact, executed release replacement;
* compiler/runtime candidates are only a low-confidence address/string
  heuristic until independent provenance and substitution evidence exists.

This module emits one deterministic, hash-bound audit receipt.  It also builds
and validates completion-compatible PROVEN_UNREACHABLE receipts, but only after
all four reachability closures have been supplied.  Missing evidence is a hard
error, never a partial promotion.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import difflib
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CODE_MAP = "content/miel_vliegt/native_code_map.json"
FUNCTION_INDEX = "content/miel_vliegt/native_function_index.json"
IMPORT_AUDIT = "content/miel_vliegt/native_import_thunk_audit.json"
OUTPUT = "content/miel_vliegt/native_boundary_cluster_audit.json"
SCHEMA = "tools/miel_vliegt/schemas/native-boundary-cluster-audit.schema.json"
PROTOCOL = "miel-vliegt-native-boundary-cluster-audit"
BOUNDARY_PROTOCOL = "miel-vliegt-native-function-boundary-evidence"
CLOSURE_REVIEW_PROTOCOL = "miel-vliegt-native-reachability-closure-review"
REACHABILITY_CLOSURES = ("roots", "callbacks", "vtables", "indirectTargets")
SHA256_LENGTH = 64


class NativeBoundaryClusterError(ValueError):
    """Raised when candidate or promotion evidence fails closed."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise NativeBoundaryClusterError(f"{path}: expected a JSON object")
    return value


def validate_schema_guard(schema: dict[str, Any]) -> None:
    """Keep structural disposition coverage conservative in the public schema."""

    required = {
        "schema", "protocol", "source", "policy", "summary", "clusters",
        "receiptSha256",
    }
    review = schema.get("$defs", {}).get("compilerStructuralReview", {})
    properties = review.get("properties", {})
    member = schema.get("$defs", {}).get("compilerStructuralMember", {})
    member_properties = member.get("properties", {})
    dispositions = member_properties.get("structuralDisposition", {}).get("enum")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" \
            or schema.get("additionalProperties") is not False \
            or set(schema.get("required", [])) != required \
            or properties.get("structuralClass", {}).get("const") \
                != "EXACT_RECOVERED_CONTROL_FLOW_BOUNDARIES" \
            or properties.get("disposition", {}).get("const") != "UNKNOWN" \
            or dispositions != [
                "CLOSED_COMPILER_CANDIDATE_GRAPH",
                "EXTERNAL_IMPORT_TRANSFER_BOUNDARY",
                "RECOVERED_NATIVE_CALL_BOUNDARY",
                "RECOVERED_NATIVE_AND_EXTERNAL_IMPORT_BOUNDARY",
            ] \
            or member_properties.get("semanticGameplayPromotion", {}).get(
                "const"
            ) is not False \
            or properties.get(
                "resolvedStackParameterCallCount", {}
            ).get("minimum") != 0 \
            or properties.get(
                "virtualBoundaryCorrectionMemberCount", {}
            ).get("minimum") != 0 \
            or review.get("properties", {}).get("policy", {}).get(
                "properties", {}
            ).get(
                "rawSectionAlignmentPaddingCountsAsExecutableDecode", {}
            ).get("const") is not False:
        raise NativeBoundaryClusterError(
            "native boundary cluster JSON schema policy differs"
        )


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SHA256_LENGTH \
        and all(character in "0123456789abcdef" for character in value)


def _members(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "functionId": row["id"],
            "nativeFunctionSha256": row["sha256"],
        }
        for row in sorted(rows, key=lambda item: item["id"])
    ]


def _validate_graph(code_map: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if code_map.get("schema") != 1:
        raise NativeBoundaryClusterError("native code map schema differs")
    functions = code_map.get("functions")
    sccs = code_map.get("sccs")
    source = code_map.get("source")
    if not isinstance(functions, list) or not functions \
            or not isinstance(sccs, list) or not isinstance(source, dict):
        raise NativeBoundaryClusterError("native code map inventory is incomplete")
    rows = {}
    for row in functions:
        if not isinstance(row, dict):
            raise NativeBoundaryClusterError("native function row is not an object")
        identifier = row.get("id")
        if not isinstance(identifier, str) or identifier in rows \
                or not _is_sha256(row.get("sha256")):
            raise NativeBoundaryClusterError("native function identity is not unique and hash-bound")
        for field in (
            "entrypoint_reachable", "has_unresolved_direct_calls",
            "has_unresolved_indirect_calls",
        ):
            if not isinstance(row.get(field), bool):
                raise NativeBoundaryClusterError(
                    f"{identifier}: {field} is not an exact boolean"
                )
        if not isinstance(row.get("calls"), list) or not isinstance(row.get("callers"), list):
            raise NativeBoundaryClusterError(f"{identifier}: call edges are unavailable")
        rows[identifier] = row

    identifiers = set(rows)
    for identifier, row in rows.items():
        calls = row["calls"]
        callers = row["callers"]
        if len(calls) != len(set(calls)) or len(callers) != len(set(callers)) \
                or not set(calls).issubset(identifiers) \
                or not set(callers).issubset(identifiers):
            raise NativeBoundaryClusterError(f"{identifier}: call graph is not total")
    for identifier, row in rows.items():
        for target in row["calls"]:
            if identifier not in rows[target]["callers"]:
                raise NativeBoundaryClusterError(
                    f"{identifier}: call/caller graph is not symmetric"
                )
        for caller in row["callers"]:
            if identifier not in rows[caller]["calls"]:
                raise NativeBoundaryClusterError(
                    f"{identifier}: caller/call graph is not symmetric"
                )

    entrypoint = source.get("entrypoint")
    if not isinstance(entrypoint, str):
        raise NativeBoundaryClusterError("native entrypoint is unavailable")
    entrypoint_id = f"fn_{int(entrypoint, 16):08x}"
    if entrypoint_id not in rows:
        raise NativeBoundaryClusterError("native entrypoint function is absent")
    reachable = {entrypoint_id}
    queue = collections.deque([entrypoint_id])
    while queue:
        current = queue.popleft()
        for target in rows[current]["calls"]:
            if target not in reachable:
                reachable.add(target)
                queue.append(target)
    reported = {
        identifier for identifier, row in rows.items()
        if row["entrypoint_reachable"]
    }
    if reported != reachable:
        raise NativeBoundaryClusterError(
            "entrypoint reachability differs from the recovered direct-call graph"
        )

    scc_by_function = {}
    for component in sccs:
        if not isinstance(component, dict) or not isinstance(component.get("members"), list):
            raise NativeBoundaryClusterError("native SCC inventory is malformed")
        for identifier in component["members"]:
            if identifier not in rows or identifier in scc_by_function:
                raise NativeBoundaryClusterError("native SCC membership is not a partition")
            scc_by_function[identifier] = component["id"]
    if set(scc_by_function) != identifiers:
        raise NativeBoundaryClusterError("native SCC inventory is incomplete")
    if any(rows[identifier].get("scc") != component
           for identifier, component in scc_by_function.items()):
        raise NativeBoundaryClusterError("native function SCC reference drifted")
    return rows


def _validate_import_audit(
    import_audit: dict[str, Any], rows: dict[str, dict[str, Any]],
    code_map_sha256: str, code_source: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    if import_audit.get("schema") != 1 \
            or import_audit.get("protocol") != "miel-vliegt-native-import-thunk-audit":
        raise NativeBoundaryClusterError("native import thunk audit protocol differs")
    unhashed_audit = dict(import_audit)
    audit_sha = unhashed_audit.pop("receiptSha256", None)
    if audit_sha != sha256_json(unhashed_audit):
        raise NativeBoundaryClusterError("native import thunk audit receipt hash differs")
    input_hashes = import_audit.get("inputHashes")
    if not isinstance(input_hashes, dict) \
            or input_hashes.get(CODE_MAP) != code_map_sha256:
        raise NativeBoundaryClusterError("native import audit is not bound to this code map")
    if import_audit.get("source") != code_source:
        raise NativeBoundaryClusterError("native import audit source identity differs")
    decisions = import_audit.get("decisions")
    if not isinstance(decisions, list):
        raise NativeBoundaryClusterError("native import decisions are unavailable")
    by_id = {}
    for decision in decisions:
        if not isinstance(decision, dict):
            raise NativeBoundaryClusterError("native import decision is malformed")
        identifier = decision.get("functionId")
        row = rows.get(identifier)
        unhashed = dict(decision)
        decision_sha = unhashed.pop("decisionSha256", None)
        if identifier in by_id or row is None \
                or row.get("kind", {}).get("value") != "import_thunk" \
                or row.get("kind", {}).get("confidence") != "high" \
                or decision.get("nativeFunctionSha256") != row["sha256"] \
                or decision_sha != sha256_json(unhashed):
            raise NativeBoundaryClusterError("native import decision identity differs")
        if decision.get("status") not in {"COMPLETE", "UNKNOWN"}:
            raise NativeBoundaryClusterError(f"{identifier}: import decision status differs")
        if decision["status"] == "COMPLETE":
            if decision.get("disposition") != "IMPORT_BOUNDARY" \
                    or not isinstance(decision.get("replacement"), dict):
                raise NativeBoundaryClusterError(
                    f"{identifier}: COMPLETE import decision lacks exact replacement evidence"
                )
        elif decision.get("disposition") != "UNKNOWN" \
                or decision.get("replacement") is not None:
            raise NativeBoundaryClusterError(
                f"{identifier}: UNKNOWN import decision contains promotion evidence"
            )
        by_id[identifier] = decision
    expected = {
        identifier for identifier, row in rows.items()
        if row.get("kind", {}).get("value") == "import_thunk"
        and row.get("kind", {}).get("confidence") == "high"
    }
    if set(by_id) != expected:
        raise NativeBoundaryClusterError("native import audit does not cover every exact thunk")
    summary = import_audit.get("summary")
    statuses = collections.Counter(row["status"] for row in decisions)
    if summary != {
        "audited": len(decisions),
        "complete": statuses["COMPLETE"],
        "unknown": statuses["UNKNOWN"],
    }:
        raise NativeBoundaryClusterError("native import audit summary differs")
    return by_id


def _cluster(
    identifier: str, disposition: str, selector: dict[str, Any],
    rows: list[dict[str, Any]], *, evidence: dict[str, Any],
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    members = _members(rows)
    return {
        "id": identifier,
        "disposition": disposition,
        "selector": selector,
        "memberCount": len(members),
        "members": members,
        "membershipSha256": sha256_json(members),
        "graph": graph,
        "evidence": evidence,
    }


def build(
    code_map: dict[str, Any], import_audit: dict[str, Any], *,
    code_map_sha256: str, import_audit_sha256: str,
) -> dict[str, Any]:
    if not _is_sha256(code_map_sha256) or not _is_sha256(import_audit_sha256):
        raise NativeBoundaryClusterError("native cluster source hashes are invalid")
    rows = _validate_graph(code_map)
    imports = _validate_import_audit(
        import_audit, rows, code_map_sha256, code_map["source"]
    )

    unreachable = [
        row for row in rows.values()
        if row["entrypoint_reachable"] is False
        and row["has_unresolved_direct_calls"] is False
        and row["has_unresolved_indirect_calls"] is False
    ]
    import_thunks = [
        row for row in rows.values()
        if row.get("kind", {}).get("value") == "import_thunk"
        and row.get("kind", {}).get("confidence") == "high"
    ]
    compiler = [
        row for row in rows.values()
        if row.get("kind", {}).get("value") == "compiler_runtime_candidate"
    ]
    unreachable_ids = {row["id"] for row in unreachable}
    import_ids = {row["id"] for row in import_thunks}
    compiler_ids = {row["id"] for row in compiler}

    split_sccs = []
    members_by_scc: dict[str, set[str]] = collections.defaultdict(set)
    for row in rows.values():
        members_by_scc[row["scc"]].add(row["id"])
    for component, members in sorted(members_by_scc.items()):
        selected = members & unreachable_ids
        if selected and selected != members:
            split_sccs.append(component)
    reachable_incoming = sorted({
        f"{caller}->{identifier}"
        for identifier in unreachable_ids
        for caller in rows[identifier]["callers"]
        if rows[caller]["entrypoint_reachable"]
    })
    direct_root_identity = {
        "entrypoint": code_map["source"]["entrypoint"],
        "candidateMembers": _members(unreachable),
        "reachableFunctions": sorted(
            identifier for identifier, row in rows.items()
            if row["entrypoint_reachable"]
        ),
        "directCallEdges": sorted(
            f"{identifier}->{target}"
            for identifier, row in rows.items() for target in row["calls"]
        ),
    }
    direct_root_proof = sha256_json(direct_root_identity)
    if split_sccs or reachable_incoming:
        raise NativeBoundaryClusterError(
            "unreachable candidate set is not closed under SCC/direct-root reachability"
        )

    complete_imports = sorted(
        identifier for identifier, decision in imports.items()
        if decision["status"] == "COMPLETE"
    )
    clusters = [
        _cluster(
            "cluster:proven-unreachable-candidates",
            "PROVEN_UNREACHABLE",
            {
                "entrypointReachable": False,
                "hasUnresolvedDirectCalls": False,
                "hasUnresolvedIndirectCalls": False,
            },
            unreachable,
            graph={
                "sccAtomic": True,
                "reachableIncomingEdges": [],
                "externalIncomingEdgeCount": sum(
                    caller not in unreachable_ids
                    for identifier in unreachable_ids
                    for caller in rows[identifier]["callers"]
                ),
                "directRootProofSha256": direct_root_proof,
                "unknownByteMembers": sorted(
                    row["id"] for row in unreachable
                    if row.get("analysis_coverage", {}).get("unknown_skipdata_bytes", 0)
                ),
                "unresolvedIndirectBranchMembers": sorted(
                    row["id"] for row in unreachable
                    if row.get("branch_counts", {}).get(
                        "unresolved_switch_or_indirect_jump", 0
                    )
                ),
            },
            evidence={
                "status": "BLOCKED",
                "promotableMembers": [],
                "provenClosures": ["roots"],
                "missingClosures": ["callbacks", "vtables", "indirectTargets"],
                "reason": (
                    "Direct-root exclusion is hash-bound, but callbacks, vtables and "
                    "indirect target inventories are not reviewed closed."
                ),
            },
        ),
        _cluster(
            "cluster:exact-import-thunks",
            "IMPORT_BOUNDARY",
            {"kind": "import_thunk", "confidence": "high"},
            import_thunks,
            graph=None,
            evidence={
                "status": "PROMOTABLE" if complete_imports else "BLOCKED",
                "promotableMembers": complete_imports,
                "blockedMembers": sorted(import_ids - set(complete_imports)),
                "sourceReceiptSha256": import_audit.get("receiptSha256"),
                "reason": (
                    "Only COMPLETE import-audit decisions with an exact native interface "
                    "and hash-bound executed release export are promotable."
                ),
            },
        ),
        _cluster(
            "cluster:compiler-runtime-candidates",
            "COMPILER_SUBSTITUTION",
            {"kind": "compiler_runtime_candidate", "confidence": "low"},
            compiler,
            graph=None,
            evidence={
                "status": "BLOCKED",
                "promotableMembers": [],
                "missingEvidence": [
                    "reviewed exact compiler/runtime provenance",
                    "exact ABI/import mapping",
                    "hash-bound executed release replacement",
                ],
                "reason": (
                    "The tail-region/string heuristic is discovery evidence, not a "
                    "compiler/runtime boundary proof."
                ),
            },
        ),
    ]
    candidates = {
        cluster["disposition"]: cluster["memberCount"] for cluster in clusters
    }
    promotable = {
        cluster["disposition"]: len(cluster["evidence"]["promotableMembers"])
        for cluster in clusters
    }
    union = unreachable_ids | import_ids | compiler_ids
    result = {
        "schema": 1,
        "protocol": PROTOCOL,
        "source": {
            "executableSha256": code_map["source"]["sha256"],
            "entrypoint": code_map["source"]["entrypoint"],
            "imageBase": code_map["source"]["image_base"],
            "codeMap": {"path": CODE_MAP, "sha256": code_map_sha256},
            "importThunkAudit": {
                "path": IMPORT_AUDIT,
                "sha256": import_audit_sha256,
            },
        },
        "policy": {
            "candidateIsPromotion": False,
            "missingEvidence": "BLOCKED",
            "clusterClaimsAreAtomic": True,
            "provenUnreachableRequires": list(REACHABILITY_CLOSURES),
            "importBoundaryRequires": (
                "COMPLETE exact-interface import audit decision and hash-bound "
                "executed release export"
            ),
            "compilerBoundaryRequires": (
                "reviewed exact provenance plus ABI/import mapping and hash-bound "
                "executed release replacement"
            ),
        },
        "summary": {
            "functions": len(rows),
            "clusters": len(clusters),
            "candidateFunctions": len(union),
            "candidateMemberships": sum(candidates.values()),
            "candidates": candidates,
            "promotable": promotable,
            "blocked": {
                disposition: candidates[disposition] - promotable[disposition]
                for disposition in candidates
            },
            "overlap": {
                "provenUnreachableAndImportBoundary": len(unreachable_ids & import_ids),
                "provenUnreachableAndCompilerSubstitution": len(
                    unreachable_ids & compiler_ids
                ),
                "importBoundaryAndCompilerSubstitution": len(import_ids & compiler_ids),
            },
        },
        "clusters": clusters,
    }
    return {**result, "receiptSha256": sha256_json(result)}


def build_from_root(root: Path = ROOT) -> dict[str, Any]:
    validate_schema_guard(load_json(root / SCHEMA))
    code_path = root / CODE_MAP
    import_path = root / IMPORT_AUDIT
    result = build(
        load_json(code_path),
        load_json(import_path),
        code_map_sha256=sha256_file(code_path),
        import_audit_sha256=sha256_file(import_path),
    )
    try:
        from tools.miel_vliegt import native_reachability_closures as closures
    except ModuleNotFoundError:  # Direct script execution.
        import native_reachability_closures as closures
    review_paths = {
        name: root / relative for name, relative in closures.OUTPUTS.items()
    }
    if not all(path.is_file() for path in review_paths.values()):
        return result
    reviews = {
        name: load_json(path) for name, path in review_paths.items()
    }
    try:
        closures.validate_all(reviews, root=root)
    except closures.NativeReachabilityClosureError as error:
        raise NativeBoundaryClusterError(
            f"native reachability closure reviews differ: {error}"
        ) from error
    code_map = load_json(code_path)
    function_index_path = root / FUNCTION_INDEX
    function_index = load_json(function_index_path)
    rows = _validate_graph(code_map)
    cluster = _cluster_by_id(
        result, "cluster:proven-unreachable-candidates",
    )
    candidate_ids = {
        member["functionId"] for member in cluster["members"]
    }
    closed = [
        name for name in REACHABILITY_CLOSURES
        if reviews[name]["reviewStatus"] == "CLOSED"
    ]
    missing = [
        name for name in REACHABILITY_CLOSURES if name not in closed
    ]
    reached = set().union(*(
        set(reviews[name]["inventory"]["targetFunctionIds"])
        for name in closed
    ))
    queue = collections.deque(sorted(reached))
    while queue:
        identifier = queue.popleft()
        for target in rows[identifier]["calls"]:
            if target not in reached:
                reached.add(target)
                queue.append(target)
    remaining = sorted(candidate_ids - reached)
    promotable = remaining if not missing else []
    review_sources = {
        name: {
            "path": closures.OUTPUTS[name],
            "sha256": sha256_file(review_paths[name]),
            "reviewStatus": reviews[name]["reviewStatus"],
            "reviewSha256": reviews[name]["reviewSha256"],
            "unresolvedPathCount": len(reviews[name]["unresolvedPaths"]),
        }
        for name in REACHABILITY_CLOSURES
    }
    cluster["evidence"] = {
        "status": "PROMOTABLE" if promotable else "BLOCKED",
        "promotableMembers": promotable,
        "provenClosures": closed,
        "missingClosures": missing,
        "closedClosureReachedCandidateCount": len(candidate_ids) - len(remaining),
        "remainingCandidateCount": len(remaining),
        "remainingCandidates": remaining,
        "closureReviews": review_sources,
        "reason": (
            "Every direct-call-unreachable candidate has an inbound literal, "
            "vtable/data or cross-function branch path; no function remains "
            "claimable as PROVEN_UNREACHABLE. Indirect targets also remain open."
            if not remaining and missing else
            "All four mechanical inbound-path closures are closed."
            if promotable else
            "One or more mechanical inbound-path closures remain open."
        ),
    }
    compiler_cluster = _cluster_by_id(
        result, "cluster:compiler-runtime-candidates",
    )
    compiler_structural_review = _compiler_structural_review(
        code_map, function_index, reviews,
        function_index_sha256=sha256_file(function_index_path),
    )
    compiler_cluster["evidence"]["structuralReview"] = compiler_structural_review
    import_cluster = _cluster_by_id(
        result, "cluster:exact-import-thunks",
    )
    import_cluster["evidence"]["structuralReview"] = (
        _import_structural_review(
            code_map, function_index, load_json(import_path),
            function_index_sha256=sha256_file(function_index_path),
        )
    )
    result["source"]["functionIndex"] = {
        "path": FUNCTION_INDEX,
        "sha256": sha256_file(function_index_path),
    }
    result["source"]["reachabilityReviews"] = review_sources
    result["summary"]["promotable"]["PROVEN_UNREACHABLE"] = len(promotable)
    result["summary"]["blocked"]["PROVEN_UNREACHABLE"] = (
        result["summary"]["candidates"]["PROVEN_UNREACHABLE"]
        - len(promotable)
    )
    result["summary"]["compilerStructural"] = {
        "candidateCount": compiler_structural_review["candidateCount"],
        "exactlyDisposedCount": compiler_structural_review["reviewedMemberCount"],
        "unresolvedCount": compiler_structural_review["blockedMemberCount"],
        "dispositions": compiler_structural_review[
            "structuralDispositionCounts"
        ],
        "promotionCount": 0,
    }
    unhashed = dict(result)
    unhashed.pop("receiptSha256")
    return {**unhashed, "receiptSha256": sha256_json(unhashed)}


def validate(audit: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    expected = build_from_root(root)
    if audit != expected:
        raise NativeBoundaryClusterError("native boundary cluster audit drifted")
    return audit


def _cluster_by_id(audit: dict[str, Any], identifier: str) -> dict[str, Any]:
    matches = [
        cluster for cluster in audit.get("clusters", [])
        if isinstance(cluster, dict) and cluster.get("id") == identifier
    ]
    if len(matches) != 1:
        raise NativeBoundaryClusterError(f"native boundary cluster differs: {identifier}")
    return matches[0]


def _pointer_reference_counts(review: dict[str, Any]) -> Counter[str]:
    """Count exact pointer-byte sites without claiming they are semantic calls."""
    counts: Counter[str] = collections.Counter()
    for site in review.get("inventory", {}).get("sites", []):
        if not isinstance(site, str) or "->" not in site:
            continue
        target = site.split("->", 1)[1].split("+", 1)[0]
        counts[target] += 1
    return counts


def _resolved_external_import_sites(
    review: dict[str, Any], indexed: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Return mechanically resolved import branches/calls keyed by site address."""

    evidence = review.get("evidence")
    if not isinstance(evidence, dict):
        raise NativeBoundaryClusterError(
            "compiler structural indirect-target evidence differs"
        )
    collections_to_validate = (
        ("resolvedExternalImportBranches", "indirect-branch", "branch"),
        ("resolvedExternalImportCalls", "indirect-call", "call"),
    )
    results: list[dict[str, dict[str, str]]] = []
    for field, prefix, kind in collections_to_validate:
        values = evidence.get(field)
        if not isinstance(values, list):
            raise NativeBoundaryClusterError(
                f"compiler structural {field} evidence differs"
            )
        resolved: dict[str, dict[str, str]] = {}
        for value in values:
            if not isinstance(value, dict) \
                    or not isinstance(value.get("site"), str) \
                    or not isinstance(value.get("symbol"), str):
                raise NativeBoundaryClusterError(
                    f"compiler structural {field} row differs"
                )
            parts = value["site"].split(":")
            if len(parts) < 4 or parts[0] != prefix \
                    or not re.fullmatch(r"0x[0-9a-f]{8}", parts[1]) \
                    or parts[-1] not in indexed \
                    or parts[1] in resolved:
                raise NativeBoundaryClusterError(
                    f"compiler structural {field} site differs"
                )
            identifier = parts[-1]
            index_row = indexed[identifier]
            if kind == "branch":
                if value["symbol"] not in index_row.get("imports", []):
                    raise NativeBoundaryClusterError(
                        f"{identifier}: resolved external import symbol differs"
                    )
                raw_sites = {
                    row.get("address")
                    for row in index_row.get("branch_sites", [])
                    if isinstance(row, dict)
                    and row.get("kind") == "unresolved_switch_or_indirect_jump"
                }
            else:
                raw_sites = {
                    row.get("address")
                    for row in index_row.get("unresolved_indirect_calls", [])
                    if isinstance(row, dict)
                }
                definition = value.get("definition")
                if not isinstance(definition, str) \
                        or not re.fullmatch(r"0x[0-9a-f]{8}", definition) \
                        or not (
                            int(index_row["address"], 16)
                            <= int(definition, 16)
                            < int(index_row["end"], 16)
                        ):
                    raise NativeBoundaryClusterError(
                        f"{identifier}: resolved external import definition differs"
                    )
            if parts[1] not in raw_sites:
                raise NativeBoundaryClusterError(
                    f"{identifier}: resolved external import site is not unresolved"
                )
            resolved[parts[1]] = {
                "site": parts[1],
                "symbol": value["symbol"],
                "kind": "INDIRECT_BRANCH" if kind == "branch" else "INDIRECT_CALL",
            }
        results.append(resolved)
    return results[0], results[1]


def _resolved_stack_parameter_call_sites(
    review: dict[str, Any], indexed: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Return exact EBP-parameter callback resolutions keyed by site address."""
    values = review.get("evidence", {}).get("resolvedStackParameterCalls")
    if not isinstance(values, list):
        raise NativeBoundaryClusterError(
            "compiler structural stack-parameter evidence differs"
        )
    resolved = {}
    for value in values:
        if not isinstance(value, dict) \
                or not isinstance(value.get("site"), str) \
                or not isinstance(value.get("functionId"), str) \
                or not isinstance(value.get("targetFunctionIds"), list) \
                or not isinstance(value.get("targetAddresses"), list) \
                or not isinstance(value.get("parameterIndex"), int) \
                or not _is_sha256(value.get("proofSha256")):
            raise NativeBoundaryClusterError(
                "compiler structural stack-parameter row differs"
            )
        parts = value["site"].split(":")
        identifier = value["functionId"]
        if len(parts) != 4 or parts[0] != "indirect-call" \
                or parts[-1] != identifier or identifier not in indexed \
                or parts[1] in resolved \
                or any(target not in indexed for target in value["targetFunctionIds"]):
            raise NativeBoundaryClusterError(
                "compiler structural stack-parameter site differs"
            )
        raw_sites = {
            row.get("address")
            for row in indexed[identifier].get("unresolved_indirect_calls", [])
            if isinstance(row, dict) and row.get("kind") == "memory"
        }
        if parts[1] not in raw_sites:
            raise NativeBoundaryClusterError(
                f"{identifier}: stack-parameter site is not unresolved"
            )
        resolved[parts[1]] = {
            "site": parts[1],
            "kind": "INDIRECT_STACK_PARAMETER_CALL",
            "parameterIndex": value["parameterIndex"],
            "entryInboundProof": value["entryInboundProof"],
            "targetAddresses": value["targetAddresses"],
            "targetFunctionIds": value["targetFunctionIds"],
            "proofSha256": value["proofSha256"],
        }
    return resolved


def _virtual_executable_boundary_correction(
    function_index: dict[str, Any], index_row: dict[str, Any],
) -> dict[str, Any] | None:
    """Exclude exact PE file-alignment padding from executable decode coverage."""
    start = int(index_row["address"], 16)
    indexed_end = int(index_row["end"], 16)
    section = next(
        (
            value for value in function_index.get("sections", [])
            if isinstance(value, dict)
            and value.get("executable") is True
            and isinstance(value.get("address"), str)
            and isinstance(value.get("virtual_size"), int)
            and isinstance(value.get("raw_size"), int)
            and int(value["address"], 16) <= start
            < int(value["address"], 16) + value["virtual_size"]
        ),
        None,
    )
    if section is None:
        return None
    section_start = int(section["address"], 16)
    virtual_end = section_start + section["virtual_size"]
    raw_end = section_start + section["raw_size"]
    if indexed_end <= virtual_end:
        return None
    if not (
        section["virtual_size"] < section["raw_size"]
        and indexed_end == raw_end
        and start < virtual_end
    ):
        return None
    effective_blocks = []
    padding_blocks = []
    cursor = start
    for block in index_row.get("basic_blocks", []):
        block_start = int(block["start"], 16)
        block_end = int(block["end"], 16)
        if block_start >= virtual_end:
            padding_blocks.append(block)
            continue
        if block_start != cursor or block_end > virtual_end \
                or block.get("decoded_instruction_bytes") != block.get("size") \
                or block.get("unknown_skipdata_bytes") != 0:
            return None
        effective_blocks.append(block)
        cursor = block_end
    if cursor != virtual_end or not padding_blocks \
            or int(padding_blocks[0]["start"], 16) != virtual_end:
        return None
    identity = {
        "sectionName": section["name"],
        "sectionAddress": section["address"],
        "sectionVirtualSize": section["virtual_size"],
        "sectionRawSize": section["raw_size"],
        "virtualExecutableEnd": f"0x{virtual_end:08x}",
        "indexedRawEnd": index_row["end"],
        "effectiveSpanBytes": virtual_end - start,
        "excludedFileAlignmentBytes": indexed_end - virtual_end,
        "effectiveBlocks": effective_blocks,
    }
    return {
        **identity,
        "proofSha256": sha256_json(identity),
    }


def _compiler_structural_review(
    code_map: dict[str, Any], function_index: dict[str, Any],
    reviews: dict[str, dict[str, Any]], *,
    function_index_sha256: str,
) -> dict[str, Any]:
    """Review a bounded compiler-candidate tranche using mechanical evidence.

    Structural closure is intentionally weaker than COMPILER_SUBSTITUTION.  It
    can prove a completely decoded CFG, exact recovered native callees and
    individually resolved external import transfers.  It never turns those
    mechanics into compiler provenance, ABI equivalence or replacement proof.
    """
    if function_index.get("schema") != 1 \
            or function_index.get("source") != code_map.get("source") \
            or not _is_sha256(function_index_sha256):
        raise NativeBoundaryClusterError(
            "compiler structural review function index differs"
        )
    if set(reviews) != set(REACHABILITY_CLOSURES) or any(
        not isinstance(review, dict)
        or review.get("protocol") != CLOSURE_REVIEW_PROTOCOL
        or review.get("closure") != name
        or review.get("executableSha256")
            != code_map.get("source", {}).get("sha256")
        or review.get("reviewStatus") not in {"CLOSED", "OPEN"}
        or not _is_sha256(review.get("reviewSha256"))
        for name, review in reviews.items()
    ):
        raise NativeBoundaryClusterError(
            "compiler structural reachability evidence differs"
        )
    for name, review in reviews.items():
        unhashed = dict(review)
        review_sha = unhashed.pop("reviewSha256", None)
        if review_sha != sha256_json(unhashed):
            raise NativeBoundaryClusterError(
                f"compiler structural {name} review hash differs"
            )
    rows = _validate_graph(code_map)
    indexed = {
        f"fn_{int(row['address'], 16):08x}": row
        for row in function_index.get("functions", [])
        if isinstance(row, dict) and isinstance(row.get("address"), str)
    }
    if len(indexed) != len(function_index.get("functions", [])) \
            or set(indexed) != set(rows):
        raise NativeBoundaryClusterError(
            "compiler structural review inventory is not total"
        )
    spans = sorted(
        (
            int(row["address"], 16), int(row["end"], 16), identifier
        )
        for identifier, row in indexed.items()
    )
    span_starts = [start for start, _end, _identifier in spans]

    def owner(address: int) -> str | None:
        position = bisect.bisect_right(span_starts, address) - 1
        if position < 0:
            return None
        start, end, identifier = spans[position]
        return identifier if start <= address < end else None

    compiler_ids = {
        identifier for identifier, row in rows.items()
        if row.get("kind", {}).get("value") == "compiler_runtime_candidate"
    }
    exact_import_ids = {
        identifier for identifier, row in rows.items()
        if row.get("kind", {}).get("value") == "import_thunk"
        and row.get("kind", {}).get("confidence") == "high"
    }
    msvcrt_import_ids = {
        identifier for identifier in exact_import_ids
        if indexed[identifier].get("imports")
        and all(
            isinstance(symbol, str) and symbol.startswith("MSVCRT.dll!")
            for symbol in indexed[identifier]["imports"]
        )
    }
    resolved_import_branches, resolved_import_calls = (
        _resolved_external_import_sites(reviews["indirectTargets"], indexed)
    )
    resolved_parameter_calls = _resolved_stack_parameter_call_sites(
        reviews["indirectTargets"], indexed,
    )
    callback_counts = _pointer_reference_counts(reviews["callbacks"])
    data_counts = _pointer_reference_counts(reviews["vtables"])
    closure_targets = {
        name: set(review["inventory"]["targetFunctionIds"])
        for name, review in reviews.items()
        if review["reviewStatus"] == "CLOSED"
    }
    members_by_scc: dict[str, list[str]] = collections.defaultdict(list)
    for identifier, row in rows.items():
        members_by_scc[row["scc"]].append(identifier)
    for members in members_by_scc.values():
        members.sort()
    reviewed = []
    blocked = []
    reason_counts: Counter[str] = collections.Counter()
    disposition_counts: Counter[str] = collections.Counter()
    resolved_import_transfer_count = 0
    resolved_parameter_call_count = 0
    virtual_boundary_correction_count = 0
    for identifier in sorted(compiler_ids):
        code_row = rows[identifier]
        index_row = indexed[identifier]
        indexed_calls = {
            f"fn_{int(address, 16):08x}"
            for address in index_row.get("calls", [])
        }
        if indexed_calls != set(code_row["calls"]):
            raise NativeBoundaryClusterError(
                f"{identifier}: compiler structural call graph differs"
            )
        branch_targets = {
            owner(int(branch["target"], 16))
            for branch in index_row.get("branch_sites", [])
            if isinstance(branch, dict)
            and isinstance(branch.get("target"), str)
        }
        branch_targets.discard(identifier)
        coverage = index_row.get("analysis_coverage", {})
        virtual_boundary_correction = _virtual_executable_boundary_correction(
            function_index, index_row,
        )
        reasons = []
        if virtual_boundary_correction is None and (
            coverage.get("decoded_instruction_bytes")
                != coverage.get("function_span_bytes")
            or coverage.get("unknown_skipdata_bytes") != 0
            or coverage.get("uncovered_bytes") != 0
        ):
            reasons.append("INCOMPLETE_DECODE")
        if index_row.get("unresolved_direct_calls"):
            reasons.append("UNRESOLVED_DIRECT_CALL")
        raw_indirect_calls = [
            row for row in index_row.get("unresolved_indirect_calls", [])
            if isinstance(row, dict) and isinstance(row.get("address"), str)
        ]
        unresolved_indirect_calls = [
            row["address"] for row in raw_indirect_calls
            if row["address"] not in resolved_import_calls
            and row["address"] not in resolved_parameter_calls
        ]
        if unresolved_indirect_calls:
            reasons.append("UNRESOLVED_INDIRECT_CALL")
        raw_indirect_branches = [
            branch for branch in index_row.get("branch_sites", [])
            if isinstance(branch, dict)
            and branch.get("kind") == "unresolved_switch_or_indirect_jump"
            and isinstance(branch.get("address"), str)
        ]
        unresolved_indirect_branches = [
            branch["address"] for branch in raw_indirect_branches
            if branch["address"] not in resolved_import_branches
        ]
        if unresolved_indirect_branches:
            reasons.append("UNRESOLVED_INDIRECT_BRANCH")
        if None in branch_targets:
            reasons.append("DIRECT_BRANCH_TARGET_OUTSIDE_RECOVERED_FUNCTIONS")
        parameter_call_targets = {
            target
            for row in raw_indirect_calls
            if row["address"] in resolved_parameter_calls
            for target in resolved_parameter_calls[
                row["address"]
            ]["targetFunctionIds"]
        }
        exact_targets = (
            set(code_row["calls"])
            | (branch_targets - {None})
            | parameter_call_targets
        )
        external_recovered_ids = sorted(
            exact_targets - compiler_ids - msvcrt_import_ids
        )
        if reasons:
            reasons = sorted(set(reasons))
            reason_counts.update(reasons)
            blocked.append({
                "functionId": identifier,
                "nativeFunctionSha256": code_row["sha256"],
                "reasons": reasons,
                "unresolvedIndirectCallSites": sorted(unresolved_indirect_calls),
                "unresolvedIndirectBranchSites": sorted(unresolved_indirect_branches),
            })
            continue
        resolved_transfers = sorted(
            (
                resolved_import_calls[row["address"]]
                for row in raw_indirect_calls
                if row["address"] in resolved_import_calls
            ),
            key=lambda row: (row["site"], row["kind"], row["symbol"]),
        ) + sorted(
            (
                resolved_import_branches[row["address"]]
                for row in raw_indirect_branches
            ),
            key=lambda row: (row["site"], row["kind"], row["symbol"]),
        )
        resolved_callbacks = sorted(
            (
                resolved_parameter_calls[row["address"]]
                for row in raw_indirect_calls
                if row["address"] in resolved_parameter_calls
            ),
            key=lambda row: (row["site"], row["proofSha256"]),
        )
        if external_recovered_ids and resolved_transfers:
            structural_disposition = (
                "RECOVERED_NATIVE_AND_EXTERNAL_IMPORT_BOUNDARY"
            )
        elif external_recovered_ids:
            structural_disposition = "RECOVERED_NATIVE_CALL_BOUNDARY"
        elif resolved_transfers:
            structural_disposition = "EXTERNAL_IMPORT_TRANSFER_BOUNDARY"
        else:
            structural_disposition = "CLOSED_COMPILER_CANDIDATE_GRAPH"
        disposition_counts[structural_disposition] += 1
        resolved_import_transfer_count += len(resolved_transfers)
        resolved_parameter_call_count += len(resolved_callbacks)
        virtual_boundary_correction_count += int(
            virtual_boundary_correction is not None
        )
        effective_blocks = (
            virtual_boundary_correction["effectiveBlocks"]
            if virtual_boundary_correction is not None
            else index_row["basic_blocks"]
        )
        cfg_identity = {
            "entry": index_row["address"],
            "blocks": effective_blocks,
            "branches": index_row["branch_sites"],
        }
        external_recovered_targets = []
        for target in external_recovered_ids:
            target_row = rows[target]
            target_identity = {
                "functionId": target,
                "nativeFunctionSha256": target_row["sha256"],
                "scc": target_row["scc"],
                "entrypointReachable": target_row["entrypoint_reachable"],
                "kind": target_row.get("kind", {}).get("value", "UNKNOWN"),
                "ownershipDisposition": target_row.get(
                    "ownership", {}
                ).get("disposition", "UNKNOWN"),
            }
            external_recovered_targets.append({
                **target_identity,
                "identitySha256": sha256_json(target_identity),
            })
        exact_runtime_import_markers = sorted(
            symbol for symbol in index_row.get("imports", [])
            if any(marker in symbol for marker in (
                "CxxFrameHandler", "except_handler", "XcptFilter",
                "_initterm", "_purecall", "_ftol",
            ))
        )
        reviewed.append({
            "functionId": identifier,
            "nativeFunctionSha256": code_row["sha256"],
            "cfgSha256": sha256_json(cfg_identity),
            "structuralDisposition": structural_disposition,
            "semanticGameplayPromotion": False,
            "entrypointReachable": code_row["entrypoint_reachable"],
            "scc": {
                "id": code_row["scc"],
                "members": members_by_scc[code_row["scc"]],
                "atomicWithinCompilerCandidates": set(
                    members_by_scc[code_row["scc"]]
                ).issubset(compiler_ids),
            },
            "compilerTargets": sorted(
                exact_targets & compiler_ids
            ),
            "exactMsvcrtImportTargets": sorted(
                exact_targets & msvcrt_import_ids
            ),
            "externalRecoveredTargets": external_recovered_targets,
            "resolvedExternalImportTransfers": resolved_transfers,
            "resolvedStackParameterCalls": resolved_callbacks,
            "virtualExecutableBoundaryCorrection": (
                virtual_boundary_correction
            ),
            "exactRuntimeImportMarkers": exact_runtime_import_markers,
            "externalDirectCallers": sorted(
                set(code_row["callers"]) - compiler_ids
            ),
            "closedClosureMemberships": sorted(
                name for name, targets in closure_targets.items()
                if identifier in targets
            ),
            "executablePointerSiteCount": callback_counts[identifier],
            "dataPointerSiteCount": data_counts[identifier],
        })
    reviewed_members = [
        {
            "functionId": row["functionId"],
            "nativeFunctionSha256": row["nativeFunctionSha256"],
        }
        for row in reviewed
    ]
    external_recovered_target_ids = {
        target["functionId"]
        for row in reviewed for target in row["externalRecoveredTargets"]
    }
    value = {
        "reviewStatus": "REVIEWED",
        "structuralClass": "EXACT_RECOVERED_CONTROL_FLOW_BOUNDARIES",
        "disposition": "UNKNOWN",
        "candidateCount": len(compiler_ids),
        "reviewedMemberCount": len(reviewed),
        "blockedMemberCount": len(blocked),
        "structuralDispositionCounts": dict(sorted(disposition_counts.items())),
        "expandedBoundaryMemberCount": (
            len(reviewed)
            - disposition_counts["CLOSED_COMPILER_CANDIDATE_GRAPH"]
        ),
        "resolvedExternalImportTransferCount": resolved_import_transfer_count,
        "resolvedStackParameterCallCount": resolved_parameter_call_count,
        "virtualBoundaryCorrectionMemberCount": (
            virtual_boundary_correction_count
        ),
        "externalRecoveredTargetCount": len(external_recovered_target_ids),
        "sccAtomicMemberCount": sum(
            row["scc"]["atomicWithinCompilerCandidates"] for row in reviewed
        ),
        "runtimeImportMarkerMemberCount": sum(
            bool(row["exactRuntimeImportMarkers"]) for row in reviewed
        ),
        "reviewedMembershipSha256": sha256_json(reviewed_members),
        "reviewedMembers": reviewed,
        "blockedMembers": blocked,
        "blockedReasonCounts": dict(sorted(reason_counts.items())),
        "exactMsvcrtImportThunkIds": sorted(msvcrt_import_ids),
        "sourceEvidence": {
            "functionIndexSha256": function_index_sha256,
            "reachabilityReviewSha256": {
                name: reviews[name]["reviewSha256"]
                for name in sorted(reviews)
            },
        },
        "policy": {
            "requiresCompleteDecode": True,
            "requiresEveryIndirectSiteResolvedOrBlocked": True,
            "exactRecoveredNativeTargetsAreStructuralBoundariesOnly": True,
            "resolvedExternalImportsAreTransferEvidenceOnly": True,
            "resolvedStackParametersAreTransferEvidenceOnly": True,
            "rawSectionAlignmentPaddingCountsAsExecutableDecode": False,
            "runtimeImportMarkersAreProvenanceEvidence": False,
            "pointerSitesAreReachabilityEvidenceOnly": True,
            "structuralReviewIsCompilerProvenance": False,
            "structuralReviewIsSubstitutionEvidence": False,
            "semanticGameplayPromotion": False,
        },
        "remainingPromotionBlockers": [
            "reviewed exact compiler/runtime provenance",
            "exact ABI/import mapping",
            "hash-bound executed release replacement",
        ],
    }
    return {**value, "reviewSha256": sha256_json(value)}


def _import_structural_review(
    code_map: dict[str, Any], function_index: dict[str, Any],
    import_audit: dict[str, Any], *, function_index_sha256: str,
) -> dict[str, Any]:
    """Separate exact import-boundary classification from replacement proof."""
    if function_index.get("schema") != 1 \
            or function_index.get("source") != code_map.get("source") \
            or not _is_sha256(function_index_sha256) \
            or import_audit.get("protocol") \
                != "miel-vliegt-native-import-thunk-audit" \
            or not _is_sha256(import_audit.get("receiptSha256")):
        raise NativeBoundaryClusterError(
            "import structural review source identity differs"
        )
    rows = _validate_graph(code_map)
    indexed = {
        f"fn_{int(row['address'], 16):08x}": row
        for row in function_index.get("functions", [])
        if isinstance(row, dict) and isinstance(row.get("address"), str)
    }
    decisions = {
        row["functionId"]: row
        for row in import_audit.get("decisions", [])
        if isinstance(row, dict) and isinstance(row.get("functionId"), str)
    }
    candidate_ids = {
        identifier for identifier, row in rows.items()
        if row.get("kind", {}).get("value") == "import_thunk"
        and row.get("kind", {}).get("confidence") == "high"
    }
    if set(indexed) != set(rows) or set(decisions) != candidate_ids:
        raise NativeBoundaryClusterError(
            "import structural review inventory differs"
        )
    reviewed = []
    for identifier in sorted(candidate_ids):
        code_row = rows[identifier]
        index_row = indexed[identifier]
        decision = decisions[identifier]
        coverage = index_row.get("analysis_coverage", {})
        imports = index_row.get("imports")
        interfaces = decision.get("nativeInterfaces")
        if not isinstance(imports, list) or len(imports) != 1 \
                or interfaces != {
                    "fallback": f"native-function:{identifier}",
                    "imports": imports,
                } \
                or index_row.get("calls") != [] \
                or index_row.get("unresolved_direct_calls") != [] \
                or index_row.get("unresolved_indirect_calls") != [] \
                or coverage.get("decoded_instruction_bytes") \
                    != coverage.get("function_span_bytes") \
                or coverage.get("unknown_skipdata_bytes") != 0 \
                or coverage.get("uncovered_bytes") != 0 \
                or decision.get("nativeFunctionSha256") != code_row["sha256"]:
            raise NativeBoundaryClusterError(
                f"{identifier}: exact import-boundary structure differs"
            )
        reviewed.append({
            "functionId": identifier,
            "nativeFunctionSha256": code_row["sha256"],
            "nativeInterface": imports[0],
            "auditDecisionSha256": decision["decisionSha256"],
            "replacementStatus": decision["status"],
        })
    members = [
        {
            "functionId": row["functionId"],
            "nativeFunctionSha256": row["nativeFunctionSha256"],
        }
        for row in reviewed
    ]
    value = {
        "reviewStatus": "REVIEWED",
        "structuralClass": "EXACT_ONE_IMPORT_IAT_THUNK",
        "disposition": "IMPORT_BOUNDARY",
        "reviewedMemberCount": len(reviewed),
        "reviewedMembershipSha256": sha256_json(members),
        "reviewedMembers": reviewed,
        "promotableMemberCount": sum(
            row["replacementStatus"] == "COMPLETE" for row in reviewed
        ),
        "sourceEvidence": {
            "functionIndexSha256": function_index_sha256,
            "importAuditReceiptSha256": import_audit["receiptSha256"],
        },
        "policy": {
            "classificationRequiresExactOneImportThunk": True,
            "classificationIsReplacementEvidence": False,
            "completionRequiresExecutedReleaseReplacement": True,
            "semanticGameplayPromotion": False,
        },
    }
    return {**value, "reviewSha256": sha256_json(value)}


def _validate_closure_review(
    review: Any, *, name: str, audit: dict[str, Any],
    cluster: dict[str, Any], rows: dict[str, dict[str, Any]], root: Path,
) -> tuple[str, set[str]]:
    try:
        from tools.miel_vliegt import native_reachability_closures as closures
    except ModuleNotFoundError:  # Direct script execution.
        import native_reachability_closures as closures

    fields = {
        "schema", "protocol", "reviewStatus", "closure",
        "executableSha256", "codeMapSha256", "candidateMembershipSha256",
        "functionIndexSha256", "generatorSha256",
        "inventory", "evidence", "unresolvedPaths", "reviewSha256",
    }
    if not isinstance(review, dict) or set(review) != fields \
            or review.get("schema") != closures.SCHEMA \
            or review.get("protocol") != CLOSURE_REVIEW_PROTOCOL \
            or review.get("reviewStatus") != "CLOSED" \
            or review.get("closure") != name \
            or review.get("executableSha256") \
                != audit.get("source", {}).get("executableSha256") \
            or review.get("codeMapSha256") \
                != audit.get("source", {}).get("codeMap", {}).get("sha256") \
            or review.get("candidateMembershipSha256") \
                != cluster.get("membershipSha256") \
            or review.get("unresolvedPaths") != []:
        raise NativeBoundaryClusterError(
            f"unreachable {name} closure review identity differs"
        )
    try:
        closures.validate_review(review, closure=name, root=root)
    except closures.NativeReachabilityClosureError as error:
        raise NativeBoundaryClusterError(
            f"unreachable {name} closure review is not mechanically valid: {error}"
        ) from error
    unhashed = dict(review)
    review_sha = unhashed.pop("reviewSha256", None)
    if review_sha != sha256_json(unhashed):
        raise NativeBoundaryClusterError(
            f"unreachable {name} closure review hash differs"
        )
    inventory = review.get("inventory")
    if not isinstance(inventory, dict) or set(inventory) != {
        "sites", "targetFunctionIds", "inventorySha256",
    }:
        raise NativeBoundaryClusterError(
            f"unreachable {name} target inventory differs"
        )
    sites = inventory["sites"]
    targets = inventory["targetFunctionIds"]
    if not isinstance(sites, list) or not isinstance(targets, list) \
            or len(sites) != len(set(sites)) \
            or len(targets) != len(set(targets)) \
            or any(not isinstance(site, str) or not site for site in sites) \
            or any(target not in rows for target in targets):
        raise NativeBoundaryClusterError(
            f"unreachable {name} target inventory is not total"
        )
    if name == "roots":
        expected_sites = [f"pe-entrypoint:{audit['source']['entrypoint']}"]
        expected_targets = sorted(
            identifier for identifier, row in rows.items()
            if row["entrypoint_reachable"]
        )
        if sites != expected_sites or targets != expected_targets \
                or review.get("evidence", {}).get("directRootProofSha256") \
                    != cluster["graph"]["directRootProofSha256"]:
            raise NativeBoundaryClusterError(
                "unreachable roots inventory differs from the direct graph"
            )
    identity = {
        "closure": name,
        "sites": sites,
        "targetFunctionIds": targets,
    }
    if inventory.get("inventorySha256") != sha256_json(identity):
        raise NativeBoundaryClusterError(
            f"unreachable {name} target inventory hash differs"
        )
    return review_sha, set(targets)


def build_unreachable_boundary(
    audit: dict[str, Any], code_map: dict[str, Any],
    closure_reviews: dict[str, Any], *, root: Path = ROOT,
) -> dict[str, Any]:
    """Build a completion receipt only after every inbound path class is closed."""
    cluster = _cluster_by_id(audit, "cluster:proven-unreachable-candidates")
    if cluster.get("disposition") != "PROVEN_UNREACHABLE":
        raise NativeBoundaryClusterError("unreachable cluster disposition differs")
    rows = _validate_graph(code_map)
    source = code_map.get("source", {})
    if source.get("sha256") != audit.get("source", {}).get("executableSha256") \
            or source.get("entrypoint") != audit.get("source", {}).get("entrypoint") \
            or source.get("image_base") != audit.get("source", {}).get("imageBase"):
        raise NativeBoundaryClusterError(
            "unreachable receipt code map targets another executable"
        )
    for member in cluster["members"]:
        row = rows.get(member["functionId"])
        if row is None or row["sha256"] != member["nativeFunctionSha256"]:
            raise NativeBoundaryClusterError(
                "unreachable cluster member identity differs from the code map"
            )
    direct_root_identity = {
        "entrypoint": source["entrypoint"],
        "candidateMembers": cluster["members"],
        "reachableFunctions": sorted(
            identifier for identifier, row in rows.items()
            if row["entrypoint_reachable"]
        ),
        "directCallEdges": sorted(
            f"{identifier}->{target}"
            for identifier, row in rows.items() for target in row["calls"]
        ),
    }
    if sha256_json(direct_root_identity) \
            != cluster.get("graph", {}).get("directRootProofSha256"):
        raise NativeBoundaryClusterError(
            "unreachable direct-root graph differs from the cluster audit"
        )
    if not isinstance(closure_reviews, dict) \
            or set(closure_reviews) != set(REACHABILITY_CLOSURES):
        raise NativeBoundaryClusterError(
            "unreachable promotion requires roots, callbacks, vtables and indirectTargets"
        )
    validated_reviews = {
        name: _validate_closure_review(
            closure_reviews[name], name=name, audit=audit,
            cluster=cluster, rows=rows, root=root,
        )
        for name in REACHABILITY_CLOSURES
    }
    reachability_closure = {
        name: {
            "closed": True,
            "reviewedTargetsSha256": validated_reviews[name][0],
            "unresolvedPaths": [],
        }
        for name in REACHABILITY_CLOSURES
    }

    reached = set().union(*(
        targets for _, targets in validated_reviews.values()
    ))
    queue = collections.deque(sorted(reached))
    while queue:
        identifier = queue.popleft()
        for target in rows[identifier]["calls"]:
            if target not in reached:
                reached.add(target)
                queue.append(target)
    claimable_members = [
        member for member in cluster["members"]
        if member["functionId"] not in reached
    ]
    if not claimable_members:
        raise NativeBoundaryClusterError(
            "closed native reachability inventories leave no unreachable functions"
        )

    boundary_id = "boundary:proven-unreachable:closed-native-graph"
    claims = []
    for member in claimable_members:
        identity = {
            "boundaryId": boundary_id,
            "disposition": "PROVEN_UNREACHABLE",
            "functionId": member["functionId"],
            "nativeFunctionSha256": member["nativeFunctionSha256"],
        }
        claims.append({
            **identity,
            "membershipSha256": sha256_json(identity),
        })
    value = {
        "schema": 1,
        "protocol": BOUNDARY_PROTOCOL,
        "reviewStatus": "REVIEWED",
        "boundaryId": boundary_id,
        "disposition": "PROVEN_UNREACHABLE",
        "claims": claims,
        "reachabilityClosure": reachability_closure,
    }
    return {**value, "boundarySha256": sha256_json(value)}


def validate_unreachable_boundary(
    receipt: dict[str, Any], audit: dict[str, Any],
    code_map: dict[str, Any], closure_reviews: dict[str, Any], *,
    root: Path = ROOT,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise NativeBoundaryClusterError("unreachable boundary receipt is not an object")
    expected = build_unreachable_boundary(
        audit, code_map, closure_reviews, root=root,
    )
    if receipt != expected:
        raise NativeBoundaryClusterError("unreachable boundary receipt drifted")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-unreachable", type=Path)
    parser.add_argument(
        "--closure-review", action="append", type=Path, default=[],
        help="one reviewed roots/callbacks/vtables/indirectTargets closure document",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    audit = build_from_root(root)
    if args.verify_unreachable is not None:
        reviews = [load_json(path) for path in args.closure_review]
        by_name = {
            review.get("closure"): review for review in reviews
            if isinstance(review.get("closure"), str)
        }
        if len(reviews) != len(REACHABILITY_CLOSURES) \
                or len(by_name) != len(REACHABILITY_CLOSURES):
            raise SystemExit(
                "--verify-unreachable requires exactly one review for each closure"
            )
        validate_unreachable_boundary(
            load_json(args.verify_unreachable), audit,
            load_json(root / CODE_MAP), by_name,
        )
        print("native unreachable boundary receipt OK")
        return 0

    output = args.output or root / OUTPUT
    encoded = json.dumps(audit, sort_keys=True, separators=(",", ":")) + "\n"
    if args.check:
        current = output.read_text(encoding="utf-8") if output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True),
                encoded.splitlines(keepends=True),
                fromfile=str(output),
                tofile="fresh native boundary cluster audit",
            ))
            raise SystemExit(f"native boundary cluster audit drifted:\n{diff}")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    summary = audit["summary"]
    print(
        "native boundary clusters OK: "
        f"unreachable={summary['candidates']['PROVEN_UNREACHABLE']}, "
        f"imports={summary['candidates']['IMPORT_BOUNDARY']}, "
        f"compiler={summary['candidates']['COMPILER_SUBSTITUTION']}, "
        f"promotable={sum(summary['promotable'].values())}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
