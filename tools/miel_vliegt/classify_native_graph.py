#!/usr/bin/env python3
"""Build a complete, conservative static code map from the native function index."""

from __future__ import annotations

import argparse
import collections
import difflib
import hashlib
import json
import sys
from pathlib import Path
from typing import Iterable


COMPILER_RUNTIME_CANDIDATE_START = 0x00448000
RESOURCE_DISPOSITIONS = {
    "SOURCE_REFERENCED", "SOURCE_NAMESPACE", "SOURCE_MISSING", "DESCOPED"
}


def _normalise_resource_path(value: str) -> str | None:
    """Return the canonical form of a native ``Data\\...`` resource string."""
    path = value.strip().replace("/", "\\").lower()
    return path if path.startswith("data\\") else None


def _resource_inventory(
    functions: list[dict[str, object]], seeds: dict[str, object]
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    references: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for function in functions:
        for string in function["strings"]:
            path = _normalise_resource_path(string["value"])
            if path is not None:
                references[path].append({
                    "function": _function_id(function["address"]),
                    "string_address": string["address"],
                    "native_value": string["value"],
                })

    policy = seeds.get("resource_inventory")
    if not isinstance(policy, dict):
        raise ValueError("reviewed seeds lack native resource inventory policy")
    paths = sorted(references)
    digest = hashlib.sha256("\n".join(paths).encode("utf-8")).hexdigest()
    if policy.get("sha256") != digest:
        raise ValueError(
            "native Data resource inventory drifted; review every added or removed path "
            f"before updating the pinned digest (actual {digest})"
        )
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("native resource inventory needs reviewed disposition rules")
    rule_ids = [rule.get("id") for rule in rules]
    if len(rule_ids) != len(set(rule_ids)) or any(not item for item in rule_ids):
        raise ValueError("native resource disposition rule ids must be unique and non-empty")

    assignments: dict[str, dict[str, object]] = {}
    for path in paths:
        matches = []
        for rule in rules:
            exact = rule.get("exact")
            prefix = rule.get("prefix")
            if (exact is not None) == (prefix is not None):
                raise ValueError(f"resource rule {rule['id']} needs exactly one of exact/prefix")
            needle = _normalise_resource_path(exact if exact is not None else prefix)
            if needle is None:
                raise ValueError(f"resource rule {rule['id']} does not target Data\\")
            if path == needle if exact is not None else path.startswith(needle):
                matches.append((len(needle), rule))
        if not matches:
            raise ValueError(f"native resource has no reviewed disposition: {path}")
        specificity = max(length for length, _rule in matches)
        winners = [rule for length, rule in matches if length == specificity]
        if len(winners) != 1:
            raise ValueError(f"native resource has ambiguous disposition rules: {path}")
        rule = winners[0]
        if rule.get("disposition") not in RESOURCE_DISPOSITIONS:
            raise ValueError(f"resource rule {rule['id']} has invalid disposition")
        if not isinstance(rule.get("evidence"), str) or not rule["evidence"].strip():
            raise ValueError(f"resource rule {rule['id']} lacks review evidence")
        assignments[path] = rule

    counts = collections.Counter(rule["disposition"] for rule in assignments.values())
    expected_counts = policy.get("counts")
    actual_counts = {key: counts[key] for key in sorted(RESOURCE_DISPOSITIONS)}
    if expected_counts != actual_counts:
        raise ValueError(
            f"native resource disposition counts drifted: expected {expected_counts}, "
            f"actual {actual_counts}"
        )
    return ({
        "paths": len(paths),
        "references": sum(map(len, references.values())),
        "sha256": digest,
        "dispositions": actual_counts,
        "all_classified": len(assignments) == len(paths),
    }, {
        path: {
            "path": path,
            "kind": "template" if "%" in path or "*" in path else "concrete",
            "disposition": assignments[path]["disposition"],
            "rule": assignments[path]["id"],
            "evidence": assignments[path]["evidence"],
            "references": references[path],
        }
        for path in paths
    })


def verify_resource_sources(
    source: Path, resources: list[dict[str, object]]
) -> None:
    """Validate concrete source claims against a decoded source tree.

    A previously absent source becoming available is useful new evidence, not a
    reason to keep carrying a stale ``SOURCE_MISSING`` exception. Template paths
    are explicitly reported as templates and cannot make an exact existence
    claim; their expansions are validated by the downstream harvesters.
    """
    available = {
        path.relative_to(source).as_posix().lower().rstrip("/")
        for path in source.rglob("*")
    }

    def exists(resource_path: str) -> bool:
        candidate = resource_path.replace("\\", "/").rstrip("/")
        return candidate in available or any(
            path.startswith(candidate + "/") for path in available
        )

    # SOURCE_NAMESPACE is reserved for exact, reviewed logical lookup roots.
    # It never grants a broad prefix exemption to concrete resource strings.
    missing = sorted(
        resource["path"]
        for resource in resources
        if resource["disposition"] == "SOURCE_REFERENCED"
        and resource["kind"] == "concrete"
        and not exists(resource["path"])
    )
    if missing:
        raise ValueError(
            "concrete native SOURCE_REFERENCED resources are absent from the decoded source: "
            + ", ".join(missing)
        )
    stale = sorted(
        resource["path"]
        for resource in resources
        if resource["disposition"] == "SOURCE_MISSING"
        and exists(resource["path"])
    )
    if stale:
        raise ValueError(
            "native resources marked SOURCE_MISSING now exist in the decoded source: "
            + ", ".join(stale)
        )


def _function_id(address: str) -> str:
    return f"fn_{int(address, 16):08x}"


def _reachable(graph: dict[str, tuple[str, ...]], seeds: Iterable[str]) -> set[str]:
    seen = set(seeds)
    queue = collections.deque(sorted(seen))
    while queue:
        address = queue.popleft()
        for target in graph[address]:
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def _paths(graph: dict[str, tuple[str, ...]], seeds: Iterable[str]) -> dict[str, list[str]]:
    """Return one deterministic shortest direct-call path from the seed set."""
    parents: dict[str, str | None] = {}
    queue = collections.deque()
    for seed in sorted(seeds):
        parents[seed] = None
        queue.append(seed)
    while queue:
        address = queue.popleft()
        for target in graph[address]:
            if target not in parents:
                parents[target] = address
                queue.append(target)
    result = {}
    for address in parents:
        path = []
        cursor: str | None = address
        while cursor is not None:
            path.append(cursor)
            cursor = parents[cursor]
        result[address] = list(reversed(path))
    return result


def _strong_components(graph: dict[str, tuple[str, ...]]) -> list[list[str]]:
    sys.setrecursionlimit(max(10000, len(graph) * 2))
    next_index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(address: str) -> None:
        nonlocal next_index
        indexes[address] = next_index
        lowlinks[address] = next_index
        next_index += 1
        stack.append(address)
        on_stack.add(address)
        for target in graph[address]:
            if target not in indexes:
                visit(target)
                lowlinks[address] = min(lowlinks[address], lowlinks[target])
            elif target in on_stack:
                lowlinks[address] = min(lowlinks[address], indexes[target])
        if lowlinks[address] == indexes[address]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == address:
                    break
            components.append(sorted(component))

    for address in sorted(graph):
        if address not in indexes:
            visit(address)
    return sorted(components, key=lambda component: component[0])


def _weak_component_sizes(graph: dict[str, tuple[str, ...]]) -> list[int]:
    undirected = {address: set(targets) for address, targets in graph.items()}
    for address, targets in graph.items():
        for target in targets:
            undirected[target].add(address)
    seen = set()
    sizes = []
    for address in sorted(graph):
        if address in seen:
            continue
        component = {address}
        queue = [address]
        seen.add(address)
        while queue:
            current = queue.pop()
            for neighbour in undirected[current]:
                if neighbour not in seen:
                    seen.add(neighbour)
                    component.add(neighbour)
                    queue.append(neighbour)
        sizes.append(len(component))
    return sorted(sizes, reverse=True)


def _kind(function: dict[str, object]) -> dict[str, object]:
    strict_import_thunk = (
        function["size"] <= 10
        and len(function["imports"]) == 1
        and not function["calls"]
        and not function["strings"]
    )
    if strict_import_thunk:
        return {
            "value": "import_thunk",
            "confidence": "high",
            "evidence": ["size<=10", "one imported jump/call", "no internal calls or strings"],
        }
    if int(function["address"], 16) >= COMPILER_RUNTIME_CANDIDATE_START and not function["strings"]:
        return {
            "value": "compiler_runtime_candidate",
            "confidence": "low",
            "evidence": ["stringless function in the compiler/runtime tail region >=0x00448000"],
        }
    return {
        "value": "native_function",
        "confidence": "low",
        "evidence": ["heuristic executable function span; debug symbols are unavailable"],
    }


def build(index: dict[str, object], seeds: dict[str, object]) -> dict[str, object]:
    if index.get("schema") != 1 or seeds.get("schema") != 1:
        raise ValueError("unsupported native index or seed schema")
    if index["source"]["sha256"] != seeds["image_sha256"]:
        raise ValueError("native index and reviewed seeds target different executables")

    functions = index.get("functions")
    if not isinstance(functions, list) or len(functions) != index["counts"]["functions"]:
        raise ValueError("native function inventory is incomplete")
    by_address = {function["address"]: function for function in functions}
    resource_summary, resources = _resource_inventory(functions, seeds)
    if len(by_address) != len(functions):
        raise ValueError("native function index contains duplicate addresses")
    if any("unresolved_indirect_calls" not in function for function in functions):
        raise ValueError("native function index predates indirect-call accounting")
    if any("unresolved_direct_calls" not in function for function in functions):
        raise ValueError("native function index predates unresolved direct-call accounting")
    if any("basic_blocks" not in function or "branch_sites" not in function for function in functions):
        raise ValueError("native function index predates basic-block accounting")
    graph = {
        address: tuple(sorted(function["calls"]))
        for address, function in by_address.items()
    }
    unknown_targets = sorted({target for targets in graph.values() for target in targets} - set(graph))
    if unknown_targets:
        raise ValueError(f"callgraph contains unknown function targets: {unknown_targets[:3]}")

    reviewed = {}
    seeds_by_module: dict[str, set[str]] = collections.defaultdict(set)
    for seed in seeds["functions"]:
        address = f"0x{int(seed['address'], 16):08x}"
        function = by_address.get(address)
        if function is None or function.get("name") != seed["name"]:
            raise ValueError(f"reviewed seed missing from native index: {seed['name']}")
        reviewed[address] = seed
        seeds_by_module[seed["module"]].add(address)

    entrypoint = index["source"]["entrypoint"]
    if entrypoint not in graph:
        raise ValueError("entrypoint is not represented as a recovered function")
    entry_reachable = _reachable(graph, [entrypoint])
    module_paths = {
        module: _paths(graph, module_seeds)
        for module, module_seeds in sorted(seeds_by_module.items())
    }

    components = _strong_components(graph)
    component_by_address = {}
    component_rows = []
    for component in components:
        component_id = f"scc_{int(component[0], 16):08x}"
        cyclic = len(component) > 1 or component[0] in graph[component[0]]
        for address in component:
            component_by_address[address] = component_id
        component_rows.append({
            "id": component_id,
            "size": len(component),
            "cyclic": cyclic,
            "members": [_function_id(address) for address in component],
        })

    callers: dict[str, list[str]] = {address: [] for address in graph}
    for address, targets in graph.items():
        for target in targets:
            callers[target].append(address)

    rows = []
    ownership_counts: collections.Counter[str] = collections.Counter()
    kind_counts: collections.Counter[str] = collections.Counter()
    for address in sorted(graph):
        function = by_address[address]
        candidate_modules = [
            module for module, paths in module_paths.items() if address in paths
        ]
        if address in reviewed:
            ownership = {
                "status": "reviewed",
                "disposition": "GAME_OWNED",
                "modules": [reviewed[address]["module"]],
                "confidence": "high",
                "evidence": [f"signature-pinned seed {reviewed[address]['name']}"],
                "paths": {},
            }
        elif candidate_modules:
            ownership = {
                "status": "candidate",
                "disposition": "UNKNOWN",
                "modules": candidate_modules,
                "confidence": "low",
                "evidence": [
                    "direct-call reachable from reviewed seed; virtual and indirect callbacks are unresolved"
                ],
                "paths": {
                    module: [_function_id(item) for item in module_paths[module][address]]
                    for module in candidate_modules
                },
            }
        else:
            ownership = {
                "status": "unassigned",
                "disposition": "UNKNOWN",
                "modules": [],
                "confidence": "none",
                "evidence": ["no reviewed gameplay seed reaches this function by a recovered direct call"],
                "paths": {},
            }
        ownership_counts[ownership["status"]] += 1
        kind = _kind(function)
        kind_counts[kind["value"]] += 1
        indirect = function["unresolved_indirect_calls"]
        unresolved_direct = function["unresolved_direct_calls"]
        rows.append({
            "id": _function_id(address),
            "address": address,
            "end": function["end"],
            "size": function["size"],
            "sha256": function["sha256"],
            "name": function["name"],
            "module": function["module"],
            "scc": component_by_address[address],
            "entrypoint_reachable": address in entry_reachable,
            "calls": [_function_id(target) for target in graph[address]],
            "callers": [_function_id(caller) for caller in sorted(callers[address])],
            "kind": kind,
            "ownership": ownership,
            "unresolved_indirect_call_count": len(indirect),
            "has_unresolved_indirect_calls": bool(indirect),
            "unresolved_direct_call_count": len(unresolved_direct),
            "has_unresolved_direct_calls": bool(unresolved_direct),
            "basic_blocks": [block["id"] for block in function["basic_blocks"]],
            "branch_counts": dict(sorted(collections.Counter(
                site["kind"] for site in function["branch_sites"]
            ).items())),
            "analysis_coverage": function["analysis_coverage"],
        })

    indirect_sites = sum(row["unresolved_indirect_call_count"] for row in rows)
    indirect_functions = sum(row["has_unresolved_indirect_calls"] for row in rows)
    direct_unresolved_sites = sum(row["unresolved_direct_call_count"] for row in rows)
    direct_unresolved_functions = sum(row["has_unresolved_direct_calls"] for row in rows)
    cyclic_components = sum(component["cyclic"] for component in component_rows)
    basic_blocks = sum(len(function["basic_blocks"]) for function in functions)
    unknown_blocks = sum(
        block["unknown_skipdata_bytes"] > 0
        for function in functions for block in function["basic_blocks"]
    )
    unresolved_branches = sum(
        site["kind"] == "unresolved_switch_or_indirect_jump"
        for function in functions for site in function["branch_sites"]
    )
    return {
        "schema": 1,
        "source": index["source"],
        "policy": {
            "reviewed_ownership": "Only signature-pinned seeds assert gameplay ownership.",
            "ownership_disposition": "Review state is separate from GAME_OWNED, ENGINE_OWNED, PLATFORM_OWNED, COMPILER_RUNTIME or UNKNOWN disposition.",
            "candidate_ownership": "Direct-call reachability is evidence, not a gameplay-equivalence claim.",
            "library_boundary": "Compiler/runtime is a low-confidence address-and-string heuristic, never ownership proof.",
            "indirect_calls": "Unresolved indirect calls make all reachability figures lower bounds.",
            "native_resources": "Every recovered Data path is digest-pinned and assigned a reviewed disposition; SOURCE_REFERENCED means a native source reference, not proof of a web export.",
        },
        "summary": {
            "functions": len(rows),
            "stable_ids": len({row["id"] for row in rows}),
            "direct_call_edges": sum(len(targets) for targets in graph.values()),
            "entrypoint_reachable": len(entry_reachable),
            "entrypoint_unreachable": len(rows) - len(entry_reachable),
            "reviewed_named_functions": len(reviewed),
            "ownership": dict(sorted(ownership_counts.items())),
            "kinds": dict(sorted(kind_counts.items())),
            "sccs": len(component_rows),
            "cyclic_sccs": cyclic_components,
            "cyclic_functions": sum(component["size"] for component in component_rows if component["cyclic"]),
            "largest_scc": max(component["size"] for component in component_rows),
            "weak_components": len(_weak_component_sizes(graph)),
            "weak_component_sizes": _weak_component_sizes(graph),
            "functions_with_unresolved_indirect_calls": indirect_functions,
            "unresolved_indirect_call_sites": indirect_sites,
            "functions_with_unresolved_direct_calls": direct_unresolved_functions,
            "unresolved_direct_call_sites": direct_unresolved_sites,
            "basic_blocks": basic_blocks,
            "basic_blocks_with_unknown_bytes": unknown_blocks,
            "direct_conditional_branches": sum(
                site["kind"] == "direct_conditional"
                for function in functions for site in function["branch_sites"]
            ),
            "unresolved_switch_or_indirect_branches": unresolved_branches,
            "executable_byte_coverage": {
                "executable_bytes": index["counts"]["executable_bytes"],
                "function_span_bytes": index["counts"]["function_span_bytes"],
                "decoded_instruction_bytes": index["counts"]["decoded_instruction_bytes"],
                "unknown_skipdata_bytes": index["counts"]["unknown_skipdata_bytes"],
                "uncovered_executable_bytes": index["counts"]["uncovered_executable_bytes"],
                "semantic_coverage_claimed": False,
            },
            "inventory_disposition_complete": len(rows) == sum(ownership_counts.values()),
            "semantic_classification_complete": (
                ownership_counts["candidate"] == 0
                and ownership_counts["unassigned"] == 0
                and index["counts"]["unknown_skipdata_bytes"] == 0
                and indirect_sites == 0
                and unresolved_branches == 0
            ),
            "resources": resource_summary,
        },
        "limitations": [
            "Function boundaries are recovered from direct-call targets and alignment padding, not debug symbols.",
            "Basic blocks are syntactic partitions of those heuristic function spans, not proof of complete control-flow recovery.",
            "Skipdata and bytes outside recovered function spans remain explicitly unknown executable bytes.",
            "Virtual, callback, register-indirect and unresolved memory calls are not callgraph edges.",
            "Entrypoint and reviewed-seed reachability are lower bounds.",
            "Resource coverage scans strings in every recovered function so indirect-call gaps cannot hide literal Data paths; paths assembled only at runtime remain unknown.",
            "Candidate ownership must not be promoted to EQUIVALENT without independent behavioral evidence.",
        ],
        "sccs": component_rows,
        "resources": list(resources.values()),
        "functions": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--seeds", type=Path,
        default=Path(__file__).resolve().parents[2] / "content/miel_vliegt/native_function_seeds.json",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = build(
        json.loads(args.index.read_text(encoding="utf-8")),
        json.loads(args.seeds.read_text(encoding="utf-8")),
    )
    encoded = json.dumps(result, separators=(",", ":")) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True), encoded.splitlines(keepends=True),
                fromfile=str(args.output), tofile="fresh native code map",
            ))
            raise SystemExit(f"native code map drifted:\n{diff}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
