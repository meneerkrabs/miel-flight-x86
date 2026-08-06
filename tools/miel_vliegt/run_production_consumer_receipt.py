#!/usr/bin/env python3
"""Execute the release-bound Jest suite and receipt positive handler coverage."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import production_consumer_registry as registry
except ModuleNotFoundError:
    import production_consumer_registry as registry


def _requirements(root: Path, path: Path | None) -> list[str]:
    if path is None:
        try:
            from tools.miel_vliegt import flight_cleanroom_completion as completion
        except ModuleNotFoundError:
            import flight_cleanroom_completion as completion
        rows, _, _ = completion.production_consumer_requirements(
            completion.load_documents(root), root,
        )
    else:
        rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not all(isinstance(row, str) for row in rows):
        raise ValueError("production consumer requirements must be a string array")
    result = sorted(set(rows))
    if result != sorted(rows) or not result:
        raise ValueError("production consumer requirements must be unique and non-empty")
    return result


def _coverage_row(coverage: dict[str, Any], root: Path, module: str) -> dict[str, Any]:
    expected = (root / module).resolve()
    matches = [
        value for path, value in coverage.items()
        if Path(path).resolve() == expected
    ]
    if len(matches) != 1:
        raise ValueError(f"Jest coverage omitted production handler module: {module}")
    return matches[0]


def handler_invocations(
    coverage: dict[str, Any], root: Path, handlers: list[dict[str, str]],
) -> list[dict[str, Any]]:
    result = []
    for handler in handlers:
        module = handler["module"]
        export = handler["export"]
        line = registry._exported_function_line(root, module, export)
        if line is None:
            raise ValueError(f"production handler is not one named function export: {module}:{export}")
        row = _coverage_row(coverage, root, module)
        function_map = row.get("fnMap")
        counts = row.get("f")
        if not isinstance(function_map, dict) or not isinstance(counts, dict):
            raise ValueError(f"Jest function coverage is malformed: {module}")
        identities = [
            key for key, function in function_map.items()
            if function.get("name") == export
            and function.get("decl", {}).get("start", {}).get("line") == line
        ]
        if len(identities) != 1:
            raise ValueError(f"Jest did not identify the exact exported handler: {module}:{export}")
        count = counts.get(identities[0])
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise ValueError(f"release integration did not invoke handler: {module}:{export}")
        result.append({
            "module": module,
            "export": export,
            "function_line": line,
            "invocation_count": count,
        })
    return result


def function_invocations(
    coverage: dict[str, Any], root: Path, functions: list[dict[str, str]],
) -> list[dict[str, Any]]:
    result = []
    for target in functions:
        module = target["module"]
        function = target["function"]
        line = registry._function_line(root, module, function)
        if line is None:
            raise ValueError(f"production function is not uniquely declared: {module}:{function}")
        row = _coverage_row(coverage, root, module)
        function_map = row.get("fnMap")
        counts = row.get("f")
        identities = [
            key for key, observed in function_map.items()
            if observed.get("decl", {}).get("start", {}).get("line") == line
        ] if isinstance(function_map, dict) and isinstance(counts, dict) else []
        if len(identities) != 1:
            raise ValueError(f"Jest did not identify exact production function: {module}:{function}")
        count = counts.get(identities[0])
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise ValueError(f"release integration did not invoke function: {module}:{function}")
        result.append({
            "module": module,
            "function": function,
            "function_line": line,
            "invocation_count": count,
        })
    return result


def entrypoint_invocations(
    coverage: dict[str, Any], root: Path, calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result = []
    for call in calls:
        entrypoint = call["entrypoint"]
        lines = call["call_lines"]
        if not lines:
            raise ValueError(
                f"production entrypoint does not import/call handler: "
                f"{entrypoint}:{call['export']}"
            )
        row = _coverage_row(coverage, root, entrypoint)
        statement_map = row.get("statementMap")
        counts = row.get("s")
        if not isinstance(statement_map, dict) or not isinstance(counts, dict):
            raise ValueError(f"Jest statement coverage is malformed: {entrypoint}")
        line_counts = []
        for line in lines:
            candidates = [
                counts.get(key)
                for key, span in statement_map.items()
                if span.get("start", {}).get("line") == line
                and span.get("end", {}).get("line", line) >= line
            ]
            candidates = [
                count for count in candidates
                if isinstance(count, int) and not isinstance(count, bool)
            ]
            line_counts.append(max(candidates, default=0))
        invocation_count = max(line_counts, default=0)
        if invocation_count <= 0:
            raise ValueError(
                f"release integration did not execute production callsite: "
                f"{entrypoint}:{call['export']}"
            )
        result.append({
            **call,
            "invocation_count": invocation_count,
        })
    return result


def build_receipt(root: Path, required_ids: list[str]) -> dict[str, Any]:
    spec = registry.proof_spec(required_ids, root)
    coverage_directory = root / registry.COVERAGE_DIRECTORY
    shutil.rmtree(coverage_directory, ignore_errors=True)
    completed = subprocess.run(
        spec["command"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if completed.returncode:
        tail = "\n".join(completed.stdout.splitlines()[-100:])
        raise ValueError(
            f"production consumer Jest suite failed ({completed.returncode})\n{tail}"
        )
    result_path = root / registry.JEST_RESULT
    if not result_path.is_file():
        raise ValueError("production consumer Jest suite emitted no result document")
    jest_result = json.loads(result_path.read_text(encoding="utf-8"))
    assertions = [
        assertion
        for test_file in jest_result.get("testResults", [])
        for assertion in test_file.get("assertionResults", [])
    ] if isinstance(jest_result, dict) else []
    pack_results = []
    for title in spec["pack_assertions"]:
        matches = [row for row in assertions if row.get("title") == title]
        if len(matches) != 1 or matches[0].get("status") != "passed":
            raise ValueError(f"release integration did not prove asset pack: {title}")
        pack_results.append({"title": title, "status": "passed"})
    coverage_path = coverage_directory / "coverage-final.json"
    if not coverage_path.is_file():
        raise ValueError("production consumer Jest suite emitted no JSON coverage")
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    if not isinstance(coverage, dict):
        raise ValueError("production consumer Jest coverage must be an object")
    invocations = handler_invocations(coverage, root, spec["handlers"])
    executed_functions = function_invocations(
        coverage, root, spec["execution_functions"]
    )
    callsite_invocations = entrypoint_invocations(
        coverage, root, spec["entrypoint_calls"]
    )
    return {
        **{key: spec[key] for key in (
            "schema", "protocol", "edition", "suite_id", "consumer_ids",
            "command", "tests", "handlers", "entrypoint_calls",
            "execution_functions",
            "pack_assertions",
        )},
        "result": "PASS",
        "exit_code": completed.returncode,
        "runtime_hashes": {
            relative: registry._sha256(root / relative)
            for relative in spec["runtime_paths"]
        },
        "handler_invocations": invocations,
        "function_invocations": executed_functions,
        "pack_assertion_results": pack_results,
        "entrypoint_invocations": callsite_invocations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=registry.ROOT)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    required_ids = _requirements(root, args.requirements)
    receipt = build_receipt(root, required_ids)
    output = args.output or root / registry.RECEIPT
    encoded = json.dumps(receipt, indent=2, ensure_ascii=True) + "\n"
    if args.check:
        current = output.read_text(encoding="utf-8") if output.is_file() else ""
        if current != encoded:
            raise SystemExit("production consumer Jest receipt is stale")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
    registry_value = registry.build(required_ids, root)
    registry_output = root / registry.OUTPUT
    registry_encoded = json.dumps(registry_value, indent=2, ensure_ascii=True) + "\n"
    if args.check:
        current = registry_output.read_text(encoding="utf-8") \
            if registry_output.is_file() else ""
        if current != registry_encoded:
            raise SystemExit("production consumer registry is stale")
    else:
        registry_output.parent.mkdir(parents=True, exist_ok=True)
        registry_output.write_text(registry_encoded, encoding="utf-8")
    print(
        f"production consumer receipt PASS: {len(receipt['consumer_ids'])} consumers, "
        f"{len(receipt['handler_invocations'])} invoked handlers"
    )


if __name__ == "__main__":
    main()
