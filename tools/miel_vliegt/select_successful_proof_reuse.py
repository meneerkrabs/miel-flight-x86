#!/usr/bin/env python3
"""Select and validate successful ancestral runs for heavy-proof reuse."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")
ORACLE_WORKFLOW_PATH = ".github/workflows/deploy-oracle.yml"

FLIGHT_PROOF_STEPS = (
    "Reconstruct and prove private flight payloads",
)
ASSET_REUSE_AUTHORIZATION_STEP = "Verify candidate boat presentation receipt family"
ASSET_PROOF_STEPS = (
    "Prove original projector and WinHelp evidence",
    "Prove WinHelp gameplay contracts against Lingo runtime",
    "Cross-check all Director sources with LibreShockwave",
    "Prove generated pixel assets",
    "Prove generated audio assets",
    ASSET_REUSE_AUTHORIZATION_STEP,
)


@dataclass(frozen=True)
class ProofReuse:
    run_id: int
    head_sha: str
    flight: bool
    assets: bool


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def _current_sha(root: Path, current: str) -> str:
    resolved = _git(root, "rev-parse", "--verify", f"{current}^{{commit}}")
    if resolved.returncode:
        raise ValueError(f"current revision is invalid: {resolved.stderr.strip()}")
    return resolved.stdout.strip()


def _run_identity(run: dict[str, Any]) -> tuple[int, str]:
    run_id = run.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise ValueError("successful workflow run has no canonical id")
    head_sha = run.get("head_sha")
    if not isinstance(head_sha, str) or not SHA.fullmatch(head_sha):
        raise ValueError("successful workflow run has no canonical head_sha")
    if run.get("path") != ORACLE_WORKFLOW_PATH:
        raise ValueError("workflow run does not belong to deploy-oracle.yml")
    return run_id, head_sha


def _is_ancestor(root: Path, candidate: str, current_sha: str) -> bool:
    exists = _git(root, "rev-parse", "--verify", f"{candidate}^{{commit}}")
    if exists.returncode:
        return False
    ancestor = _git(root, "merge-base", "--is-ancestor", candidate, current_sha)
    if ancestor.returncode not in (0, 1):
        raise ValueError(f"cannot compare workflow baseline: {ancestor.stderr.strip()}")
    return ancestor.returncode == 0


def successful_ancestral_run_ids(
    document: dict[str, Any], *, root: Path = ROOT, current: str = "HEAD",
    require_candidate: bool = True,
) -> list[int]:
    """Return successful ancestral Oracle run IDs in API order."""
    runs = document.get("workflow_runs")
    if not isinstance(runs, list):
        raise ValueError("workflow-run response has no workflow_runs array")
    current_sha = _current_sha(root, current)
    candidates: list[int] = []
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("workflow-run response contains a non-object run")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            continue
        run_id, head_sha = _run_identity(run)
        if _is_ancestor(root, head_sha, current_sha):
            candidates.append(run_id)
    if not candidates and require_candidate:
        raise ValueError("no successful ancestral Oracle workflow run found")
    return candidates


def _all_steps_succeeded(jobs: list[dict[str, Any]], wanted: tuple[str, ...]) -> bool:
    for name in wanted:
        matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for job in jobs:
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                raise ValueError("workflow job has no steps array")
            for step in steps:
                if not isinstance(step, dict):
                    raise ValueError("workflow job contains a non-object step")
                if step.get("name") == name:
                    matches.append((job, step))
        if not matches or not all(
            job.get("conclusion") == "success"
            and step.get("conclusion") == "success"
            for job, step in matches
        ):
            return False
    return True


def evaluate_proof_run(
    run: dict[str, Any],
    jobs_document: dict[str, Any],
    *,
    root: Path = ROOT,
    current: str = "HEAD",
    expected_run_id: int | None = None,
) -> ProofReuse:
    """Validate one exact run and report which complete proof groups it owns."""
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("proof run did not complete successfully")
    run_id, head_sha = _run_identity(run)
    if expected_run_id is not None and run_id != expected_run_id:
        raise ValueError("proof-run response does not match requested run id")
    if not _is_ancestor(root, head_sha, _current_sha(root, current)):
        raise ValueError("proof run is not an ancestor of the current revision")

    jobs = jobs_document.get("jobs")
    if not isinstance(jobs, list):
        raise ValueError("workflow-jobs response has no jobs array")
    for job in jobs:
        if not isinstance(job, dict):
            raise ValueError("workflow-jobs response contains a non-object job")

    return ProofReuse(
        run_id=run_id,
        head_sha=head_sha,
        flight=_all_steps_succeeded(jobs, FLIGHT_PROOF_STEPS),
        assets=_all_steps_succeeded(jobs, ASSET_PROOF_STEPS),
    )


def _read_object(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    return document


def _parse_run_id(value: str) -> int:
    if not RUN_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("run id must be a positive canonical integer")
    return int(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current", default="HEAD")
    subparsers = parser.add_subparsers(dest="command", required=True)

    candidates = subparsers.add_parser("candidates")
    candidates.add_argument("runs", type=Path)
    candidates.add_argument("--allow-empty", action="store_true")

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("run", type=Path)
    evaluate.add_argument("jobs", type=Path)
    evaluate.add_argument("--expected-run-id", type=_parse_run_id)
    evaluate.add_argument("--require-reusable", action="store_true")

    args = parser.parse_args()
    try:
        root = args.root.resolve()
        if args.command == "candidates":
            for run_id in successful_ancestral_run_ids(
                _read_object(args.runs), root=root, current=args.current,
                require_candidate=not args.allow_empty,
            ):
                print(run_id)
            return
        result = evaluate_proof_run(
            _read_object(args.run),
            _read_object(args.jobs),
            root=root,
            current=args.current,
            expected_run_id=args.expected_run_id,
        )
        if args.require_reusable and not (result.flight or result.assets):
            raise ValueError("proof run has no complete successful reusable proof group")
        print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"cannot resolve reusable heavy-proof run: {error}")


if __name__ == "__main__":
    main()
