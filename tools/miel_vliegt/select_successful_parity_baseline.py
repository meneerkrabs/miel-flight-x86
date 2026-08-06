#!/usr/bin/env python3
"""Select the newest successful Oracle workflow commit that is an ancestor."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"^[0-9a-f]{40}$")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def select_baseline(
    document: dict[str, Any], *, root: Path = ROOT, current: str = "HEAD",
) -> str:
    runs = document.get("workflow_runs")
    if not isinstance(runs, list):
        raise ValueError("workflow-run response has no workflow_runs array")
    resolved = _git(root, "rev-parse", "--verify", f"{current}^{{commit}}")
    if resolved.returncode:
        raise ValueError(f"current revision is invalid: {resolved.stderr.strip()}")
    current_sha = resolved.stdout.strip()

    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("workflow-run response contains a non-object run")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            continue
        candidate = run.get("head_sha")
        if not isinstance(candidate, str) or not SHA.fullmatch(candidate):
            raise ValueError("successful workflow run has no canonical head_sha")
        exists = _git(root, "rev-parse", "--verify", f"{candidate}^{{commit}}")
        if exists.returncode:
            continue
        ancestor = _git(root, "merge-base", "--is-ancestor", candidate, current_sha)
        if ancestor.returncode == 0:
            return candidate
        if ancestor.returncode not in (0, 1):
            raise ValueError(f"cannot compare workflow baseline: {ancestor.stderr.strip()}")
    raise ValueError("no successful ancestral Oracle workflow baseline found")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current", default="HEAD")
    args = parser.parse_args()
    try:
        document = json.loads(args.runs.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("workflow-run response is not an object")
        baseline = select_baseline(
            document, root=args.root.resolve(), current=args.current,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"cannot resolve last successful parity baseline: {error}")
    print(baseline)


if __name__ == "__main__":
    main()
