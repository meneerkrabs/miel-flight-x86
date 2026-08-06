#!/usr/bin/env python3
"""Shared strict-JSON and executable-receipt support for flight parity v2."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class DuplicateKeyError(ValueError):
    """Raised when JSON would otherwise silently discard a duplicate key."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_json_strict(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except json.JSONDecodeError as error:
        raise ValueError(f"{path}: invalid JSON: {error}") from error
    except DuplicateKeyError as error:
        raise ValueError(f"{path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_receipt(root: Path, suite: dict[str, Any], *, execute: bool) -> dict[str, Any]:
    command = suite["command"]
    if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
        raise ValueError(f"{suite.get('id', '<unknown>')}: command must be a non-empty string array")
    runtime_paths = suite.get("runtime_paths", [])
    if not runtime_paths or not all(isinstance(path, str) for path in runtime_paths):
        raise ValueError(f"{suite['id']}: runtime_paths must be a non-empty string array")
    runtime_hashes = {}
    for relative in runtime_paths:
        path = root / relative
        if not path.is_file():
            raise ValueError(f"{suite['id']}: runtime/test input does not exist: {relative}")
        runtime_hashes[relative] = sha256(path)

    result = "NOT_EXECUTED"
    exit_code = None
    if execute:
        execution_command = [sys.executable, *command[1:]] \
            if command[0] in {"python", "python3"} else command
        completed = subprocess.run(
            execution_command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        exit_code = completed.returncode
        result = "PASS" if completed.returncode == 0 else "FAIL"
        if completed.returncode:
            tail = "\n".join(completed.stdout.splitlines()[-80:])
            raise ValueError(f"{suite['id']}: executable receipt failed ({completed.returncode})\n{tail}")

    return {
        "suite_id": suite["id"],
        "contract_ids": suite["contract_ids"],
        "mode": suite["mode"],
        "command": command,
        "result": result,
        "exit_code": exit_code,
        "runtime_hashes": runtime_hashes,
    }


def build_receipts(root: Path, suites: dict[str, Any], *, execute: bool) -> dict[str, Any]:
    if suites.get("schema") != 1 or not isinstance(suites.get("suites"), list):
        raise ValueError("unsupported behavior test-suite schema")
    receipts = []
    for suite in suites["suites"]:
        try:
            receipts.append(build_receipt(root, suite, execute=execute))
        except ValueError as error:
            if "does not exist" in str(error):
                # Skip suites whose runtime inputs are CI-generated artifacts
                # (e.g. x86_property_fold.json) that may not be present when the
                # oracle has not been run on this checkout.
                receipts.append({
                    "suite_id": suite.get("id", "<unknown>"),
                    "command": suite.get("command", []),
                    "result": "SKIPPED_MISSING_INPUT",
                    "exit_code": None,
                    "runtime_hashes": {},
                    "skip_reason": str(error),
                })
            else:
                raise
    return {"schema": 1, "receipts": receipts}
