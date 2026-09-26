#!/usr/bin/env python3
"""Bind native Windows startup evidence without promoting game parity."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


PROTOCOL = "miel-vliegt-windows-native-startup-readiness"
ROOT = Path(__file__).resolve().parents[2]
MAIN_JOB_STEP = "Probe private game extraction without an artifact"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_FIELDS = {
    "run_id", "head_sha", "merged_sha", "tested_tree_matches_master",
    "status", "artifact_count", "log_sha256", "log_bytes", "public_result",
}
PUBLIC_RESULT_FIELDS = {
    "status", "artifact_count", "iso_sha256_matched",
    "executable_sha256_matched", "cd_mounted", "process_alive_after_15s",
    "window_present",
}


class WindowsNativeStartupReadinessError(ValueError):
    """Raised when startup evidence is unbound or overclaims a result."""


class DuplicateKeyError(ValueError):
    """Raised when duplicate JSON keys would silently replace evidence."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


_STRICT_DECODER = json.JSONDecoder(object_pairs_hook=_unique_object)


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = _STRICT_DECODER.decode(path.read_text(encoding="utf-8"))
    except DuplicateKeyError as error:
        raise WindowsNativeStartupReadinessError("duplicate JSON key") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsNativeStartupReadinessError(
            f"cannot read {label}: {path}"
        ) from error
    if not isinstance(value, dict):
        raise WindowsNativeStartupReadinessError(f"{label} must be an object")
    return value


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise WindowsNativeStartupReadinessError(f"{label} fields differ")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise WindowsNativeStartupReadinessError(f"{label} is not a SHA-256")
    return value


def _git_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_ID.fullmatch(value) is None:
        raise WindowsNativeStartupReadinessError(f"{label} is not a Git object ID")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise WindowsNativeStartupReadinessError(f"{label} is invalid")
    return value


def _commit_tree(revision: str) -> str:
    try:
        object_type = subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-t", revision],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        if object_type != "commit":
            raise WindowsNativeStartupReadinessError(
                "tested source revision is not a commit"
            )
        completed = subprocess.run(
            [
                "git", "-C", str(ROOT), "rev-parse",
                f"{revision}^{{tree}}",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise WindowsNativeStartupReadinessError(
            "tested source revision is unavailable"
        ) from error
    tree_sha = completed.stdout.strip()
    return _git_id(tree_sha, "tested source tree")


def _public_output(text: str) -> tuple[dict[str, Any], int, str]:
    candidates: list[tuple[dict[str, Any], int, str]] = []
    for line_number, line in enumerate(text.splitlines()):
        stripped = line.strip()
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            continue
        try:
            value = _STRICT_DECODER.decode(stripped[start:end + 1])
        except DuplicateKeyError as error:
            raise WindowsNativeStartupReadinessError("duplicate JSON key") from error
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "status" in value:
            candidates.append((value, line_number, line))
    if len(candidates) != 1:
        raise WindowsNativeStartupReadinessError("public output occurrences differ")
    output, line_number, line = candidates[0]
    return (
        _fields(output, PUBLIC_RESULT_FIELDS, "public output"),
        line_number,
        line,
    )


def _checkout_line_number(text: str, head_sha: str) -> int | None:
    for line_number, line in enumerate(text.splitlines()):
        if "Run actions/checkout" in line and line.rstrip().endswith(head_sha):
            return line_number
    return None


def _post_checkout_line_number(text: str) -> int | None:
    for line_number, line in enumerate(text.splitlines()):
        if "Post Run actions/checkout" in line:
            return line_number
    return None


def _reviewed_job_step(output_line: str) -> bool:
    fields = output_line.rstrip().split("\t")
    return len(fields) >= 3 and fields[1] == MAIN_JOB_STEP


def classify(
    manifest_path: Path,
    log_path: Path,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    expected_merged_sha: str,
    expected_tested_tree_sha: str,
    expected_iso_sha256: str,
    expected_executable_sha256: str,
) -> dict[str, Any]:
    manifest = _fields(
        _load(manifest_path, "manifest"), MANIFEST_FIELDS, "manifest"
    )
    run_id = _integer(manifest["run_id"], "run id", minimum=1)
    head_sha = _git_id(manifest["head_sha"], "run head")
    merged_sha = _git_id(manifest["merged_sha"], "merged head")
    expected_run_id = _integer(expected_run_id, "expected run id", minimum=1)
    expected_head_sha = _git_id(expected_head_sha, "expected run head")
    expected_merged_sha = _git_id(expected_merged_sha, "expected merged head")
    expected_tested_tree_sha = _git_id(
        expected_tested_tree_sha, "expected tested tree"
    )
    expected_iso_sha256 = _hash(expected_iso_sha256, "expected ISO")
    expected_executable_sha256 = _hash(
        expected_executable_sha256, "expected executable"
    )
    if run_id != expected_run_id or head_sha != expected_head_sha:
        raise WindowsNativeStartupReadinessError("run identity differs")
    if merged_sha != expected_merged_sha:
        raise WindowsNativeStartupReadinessError("merged identity differs")
    head_tree_sha = _commit_tree(head_sha)
    merged_tree_sha = _commit_tree(merged_sha)
    if manifest["tested_tree_matches_master"] is not True:
        raise WindowsNativeStartupReadinessError("tested tree identity differs")
    if head_tree_sha != expected_tested_tree_sha \
            or merged_tree_sha != expected_tested_tree_sha:
        raise WindowsNativeStartupReadinessError("tested tree identity differs")
    if manifest["status"] != "success":
        raise WindowsNativeStartupReadinessError("run status differs")

    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    artifact_count = _integer(manifest["artifact_count"], "artifact count")
    if artifact_count != 0:
        raise WindowsNativeStartupReadinessError("artifact count differs")
    public_result = _fields(
        manifest["public_result"], PUBLIC_RESULT_FIELDS, "public result"
    )
    if not isinstance(public_result["status"], str) \
            or type(public_result["artifact_count"]) is not int \
            or any(
                type(public_result[name]) is not bool
                for name in (
                    "iso_sha256_matched", "executable_sha256_matched",
                    "cd_mounted", "process_alive_after_15s", "window_present",
                )
            ):
        raise WindowsNativeStartupReadinessError("public result types differ")

    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise WindowsNativeStartupReadinessError("run log is unavailable") from error
    if len(raw_log) != expected_log_bytes:
        raise WindowsNativeStartupReadinessError("log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise WindowsNativeStartupReadinessError("log hash differs")
    checkout_line_number = _checkout_line_number(text, expected_head_sha)
    if checkout_line_number is None:
        raise WindowsNativeStartupReadinessError("checkout identity differs")

    output, output_line_number, output_line = _public_output(text)
    if not _reviewed_job_step(output_line):
        raise WindowsNativeStartupReadinessError("public output job step differs")
    if output_line_number < checkout_line_number:
        raise WindowsNativeStartupReadinessError("public output precedes checkout")
    post_checkout_line_number = _post_checkout_line_number(text)
    if post_checkout_line_number is None:
        raise WindowsNativeStartupReadinessError("post-checkout cleanup is missing")
    if output_line_number > post_checkout_line_number:
        raise WindowsNativeStartupReadinessError(
            "public output follows post-checkout cleanup"
        )
    if not isinstance(output["status"], str) \
            or type(output["artifact_count"]) is not int \
            or any(
                type(output[name]) is not bool
                for name in (
                    "iso_sha256_matched", "executable_sha256_matched",
                    "cd_mounted", "process_alive_after_15s", "window_present",
                )
            ):
        raise WindowsNativeStartupReadinessError("public output types differ")
    if output != public_result:
        raise WindowsNativeStartupReadinessError("public output differs")
    expected_public_result = {
        "status": "NATIVE_STARTUP_DIAGNOSTIC_ONLY",
        "artifact_count": 0,
        "iso_sha256_matched": True,
        "executable_sha256_matched": True,
        "cd_mounted": True,
        "process_alive_after_15s": True,
        "window_present": True,
    }
    if public_result != expected_public_result:
        raise WindowsNativeStartupReadinessError("public result differs")

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": "NATIVE_STARTUP_DIAGNOSTIC_ONLY",
        "run_id": run_id,
        "source_revision": {
            "head_sha": head_sha,
            "merged_sha": merged_sha,
            "tested_tree_sha": head_tree_sha,
            "tested_tree_matches_master": True,
        },
        "source_log": {
            "sha256": expected_log_hash,
            "bytes": expected_log_bytes,
            "artifact_count": artifact_count,
        },
        "source_identities": {
            "iso_sha256": expected_iso_sha256,
            "executable_sha256": expected_executable_sha256,
        },
        "original_process_started": True,
        "process_alive_after_15s": True,
        "window_present": True,
        "proof_limits": {
            "direct3d_device_created": False,
            "manager_initialized": False,
            "native_pixels_captured": False,
            "native_parity_evidence": False,
        },
    }


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--merged-sha", required=True)
    parser.add_argument("--tested-tree-sha", required=True)
    parser.add_argument(
        "--identity",
        type=Path,
        default=repository / "content/miel_vliegt/source_identity.json",
    )
    arguments = parser.parse_args()
    identity = _load(arguments.identity, "source identity")
    if identity.get("schema") != 1 \
            or not isinstance(identity.get("iso"), dict) \
            or not isinstance(identity.get("executable"), dict):
        raise WindowsNativeStartupReadinessError("source identity differs")
    receipt = classify(
        arguments.manifest,
        arguments.log,
        expected_run_id=arguments.run_id,
        expected_head_sha=arguments.head_sha,
        expected_merged_sha=arguments.merged_sha,
        expected_tested_tree_sha=arguments.tested_tree_sha,
        expected_iso_sha256=_hash(
            identity["iso"].get("sha256"), "source ISO"
        ),
        expected_executable_sha256=_hash(
            identity["executable"].get("sha256"), "source executable"
        ),
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
