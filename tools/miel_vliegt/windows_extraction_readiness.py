#!/usr/bin/env python3
"""Bind Windows extraction readiness without promoting native-game claims."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


PROTOCOL = "miel-vliegt-windows-extraction-readiness"
MAIN_JOB_STEP = "Probe private game extraction without an artifact"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_FIELDS = {
    "run_id", "head_sha", "status", "artifact_count", "log_sha256",
    "log_bytes", "public_status",
}
PUBLIC_STATUS_FIELDS = {
    "iso_sha256_matched", "executable_sha256_matched", "native_game_started",
}
PUBLIC_OUTPUT_FIELDS = {
    "status", "artifact_count", "iso_sha256_matched",
    "executable_sha256_matched",
}


class WindowsExtractionReadinessError(ValueError):
    """Raised when extraction evidence is unbound or overclaims readiness."""


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
        raise WindowsExtractionReadinessError("duplicate JSON key") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsExtractionReadinessError(
            f"cannot read {label}: {path}"
        ) from error
    if not isinstance(value, dict):
        raise WindowsExtractionReadinessError(f"{label} must be an object")
    return value


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise WindowsExtractionReadinessError(f"{label} fields differ")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise WindowsExtractionReadinessError(f"{label} is not a SHA-256")
    return value


def _commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_COMMIT.fullmatch(value) is None:
        raise WindowsExtractionReadinessError(f"{label} is not a Git commit")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise WindowsExtractionReadinessError(f"{label} is invalid")
    return value


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
            raise WindowsExtractionReadinessError("duplicate JSON key") from error
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "status" in value:
            candidates.append((value, line_number, line))
    if len(candidates) != 1:
        raise WindowsExtractionReadinessError("public output occurrences differ")
    output, line_number, line = candidates[0]
    return (
        _fields(output, PUBLIC_OUTPUT_FIELDS, "public output"),
        line_number,
        line,
    )


def _checkout_line_number(text: str, head_sha: str) -> int | None:
    for line_number, line in enumerate(text.splitlines()):
        fields = line.rstrip().split("\t")
        if len(fields) >= 3 \
                and fields[1].startswith("Run actions/checkout@") \
                and line.rstrip().endswith(head_sha):
            return line_number
    return None


def _post_checkout_line_number(text: str) -> int | None:
    for line_number, line in enumerate(text.splitlines()):
        fields = line.rstrip().split("\t")
        if len(fields) >= 3 \
                and fields[1].startswith("Post Run actions/checkout@"):
            return line_number
    return None


def classify(
    manifest_path: Path,
    log_path: Path,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    expected_iso_sha256: str,
    expected_executable_sha256: str,
) -> dict[str, Any]:
    manifest = _fields(_load(manifest_path, "manifest"), MANIFEST_FIELDS, "manifest")
    run_id = _integer(manifest["run_id"], "run id", minimum=1)
    head_sha = _commit(manifest["head_sha"], "run head")
    expected_run_id = _integer(expected_run_id, "expected run id", minimum=1)
    expected_head_sha = _commit(expected_head_sha, "expected run head")
    expected_iso_sha256 = _hash(expected_iso_sha256, "expected ISO")
    expected_executable_sha256 = _hash(
        expected_executable_sha256, "expected executable"
    )
    if run_id != expected_run_id or head_sha != expected_head_sha:
        raise WindowsExtractionReadinessError("run identity differs")
    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    artifact_count = _integer(manifest["artifact_count"], "artifact count")
    if artifact_count != 0:
        raise WindowsExtractionReadinessError("artifact count differs")
    if manifest["status"] != "success":
        raise WindowsExtractionReadinessError("run status differs")

    public_status = _fields(
        manifest["public_status"], PUBLIC_STATUS_FIELDS, "public status"
    )
    if any(type(value) is not bool for value in public_status.values()):
        raise WindowsExtractionReadinessError("public status types differ")
    if public_status["native_game_started"] is not False:
        raise WindowsExtractionReadinessError("extraction output promotes a claim")

    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise WindowsExtractionReadinessError("run log is unavailable") from error
    if len(raw_log) != expected_log_bytes:
        raise WindowsExtractionReadinessError("log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise WindowsExtractionReadinessError("log hash differs")
    checkout_line_number = _checkout_line_number(text, expected_head_sha)
    if checkout_line_number is None:
        raise WindowsExtractionReadinessError("checkout identity differs")

    output, output_line_number, output_line = _public_output(text)
    output_fields = output_line.rstrip().split("\t")
    if len(output_fields) < 3 \
            or output_fields[1] != MAIN_JOB_STEP:
        raise WindowsExtractionReadinessError("public output job step differs")
    if output_line_number < checkout_line_number:
        raise WindowsExtractionReadinessError("public output precedes checkout")
    post_checkout_line_number = _post_checkout_line_number(text)
    if post_checkout_line_number is None:
        raise WindowsExtractionReadinessError("post-checkout cleanup is missing")
    if output_line_number > post_checkout_line_number:
        raise WindowsExtractionReadinessError(
            "public output follows post-checkout cleanup"
        )
    if not isinstance(output["status"], str) \
            or type(output["artifact_count"]) is not int \
            or type(output["iso_sha256_matched"]) is not bool \
            or type(output["executable_sha256_matched"]) is not bool:
        raise WindowsExtractionReadinessError("public output types differ")
    if output["status"] != "EXTRACTION_READY":
        raise WindowsExtractionReadinessError("extraction output promotes a claim")
    expected_output = {
        "status": "EXTRACTION_READY",
        "artifact_count": 0,
        "iso_sha256_matched": True,
        "executable_sha256_matched": True,
    }
    if output != expected_output:
        raise WindowsExtractionReadinessError("public output differs")
    expected_public_status = {
        "iso_sha256_matched": True,
        "executable_sha256_matched": True,
        "native_game_started": False,
    }
    if public_status != expected_public_status:
        raise WindowsExtractionReadinessError("public status differs")

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": "EXTRACTION_READY",
        "extraction_ready": True,
        "native_game_started": False,
        "run_id": run_id,
        "head_sha": head_sha,
        "source_log": {
            "sha256": expected_log_hash,
            "bytes": expected_log_bytes,
            "artifact_count": artifact_count,
        },
        "source_identities": {
            "iso_sha256": expected_iso_sha256,
            "executable_sha256": expected_executable_sha256,
        },
        "proof_limits": {
            "original_process_started": False,
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
        raise WindowsExtractionReadinessError("source identity differs")
    receipt = classify(
        arguments.manifest,
        arguments.log,
        expected_run_id=arguments.run_id,
        expected_head_sha=arguments.head_sha,
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
