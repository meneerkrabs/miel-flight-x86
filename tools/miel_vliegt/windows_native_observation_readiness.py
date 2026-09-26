#!/usr/bin/env python3
"""Bind the reviewed native Windows UI-dialog observation without parity claims."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


PROTOCOL = "miel-vliegt-windows-native-observation-readiness"
ROOT = Path(__file__).resolve().parents[2]
MAIN_JOB_STEP = "Probe private game extraction without an artifact"
PROBE_SOURCE_PATH = "tools/miel_vliegt/windows_native_probe/native_probe.c"
EXPECTED_WORKFLOW = "Native Flight Windows extraction readiness"
EXPECTED_CREATED_AT = "2026-09-26T09:38:29Z"
EXPECTED_UPDATED_AT = "2026-09-26T09:40:25Z"
SELECTOR_CREATED_AT = "2026-09-26T09:55:33Z"
SELECTOR_UPDATED_AT = "2026-09-26T09:56:40Z"
HARDWARE_CREATED_AT = "2026-09-26T09:59:40Z"
HARDWARE_UPDATED_AT = "2026-09-26T10:00:26Z"
FATAL_CREATED_AT = "2026-09-26T10:03:17Z"
FATAL_UPDATED_AT = "2026-09-26T10:04:16Z"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_FIELDS = {
    "run_id", "head_branch", "head_sha", "status", "conclusion",
    "workflow_name", "created_at", "updated_at", "log_sha256", "log_bytes",
}
PUBLIC_OUTPUT_FIELDS = {
    "artifact_count", "captured_height", "captured_width", "cd_mounted",
    "child_button_count", "child_edit_count", "child_static_count",
    "create_calls", "create_callsite_verified", "create_hr", "create_returns",
    "create_success", "device_nonnull", "dialog_reason", "gt_loaded",
    "manager_renders", "manager_slots_verified", "manager_ticks",
    "nonblack_pixels_max", "pixel_changes", "pixel_samples", "probe_sha256",
    "process_alive_after_15s", "process_cpu_ms", "process_exit_code", "stage",
    "status", "window_class", "window_present",
}
BOOLEAN_FIELDS = {
    "cd_mounted", "create_callsite_verified", "device_nonnull", "gt_loaded",
    "manager_slots_verified", "process_alive_after_15s", "window_present",
}
INTEGER_FIELDS = {
    "artifact_count", "captured_height", "captured_width",
    "child_button_count", "child_edit_count", "child_static_count",
    "create_calls", "create_returns", "create_success", "manager_renders",
    "manager_ticks", "nonblack_pixels_max", "pixel_changes", "pixel_samples",
    "process_cpu_ms", "process_exit_code",
}
SELECTOR_OUTPUT_FIELDS = PUBLIC_OUTPUT_FIELDS | {
    "button_labels_safe", "profile_dialog_closed",
    "profile_dialog_identified", "profile_submit_accepted",
    "profile_submit_attempted", "profile_submit_guard",
    "profile_submit_requested", "profile_submit_sent",
    "ui_profile_hint", "window_title_safe",
}
SELECTOR_BOOLEAN_FIELDS = BOOLEAN_FIELDS | {
    "profile_dialog_closed", "profile_dialog_identified",
    "profile_submit_accepted", "profile_submit_attempted",
    "profile_submit_requested", "profile_submit_sent", "ui_profile_hint",
}
HARDWARE_OUTPUT_FIELDS = PUBLIC_OUTPUT_FIELDS | {
    "button_labels_safe", "hardware_dialog_closed",
    "hardware_selection_attempted", "hardware_selection_guard",
    "hardware_selection_requested", "hardware_selection_sent",
    "window_title_safe",
}
HARDWARE_BOOLEAN_FIELDS = BOOLEAN_FIELDS | {
    "hardware_dialog_closed", "hardware_selection_attempted",
    "hardware_selection_requested", "hardware_selection_sent",
}
FATAL_OUTPUT_FIELDS = HARDWARE_OUTPUT_FIELDS | {
    "fatal_access_type", "fatal_exception_code", "fatal_exception_module",
    "fatal_exception_rva", "fatal_fault_category", "first_chance_av_count",
}
FATAL_INTEGER_FIELDS = INTEGER_FIELDS | {"first_chance_av_count"}


class WindowsNativeObservationReadinessError(ValueError):
    """Raised when native observation evidence is unbound or overclaims."""


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
        raise WindowsNativeObservationReadinessError(
            f"duplicate JSON key in {label}"
        ) from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsNativeObservationReadinessError(
            f"cannot read {label}: {path}"
        ) from error
    if not isinstance(value, dict):
        raise WindowsNativeObservationReadinessError(f"{label} must be an object")
    return value


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise WindowsNativeObservationReadinessError(f"{label} fields differ")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise WindowsNativeObservationReadinessError(
            f"{label} is not a SHA-256"
        )
    return value


def _git_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_ID.fullmatch(value) is None:
        raise WindowsNativeObservationReadinessError(
            f"{label} is not a Git object ID"
        )
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise WindowsNativeObservationReadinessError(f"{label} is invalid")
    return value


def _git_output(arguments: list[str]) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *arguments],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise WindowsNativeObservationReadinessError(
            "reviewed source revision is unavailable"
        ) from error


def _commit_tree(revision: str) -> str:
    if _git_output(["cat-file", "-t", revision]) != "commit":
        raise WindowsNativeObservationReadinessError(
            "reviewed source revision is not a commit"
        )
    return _git_id(
        _git_output(["rev-parse", f"{revision}^{{tree}}"]),
        "reviewed source tree",
    )


def _source_blob(revision: str, path: str) -> str:
    return _git_id(
        _git_output(["rev-parse", f"{revision}:{path}"]),
        "reviewed probe source blob",
    )


def _public_output(
    text: str,
    expected_fields: set[str] = PUBLIC_OUTPUT_FIELDS,
) -> tuple[dict[str, Any], int, str]:
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
            raise WindowsNativeObservationReadinessError(
                "duplicate JSON key in public output"
            ) from error
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "probe_sha256" in value:
            candidates.append((value, line_number, line))
    if len(candidates) != 1:
        raise WindowsNativeObservationReadinessError(
            "public output occurrences differ"
        )
    output, line_number, line = candidates[0]
    return (
        _fields(output, expected_fields, "public output"),
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


def classify(
    manifest_path: Path,
    log_path: Path,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    expected_head_branch: str,
    expected_tested_tree_sha: str,
    expected_probe_source_sha256: str,
    expected_probe_executable_sha256: str,
) -> dict[str, Any]:
    manifest = _fields(
        _load(manifest_path, "manifest"), MANIFEST_FIELDS, "manifest"
    )
    run_id = _integer(manifest["run_id"], "run id", minimum=1)
    head_sha = _git_id(manifest["head_sha"], "run head")
    expected_run_id = _integer(
        expected_run_id, "expected run id", minimum=1
    )
    expected_head_sha = _git_id(expected_head_sha, "expected run head")
    expected_tested_tree_sha = _git_id(
        expected_tested_tree_sha, "expected tested tree"
    )
    expected_probe_source_sha256 = _git_id(
        expected_probe_source_sha256, "expected probe source blob"
    )
    expected_probe_executable_sha256 = _hash(
        expected_probe_executable_sha256, "expected observer probe executable"
    )
    for name, value in (
        ("head branch", manifest["head_branch"]),
        ("run status", manifest["status"]),
        ("run conclusion", manifest["conclusion"]),
        ("workflow name", manifest["workflow_name"]),
        ("created timestamp", manifest["created_at"]),
        ("updated timestamp", manifest["updated_at"]),
        ("expected head branch", expected_head_branch),
    ):
        if not isinstance(value, str) or not value:
            raise WindowsNativeObservationReadinessError(
                f"{name} is invalid"
            )
    if run_id != expected_run_id or head_sha != expected_head_sha \
            or manifest["head_branch"] != expected_head_branch:
        raise WindowsNativeObservationReadinessError("run identity differs")
    if manifest["status"] != "completed" \
            or manifest["conclusion"] != "failure" \
            or manifest["workflow_name"] != EXPECTED_WORKFLOW \
            or manifest["created_at"] != EXPECTED_CREATED_AT \
            or manifest["updated_at"] != EXPECTED_UPDATED_AT:
        raise WindowsNativeObservationReadinessError("run metadata differs")

    tested_tree_sha = _commit_tree(head_sha)
    probe_source_sha256 = _source_blob(head_sha, PROBE_SOURCE_PATH)
    if tested_tree_sha != expected_tested_tree_sha:
        raise WindowsNativeObservationReadinessError("tested tree differs")
    if probe_source_sha256 != expected_probe_source_sha256:
        raise WindowsNativeObservationReadinessError("probe source differs")

    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise WindowsNativeObservationReadinessError(
            "run log is unavailable"
        ) from error
    if len(raw_log) != expected_log_bytes:
        raise WindowsNativeObservationReadinessError("log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise WindowsNativeObservationReadinessError("log hash differs")

    checkout_line_number = _checkout_line_number(text, expected_head_sha)
    if checkout_line_number is None:
        raise WindowsNativeObservationReadinessError("checkout identity differs")
    output, output_line_number, output_line = _public_output(text)
    if MAIN_JOB_STEP not in output_line:
        raise WindowsNativeObservationReadinessError(
            "public output job step differs"
        )
    if output_line_number < checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output precedes checkout"
        )
    post_checkout_line_number = _post_checkout_line_number(text)
    if post_checkout_line_number is None:
        raise WindowsNativeObservationReadinessError(
            "post-checkout cleanup is missing"
        )
    if output_line_number > post_checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output follows post-checkout cleanup"
        )

    if any(type(output[name]) is not bool for name in BOOLEAN_FIELDS) \
            or any(type(output[name]) is not int for name in INTEGER_FIELDS) \
            or any(
                not isinstance(output[name], str) or not output[name]
                for name in ("dialog_reason", "stage", "status", "window_class")
            ) \
            or not isinstance(output["probe_sha256"], str) \
            or SHA256.fullmatch(output["probe_sha256"]) is None \
            or output["create_hr"] is not None:
        raise WindowsNativeObservationReadinessError("public output types differ")
    if _integer(output["artifact_count"], "artifact count") != 0:
        raise WindowsNativeObservationReadinessError("artifact count differs")
    if _hash(output["probe_sha256"], "observer probe executable") \
            != expected_probe_executable_sha256:
        raise WindowsNativeObservationReadinessError(
            "observer probe identity differs"
        )

    static_boundary = (
        output["status"] == "FAIL"
        and output["stage"] == "native-observation"
        and output["cd_mounted"]
        and output["process_alive_after_15s"]
        and output["window_present"]
        and output["window_class"] == "#32770"
        and output["dialog_reason"] == "unknown_dialog"
        and output["captured_width"] == 318
        and output["captured_height"] == 140
        and output["child_static_count"] == 0
        and output["child_edit_count"] == 1
        and output["child_button_count"] == 2
        and output["manager_slots_verified"]
        and output["pixel_samples"] == 116
        and output["pixel_changes"] == 0
        and output["nonblack_pixels_max"] == 42757
        and output["process_cpu_ms"] == 187
        and output["process_exit_code"] == 0
    )
    renderer_absent = (
        not output["gt_loaded"]
        and not output["create_callsite_verified"]
        and output["create_calls"] == 0
        and output["create_returns"] == 0
        and output["create_success"] == 0
        and not output["device_nonnull"]
        and output["manager_ticks"] == 0
        and output["manager_renders"] == 0
    )
    if not static_boundary or not renderer_absent:
        raise WindowsNativeObservationReadinessError(
            "static dialog renderer boundary differs"
        )

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "run_id": run_id,
        "head_sha": head_sha,
        "status": "NATIVE_UI_DIALOG_DIAGNOSTIC_ONLY",
        "source_revision": {
            "head_sha": head_sha,
            "tested_tree_sha": tested_tree_sha,
        },
        "source_identities": {
            "probe_source_path": PROBE_SOURCE_PATH,
            "probe_source_blob_sha256": probe_source_sha256,
            "probe_executable_sha256": output["probe_sha256"],
        },
        "source_log": {
            "path": log_path.name,
            "sha256": expected_log_hash,
            "bytes": expected_log_bytes,
        },
        "process_alive_after_15s": output["process_alive_after_15s"],
        "window_present": output["window_present"],
        "window_class": output["window_class"],
        "captured_width": output["captured_width"],
        "captured_height": output["captured_height"],
        "pixel_samples": output["pixel_samples"],
        "pixel_changes": output["pixel_changes"],
        "manager_slots_verified": output["manager_slots_verified"],
        "proof_limits": {
            "direct3d_module_loaded": False,
            "direct3d_device_creation_called": False,
            "manager_ticks_observed": False,
            "native_pixel_changes_observed": False,
            "native_gameplay_progress": False,
            "native_parity_evidence": False,
        },
    }


def classify_renderer_selector(
    manifest_path: Path,
    log_path: Path,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    expected_head_branch: str,
    expected_tested_tree_sha: str,
    expected_probe_source_sha256: str,
    expected_probe_executable_sha256: str,
) -> dict[str, Any]:
    manifest = _fields(
        _load(manifest_path, "manifest"), MANIFEST_FIELDS, "manifest"
    )
    run_id = _integer(manifest["run_id"], "run id", minimum=1)
    head_sha = _git_id(manifest["head_sha"], "run head")
    expected_run_id = _integer(expected_run_id, "expected run id", minimum=1)
    expected_head_sha = _git_id(expected_head_sha, "expected run head")
    expected_tested_tree_sha = _git_id(
        expected_tested_tree_sha, "expected tested tree"
    )
    expected_probe_source_sha256 = _git_id(
        expected_probe_source_sha256, "expected probe source blob"
    )
    expected_probe_executable_sha256 = _hash(
        expected_probe_executable_sha256, "expected observer probe executable"
    )
    for name, value in (
        ("head branch", manifest["head_branch"]),
        ("run status", manifest["status"]),
        ("run conclusion", manifest["conclusion"]),
        ("workflow name", manifest["workflow_name"]),
        ("created timestamp", manifest["created_at"]),
        ("updated timestamp", manifest["updated_at"]),
        ("expected head branch", expected_head_branch),
    ):
        if not isinstance(value, str) or not value:
            raise WindowsNativeObservationReadinessError(f"{name} is invalid")
    if run_id != expected_run_id or head_sha != expected_head_sha \
            or manifest["head_branch"] != expected_head_branch:
        raise WindowsNativeObservationReadinessError("run identity differs")
    if manifest["status"] != "completed" \
            or manifest["conclusion"] != "failure" \
            or manifest["workflow_name"] != EXPECTED_WORKFLOW \
            or manifest["created_at"] != SELECTOR_CREATED_AT \
            or manifest["updated_at"] != SELECTOR_UPDATED_AT:
        raise WindowsNativeObservationReadinessError("run metadata differs")

    tested_tree_sha = _commit_tree(head_sha)
    probe_source_sha256 = _source_blob(head_sha, PROBE_SOURCE_PATH)
    if tested_tree_sha != expected_tested_tree_sha:
        raise WindowsNativeObservationReadinessError("tested tree differs")
    if probe_source_sha256 != expected_probe_source_sha256:
        raise WindowsNativeObservationReadinessError("probe source differs")

    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise WindowsNativeObservationReadinessError(
            "run log is unavailable"
        ) from error
    if len(raw_log) != expected_log_bytes:
        raise WindowsNativeObservationReadinessError("log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise WindowsNativeObservationReadinessError("log hash differs")

    checkout_line_number = _checkout_line_number(text, expected_head_sha)
    if checkout_line_number is None:
        raise WindowsNativeObservationReadinessError("checkout identity differs")
    output, output_line_number, output_line = _public_output(
        text, SELECTOR_OUTPUT_FIELDS
    )
    if MAIN_JOB_STEP not in output_line:
        raise WindowsNativeObservationReadinessError(
            "public output job step differs"
        )
    if output_line_number < checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output precedes checkout"
        )
    post_checkout_line_number = _post_checkout_line_number(text)
    if post_checkout_line_number is None:
        raise WindowsNativeObservationReadinessError(
            "post-checkout cleanup is missing"
        )
    if output_line_number > post_checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output follows post-checkout cleanup"
        )

    labels = output["button_labels_safe"]
    if any(type(output[name]) is not bool for name in SELECTOR_BOOLEAN_FIELDS) \
            or any(type(output[name]) is not int for name in INTEGER_FIELDS) \
            or any(
                not isinstance(output[name], str) or not output[name]
                for name in (
                    "dialog_reason", "profile_submit_guard", "stage",
                    "status", "window_class", "window_title_safe",
                )
            ) \
            or not isinstance(output["probe_sha256"], str) \
            or SHA256.fullmatch(output["probe_sha256"]) is None \
            or output["create_hr"] is not None \
            or not isinstance(labels, list) \
            or len(labels) != 2 \
            or any(not isinstance(label, str) for label in labels):
        raise WindowsNativeObservationReadinessError("public output types differ")
    if _integer(output["artifact_count"], "artifact count") != 0:
        raise WindowsNativeObservationReadinessError("artifact count differs")
    if _hash(output["probe_sha256"], "observer probe executable") \
            != expected_probe_executable_sha256:
        raise WindowsNativeObservationReadinessError(
            "observer probe identity differs"
        )

    passive_boundary = (
        output["status"] == "FAIL"
        and output["stage"] == "native-observation"
        and output["cd_mounted"]
        and output["process_alive_after_15s"]
        and output["window_present"]
        and output["window_class"] == "#32770"
        and output["dialog_reason"] == "unknown_dialog"
        and output["captured_width"] == 318
        and output["captured_height"] == 140
        and output["child_static_count"] == 0
        and output["child_edit_count"] == 1
        and output["child_button_count"] == 2
        and output["button_labels_safe"] == ["Hardware", "Software"]
        and output["window_title_safe"] == "REDACTED"
        and output["manager_slots_verified"]
        and output["pixel_samples"] == 36
        and output["pixel_changes"] == 0
        and output["nonblack_pixels_max"] == 42757
        and output["process_cpu_ms"] == 265
        and output["process_exit_code"] == 0
        and not output["ui_profile_hint"]
        and not output["profile_dialog_identified"]
        and not output["profile_submit_requested"]
        and not output["profile_submit_attempted"]
        and not output["profile_submit_sent"]
        and not output["profile_submit_accepted"]
        and not output["profile_dialog_closed"]
        and output["profile_submit_guard"] == "not_requested"
    )
    renderer_absent = (
        not output["gt_loaded"]
        and not output["create_callsite_verified"]
        and output["create_calls"] == 0
        and output["create_returns"] == 0
        and output["create_success"] == 0
        and not output["device_nonnull"]
        and output["manager_ticks"] == 0
        and output["manager_renders"] == 0
    )
    if not passive_boundary or not renderer_absent:
        raise WindowsNativeObservationReadinessError(
            "passive renderer-selector boundary differs"
        )

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "run_id": run_id,
        "head_sha": head_sha,
        "status": "NATIVE_RENDERER_SELECTOR_PASSIVE_DIAGNOSTIC_ONLY",
        "source_revision": {
            "head_sha": head_sha,
            "tested_tree_sha": tested_tree_sha,
        },
        "source_identities": {
            "probe_source_path": PROBE_SOURCE_PATH,
            "probe_source_blob_sha256": probe_source_sha256,
            "probe_executable_sha256": output["probe_sha256"],
        },
        "source_log": {
            "path": log_path.name,
            "sha256": expected_log_hash,
            "bytes": expected_log_bytes,
        },
        "process_alive_after_15s": output["process_alive_after_15s"],
        "window_present": output["window_present"],
        "window_class": output["window_class"],
        "window_title_safe": output["window_title_safe"],
        "button_labels_safe": list(output["button_labels_safe"]),
        "captured_width": output["captured_width"],
        "captured_height": output["captured_height"],
        "pixel_samples": output["pixel_samples"],
        "pixel_changes": output["pixel_changes"],
        "manager_slots_verified": output["manager_slots_verified"],
        "profile_submit_guard": output["profile_submit_guard"],
        "proof_limits": {
            "renderer_selection_input_sent": False,
            "direct3d_module_loaded": False,
            "direct3d_device_creation_called": False,
            "manager_ticks_observed": False,
            "native_pixel_changes_observed": False,
            "native_gameplay_progress": False,
            "native_parity_evidence": False,
        },
    }


def classify_hardware_progress(
    manifest_path: Path,
    log_path: Path,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    expected_head_branch: str,
    expected_tested_tree_sha: str,
    expected_probe_source_sha256: str,
    expected_probe_executable_sha256: str,
) -> dict[str, Any]:
    manifest = _fields(
        _load(manifest_path, "manifest"), MANIFEST_FIELDS, "manifest"
    )
    run_id = _integer(manifest["run_id"], "run id", minimum=1)
    head_sha = _git_id(manifest["head_sha"], "run head")
    expected_run_id = _integer(expected_run_id, "expected run id", minimum=1)
    expected_head_sha = _git_id(expected_head_sha, "expected run head")
    expected_tested_tree_sha = _git_id(
        expected_tested_tree_sha, "expected tested tree"
    )
    expected_probe_source_sha256 = _git_id(
        expected_probe_source_sha256, "expected probe source blob"
    )
    expected_probe_executable_sha256 = _hash(
        expected_probe_executable_sha256, "expected observer probe executable"
    )
    for name, value in (
        ("head branch", manifest["head_branch"]),
        ("run status", manifest["status"]),
        ("run conclusion", manifest["conclusion"]),
        ("workflow name", manifest["workflow_name"]),
        ("created timestamp", manifest["created_at"]),
        ("updated timestamp", manifest["updated_at"]),
        ("expected head branch", expected_head_branch),
    ):
        if not isinstance(value, str) or not value:
            raise WindowsNativeObservationReadinessError(f"{name} is invalid")
    if run_id != expected_run_id or head_sha != expected_head_sha \
            or manifest["head_branch"] != expected_head_branch:
        raise WindowsNativeObservationReadinessError("run identity differs")
    if manifest["status"] != "completed" \
            or manifest["conclusion"] != "failure" \
            or manifest["workflow_name"] != EXPECTED_WORKFLOW \
            or manifest["created_at"] != HARDWARE_CREATED_AT \
            or manifest["updated_at"] != HARDWARE_UPDATED_AT:
        raise WindowsNativeObservationReadinessError("run metadata differs")

    tested_tree_sha = _commit_tree(head_sha)
    probe_source_sha256 = _source_blob(head_sha, PROBE_SOURCE_PATH)
    if tested_tree_sha != expected_tested_tree_sha:
        raise WindowsNativeObservationReadinessError("tested tree differs")
    if probe_source_sha256 != expected_probe_source_sha256:
        raise WindowsNativeObservationReadinessError("probe source differs")

    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise WindowsNativeObservationReadinessError(
            "run log is unavailable"
        ) from error
    if len(raw_log) != expected_log_bytes:
        raise WindowsNativeObservationReadinessError("log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise WindowsNativeObservationReadinessError("log hash differs")

    checkout_line_number = _checkout_line_number(text, expected_head_sha)
    if checkout_line_number is None:
        raise WindowsNativeObservationReadinessError("checkout identity differs")
    output, output_line_number, output_line = _public_output(
        text, HARDWARE_OUTPUT_FIELDS
    )
    if MAIN_JOB_STEP not in output_line:
        raise WindowsNativeObservationReadinessError(
            "public output job step differs"
        )
    if output_line_number < checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output precedes checkout"
        )
    post_checkout_line_number = _post_checkout_line_number(text)
    if post_checkout_line_number is None:
        raise WindowsNativeObservationReadinessError(
            "post-checkout cleanup is missing"
        )
    if output_line_number > post_checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output follows post-checkout cleanup"
        )

    labels = output["button_labels_safe"]
    if any(type(output[name]) is not bool for name in HARDWARE_BOOLEAN_FIELDS) \
            or any(type(output[name]) is not int for name in INTEGER_FIELDS) \
            or any(
                not isinstance(output[name], str)
                for name in (
                    "dialog_reason", "hardware_selection_guard", "stage",
                    "status", "window_class", "window_title_safe",
                )
            ) \
            or not isinstance(output["probe_sha256"], str) \
            or SHA256.fullmatch(output["probe_sha256"]) is None \
            or output["create_hr"] is not None \
            or not isinstance(labels, list) \
            or len(labels) != 2 \
            or any(not isinstance(label, str) for label in labels):
        raise WindowsNativeObservationReadinessError("public output types differ")
    if _integer(output["artifact_count"], "artifact count") != 0:
        raise WindowsNativeObservationReadinessError("artifact count differs")
    if _hash(output["probe_sha256"], "observer probe executable") \
            != expected_probe_executable_sha256:
        raise WindowsNativeObservationReadinessError(
            "observer probe identity differs"
        )

    progress_boundary = (
        output["status"] == "FAIL"
        and output["stage"] == "native-observation"
        and output["cd_mounted"]
        and output["hardware_selection_requested"]
        and output["hardware_selection_attempted"]
        and output["hardware_selection_sent"]
        and output["hardware_dialog_closed"]
        and output["hardware_selection_guard"] == "HARDWARE_CLICK_SENT"
        and output["gt_loaded"]
        and output["create_callsite_verified"]
        and output["manager_slots_verified"]
        and output["manager_ticks"] == 120
        and output["manager_renders"] == 119
        and output["pixel_samples"] == 8
        and output["pixel_changes"] == 6
        and output["nonblack_pixels_max"] == 290688
        and output["captured_width"] == 640
        and output["captured_height"] == 457
        and output["process_cpu_ms"] == 2640
    )
    crash_boundary = (
        not output["process_alive_after_15s"]
        and not output["window_present"]
        and output["window_class"] == "none"
        and output["dialog_reason"] == "none"
        and output["window_title_safe"] == ""
        and output["button_labels_safe"] == ["", ""]
        and output["child_static_count"] == 0
        and output["child_button_count"] == 0
        and output["child_edit_count"] == 0
        and output["process_exit_code"] == 0xC0000005
    )
    device_boundary = (
        output["create_calls"] == 0
        and output["create_returns"] == 0
        and output["create_success"] == 0
        and not output["device_nonnull"]
    )
    if not progress_boundary or not crash_boundary or not device_boundary:
        raise WindowsNativeObservationReadinessError(
            "hardware progress crash boundary differs"
        )

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "run_id": run_id,
        "head_sha": head_sha,
        "status": "NATIVE_HARDWARE_PROGRESS_CRASH_DIAGNOSTIC_ONLY",
        "source_revision": {
            "head_sha": head_sha,
            "tested_tree_sha": tested_tree_sha,
        },
        "source_identities": {
            "probe_source_path": PROBE_SOURCE_PATH,
            "probe_source_blob_sha256": probe_source_sha256,
            "probe_executable_sha256": output["probe_sha256"],
        },
        "source_log": {
            "path": log_path.name,
            "sha256": expected_log_hash,
            "bytes": expected_log_bytes,
        },
        "runtime_progress": {
            "hardware_selection_sent": output["hardware_selection_sent"],
            "direct3d_module_loaded": output["gt_loaded"],
            "manager_ticks": output["manager_ticks"],
            "manager_renders": output["manager_renders"],
            "pixel_samples": output["pixel_samples"],
            "pixel_changes": output["pixel_changes"],
            "captured_width": output["captured_width"],
            "captured_height": output["captured_height"],
        },
        "failure_boundary": {
            "process_alive_after_15s": output["process_alive_after_15s"],
            "process_exit_code": output["process_exit_code"],
            "process_exit_code_hex": "0xC0000005",
            "fatal_access_violation_inferred_from_exit_code": True,
        },
        "proof_limits": {
            "direct3d_device_creation_called": False,
            "direct3d_device_created": False,
            "process_survived_15s": False,
            "fatal_exception_module_proven": False,
            "fatal_exception_rva_proven": False,
            "complete_native_gameplay_progress": False,
            "native_parity_evidence": False,
        },
    }


def classify_fatal_exception(
    manifest_path: Path,
    log_path: Path,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    expected_head_branch: str,
    expected_tested_tree_sha: str,
    expected_probe_source_sha256: str,
    expected_probe_executable_sha256: str,
) -> dict[str, Any]:
    manifest = _fields(
        _load(manifest_path, "manifest"), MANIFEST_FIELDS, "manifest"
    )
    run_id = _integer(manifest["run_id"], "run id", minimum=1)
    head_sha = _git_id(manifest["head_sha"], "run head")
    expected_run_id = _integer(expected_run_id, "expected run id", minimum=1)
    expected_head_sha = _git_id(expected_head_sha, "expected run head")
    expected_tested_tree_sha = _git_id(
        expected_tested_tree_sha, "expected tested tree"
    )
    expected_probe_source_sha256 = _git_id(
        expected_probe_source_sha256, "expected probe source blob"
    )
    expected_probe_executable_sha256 = _hash(
        expected_probe_executable_sha256, "expected observer probe executable"
    )
    for name, value in (
        ("head branch", manifest["head_branch"]),
        ("run status", manifest["status"]),
        ("run conclusion", manifest["conclusion"]),
        ("workflow name", manifest["workflow_name"]),
        ("created timestamp", manifest["created_at"]),
        ("updated timestamp", manifest["updated_at"]),
        ("expected head branch", expected_head_branch),
    ):
        if not isinstance(value, str) or not value:
            raise WindowsNativeObservationReadinessError(f"{name} is invalid")
    if run_id != expected_run_id or head_sha != expected_head_sha \
            or manifest["head_branch"] != expected_head_branch:
        raise WindowsNativeObservationReadinessError("run identity differs")
    if manifest["status"] != "completed" \
            or manifest["conclusion"] != "failure" \
            or manifest["workflow_name"] != EXPECTED_WORKFLOW \
            or manifest["created_at"] != FATAL_CREATED_AT \
            or manifest["updated_at"] != FATAL_UPDATED_AT:
        raise WindowsNativeObservationReadinessError("run metadata differs")

    tested_tree_sha = _commit_tree(head_sha)
    probe_source_sha256 = _source_blob(head_sha, PROBE_SOURCE_PATH)
    if tested_tree_sha != expected_tested_tree_sha:
        raise WindowsNativeObservationReadinessError("tested tree differs")
    if probe_source_sha256 != expected_probe_source_sha256:
        raise WindowsNativeObservationReadinessError("probe source differs")

    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise WindowsNativeObservationReadinessError(
            "run log is unavailable"
        ) from error
    if len(raw_log) != expected_log_bytes:
        raise WindowsNativeObservationReadinessError("log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise WindowsNativeObservationReadinessError("log hash differs")

    checkout_line_number = _checkout_line_number(text, expected_head_sha)
    if checkout_line_number is None:
        raise WindowsNativeObservationReadinessError("checkout identity differs")
    output, output_line_number, output_line = _public_output(
        text, FATAL_OUTPUT_FIELDS
    )
    if MAIN_JOB_STEP not in output_line:
        raise WindowsNativeObservationReadinessError(
            "public output job step differs"
        )
    if output_line_number < checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output precedes checkout"
        )
    post_checkout_line_number = _post_checkout_line_number(text)
    if post_checkout_line_number is None:
        raise WindowsNativeObservationReadinessError(
            "post-checkout cleanup is missing"
        )
    if output_line_number > post_checkout_line_number:
        raise WindowsNativeObservationReadinessError(
            "public output follows post-checkout cleanup"
        )

    labels = output["button_labels_safe"]
    if any(type(output[name]) is not bool for name in HARDWARE_BOOLEAN_FIELDS) \
            or any(
                type(output[name]) is not int
                for name in FATAL_INTEGER_FIELDS
            ) \
            or any(
                not isinstance(output[name], str)
                for name in (
                    "dialog_reason", "hardware_selection_guard", "stage",
                    "status", "window_class", "window_title_safe",
                    "fatal_access_type", "fatal_exception_module",
                    "fatal_fault_category",
                )
            ) \
            or not isinstance(output["probe_sha256"], str) \
            or SHA256.fullmatch(output["probe_sha256"]) is None \
            or output["create_hr"] is not None \
            or not isinstance(
                output["fatal_exception_code"], (str, type(None))
            ) \
            or not isinstance(
                output["fatal_exception_rva"], (str, type(None))
            ) \
            or not isinstance(labels, list) \
            or len(labels) != 2 \
            or any(not isinstance(label, str) for label in labels):
        raise WindowsNativeObservationReadinessError("public output types differ")
    if _integer(output["artifact_count"], "artifact count") != 0:
        raise WindowsNativeObservationReadinessError("artifact count differs")
    if _hash(output["probe_sha256"], "observer probe executable") \
            != expected_probe_executable_sha256:
        raise WindowsNativeObservationReadinessError(
            "observer probe identity differs"
        )

    progress_boundary = (
        output["status"] == "FAIL"
        and output["stage"] == "native-observation"
        and output["cd_mounted"]
        and output["hardware_selection_requested"]
        and output["hardware_selection_attempted"]
        and output["hardware_selection_sent"]
        and output["hardware_dialog_closed"]
        and output["hardware_selection_guard"] == "HARDWARE_CLICK_SENT"
        and output["gt_loaded"]
        and output["create_callsite_verified"]
        and output["manager_slots_verified"]
        and output["manager_ticks"] == 125
        and output["manager_renders"] == 124
        and output["pixel_samples"] == 8
        and output["pixel_changes"] == 5
        and output["nonblack_pixels_max"] == 290688
        and output["captured_width"] == 640
        and output["captured_height"] == 457
        and output["process_cpu_ms"] == 2296
    )
    located_fatal = (
        output["fatal_exception_code"] == "0xC0000005"
        and output["fatal_exception_module"] == "MulleMeck.exe"
        and output["fatal_exception_rva"] == "0x00009B22"
        and output["fatal_access_type"] == "read"
        and output["fatal_fault_category"] == "unmapped"
        and output["first_chance_av_count"] == 1
    )
    crash_boundary = (
        not output["process_alive_after_15s"]
        and not output["window_present"]
        and output["window_class"] == "none"
        and output["dialog_reason"] == "none"
        and output["window_title_safe"] == ""
        and output["button_labels_safe"] == ["", ""]
        and output["child_static_count"] == 0
        and output["child_button_count"] == 0
        and output["child_edit_count"] == 0
        and output["process_exit_code"] == 0xC0000005
    )
    device_boundary = (
        output["create_calls"] == 0
        and output["create_returns"] == 0
        and output["create_success"] == 0
        and not output["device_nonnull"]
    )
    if not progress_boundary or not located_fatal \
            or not crash_boundary or not device_boundary:
        raise WindowsNativeObservationReadinessError(
            "located fatal exception boundary differs"
        )

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "run_id": run_id,
        "head_sha": head_sha,
        "status": "NATIVE_FATAL_EXCEPTION_LOCATED_DIAGNOSTIC_ONLY",
        "source_revision": {
            "head_sha": head_sha,
            "tested_tree_sha": tested_tree_sha,
        },
        "source_identities": {
            "probe_source_path": PROBE_SOURCE_PATH,
            "probe_source_blob_sha256": probe_source_sha256,
            "probe_executable_sha256": output["probe_sha256"],
        },
        "source_log": {
            "path": log_path.name,
            "sha256": expected_log_hash,
            "bytes": expected_log_bytes,
        },
        "runtime_progress": {
            "hardware_selection_sent": output["hardware_selection_sent"],
            "direct3d_module_loaded": output["gt_loaded"],
            "manager_ticks": output["manager_ticks"],
            "manager_renders": output["manager_renders"],
            "pixel_samples": output["pixel_samples"],
            "pixel_changes": output["pixel_changes"],
            "captured_width": output["captured_width"],
            "captured_height": output["captured_height"],
        },
        "fatal_exception": {
            "code": output["fatal_exception_code"],
            "module": output["fatal_exception_module"],
            "rva": output["fatal_exception_rva"],
            "access_type": output["fatal_access_type"],
            "fault_category": output["fatal_fault_category"],
            "first_chance_av_count": output["first_chance_av_count"],
            "process_exit_code": output["process_exit_code"],
        },
        "proof_limits": {
            "direct3d_device_creation_called": False,
            "direct3d_device_created": False,
            "fatal_root_cause_proven": False,
            "fatal_fault_target_address_proven": False,
            "fatal_call_stack_proven": False,
            "complete_native_gameplay_progress": False,
            "native_parity_evidence": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--head-branch", required=True)
    parser.add_argument("--tested-tree-sha", required=True)
    parser.add_argument("--probe-source-sha256", required=True)
    parser.add_argument("--probe-executable-sha256", required=True)
    parser.add_argument(
        "--receipt-type",
        choices=(
            "static-dialog", "renderer-selector", "hardware-progress",
            "fatal-exception",
        ),
        default="static-dialog",
    )
    arguments = parser.parse_args()
    classifiers = {
        "static-dialog": classify,
        "renderer-selector": classify_renderer_selector,
        "hardware-progress": classify_hardware_progress,
        "fatal-exception": classify_fatal_exception,
    }
    classifier = classifiers[arguments.receipt_type]
    receipt = classifier(
        arguments.manifest,
        arguments.log,
        expected_run_id=arguments.run_id,
        expected_head_sha=arguments.head_sha,
        expected_head_branch=arguments.head_branch,
        expected_tested_tree_sha=arguments.tested_tree_sha,
        expected_probe_source_sha256=arguments.probe_source_sha256,
        expected_probe_executable_sha256=arguments.probe_executable_sha256,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
