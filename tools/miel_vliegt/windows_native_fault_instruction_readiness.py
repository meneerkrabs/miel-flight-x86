#!/usr/bin/env python3
"""Bind the reviewed native fault instruction without claiming its cause."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


PROTOCOL = "miel-vliegt-windows-native-fault-instruction-readiness"
ROOT = Path(__file__).resolve().parents[2]
MAIN_JOB_NAME = "extract-in-one-job"
MAIN_JOB_STEP = "Probe private game extraction without an artifact"
PROBE_SOURCE_PATH = "tools/miel_vliegt/windows_native_probe/native_probe.c"
WORKFLOW_SOURCE_PATH = ".github/workflows/native-flight-windows-readiness.yml"
SOURCE_IDENTITY_PATH = "content/miel_vliegt/source_identity.json"
EXPECTED_WORKFLOW = "Native Flight Windows extraction readiness"
EXPECTED_CREATED_AT = "2026-09-26T10:45:20Z"
EXPECTED_UPDATED_AT = "2026-09-26T10:46:21Z"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_FIELDS = {
    "run_id", "head_branch", "head_sha", "status", "conclusion",
    "workflow_name", "created_at", "updated_at", "log_sha256", "log_bytes",
}
PUBLIC_OUTPUT_FIELDS = {
    "artifact_count", "audio_entry_count", "audio_entry_esi_unchanged",
    "audio_entry_same_thread", "audio_entry_verified", "b1c_changed_esi",
    "b1c_post_esi_category", "b1c_post_matches_fatal",
    "b1c_single_step_seen", "button_labels_safe", "captured_height",
    "captured_width", "cd_mounted", "child_button_count",
    "child_edit_count", "child_static_count", "create_calls",
    "create_callsite_verified", "create_hr", "create_returns",
    "create_success", "debugger_attached", "device_nonnull",
    "dialog_reason", "esi_block_categories", "esi_block_hits",
    "esi_block_matches_fatal", "esi_block_verified", "fatal_access_type",
    "fatal_context_available", "fatal_exception_code",
    "fatal_exception_module", "fatal_exception_rva", "fatal_fault_category",
    "fault_instruction_esi_plus_620", "fault_instruction_shape",
    "fault_mnemonic", "fault_offset", "fault_register",
    "fault_register_category", "first_chance_av_count", "gt_loaded",
    "hardware_dialog_closed", "hardware_selection_attempted",
    "hardware_selection_guard", "hardware_selection_requested",
    "hardware_selection_sent", "instruction_shape_verified",
    "last_audio_arg_category", "last_audio_ecx_category",
    "last_audio_esi_category", "last_audio_return_rva",
    "last_b1c_after_audio_entry", "last_esi_transition_block",
    "manager_renders", "manager_slots_verified", "manager_ticks",
    "nonblack_pixels_max", "pixel_changes", "pixel_samples",
    "pre_fault_destinations", "pre_fault_instruction_shape",
    "pre_fault_mnemonics", "pre_fault_writes_esi", "probe_sha256",
    "process_alive_after_15s", "process_cpu_ms", "process_exit_code",
    "register_categories", "stack_return_rvas", "stage", "status",
    "wave_out_devices", "window_class", "window_present",
    "window_title_safe",
}
BOOLEAN_FIELDS = {
    "audio_entry_esi_unchanged", "audio_entry_same_thread",
    "audio_entry_verified", "b1c_changed_esi", "b1c_post_matches_fatal",
    "b1c_single_step_seen", "cd_mounted", "create_callsite_verified",
    "debugger_attached", "device_nonnull", "fatal_context_available",
    "fault_instruction_esi_plus_620", "gt_loaded",
    "hardware_dialog_closed", "hardware_selection_attempted",
    "hardware_selection_requested", "hardware_selection_sent",
    "instruction_shape_verified", "last_b1c_after_audio_entry",
    "manager_slots_verified", "pre_fault_writes_esi",
    "process_alive_after_15s", "window_present",
}
INTEGER_FIELDS = {
    "artifact_count", "audio_entry_count", "captured_height",
    "captured_width", "child_button_count", "child_edit_count",
    "child_static_count", "create_calls", "create_returns",
    "create_success", "first_chance_av_count", "fault_offset",
    "manager_renders",
    "manager_ticks", "nonblack_pixels_max", "pixel_changes",
    "pixel_samples", "process_cpu_ms", "process_exit_code",
    "wave_out_devices",
}
STRING_FIELDS = {
    "b1c_post_esi_category", "dialog_reason", "fatal_access_type",
    "fatal_exception_code", "fatal_exception_module", "fatal_exception_rva",
    "fatal_fault_category", "fault_instruction_shape", "fault_mnemonic",
    "fault_register", "fault_register_category", "hardware_selection_guard",
    "last_audio_arg_category",
    "last_audio_ecx_category", "last_audio_esi_category",
    "last_audio_return_rva", "pre_fault_instruction_shape", "stage",
    "status", "window_class",
}
ESI_BLOCK_KEYS = {"0x00409AF1", "0x00409B10", "0x00409B1C"}
REGISTER_NAMES = {
    "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
}


class WindowsNativeFaultInstructionReadinessError(ValueError):
    """Raised when fault-instruction evidence is unbound or overclaims."""


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
        raise WindowsNativeFaultInstructionReadinessError(
            f"duplicate JSON key in {label}"
        ) from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsNativeFaultInstructionReadinessError(
            f"cannot read {label}: {path}"
        ) from error
    if not isinstance(value, dict):
        raise WindowsNativeFaultInstructionReadinessError(
            f"{label} must be an object"
        )
    return value


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise WindowsNativeFaultInstructionReadinessError(
            f"{label} fields differ"
        )
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise WindowsNativeFaultInstructionReadinessError(
            f"{label} is not a SHA-256"
        )
    return value


def _git_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_ID.fullmatch(value) is None:
        raise WindowsNativeFaultInstructionReadinessError(
            f"{label} is not a Git object ID"
        )
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise WindowsNativeFaultInstructionReadinessError(
            f"{label} is invalid"
        )
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
        raise WindowsNativeFaultInstructionReadinessError(
            "reviewed source revision is unavailable"
        ) from error


def _commit_tree(revision: str) -> str:
    if _git_output(["cat-file", "-t", revision]) != "commit":
        raise WindowsNativeFaultInstructionReadinessError(
            "reviewed source revision is not a commit"
        )
    return _git_id(
        _git_output(["rev-parse", f"{revision}^{{tree}}"]),
        "reviewed source tree",
    )


def _source_blob(revision: str, path: str) -> str:
    return _git_id(
        _git_output(["rev-parse", f"{revision}:{path}"]),
        f"reviewed source blob {path}",
    )


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
            raise WindowsNativeFaultInstructionReadinessError(
                "duplicate JSON key in public output"
            ) from error
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "probe_sha256" in value:
            candidates.append((value, line_number, line))
    if len(candidates) != 1:
        raise WindowsNativeFaultInstructionReadinessError(
            "public output occurrences differ"
        )
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
                and fields[0] == MAIN_JOB_NAME \
                and fields[1].startswith("Run actions/checkout@") \
                and line.rstrip().endswith(head_sha):
            return line_number
    return None


def _post_checkout_line_number(text: str) -> int | None:
    for line_number, line in enumerate(text.splitlines()):
        fields = line.rstrip().split("\t")
        if len(fields) >= 3 \
                and fields[0] == MAIN_JOB_NAME \
                and fields[1].startswith("Post Run actions/checkout@"):
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
    expected_workflow_source_sha256: str,
    expected_source_identity_sha256: str,
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
    expected_workflow_source_sha256 = _git_id(
        expected_workflow_source_sha256, "expected workflow source blob"
    )
    expected_source_identity_sha256 = _git_id(
        expected_source_identity_sha256, "expected source identity blob"
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
            raise WindowsNativeFaultInstructionReadinessError(
                f"{name} is invalid"
            )
    if run_id != expected_run_id or head_sha != expected_head_sha \
            or manifest["head_branch"] != expected_head_branch:
        raise WindowsNativeFaultInstructionReadinessError(
            "run identity differs"
        )
    if manifest["status"] != "completed" \
            or manifest["conclusion"] != "failure" \
            or manifest["workflow_name"] != EXPECTED_WORKFLOW \
            or manifest["created_at"] != EXPECTED_CREATED_AT \
            or manifest["updated_at"] != EXPECTED_UPDATED_AT:
        raise WindowsNativeFaultInstructionReadinessError(
            "run metadata differs"
        )

    tested_tree_sha = _commit_tree(head_sha)
    probe_source_sha = _source_blob(head_sha, PROBE_SOURCE_PATH)
    workflow_source_sha = _source_blob(head_sha, WORKFLOW_SOURCE_PATH)
    source_identity_sha = _source_blob(head_sha, SOURCE_IDENTITY_PATH)
    if tested_tree_sha != expected_tested_tree_sha:
        raise WindowsNativeFaultInstructionReadinessError(
            "tested tree differs"
        )
    if probe_source_sha != expected_probe_source_sha256 \
            or workflow_source_sha != expected_workflow_source_sha256 \
            or source_identity_sha != expected_source_identity_sha256:
        raise WindowsNativeFaultInstructionReadinessError(
            "reviewed source identity differs"
        )

    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise WindowsNativeFaultInstructionReadinessError(
            "run log is unavailable"
        ) from error
    if len(raw_log) != expected_log_bytes:
        raise WindowsNativeFaultInstructionReadinessError("log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise WindowsNativeFaultInstructionReadinessError("log hash differs")

    checkout_line_number = _checkout_line_number(text, expected_head_sha)
    if checkout_line_number is None:
        raise WindowsNativeFaultInstructionReadinessError(
            "checkout identity differs"
        )
    output, output_line_number, output_line = _public_output(text)
    output_fields = output_line.rstrip().split("\t")
    if len(output_fields) < 3 \
            or output_fields[0] != MAIN_JOB_NAME \
            or output_fields[1] != MAIN_JOB_STEP:
        raise WindowsNativeFaultInstructionReadinessError(
            "public output job step differs"
        )
    if output_line_number < checkout_line_number:
        raise WindowsNativeFaultInstructionReadinessError(
            "public output precedes checkout"
        )
    post_checkout_line_number = _post_checkout_line_number(text)
    if post_checkout_line_number is None:
        raise WindowsNativeFaultInstructionReadinessError(
            "post-checkout cleanup is missing"
        )
    if output_line_number > post_checkout_line_number:
        raise WindowsNativeFaultInstructionReadinessError(
            "public output follows post-checkout cleanup"
        )

    labels = output["button_labels_safe"]
    block_categories = output["esi_block_categories"]
    block_hits = output["esi_block_hits"]
    block_matches = output["esi_block_matches_fatal"]
    block_verified = output["esi_block_verified"]
    register_categories = output["register_categories"]
    stack_returns = output["stack_return_rvas"]
    if any(type(output[name]) is not bool for name in BOOLEAN_FIELDS) \
            or any(type(output[name]) is not int for name in INTEGER_FIELDS) \
            or any(
                not isinstance(output[name], str) or not output[name]
                for name in STRING_FIELDS
            ) \
            or not isinstance(output["probe_sha256"], str) \
            or not isinstance(output["window_title_safe"], str) \
            or SHA256.fullmatch(output["probe_sha256"]) is None \
            or output["create_hr"] is not None \
            or output["last_esi_transition_block"] is not None \
            or not isinstance(labels, list) \
            or len(labels) != 2 \
            or any(not isinstance(label, str) for label in labels) \
            or any(
                not isinstance(value, dict) or set(value) != ESI_BLOCK_KEYS
                or any(not isinstance(item, str) for item in value.values())
                for value in (block_categories,)
            ) \
            or any(
                not isinstance(value, dict) or set(value) != ESI_BLOCK_KEYS
                or any(type(item) is not int for item in value.values())
                for value in (block_hits,)
            ) \
            or any(
                not isinstance(value, dict) or set(value) != ESI_BLOCK_KEYS
                or any(type(item) is not bool for item in value.values())
                for value in (block_matches, block_verified)
            ) \
            or not isinstance(register_categories, dict) \
            or set(register_categories) != REGISTER_NAMES \
            or any(
                not isinstance(value, str)
                for value in register_categories.values()
            ) \
            or not isinstance(stack_returns, list) \
            or any(
                not isinstance(row, dict) or set(row) != {"module", "rva"}
                or not isinstance(row.get("module"), str)
                or not isinstance(row.get("rva"), str)
                for row in stack_returns
            ) \
            or not isinstance(output["pre_fault_mnemonics"], list) \
            or any(
                not isinstance(value, str)
                for value in output["pre_fault_mnemonics"]
            ) \
            or not isinstance(output["pre_fault_destinations"], list) \
            or any(
                not isinstance(value, str)
                for value in output["pre_fault_destinations"]
            ):
        raise WindowsNativeFaultInstructionReadinessError(
            "public output types differ"
        )
    if _integer(output["artifact_count"], "artifact count") != 0:
        raise WindowsNativeFaultInstructionReadinessError(
            "artifact count differs"
        )
    if _hash(output["probe_sha256"], "observer probe executable") \
            != expected_probe_executable_sha256:
        raise WindowsNativeFaultInstructionReadinessError(
            "observer probe identity differs"
        )

    expected_stack_returns = [
        {"module": "MulleMeck.exe", "rva": "0x00009942"},
        {"module": "MulleMeck.exe", "rva": "0x000086F3"},
        {"module": "MulleMeck.exe", "rva": "0x0000E0F5"},
        {"module": "MulleMeck.exe", "rva": "0x000058AC"},
    ]
    expected_registers = {
        "EAX": "near_null", "EBX": "private", "ECX": "near_null",
        "EDX": "private", "ESI": "unmapped", "EDI": "module",
        "EBP": "near_null", "ESP": "private",
    }
    runtime_boundary = (
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
        and output["pixel_samples"] == 11
        and output["pixel_changes"] == 8
        and output["nonblack_pixels_max"] == 292480
        and output["captured_width"] == 640
        and output["captured_height"] == 457
        and output["process_cpu_ms"] == 3140
        and output["wave_out_devices"] == 0
    )
    fault_context = (
        output["debugger_attached"]
        and output["fatal_context_available"]
        and output["fatal_exception_code"] == "0xC0000005"
        and output["fatal_exception_module"] == "MulleMeck.exe"
        and output["fatal_exception_rva"] == "0x00009B22"
        and output["fatal_access_type"] == "read"
        and output["fatal_fault_category"] == "unmapped"
        and output["first_chance_av_count"] == 1
        and output["fault_register"] == "ESI"
        and output["fault_offset"] == 620
        and output["fault_register_category"] == "unmapped"
        and output["register_categories"] == expected_registers
        and output["stack_return_rvas"] == expected_stack_returns
    )
    instruction_boundary = (
        output["instruction_shape_verified"]
        and output["fault_mnemonic"] == "CMP"
        and output["fault_instruction_shape"] == "ACCESS_ESI_PLUS_620"
        and output["fault_instruction_esi_plus_620"]
        and output["pre_fault_instruction_shape"] == "OTHER"
        and output["pre_fault_mnemonics"] == ["MOV"]
        and output["pre_fault_destinations"] == ["OTHER_REGISTER"]
        and not output["pre_fault_writes_esi"]
    )
    entry_boundary = (
        output["audio_entry_verified"]
        and output["audio_entry_count"] == 38
        and output["audio_entry_same_thread"]
        and not output["audio_entry_esi_unchanged"]
        and output["last_audio_esi_category"] == "private"
        and output["last_audio_ecx_category"] == "private"
        and output["last_audio_arg_category"] == "module"
        and output["last_audio_return_rva"] == "0x00009942"
        and output["esi_block_verified"] == {
            "0x00409AF1": True,
            "0x00409B10": True,
            "0x00409B1C": True,
        }
        and output["esi_block_hits"] == {
            "0x00409AF1": 502,
            "0x00409B10": 38,
            "0x00409B1C": 3,
        }
        and output["esi_block_categories"] == {
            "0x00409AF1": "near_null",
            "0x00409B10": "near_null",
            "0x00409B1C": "module",
        }
        and output["esi_block_matches_fatal"] == {
            "0x00409AF1": False,
            "0x00409B10": False,
            "0x00409B1C": False,
        }
        and output["last_b1c_after_audio_entry"]
        and output["b1c_single_step_seen"]
        and output["b1c_post_esi_category"] == "module"
        and not output["b1c_changed_esi"]
        and not output["b1c_post_matches_fatal"]
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
    if not runtime_boundary or not fault_context \
            or not instruction_boundary or not entry_boundary \
            or not crash_boundary or not device_boundary:
        raise WindowsNativeFaultInstructionReadinessError(
            "fault instruction boundary differs"
        )

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "run_id": run_id,
        "head_sha": head_sha,
        "status": "NATIVE_FAULT_INSTRUCTION_BOUND_DIAGNOSTIC_ONLY",
        "source_revision": {
            "head_sha": head_sha,
            "tested_tree_sha": tested_tree_sha,
        },
        "source_identities": {
            "probe_source_path": PROBE_SOURCE_PATH,
            "probe_source_blob_sha256": probe_source_sha,
            "probe_executable_sha256": output["probe_sha256"],
            "workflow_source_path": WORKFLOW_SOURCE_PATH,
            "workflow_source_blob_sha256": workflow_source_sha,
            "source_identity_path": SOURCE_IDENTITY_PATH,
            "source_identity_blob_sha256": source_identity_sha,
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
        "fault_instruction": {
            "shape_verified": output["instruction_shape_verified"],
            "mnemonic": output["fault_mnemonic"],
            "shape": output["fault_instruction_shape"],
            "esi_plus_620": output["fault_instruction_esi_plus_620"],
            "pre_fault_mnemonics": list(output["pre_fault_mnemonics"]),
            "pre_fault_destinations": list(
                output["pre_fault_destinations"]
            ),
            "pre_fault_writes_esi": output["pre_fault_writes_esi"],
        },
        "fault_context": {
            "exception_code": output["fatal_exception_code"],
            "module": output["fatal_exception_module"],
            "rva": output["fatal_exception_rva"],
            "access_type": output["fatal_access_type"],
            "fault_register": output["fault_register"],
            "fault_offset": output["fault_offset"],
            "fault_register_category": output["fault_register_category"],
        },
        "raw_instruction_bytes_published": False,
        "raw_register_values_published": False,
        "proof_limits": {
            "esi_writing_instruction_proven": False,
            "fatal_root_cause_proven": False,
            "audio_service_absence_caused_fault_proven": False,
            "direct3d_device_creation_called": False,
            "direct3d_device_created": False,
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
    parser.add_argument("--workflow-source-sha256", required=True)
    parser.add_argument("--source-identity-sha256", required=True)
    arguments = parser.parse_args()
    receipt = classify(
        arguments.manifest,
        arguments.log,
        expected_run_id=arguments.run_id,
        expected_head_sha=arguments.head_sha,
        expected_head_branch=arguments.head_branch,
        expected_tested_tree_sha=arguments.tested_tree_sha,
        expected_probe_source_sha256=arguments.probe_source_sha256,
        expected_probe_executable_sha256=arguments.probe_executable_sha256,
        expected_workflow_source_sha256=arguments.workflow_source_sha256,
        expected_source_identity_sha256=arguments.source_identity_sha256,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
