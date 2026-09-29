#!/usr/bin/env python3
"""Convert a bounded public x86 Flight run into non-promotional diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


PROTOCOL = "miel-vliegt-flight-x86-diagnostic-receipt"
ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_BOOTSTRAP_STRATEGY = (
    "dinput-post-loader-worker-or-call-bootstrap"
)
LAUNCHER_INPUT_IDLE_TIMEOUT_MS = 0
LAUNCHER_PROXY_BOOTSTRAP_TIMEOUT_MS = 600000
MAX_TAIL = 64 * 1024
MIN_WINE_ERROR_BYTES = len("err:x:")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
MARKERS = frozenset({
    "MVP_INIT", "MVP_DllMain", "MVP_DI", "MVP_DDCREATE", "MVP_DD7",
    "MVP_EXC", "MVO", "MVT", "CreateDevice", "DirectDrawCreate",
})
ERROR_CODES = frozenset({
    "E_OUTOFMEMORY", "REGDB_E_CLASSNOTREG", "RPC_S_SERVER_UNAVAILABLE",
})
OUTCOME_ERROR_CODES = {
    "0x8007000E": "E_OUTOFMEMORY",
    "0x80040154": "REGDB_E_CLASSNOTREG",
    "0x800706BA": "RPC_S_SERVER_UNAVAILABLE",
}
ROLES = frozenset({
    "orchestration", "observer", "wine", "game", "proxy", "other",
})
DEVICE_ROUTES = frozenset({"HAL", "RGB_RETRY"})
DEVICE_STATES = frozenset({"NULL", "NONNULL", "UNKNOWN"})
EXCEPTION_CLASSES = frozenset({
    "DEBUG_PRINT", "ACCESS_VIOLATION", "ILLEGAL_INSTRUCTION",
    "INTEGER_DIVIDE_BY_ZERO", "CPP_EXCEPTION", "THREAD_NAME", "OTHER",
})
HRESULT = re.compile(r"^0x[0-9A-F]{8}$")
BASE_ROW_FIELDS = {
    "alias", "known_error_codes", "markers", "role",
    "size_bytes", "tail_bytes", "wine_error_count",
}
ENRICHED_ROW_FIELDS = BASE_ROW_FIELDS | {
    "device_outcomes", "exception_classes", "tail_truncated",
}


class FlightX86DiagnosticReceiptError(ValueError):
    """Raised when a run diagnostic cannot be bound or remains ambiguous."""


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


def _load(path: Path) -> dict[str, Any]:
    try:
        value = _STRICT_DECODER.decode(path.read_text(encoding="utf-8"))
    except DuplicateKeyError as error:
        raise FlightX86DiagnosticReceiptError("duplicate JSON key") from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FlightX86DiagnosticReceiptError(
            f"cannot read diagnostic input: {path}"
        ) from error
    if not isinstance(value, dict):
        raise FlightX86DiagnosticReceiptError("diagnostic input must be an object")
    return value


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise FlightX86DiagnosticReceiptError(f"{label} fields differ")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise FlightX86DiagnosticReceiptError(f"{label} is not a SHA-256")
    return value


def _commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_COMMIT.fullmatch(value) is None:
        raise FlightX86DiagnosticReceiptError(f"{label} is not a Git commit")
    return value


def _git_output(arguments: list[str]) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *arguments],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise FlightX86DiagnosticReceiptError(
            "reviewed source revision is unavailable"
        ) from error


def _commit_tree(revision: str) -> str:
    if _git_output(["cat-file", "-t", revision]).strip() != "commit":
        raise FlightX86DiagnosticReceiptError(
            "tested source revision is not a commit"
        )
    return _commit(
        _git_output(["rev-parse", f"{revision}^{{tree}}"]).strip(),
        "tested source tree",
    )


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise FlightX86DiagnosticReceiptError(f"{label} is invalid")
    return value


def _json_object_at(
    text: str, marker: str, label: str, *, consume_marker: bool = True,
) -> dict[str, Any]:
    starts = [index for index in range(len(text)) if text.startswith(marker, index)]
    if len(starts) != 1:
        raise FlightX86DiagnosticReceiptError(
            f"{label} occurrences differ"
        )
    decode_start = starts[0] + len(marker) if consume_marker else starts[0]
    try:
        value, end = _STRICT_DECODER.raw_decode(text, decode_start)
    except DuplicateKeyError as error:
        raise FlightX86DiagnosticReceiptError("duplicate JSON key") from error
    if not isinstance(value, dict) or end >= len(text) or text[end] not in "\r\n":
        raise FlightX86DiagnosticReceiptError(f"{label} is not one JSON line")
    return value


def _validate_diagnostic(value: Any) -> dict[str, Any]:
    diagnostic = _fields(
        value,
        {"schema", "protocol", "status", "logs"},
        "bounded diagnostic",
    )
    if type(diagnostic["schema"]) is not int or diagnostic["schema"] != 1 \
            or diagnostic["protocol"] != "miel-flight-bounded-log-diagnostics" \
            or diagnostic["status"] != "DIAGNOSTIC_ONLY" \
            or not isinstance(diagnostic["logs"], list) \
            or not 1 <= len(diagnostic["logs"]) <= 12:
        raise FlightX86DiagnosticReceiptError("bounded diagnostic protocol differs")
    first = diagnostic["logs"][0]
    enriched = isinstance(first, dict) and "device_outcomes" in first
    row_fields = ENRICHED_ROW_FIELDS if enriched else BASE_ROW_FIELDS
    aliases: set[str] = set()
    for index, raw in enumerate(diagnostic["logs"], 1):
        row = _fields(
            raw,
            row_fields,
            f"diagnostic log {index}",
        )
        alias = f"log_{index:02d}"
        if row["alias"] != alias or alias in aliases:
            raise FlightX86DiagnosticReceiptError("diagnostic aliases differ")
        aliases.add(alias)
        if row["role"] not in ROLES:
            raise FlightX86DiagnosticReceiptError("diagnostic role differs")
        size = _integer(row["size_bytes"], f"{alias} size")
        tail = _integer(row["tail_bytes"], f"{alias} tail")
        wine_errors = _integer(row["wine_error_count"], f"{alias} wine error count")
        if tail > size:
            raise FlightX86DiagnosticReceiptError("diagnostic tail exceeds log")
        if tail > MAX_TAIL:
            raise FlightX86DiagnosticReceiptError("diagnostic tail exceeds bound")
        if wine_errors * MIN_WINE_ERROR_BYTES > tail:
            raise FlightX86DiagnosticReceiptError("wine error count exceeds tail")
        if not isinstance(row["markers"], dict):
            raise FlightX86DiagnosticReceiptError("diagnostic markers differ")
        categorical_bytes = wine_errors * MIN_WINE_ERROR_BYTES
        for name, count in row["markers"].items():
            if name not in MARKERS:
                raise FlightX86DiagnosticReceiptError("diagnostic marker differs")
            count = _integer(count, f"{alias} marker {name}")
            if count * len(name) > tail:
                raise FlightX86DiagnosticReceiptError(
                    "diagnostic marker count exceeds tail"
                )
            categorical_bytes += count * len(name)
        if categorical_bytes > tail:
            raise FlightX86DiagnosticReceiptError(
                "diagnostic categorical bytes exceed tail"
            )
        if enriched:
            if type(row["tail_truncated"]) is not bool \
                    or row["tail_truncated"] != (size > tail):
                raise FlightX86DiagnosticReceiptError(
                    "diagnostic tail-truncation differs"
                )
            outcomes = row["device_outcomes"]
            if not isinstance(outcomes, list) or len(outcomes) > 8:
                raise FlightX86DiagnosticReceiptError("device outcomes differ")
            if outcomes and row["role"] != "proxy":
                raise FlightX86DiagnosticReceiptError("device outcome role differs")
            for outcome in outcomes:
                outcome = _fields(
                    outcome,
                    {"route", "hresult", "device"},
                    "device outcome",
                )
                if outcome["route"] not in DEVICE_ROUTES \
                        or outcome["device"] not in DEVICE_STATES \
                        or not isinstance(outcome["hresult"], str) \
                        or HRESULT.fullmatch(outcome["hresult"]) is None:
                    raise FlightX86DiagnosticReceiptError("device outcome differs")
                error_code = OUTCOME_ERROR_CODES.get(outcome["hresult"])
                if error_code is not None \
                        and error_code not in row["known_error_codes"]:
                    raise FlightX86DiagnosticReceiptError(
                        "device outcome error code is missing"
                    )
            if 2 * len(outcomes) > row["markers"].get("CreateDevice", 0):
                raise FlightX86DiagnosticReceiptError(
                    "device outcome count exceeds markers"
                )
            exception_classes = row["exception_classes"]
            if not isinstance(exception_classes, dict):
                raise FlightX86DiagnosticReceiptError("exception classes differ")
            exception_count = 0
            for name, count in exception_classes.items():
                if name not in EXCEPTION_CLASSES:
                    raise FlightX86DiagnosticReceiptError("exception class differs")
                count = _integer(count, f"{alias} exception {name}")
                exception_count += count
            if exception_count != row["markers"].get("MVP_EXC", 0):
                raise FlightX86DiagnosticReceiptError(
                    "exception count differs from markers"
                )
        if not isinstance(row["known_error_codes"], list):
            raise FlightX86DiagnosticReceiptError("diagnostic error codes differ")
        for code in row["known_error_codes"]:
            if code not in ERROR_CODES:
                raise FlightX86DiagnosticReceiptError("diagnostic error code differs")
        if len(row["known_error_codes"]) != len(set(row["known_error_codes"])):
            raise FlightX86DiagnosticReceiptError("diagnostic error codes are reused")
    return diagnostic


def _boundary(checks: dict[str, Any]) -> str:
    if not checks["proxy_observer_ready"]:
        return "target-exited-before-proxy-bootstrap"
    if not checks["login_pending_observed"]:
        return "target-exited-after-observer-ready-before-login-pending"
    if not checks["login_activation_observed"]:
        return "target-exited-after-login-pending-before-activation"
    raise FlightX86DiagnosticReceiptError("launcher receipt has no exit boundary")


def classify(
    manifest_path: Path,
    log_path: Path,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    expected_executable_sha256: str,
    expected_observer_dll_sha256: str,
    expected_real_dinput_sha256: str,
    expected_patch_receipt_sha256: str,
) -> dict[str, Any]:
    manifest = _fields(
        _load(manifest_path),
        {
            "run_id", "head_sha", "status", "artifact_count", "log_sha256",
            "log_bytes", "receipt", "bounded_diagnostic",
        },
        "run manifest",
    )
    run_id = _integer(manifest["run_id"], "run id", minimum=1)
    head_sha = _commit(manifest["head_sha"], "run head")
    expected_run_id = _integer(expected_run_id, "expected run id", minimum=1)
    expected_head_sha = _commit(expected_head_sha, "expected run head")
    expected_executable_sha256 = _hash(
        expected_executable_sha256, "expected executable"
    )
    expected_observer_dll_sha256 = _hash(
        expected_observer_dll_sha256, "expected observer DLL"
    )
    expected_real_dinput_sha256 = _hash(
        expected_real_dinput_sha256, "expected real dinput"
    )
    expected_patch_receipt_sha256 = _hash(
        expected_patch_receipt_sha256, "expected patch receipt"
    )
    if run_id != expected_run_id or head_sha != expected_head_sha:
        raise FlightX86DiagnosticReceiptError("run identity differs")
    tested_tree_sha = _commit_tree(head_sha)
    expected_log_hash = _hash(manifest["log_sha256"], "run log")
    expected_log_bytes = _integer(manifest["log_bytes"], "run log size")
    artifact_count = manifest["artifact_count"]
    if type(artifact_count) is not int or artifact_count != 0:
        raise FlightX86DiagnosticReceiptError("run artifact count differs")
    if manifest["status"] != "failure":
        raise FlightX86DiagnosticReceiptError("run publication status differs")

    receipt_summary = _fields(
        manifest["receipt"], {"phase", "detail", "checks"}, "manifest receipt"
    )
    checks = _fields(
        receipt_summary["checks"],
        {
            "proxy_observer_ready", "observer_initialized",
            "login_pending_observed", "login_activation_observed",
        },
        "manifest receipt checks",
    )
    if any(type(value) is not bool for value in checks.values()):
        raise FlightX86DiagnosticReceiptError("manifest receipt checks differ")
    diagnostic = _validate_diagnostic(manifest["bounded_diagnostic"])

    try:
        raw_log = log_path.read_bytes()
        text = raw_log.decode("utf-8", errors="replace")
    except OSError as error:
        raise FlightX86DiagnosticReceiptError("run log is unavailable") from error
    if len(raw_log) != expected_log_bytes:
        raise FlightX86DiagnosticReceiptError("run log bytes differ")
    if hashlib.sha256(raw_log).hexdigest() != expected_log_hash:
        raise FlightX86DiagnosticReceiptError("run log hash differs")

    launcher = _json_object_at(text, "RECEIPT CONTENT: ", "launcher receipt")
    if launcher.get("status") != "FAIL":
        raise FlightX86DiagnosticReceiptError("launcher status differs")
    if launcher.get("scene") != "flight":
        raise FlightX86DiagnosticReceiptError("launcher scene differs")
    input_idle_timeout = launcher.get("input_idle_probe_timeout_ms")
    proxy_timeout = launcher.get("proxy_bootstrap_timeout_ms")
    if launcher.get("bootstrap_strategy") != LAUNCHER_BOOTSTRAP_STRATEGY \
            or type(input_idle_timeout) is not int \
            or input_idle_timeout != LAUNCHER_INPUT_IDLE_TIMEOUT_MS \
            or type(proxy_timeout) is not int \
            or proxy_timeout != LAUNCHER_PROXY_BOOTSTRAP_TIMEOUT_MS:
        raise FlightX86DiagnosticReceiptError(
            "launcher bootstrap contract differs"
        )
    if type(launcher.get("schema")) is not int or launcher.get("schema") != 1 \
            or launcher.get("protocol") != "miel-vliegt-native-observer-launch" \
            or launcher.get("phase") != receipt_summary["phase"] \
            or launcher.get("detail") != receipt_summary["detail"] \
            or not isinstance(launcher.get("checks"), dict) \
            or any(launcher["checks"].get(key) != value for key, value in checks.items()):
        raise FlightX86DiagnosticReceiptError("launcher receipt differs")
    source_identities = {
        name: _hash(launcher.get(name), f"launcher {name}")
        for name in (
            "original_executable_sha256", "patched_executable_sha256",
            "observer_dll_sha256", "real_dinput_sha256",
            "patch_receipt_sha256",
        )
    }
    if source_identities["patched_executable_sha256"] != \
            source_identities["original_executable_sha256"]:
        raise FlightX86DiagnosticReceiptError(
            "byte-identical target identity differs"
        )
    if source_identities["original_executable_sha256"] != \
            expected_executable_sha256:
        raise FlightX86DiagnosticReceiptError("executable identity differs")
    if source_identities["observer_dll_sha256"] != \
            expected_observer_dll_sha256:
        raise FlightX86DiagnosticReceiptError("observer identity differs")
    if source_identities["real_dinput_sha256"] != \
            expected_real_dinput_sha256:
        raise FlightX86DiagnosticReceiptError("real dinput identity differs")
    if source_identities["patch_receipt_sha256"] != \
            expected_patch_receipt_sha256:
        raise FlightX86DiagnosticReceiptError("patch receipt identity differs")
    parsed_diagnostic = _json_object_at(
        text, '{"logs":', "bounded diagnostic", consume_marker=False,
    )
    if parsed_diagnostic != diagnostic:
        raise FlightX86DiagnosticReceiptError("bounded diagnostic differs")

    markers = Counter()
    error_codes: set[str] = set()
    wine_errors = 0
    device_outcomes: list[dict[str, Any]] = []
    exception_classes: Counter[str] = Counter()
    for row in diagnostic["logs"]:
        markers.update(row["markers"])
        error_codes.update(row["known_error_codes"])
        wine_errors += row["wine_error_count"]
        if "device_outcomes" in row:
            device_outcomes.extend(row["device_outcomes"])
            exception_classes.update(row["exception_classes"])
    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": "DIAGNOSTIC_ONLY",
        "run_id": run_id,
        "head_sha": head_sha,
        "source_revision": {
            "head_sha": head_sha,
            "tested_tree_sha": tested_tree_sha,
        },
        "run_status": manifest["status"],
        "source_log": {
            "sha256": expected_log_hash,
            "bytes": expected_log_bytes,
            "artifact_count": manifest["artifact_count"],
        },
        "source_identities": source_identities,
        "launcher_boundary": {
            "phase": receipt_summary["phase"],
            "reported_detail": receipt_summary["detail"],
            "last_proven_boundary": _boundary(checks),
            "checks": checks,
        },
        "aggregate_diagnostics": {
            "semantics": "tail_counts_across_distinct_logs",
            "markers": dict(sorted(markers.items())),
            "known_error_codes": sorted(error_codes),
            "wine_error_count": wine_errors,
        },
        "device_outcomes": device_outcomes,
        "exception_classes": dict(sorted(exception_classes.items())),
        "proof_limits": {
            "causal_device_failure_path_proven": False,
            "device_creation_reached_proven": bool(device_outcomes) and all(
                not row["tail_truncated"]
                for row in diagnostic["logs"] if "tail_truncated" in row
            ),
            "successful_device_creation_proven": False,
            "manager_initialization_proven": False,
            "native_parity_evidence": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--executable-sha256", required=True)
    parser.add_argument("--observer-dll-sha256", required=True)
    parser.add_argument("--real-dinput-sha256", required=True)
    parser.add_argument("--patch-receipt-sha256", required=True)
    arguments = parser.parse_args()
    receipt = classify(
        arguments.manifest,
        arguments.log,
        expected_run_id=arguments.run_id,
        expected_head_sha=arguments.head_sha,
        expected_executable_sha256=arguments.executable_sha256,
        expected_observer_dll_sha256=arguments.observer_dll_sha256,
        expected_real_dinput_sha256=arguments.real_dinput_sha256,
        expected_patch_receipt_sha256=arguments.patch_receipt_sha256,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    main()
