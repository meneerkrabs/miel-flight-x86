#!/usr/bin/env python3
"""Capture all 22 native mode bodies as fail-closed candidate evidence.

The suite drives the registered ``engine_mode`` callback through the existing
suspended-process observer launcher.  Its receipt proves only isolated BODY
activation/capture candidates.  It can never promote natural-transition or
native/web runtime-equivalence claims.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.miel_vliegt import hangover_probe
from tools.miel_vliegt import native_mode_bodies
from tools.miel_vliegt import native_body_trace


SCHEMA = 1
PROTOCOL = "miel-vliegt-native-body-suite"
SUITE_RECEIPT = "native-body-suite.json"
MODE_RECEIPT = "body-dispatch.json"
NAVIGATION_ARTIFACT = "navigation.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BACKEND_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
HEADLESS_POLICY = {
    "sha256": hangover_probe.HEADLESS_CONFIG_SHA256,
    "driver": "gtSoftware",
    "setupwindow": False,
    "fullscreen": False,
}


def _write_canonical_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _relative_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("BODY suite artifact path is invalid")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("BODY suite artifact escapes its output root") from error
    if not path.is_file():
        raise ValueError(f"BODY suite artifact is missing: {relative}")
    return path


def _artifact(root: Path, path: Path) -> dict[str, str]:
    return {
        "path": path.resolve().relative_to(root.resolve()).as_posix(),
        "sha256": hangover_probe.sha256(path),
    }


def _validate_dispatch_receipt(
    path: Path, executable: Path, mode_name: str, mode_id: str,
    lifecycle_validation: dict[str, Any],
) -> dict[str, Any]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("native BODY dispatcher produced no valid receipt") from error
    if not isinstance(receipt, dict):
        raise ValueError("native BODY dispatcher produced no valid receipt")
    try:
        return native_body_trace.validate_dispatch_receipt(
            receipt,
            executable_sha256=hangover_probe.sha256(executable),
            requested_mode=mode_name,
            mode_id=mode_id,
            lifecycle_validation=lifecycle_validation,
        )
    except native_body_trace.BodyTraceError as error:
        raise ValueError(f"native BODY dispatcher receipt failed closed: {error}") from error


def _validate_mode_inventory(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    modes = contract.get("modes")
    if not isinstance(modes, list) or len(modes) != 22:
        raise ValueError("BODY suite requires the exact 22-mode contract")
    ids = [row.get("id") for row in modes]
    names = [row.get("mode") for row in modes]
    if len(set(ids)) != len(ids) or len(set(names)) != len(names):
        raise ValueError("BODY suite mode inventory contains duplicates")
    if set(names) != set(hangover_probe.BODY_MODES):
        raise ValueError("BODY suite mode inventory differs from dispatcher allowlist")
    return modes


def _validate_immutable_inputs(
    expected: Mapping[Path, str], *, label: str = "BODY suite input",
) -> None:
    drifted = [path.name for path, digest in expected.items()
               if not path.is_file() or hangover_probe.sha256(path) != digest]
    if drifted:
        raise ValueError(f"{label} hash drifted: {', '.join(sorted(drifted))}")


def _validate_navigation(
    result: Mapping[str, Any], mode_name: str, game_directory: Path,
) -> None:
    headless = result.get("headless_config")
    headless_valid = bool(
        isinstance(headless, dict)
        and set(headless) == {"path", "sha256", "driver"}
        and isinstance(headless.get("path"), str)
        and Path(headless["path"]).resolve()
        == (game_directory / "config.ini").resolve()
        and headless.get("sha256") == hangover_probe.HEADLESS_CONFIG_SHA256
        and headless.get("driver") == "gtSoftware"
    )
    if (
        result.get("route") != "suspended-process-observer-launcher"
        or result.get("scene_bootstrap_confirmed") is not True
        or not isinstance(result.get("observer_launcher_receipt"), dict)
        or not isinstance(result.get("observer_log"), dict)
        or result["observer_log"].get("hook_loaded") is not True
        or not headless_valid
    ):
        raise ValueError(f"BODY suite mode {mode_name} did not bootstrap cleanly")


def capture_body_suite(
    environment: list[str],
    backend: dict[str, Any],
    executable: Path,
    output_root: Path,
    scene_debugger: Path,
    observer_dll: Path,
    observer_launcher: Path = hangover_probe.OBSERVER_LAUNCHER,
    *,
    mode_contract_path: Path = native_mode_bodies.DEFAULT_CONTRACT,
    observe_ms: int = hangover_probe.DEFAULT_OBSERVE_MS,
) -> dict[str, Any]:
    """Run every registered mode once and emit a canonical BODY-only receipt."""

    contract = native_mode_bodies.load_contract(mode_contract_path)
    modes = _validate_mode_inventory(contract)
    try:
        checked_backend = hangover_probe.validate_capture_backend(backend)
    except ValueError as error:
        raise ValueError("BODY suite backend identity is invalid") from error
    backend_id = checked_backend["id"]
    hangover_probe.validate_observe_ms(observe_ms)
    required_inputs = (
        executable, observer_dll, observer_launcher, scene_debugger,
        mode_contract_path, hangover_probe.HEADLESS_CONFIG,
    )
    if any(not path.is_file() for path in required_inputs):
        raise ValueError("BODY suite requires all hash-bound input files")
    if contract["source"]["executable_sha256"] != hangover_probe.sha256(executable):
        raise ValueError("BODY suite executable differs from native mode contract")
    if output_root.exists() and (
        not output_root.is_dir() or any(output_root.iterdir())
    ):
        raise ValueError("BODY suite output root must be absent or empty")
    output_root.mkdir(parents=True, exist_ok=True)

    immutable = {
        executable: hangover_probe.sha256(executable),
        observer_dll: hangover_probe.sha256(observer_dll),
        observer_launcher: hangover_probe.sha256(observer_launcher),
        scene_debugger: hangover_probe.sha256(scene_debugger),
        mode_contract_path: hangover_probe.sha256(mode_contract_path),
        hangover_probe.HEADLESS_CONFIG: hangover_probe.sha256(
            hangover_probe.HEADLESS_CONFIG,
        ),
    }
    captures: list[dict[str, Any]] = []
    seen_modes: set[str] = set()
    for mode in modes:
        mode_id = mode["id"]
        mode_name = mode["mode"]
        if mode_name in seen_modes:
            raise ValueError(f"BODY suite duplicate capture: {mode_name}")
        seen_modes.add(mode_name)
        _validate_immutable_inputs(immutable)

        mode_root = output_root / mode_id
        mode_root.mkdir()
        body_receipt_path = mode_root / MODE_RECEIPT
        navigation_path = mode_root / NAVIGATION_ARTIFACT
        observer_environment = {
            "MIEL_OBSERVER_BODY_MODE": mode_name,
            "MIEL_OBSERVER_BODY_RECEIPT": hangover_probe.wine_z_path(body_receipt_path),
        }
        result = hangover_probe.run_scene_navigation(
            environment,
            checked_backend,
            executable,
            mode_root / "capture.json",
            "barn",
            scene_debugger,
            observer_dll,
            observer_launcher,
            attempt_debug=False,
            allow_fallback=True,
            observe_ms=observe_ms,
            observer_environment=observer_environment,
        )
        _validate_navigation(result, mode_name, executable.parent)
        try:
            preliminary_dispatch = json.loads(
                body_receipt_path.read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(
                "native BODY dispatcher produced no valid receipt"
            ) from error
        if not isinstance(preliminary_dispatch, dict):
            raise ValueError("native BODY dispatcher produced no valid receipt")
        log_reference = result["observer_log"]
        observer_log = _relative_file(mode_root, log_reference.get("path"))
        if hangover_probe.sha256(observer_log) != log_reference.get("sha256"):
            raise ValueError(f"BODY suite observer log hash drifted: {mode_name}")
        lifecycle_validation = native_body_trace.validate_trace(
            observer_log, mode_contract_path, required_mode_ids=(mode_id,),
        )
        _validate_dispatch_receipt(
            body_receipt_path, executable, mode_name, mode_id,
            lifecycle_validation,
        )
        missing_phases = lifecycle_validation["phase_coverage"][mode_id][
            "missing_phases"
        ]

        _write_canonical_json(navigation_path, result)
        captures.append({
            "mode_id": mode_id,
            "mode": mode_name,
            "status": "INCOMPLETE" if missing_phases else "CANDIDATE_ONLY",
            "evidence_scope": "BODY_ONLY",
            "natural_transition_evidence": False,
            "runtime_equivalence": "UNPROVEN",
            "parity_eligible": False,
            "headless_config": dict(HEADLESS_POLICY),
            "missing_phases": missing_phases,
            "lifecycle_validation": lifecycle_validation,
            "dispatcher_receipt": _artifact(output_root, body_receipt_path),
            "observer_log": _artifact(output_root, observer_log),
            "navigation": _artifact(output_root, navigation_path),
        })

    _validate_immutable_inputs(immutable)
    expected_names = [row["mode"] for row in modes]
    if [row["mode"] for row in captures] != expected_names:
        raise ValueError("BODY suite capture order or completeness drifted")
    missing_phases = {
        capture["mode_id"]: capture["missing_phases"] for capture in captures
    }
    suite_complete = all(not phases for phases in missing_phases.values())
    receipt = {
        "schema": SCHEMA,
        "protocol": PROTOCOL,
        "status": "CANDIDATE_ONLY" if suite_complete else "INCOMPLETE",
        "evidence_scope": "BODY_ONLY",
        "claim": (
            "ISOLATED_NATIVE_BODY_CAPTURE_CANDIDATES"
            if suite_complete
            else "ISOLATED_NATIVE_BODY_CAPTURE_INCOMPLETE"
        ),
        "natural_transition_evidence": False,
        "runtime_equivalence": "UNPROVEN",
        "parity_eligible": False,
        "mode_count": 22,
        "missing_phases": missing_phases,
        "backend": backend_id,
        "inputs": {
            "executable_sha256": immutable[executable],
            "observer_dll_sha256": immutable[observer_dll],
            "observer_launcher_sha256": immutable[observer_launcher],
            "scene_debugger_sha256": immutable[scene_debugger],
            "native_mode_bodies_sha256": immutable[mode_contract_path],
            "headless_config_source_sha256": immutable[
                hangover_probe.HEADLESS_CONFIG
            ],
        },
        "captures": captures,
    }
    validate_body_suite_receipt(
        receipt, output_root, executable, observer_dll, observer_launcher,
        scene_debugger, mode_contract_path,
    )
    _write_canonical_json(output_root / SUITE_RECEIPT, receipt)
    return receipt


def validate_body_suite_receipt(
    receipt: Mapping[str, Any],
    output_root: Path,
    executable: Path,
    observer_dll: Path,
    observer_launcher: Path,
    scene_debugger: Path,
    mode_contract_path: Path = native_mode_bodies.DEFAULT_CONTRACT,
) -> dict[str, Any]:
    """Validate suite policy, exact coverage and every referenced artifact."""

    contract = native_mode_bodies.load_contract(mode_contract_path)
    modes = _validate_mode_inventory(contract)
    if contract["source"]["executable_sha256"] != hangover_probe.sha256(executable):
        raise ValueError("BODY suite executable differs from native mode contract")
    required = {
        "schema", "protocol", "status", "evidence_scope", "claim",
        "natural_transition_evidence", "runtime_equivalence",
        "parity_eligible", "mode_count", "missing_phases", "backend",
        "inputs", "captures",
    }
    expected_inputs = {
        "executable_sha256": hangover_probe.sha256(executable),
        "observer_dll_sha256": hangover_probe.sha256(observer_dll),
        "observer_launcher_sha256": hangover_probe.sha256(observer_launcher),
        "scene_debugger_sha256": hangover_probe.sha256(scene_debugger),
        "native_mode_bodies_sha256": hangover_probe.sha256(mode_contract_path),
        "headless_config_source_sha256": hangover_probe.sha256(
            hangover_probe.HEADLESS_CONFIG,
        ),
    }
    if (
        set(receipt) != required
        or receipt.get("schema") != SCHEMA
        or receipt.get("protocol") != PROTOCOL
        or receipt.get("status") not in {"CANDIDATE_ONLY", "INCOMPLETE"}
        or receipt.get("evidence_scope") != "BODY_ONLY"
        or receipt.get("claim") not in {
            "ISOLATED_NATIVE_BODY_CAPTURE_CANDIDATES",
            "ISOLATED_NATIVE_BODY_CAPTURE_INCOMPLETE",
        }
        or receipt.get("natural_transition_evidence") is not False
        or receipt.get("runtime_equivalence") != "UNPROVEN"
        or receipt.get("parity_eligible") is not False
        or receipt.get("mode_count") != 22
        or not isinstance(receipt.get("backend"), str)
        or BACKEND_ID.fullmatch(receipt.get("backend")) is None
        or receipt.get("inputs") != expected_inputs
    ):
        raise ValueError("BODY suite receipt policy or input identity failed closed")
    captures = receipt.get("captures")
    if not isinstance(captures, list) or len(captures) != 22:
        raise ValueError("BODY suite receipt must contain exactly 22 captures")
    if [row.get("mode") for row in captures] != [row["mode"] for row in modes]:
        raise ValueError("BODY suite receipt mode order or completeness drifted")
    if len({row.get("mode") for row in captures}) != 22:
        raise ValueError("BODY suite receipt contains duplicate modes")

    artifact_paths: set[str] = set()
    capture_fields = {
        "mode_id", "mode", "status", "evidence_scope",
        "natural_transition_evidence", "runtime_equivalence",
        "parity_eligible", "headless_config", "missing_phases",
        "lifecycle_validation", "dispatcher_receipt", "observer_log",
        "navigation",
    }
    validated_missing_phases = {}
    for capture, mode in zip(captures, modes):
        if (
            set(capture) != capture_fields
            or capture.get("mode_id") != mode["id"]
            or capture.get("mode") != mode["mode"]
            or capture.get("status") not in {"CANDIDATE_ONLY", "INCOMPLETE"}
            or capture.get("evidence_scope") != "BODY_ONLY"
            or capture.get("natural_transition_evidence") is not False
            or capture.get("runtime_equivalence") != "UNPROVEN"
            or capture.get("parity_eligible") is not False
            or capture.get("headless_config") != HEADLESS_POLICY
        ):
            raise ValueError(f"BODY suite capture escaped candidate policy: {mode['id']}")
        for artifact_name in ("dispatcher_receipt", "observer_log", "navigation"):
            artifact = capture.get(artifact_name)
            if (
                not isinstance(artifact, dict)
                or set(artifact) != {"path", "sha256"}
                or SHA256.fullmatch(artifact.get("sha256", "")) is None
                or artifact.get("path") in artifact_paths
            ):
                raise ValueError(f"BODY suite artifact identity failed: {mode['id']}")
            artifact_paths.add(artifact["path"])
            path = _relative_file(output_root, artifact["path"])
            if hangover_probe.sha256(path) != artifact["sha256"]:
                raise ValueError(f"BODY suite artifact hash drifted: {artifact['path']}")
            try:
                path.resolve().relative_to((output_root / mode["id"]).resolve())
            except ValueError as error:
                raise ValueError(
                    f"BODY suite artifact escaped mode isolation: {mode['id']}"
                ) from error
        if capture["dispatcher_receipt"]["path"] != f"{mode['id']}/{MODE_RECEIPT}" \
                or capture["navigation"]["path"] != f"{mode['id']}/{NAVIGATION_ARTIFACT}":
            raise ValueError(f"BODY suite canonical artifact names drifted: {mode['id']}")
        dispatch_path = _relative_file(
            output_root, capture["dispatcher_receipt"]["path"],
        )
        navigation_path = _relative_file(
            output_root, capture["navigation"]["path"],
        )
        try:
            navigation = json.loads(navigation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(
                f"BODY suite navigation is invalid: {mode['id']}"
            ) from error
        _validate_navigation(navigation, mode["mode"], executable.parent)
        log_reference = navigation["observer_log"]
        observer_log = _relative_file(
            navigation_path.parent, log_reference.get("path"),
        )
        expected_log = _relative_file(
            output_root, capture["observer_log"]["path"],
        )
        if (
            observer_log != expected_log
            or log_reference.get("sha256") != capture["observer_log"]["sha256"]
        ):
            raise ValueError(f"BODY suite navigation/log binding drifted: {mode['id']}")
        lifecycle_validation = native_body_trace.validate_trace(
            observer_log, mode_contract_path,
            required_mode_ids=(mode["id"],),
        )
        _validate_dispatch_receipt(
            dispatch_path, executable, mode["mode"], mode["id"],
            lifecycle_validation,
        )
        expected_missing = lifecycle_validation["phase_coverage"][mode["id"]][
            "missing_phases"
        ]
        expected_capture_status = (
            "INCOMPLETE" if expected_missing else "CANDIDATE_ONLY"
        )
        if (
            capture.get("lifecycle_validation") != lifecycle_validation
            or capture.get("missing_phases") != expected_missing
            or capture.get("status") != expected_capture_status
        ):
            raise ValueError(
                f"BODY suite lifecycle binding failed: {mode['id']}"
            )
        validated_missing_phases[mode["id"]] = expected_missing
    suite_complete = all(
        not phases for phases in validated_missing_phases.values()
    )
    expected_status = "CANDIDATE_ONLY" if suite_complete else "INCOMPLETE"
    expected_claim = (
        "ISOLATED_NATIVE_BODY_CAPTURE_CANDIDATES"
        if suite_complete
        else "ISOLATED_NATIVE_BODY_CAPTURE_INCOMPLETE"
    )
    if (
        receipt.get("missing_phases") != validated_missing_phases
        or receipt.get("status") != expected_status
        or receipt.get("claim") != expected_claim
    ):
        raise ValueError("BODY suite lifecycle completeness failed closed")
    return dict(receipt)


def load_body_suite_receipt(
    path: Path,
    executable: Path,
    observer_dll: Path,
    observer_launcher: Path,
    scene_debugger: Path,
    mode_contract_path: Path = native_mode_bodies.DEFAULT_CONTRACT,
) -> dict[str, Any]:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("BODY suite produced no valid canonical receipt") from error
    return validate_body_suite_receipt(
        receipt, path.parent, executable, observer_dll, observer_launcher,
        scene_debugger, mode_contract_path,
    )


def _environment(values: Sequence[str]) -> list[str]:
    keys: set[str] = set()
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key or not item or key in keys or any(c in value for c in "\0\r\n"):
            raise ValueError("BODY suite --env values must be unique KEY=VALUE pairs")
        keys.add(key)
    return ["env", *values]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--backend-id", required=True)
    parser.add_argument("--backend-hodll", required=True)
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("--scene-debugger", type=Path, default=hangover_probe.SCENE_DEBUGGER)
    parser.add_argument("--observer-dll", type=Path, default=hangover_probe.OBSERVER_DLL)
    parser.add_argument("--observer-launcher", type=Path, default=hangover_probe.OBSERVER_LAUNCHER)
    parser.add_argument("--mode-contract", type=Path, default=native_mode_bodies.DEFAULT_CONTRACT)
    parser.add_argument("--observe-ms", type=int, default=hangover_probe.DEFAULT_OBSERVE_MS)
    args = parser.parse_args()
    receipt = capture_body_suite(
        _environment(args.env), {
            "id": args.backend_id, "hodll": args.backend_hodll,
        }, args.executable,
        args.output_root, args.scene_debugger, args.observer_dll,
        args.observer_launcher, mode_contract_path=args.mode_contract,
        observe_ms=args.observe_ms,
    )
    return 0 if receipt["status"] == "CANDIDATE_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
