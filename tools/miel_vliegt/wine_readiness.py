#!/usr/bin/env python3
"""Validate a completed Wine capture-host lifecycle from bound diagnostics.

This validator deliberately treats process exit codes as necessary but never
sufficient.  A ready receipt also needs positive transport, RpcSs, registry,
COM activation, process-topology and clean-shutdown observations.  Live
pre-capture readiness is a separate gate because this receipt ends only after
the private wineserver has been stopped and waited.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


OBSERVATION_PROTOCOL = "miel-vliegt-wine-readiness-observation"
RECEIPT_PROTOCOL = "miel-vliegt-wine-readiness-receipt"
CLSID = re.compile(r"^\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SERVICE_RUNNING = re.compile(
    r"SERVICE_NAME\s*:\s*RpcSs.*?STATE\s*:\s*4\s+RUNNING",
    re.IGNORECASE | re.DOTALL,
)
FATAL_PATTERNS = (
    (
        "RPCSS_START_FAILED",
        re.compile(
            r"start_rpcss.*failed|failed to start RpcSs|"
            r"RpcSs.*(?:timed out|timeout)|"
            r"service did not respond.*timely fashion",
            re.IGNORECASE,
        ),
    ),
    (
        "RPC_SERVER_UNAVAILABLE",
        re.compile(
            r"RPC server is unavailable|RPC_S_SERVER_UNAVAILABLE|0x800706ba",
            re.IGNORECASE,
        ),
    ),
    (
        "COM_CLASS_NOT_REGISTERED",
        re.compile(r"class not registered|REGDB_E_CLASSNOTREG|0x80040154", re.IGNORECASE),
    ),
    (
        "COM_INITIALIZATION_FAILED",
        re.compile(r"CoInitialize(?:Ex)?.*(?:failed|error)", re.IGNORECASE),
    ),
    (
        "SERVICE_PROTOCOL_FAILED",
        re.compile(r"service protocol error|failed to write pipe", re.IGNORECASE),
    ),
    (
        "PREFIX_REGISTRY_FAILED",
        re.compile(r"could not save registry|registry.*(?:corrupt|failed)", re.IGNORECASE),
    ),
)


class WineReadinessError(ValueError):
    """Raised when readiness evidence is malformed or unbound."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WineReadinessError(f"cannot read Wine readiness observation: {path}") from error
    if not isinstance(value, dict):
        raise WineReadinessError("Wine readiness observation must be an object")
    return value


def _read_log(root: Path, reference: Any, label: str) -> tuple[str, dict[str, Any]]:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"} \
            or not isinstance(reference.get("path"), str) \
            or not SHA256.fullmatch(str(reference.get("sha256", ""))):
        raise WineReadinessError(f"{label} log reference is invalid")
    path = (root / reference["path"]).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise WineReadinessError(f"{label} log escapes its evidence directory") from error
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
    except OSError as error:
        raise WineReadinessError(f"{label} log is unavailable") from error
    digest = sha256_bytes(raw)
    if digest != reference["sha256"]:
        raise WineReadinessError(f"{label} log hash differs")
    return text, {
        "path": reference["path"],
        "sha256": digest,
        "size": len(raw),
    }


def _phase_ok(phase: dict[str, Any]) -> bool:
    return phase["exitCode"] == 0 and phase["timedOut"] is False


def _activation_pattern(clsid: str) -> re.Pattern[str]:
    return re.compile(
        rf"MIEL_COM_ACTIVATION\s+clsid={re.escape(clsid)}\s+"
        rf"hresult=0x00000000(?:\s|$)",
        re.IGNORECASE,
    )


def _registry_proven(text: str, clsid: str) -> bool:
    compact = text.replace("/", "\\")
    return (
        f"CLSID\\{clsid}\\InprocServer32".lower() in compact.lower()
        and re.search(r"\bREG_SZ\b", text, re.IGNORECASE) is not None
        and re.search(r"\.dll(?:\s|$)", text, re.IGNORECASE) is not None
    )


def _process_topology_proven(text: str) -> bool:
    lowered = text.lower()
    return all(name in lowered for name in ("wineserver", "services.exe", "rpcss.exe"))


def validate_observation(
    observation: dict[str, Any], *, evidence_root: Path,
) -> dict[str, Any]:
    required_fields = {
        "schema", "protocol", "backend", "requirements", "phases",
    }
    if set(observation) != required_fields \
            or observation.get("schema") != 1 \
            or observation.get("protocol") != OBSERVATION_PROTOCOL:
        raise WineReadinessError("unsupported Wine readiness observation")
    requirements = observation.get("requirements")
    if not isinstance(requirements, dict) or set(requirements) != {
        "service", "transportSentinel", "comClasses",
    } or requirements.get("service") != "RpcSs" \
            or not isinstance(requirements.get("transportSentinel"), str) \
            or not requirements["transportSentinel"]:
        raise WineReadinessError("Wine readiness requirements are invalid")
    classes = requirements.get("comClasses")
    if not isinstance(classes, list) or not classes \
            or len(set(classes)) != len(classes) \
            or any(not isinstance(value, str) or not CLSID.fullmatch(value)
                   for value in classes):
        raise WineReadinessError("Wine readiness COM-class inventory is invalid")
    phases = observation.get("phases")
    if not isinstance(phases, list):
        raise WineReadinessError("Wine readiness phases are unavailable")
    indexed: dict[str, dict[str, Any]] = {}
    texts: dict[str, str] = {}
    log_sources: dict[str, dict[str, Any]] = {}
    for phase in phases:
        if not isinstance(phase, dict) or set(phase) != {
            "id", "command", "exitCode", "timedOut", "log",
        } or not isinstance(phase.get("id"), str) or not phase["id"] \
                or not isinstance(phase.get("command"), list) \
                or not phase["command"] \
                or any(not isinstance(item, str) or not item for item in phase["command"]) \
                or type(phase.get("exitCode")) is not int \
                or type(phase.get("timedOut")) is not bool \
                or phase["id"] in indexed:
            raise WineReadinessError("Wine readiness phase fields differ")
        indexed[phase["id"]] = phase
        texts[phase["id"]], log_sources[phase["id"]] = _read_log(
            evidence_root, phase["log"], phase["id"],
        )

    class_phase_ids = [
        *(f"com-registry:{value}" for value in classes),
        *(f"com-activation:{value}" for value in classes),
    ]
    required_phase_ids = {
        "wineboot", "transport", "rpcss-service", "process-snapshot",
        "wineserver-shutdown", *class_phase_ids,
    }
    missing = sorted(required_phase_ids - set(indexed))
    if missing:
        raise WineReadinessError(f"Wine readiness phases are missing: {missing}")

    fatal_diagnostics = []
    for phase_id, text in texts.items():
        for code, pattern in FATAL_PATTERNS:
            if pattern.search(text):
                fatal_diagnostics.append({"code": code, "phase": phase_id})
        if indexed[phase_id]["timedOut"]:
            fatal_diagnostics.append({"code": "PHASE_TIMEOUT", "phase": phase_id})

    registry_checks = {
        clsid: (
            _phase_ok(indexed[f"com-registry:{clsid}"])
            and _registry_proven(texts[f"com-registry:{clsid}"], clsid)
        )
        for clsid in classes
    }
    activation_checks = {
        clsid: (
            _phase_ok(indexed[f"com-activation:{clsid}"])
            and _activation_pattern(clsid).search(
                texts[f"com-activation:{clsid}"]
            ) is not None
        )
        for clsid in classes
    }
    checks = {
        "wineboot_process_completed": _phase_ok(indexed["wineboot"]),
        "transport_roundtrip": (
            _phase_ok(indexed["transport"])
            and requirements["transportSentinel"] in texts["transport"]
        ),
        "rpcss_service_running": (
            _phase_ok(indexed["rpcss-service"])
            and SERVICE_RUNNING.search(texts["rpcss-service"]) is not None
        ),
        "required_com_registered": all(registry_checks.values()),
        "required_com_activated": all(activation_checks.values()),
        "service_process_topology": (
            _phase_ok(indexed["process-snapshot"])
            and _process_topology_proven(texts["process-snapshot"])
        ),
        "wineserver_clean_shutdown": (
            _phase_ok(indexed["wineserver-shutdown"])
            and "MIEL_WINESERVER_STOPPED" in texts["wineserver-shutdown"]
        ),
        "fatal_diagnostics_absent": not fatal_diagnostics,
    }
    blockers = [
        name for name, passed in checks.items() if not passed
    ]
    return {
        "schema": 1,
        "protocol": RECEIPT_PROTOCOL,
        "backend": observation["backend"],
        "requirements": requirements,
        "status": "READY" if not blockers else "BLOCKED",
        "checks": checks,
        "com": {
            "registry": registry_checks,
            "activation": activation_checks,
        },
        "blockers": blockers,
        "diagnostics": fatal_diagnostics,
        "phases": {
            phase_id: {
                "command": indexed[phase_id]["command"],
                "exitCode": indexed[phase_id]["exitCode"],
                "timedOut": indexed[phase_id]["timedOut"],
                "log": log_sources[phase_id],
            }
            for phase_id in sorted(indexed)
        },
        "exitZeroIsReadinessEvidence": False,
        "nativeParityEvidence": False,
    }


def validate_file(input_path: Path, output_path: Path | None = None) -> dict[str, Any]:
    input_path = input_path.resolve()
    observation = _load_json(input_path)
    receipt = validate_observation(observation, evidence_root=input_path.parent)
    receipt["source"] = {
        "path": input_path.name,
        "sha256": sha256_bytes(input_path.read_bytes()),
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = validate_file(args.input, args.output)
    print(json.dumps({
        "status": receipt["status"],
        "blockers": receipt["blockers"],
        "diagnostics": receipt["diagnostics"],
    }, sort_keys=True))
    return 0 if receipt["status"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
