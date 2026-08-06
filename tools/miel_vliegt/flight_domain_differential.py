#!/usr/bin/env python3
"""Generate seven headless web traces and fail-closed native domain reports.

Scenario/replay files define deterministic capture inputs; they are not native
runtime evidence. At present the retained native consensus supplies a partial
baseline only for ``default-airplane-fixed-camera-frame``. Every unavailable
domain therefore remains explicitly blocked instead of being inferred.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import flight_trace_differential as differential
    from tools.miel_vliegt import native_scenario_artifacts as artifacts
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import flight_trace_differential as differential
    import native_scenario_artifacts as artifacts


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SUITE = Path("/tmp/miel-native-suite/suite-spec.json")
DEFAULT_CONSENSUS = ROOT / "content/miel_vliegt/native_default_flight_consensus.json"
DEFAULT_OUTPUT = ROOT / "tmp/miel-flight-domain-differential"
NODE_CAPTURE = ROOT / "tools/miel_vliegt/run_web_flight_domain_capture.cjs"
PROTOCOL = "miel-vliegt-flight-domain-differential"
VERSION = 1
DOMAIN_ORDER = (
    "timing", "controls", "physics", "systems", "collision", "camera",
    "rendering",
)
DOMAIN_LABEL = {"rendering": "render"}


class DomainDifferentialError(ValueError):
    pass


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise DomainDifferentialError(
            f"{path}: invalid JSON at line {error.lineno}",
        ) from error


def _render(value: Any) -> str:
    return json.dumps(
        value, indent=2, ensure_ascii=False, sort_keys=False, allow_nan=False,
    ) + "\n"


def _sha256_file(path: Path) -> str:
    return artifacts.sha256_file(path)


def _sha256_text(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _run_web_capture(scenario_path: Path) -> dict[str, Any]:
    process = subprocess.run(
        ["node", str(NODE_CAPTURE), str(scenario_path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise DomainDifferentialError(
            f"headless web capture failed for {scenario_path.name}:\n"
            f"{process.stderr.strip()}",
        )
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise DomainDifferentialError(
            f"headless web capture returned invalid JSON for {scenario_path.name}",
        ) from error
    required = {
        "schema", "protocol", "status", "promotion_allowed", "renderer",
        "runtime_identity", "trace",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema") != 1 \
            or value.get("protocol") != "miel-vliegt-headless-web-domain-capture" \
            or value.get("status") != "DIAGNOSTIC_STATE_TRACE_ONLY" \
            or value.get("promotion_allowed") is not False:
        raise DomainDifferentialError("headless web capture did not stay fail-closed")
    renderer = value["renderer"]
    if not isinstance(renderer, dict) \
            or renderer.get("rasterized") is not False \
            or renderer.get("framebuffer_evidence") is not False:
        raise DomainDifferentialError("headless web capture claimed visual evidence")
    differential.validate_trace(value["trace"], f"web capture {scenario_path.name}")
    if value["trace"]["capture_kind"] != "web":
        raise DomainDifferentialError("headless web capture has the wrong capture_kind")
    return value


def _load_detached_suite(path: Path) -> dict[str, Any]:
    """Validate a copied suite whose hashed save fixture is not locally present.

    The scenario JSON and compiled MVO bytes are still checked exactly. Missing
    save bytes remain an explicit provenance gap and are never treated as a
    native capture.
    """
    suite = _load_json(path)
    required = {
        "schema", "protocol", "status", "production_claim", "scenario_order",
        "scenarios",
    }
    if not isinstance(suite, dict) or set(suite) != required \
            or suite.get("schema") != 1 \
            or suite.get("protocol") != artifacts.SUITE_SPEC_PROTOCOL \
            or suite.get("status") != "CAPTURE_SPEC_ONLY" \
            or suite.get("production_claim") is not False \
            or suite.get("scenario_order") != list(artifacts.SCENARIO_ID_ORDER):
        raise DomainDifferentialError("detached scenario suite contract differs")
    rows = suite.get("scenarios")
    if not isinstance(rows, list) or len(rows) != len(artifacts.SCENARIO_ID_ORDER):
        raise DomainDifferentialError("detached scenario suite must contain seven entries")
    root = path.parent
    for expected_id, row in zip(artifacts.SCENARIO_ID_ORDER, rows, strict=True):
        if not isinstance(row, dict) or set(row) != {
            "id", "scenario", "native_replay", "observation_profile",
            "capture_tick", "complete_tick",
        } or row.get("id") != expected_id:
            raise DomainDifferentialError("detached scenario suite order differs")
        scenario_ref = row["scenario"]
        replay_ref = row["native_replay"]
        if not isinstance(scenario_ref, dict) or set(scenario_ref) != {
            "path", "sha256", "semantic_sha256",
        } or not isinstance(replay_ref, dict) or set(replay_ref) != {
            "path", "sha256",
        }:
            raise DomainDifferentialError(f"detached suite reference differs for {expected_id}")
        try:
            observation_profile = artifacts.validate_scenario_observation_profile(
                row["observation_profile"], scenario_id=expected_id,
            )
            observation_profile_sha256 = artifacts.observation_profile_sha256(
                observation_profile, scenario_id=expected_id,
            )
            expected_profile_sha256 = artifacts.observation_profile_sha256(
                artifacts.scenario_observation_profile(expected_id),
                scenario_id=expected_id,
            )
        except artifacts.ArtifactError as error:
            raise DomainDifferentialError(
                f"detached suite observation profile differs for {expected_id}"
            ) from error
        if observation_profile_sha256 != expected_profile_sha256:
            raise DomainDifferentialError(
                f"detached suite observation profile hash drifted for {expected_id}"
            )
        scenario_path = root / scenario_ref["path"]
        replay_path = root / replay_ref["path"]
        if _sha256_file(scenario_path) != scenario_ref["sha256"] \
                or _sha256_file(replay_path) != replay_ref["sha256"]:
            raise DomainDifferentialError(f"detached suite file hash drifted for {expected_id}")
        scenario = artifacts.load_scenario(scenario_path)
        if scenario["id"] != expected_id \
                or artifacts.scenario_sha256(scenario) != scenario_ref["semantic_sha256"] \
                or replay_path.read_bytes() != artifacts.build_native_replay_script(scenario):
            raise DomainDifferentialError(
                f"detached suite semantic or replay identity drifted for {expected_id}",
            )
        if row["capture_tick"] != scenario["checkpoints"][-1]["tick"] \
                or row["complete_tick"] != scenario["input_script"]["tick_count"] - 1:
            raise DomainDifferentialError(f"detached suite tick binding drifted for {expected_id}")
    return suite


def _divergence_value(divergence: differential.Divergence) -> dict[str, Any]:
    value = {
        "frame": divergence.frame,
        "path": divergence.path,
        "reason": divergence.reason,
        "native": divergence.native,
        "web": divergence.web,
    }
    if divergence.tolerance is not None:
        value["tolerance"] = {
            "absolute": divergence.tolerance.absolute,
            "relative": divergence.tolerance.relative,
        }
    return value


def _comparison_status(report: differential.ComparisonReport) -> str:
    if report.matches:
        return "MATCH"
    reason = report.divergence.reason
    if reason.startswith("native ") or "no canonical native" in reason:
        return "NATIVE_OBSERVATION_INCOMPLETE"
    if reason.startswith("web ") or "no canonical web" in reason:
        return "WEB_OBSERVATION_INCOMPLETE"
    return "DIVERGED"


def _missing_native_domains() -> dict[str, Any]:
    return {
        DOMAIN_LABEL.get(domain, domain): {
            "status": "NATIVE_EVIDENCE_MISSING",
            "frames_compared": 0,
            "first_divergence": {
                "frame": None,
                "path": "native_evidence",
                "reason": (
                    "The calibrated scenario and MVO replay are capture specs, "
                    "not a completed native runtime trace."
                ),
                "native": None,
                "web": "headless diagnostic trace available",
            },
        }
        for domain in DOMAIN_ORDER
    }


def _compare_domains(
    native: dict[str, Any], web: dict[str, Any],
) -> dict[str, Any]:
    result = {}
    for domain in DOMAIN_ORDER:
        report = differential.compare_trace_domain(native, web, domain)
        row = {
            "status": _comparison_status(report),
            "frames_compared": report.frames_compared,
            "first_divergence": (
                None if report.matches else _divergence_value(report.divergence)
            ),
        }
        result[DOMAIN_LABEL.get(domain, domain)] = row
    return result


def build_artifacts(
    suite_path: Path, consensus_path: Path,
) -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    suite_path = suite_path.resolve()
    consensus_path = consensus_path.resolve()
    try:
        suite = _load_detached_suite(suite_path)
    except (OSError, artifacts.ArtifactError) as error:
        raise DomainDifferentialError(str(error)) from error
    consensus = _load_json(consensus_path)
    suite_root = suite_path.parent
    web_traces: dict[str, str] = {}
    scenario_rows = []
    runtime_identity = None

    for entry in suite["scenarios"]:
        scenario_path = suite_root / entry["scenario"]["path"]
        scenario = artifacts.load_scenario(scenario_path)
        capture = _run_web_capture(scenario_path)
        web = capture["trace"]
        if web["scenario"] != scenario:
            raise DomainDifferentialError(
                f"web trace scenario differs for {entry['id']}",
            )
        if runtime_identity is None:
            runtime_identity = capture["runtime_identity"]
        elif runtime_identity != capture["runtime_identity"]:
            raise DomainDifferentialError("web runtime identity changed during capture")
        trace_name = f"web-traces/{entry['id']}.json"
        trace_text = _render(web)
        web_traces[trace_name] = trace_text

        native_status = "NATIVE_RUNTIME_EVIDENCE_MISSING"
        native_source = None
        domains = _missing_native_domains()
        if entry["id"] == consensus.get("scenario"):
            native_source = {
                "consensus_artifact_sha256": _sha256_file(consensus_path),
            }
            native = differential.native_consensus_to_trace(
                consensus, native_source, scenario,
            )
            domains = _compare_domains(native, web)
            native_status = consensus["status"]

        scenario_rows.append({
            "id": entry["id"],
            "capture_spec": {
                "scenario_sha256": entry["scenario"]["sha256"],
                "scenario_semantic_sha256": entry["scenario"]["semantic_sha256"],
                "native_replay_sha256": entry["native_replay"]["sha256"],
                "native_replay_is_evidence": False,
                "initial_files_present": all(
                    (suite_root / row["path"]).is_file()
                    for row in scenario["initial_state"]["files"]
                ),
                "tick_count": scenario["input_script"]["tick_count"],
            },
            "web_trace": {
                "path": trace_name,
                "sha256": _sha256_text(trace_text),
                "frame_count": len(web["frames"]),
                "status": capture["status"],
                "promotion_allowed": False,
            },
            "native_evidence": {
                "status": native_status,
                "source": native_source,
                "promotion_allowed": False,
            },
            "domains": domains,
        })

    statuses = Counter(
        domain["status"]
        for scenario in scenario_rows
        for domain in scenario["domains"].values()
    )
    report = {
        "schema": VERSION,
        "protocol": PROTOCOL,
        "status": "FAIL_CLOSED",
        "promotion_allowed": False,
        "tolerance_policy": {
            "default_absolute": 0.0,
            "default_relative": 0.0,
            "overrides": [],
        },
        "domain_order": [DOMAIN_LABEL.get(value, value) for value in DOMAIN_ORDER],
        "summary": {
            "scenario_count": len(scenario_rows),
            "domain_check_count": len(scenario_rows) * len(DOMAIN_ORDER),
            "status_counts": dict(sorted(statuses.items())),
        },
        "scenarios": scenario_rows,
    }
    report_text = _render(report)
    manifest = {
        "schema": VERSION,
        "protocol": f"{PROTOCOL}-manifest",
        "status": "DIAGNOSTIC_ONLY",
        "promotion_allowed": False,
        "inputs": {
            "suite_spec_sha256": _sha256_file(suite_path),
            "native_consensus_sha256": _sha256_file(consensus_path),
            "suite_status": suite["status"],
            "suite_production_claim": suite["production_claim"],
        },
        "web_capture": {
            "protocol": "miel-vliegt-headless-web-domain-capture",
            "browser_e2e": False,
            "rasterized": False,
            "runtime_identity": runtime_identity,
        },
        "artifacts": {
            **{
                name: {"sha256": _sha256_text(text)}
                for name, text in web_traces.items()
            },
            "mismatch-report.json": {"sha256": _sha256_text(report_text)},
        },
    }
    return web_traces, manifest, report


def _expected_files(
    web_traces: dict[str, str], manifest: dict[str, Any], report: dict[str, Any],
) -> dict[str, str]:
    return {
        **web_traces,
        "manifest.json": _render(manifest),
        "mismatch-report.json": _render(report),
    }


def write_or_check(output: Path, files: dict[str, str], *, check: bool) -> None:
    output = output.resolve()
    if check:
        for relative, expected in files.items():
            path = output / relative
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                raise DomainDifferentialError(
                    f"domain differential artifact is stale: {path}",
                )
        return
    for relative, rendered in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--consensus", type=Path, default=DEFAULT_CONSENSUS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check", action="store_true",
        help="verify that the output directory matches a fresh headless run",
    )
    args = parser.parse_args(argv)
    try:
        web_traces, manifest, report = build_artifacts(
            args.suite, args.consensus,
        )
        write_or_check(
            args.output,
            _expected_files(web_traces, manifest, report),
            check=args.check,
        )
    except (OSError, DomainDifferentialError, ValueError, TypeError) as error:
        print(f"FLIGHT DOMAIN DIFFERENTIAL FAILED: {error}", file=sys.stderr)
        return 2
    counts = report["summary"]["status_counts"]
    print(
        f"flight domain differential: scenarios={report['summary']['scenario_count']} "
        f"checks={report['summary']['domain_check_count']} "
        f"statuses={json.dumps(counts, sort_keys=True)}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
