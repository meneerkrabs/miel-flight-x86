#!/usr/bin/env python3
"""Plan, import and compare deterministic native/web scene capture artifacts.

This is deliberately an evidence transport, not a parity authority.  It binds
every imported artifact to an immutable semantic-evidence job and delegates
validation to the existing channel-specific validators.  A matching result is
therefore only ``CANDIDATE_MATCH``; release promotion remains owned by the
semantic coverage and runtime-parity validators.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.miel_vliegt import (
        flight_trace_differential,
        native_body_trace,
        native_scenario_artifacts,
        natural_transition_trace,
        scene_semantic_evidence_batches,
        udsp_semantic_oracle,
        verify_flight_runtime_contract,
    )
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import flight_trace_differential
    import native_body_trace
    import native_scenario_artifacts
    import natural_transition_trace
    import scene_semantic_evidence_batches
    import udsp_semantic_oracle
    import verify_flight_runtime_contract


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BATCH_PLAN = ROOT / "content/miel_vliegt/scene_semantic_evidence_batches.json"
DEFAULT_LEDGER = ROOT / "content/miel_vliegt/scene_semantic_coverage.json"
DEFAULT_EXECUTABLE = ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json"
SCHEMA = 1
PLAN_PROTOCOL = "miel-vliegt-deterministic-scene-scenario-plan"
IMPORT_PROTOCOL = "miel-vliegt-deterministic-scene-capture-import"
RESULT_PROTOCOL = "miel-vliegt-deterministic-scene-capture-result"
NORMALIZED_PROTOCOL = "miel-vliegt-deterministic-scene-normalized-channel"
DIFFERENTIAL_PROTOCOL = "miel-vliegt-deterministic-scene-candidate-differential"
CHANNELS = ("mode", "body", "transition", "semantic", "framebuffer")
PRODUCERS = ("NATIVE", "WEB")
SHA256 = frozenset("0123456789abcdef")
ADAPTERS = {
    "semantic": {
        "semantic-document": ("NATIVE", "WEB"),
    },
    "mode": {
        "flight-frame-trace": ("NATIVE", "WEB"),
        "native-semantic-log": ("NATIVE",),
    },
    "body": {
        "native-body-trace": ("NATIVE",),
        "flight-frame-trace": ("NATIVE", "WEB"),
    },
    "transition": {
        "natural-transition": ("NATIVE", "WEB"),
    },
    "framebuffer": {
        "framebuffer-manifest": ("NATIVE", "WEB"),
        "native-framebuffer-metadata": ("NATIVE",),
    },
}


class ScenarioRunnerError(ValueError):
    """Raised when capture planning/import is not exact and fail-closed."""


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= SHA256


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScenarioRunnerError(f"cannot read {label}: {path}") from error


def _inside(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ScenarioRunnerError(f"{label} must be a relative path")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ScenarioRunnerError(f"{label} escapes evidence root") from error
    if not path.is_file():
        raise ScenarioRunnerError(f"{label} does not exist: {relative}")
    return path


def _jobs(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [job for batch in plan["batches"] for job in batch["jobs"]]


def load_checked_batch_plan(path: Path = DEFAULT_BATCH_PLAN) -> dict[str, Any]:
    plan = _load_json(path, "semantic evidence batch plan")
    scene_semantic_evidence_batches.validate_plan(
        plan, ledger_path=DEFAULT_LEDGER,
    )
    return plan


def build_run_plan(
    batch_plan: dict[str, Any], *, batch_ids: Iterable[str] = (),
    claim_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Create a deterministic execution/import plan over checked jobs."""

    batch_ids = tuple(batch_ids)
    claim_ids = tuple(claim_ids)
    selected_batches = set(batch_ids)
    selected_claims = set(claim_ids)
    if len(selected_batches) != len(batch_ids) \
            or len(selected_claims) != len(claim_ids):
        raise ScenarioRunnerError("batch/claim selectors must be unique")
    available_batches = {batch["id"] for batch in batch_plan["batches"]}
    available_claims = {job["claimId"] for job in _jobs(batch_plan)}
    if not selected_batches <= available_batches:
        raise ScenarioRunnerError("run plan selects an unknown batch")
    if not selected_claims <= available_claims:
        raise ScenarioRunnerError("run plan selects an unknown claim")

    runs = []
    for batch in batch_plan["batches"]:
        for job in batch["jobs"]:
            if selected_batches and batch["id"] not in selected_batches:
                continue
            if selected_claims and job["claimId"] not in selected_claims:
                continue
            channels = []
            for channel in CHANNELS:
                channels.append({
                    "channel": channel,
                    "required": channel == "semantic",
                    "producerAdapters": {
                        producer: sorted(
                            adapter for adapter, producers in ADAPTERS[channel].items()
                            if producer in producers
                        )
                        for producer in PRODUCERS
                    },
                    "missingProducerPolicy": "FAIL_CLOSED_NOT_COMPARABLE",
                })
            runs.append({
                "schema": SCHEMA,
                "id": f"SCENARIO_RUN:{job['jobSha256']}",
                "batchId": batch["id"],
                "jobId": job["id"],
                "jobSha256": job["jobSha256"],
                "claimId": job["claimId"],
                "evidenceClass": job["evidenceClass"],
                "scenarioId": job["scenario"]["scenarioId"],
                "scenarioSha256": job["scenarioSha256"],
                "subjectSha256": job["subjectSha256"],
                "expectationSha256": job["expectationSha256"],
                "captureSlices": copy.deepcopy(job["captureSlices"]),
                "channels": channels,
                "promotionAllowed": False,
            })
    if not runs:
        raise ScenarioRunnerError("run plan selects no jobs")
    result = {
        "schema": SCHEMA,
        "protocol": PLAN_PROTOCOL,
        "edition": batch_plan["edition"],
        "status": "PLANNED_NOT_EXECUTED",
        "parityEligible": False,
        "sourcePlan": {
            "contract": batch_plan["contract"],
            "manifestSha256": batch_plan["manifestSha256"],
            "fileSha256": sha256_file(DEFAULT_BATCH_PLAN),
        },
        "policy": {
            "channels": list(CHANNELS),
            "producers": list(PRODUCERS),
            "requiredChannel": "semantic",
            "rawArtifactsMustBeDistinct": True,
            "promotionAuthority": "EXTERNAL_VALIDATORS_ONLY",
            "maximumResult": "CANDIDATE_MATCH",
        },
        "runs": runs,
        "runsSha256": canonical_sha256([
            {"id": run["id"], "jobSha256": run["jobSha256"]}
            for run in runs
        ]),
    }
    result["planSha256"] = canonical_sha256(result)
    return result


def validate_run_plan(
    value: Any, batch_plan: dict[str, Any],
) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "protocol", "edition", "status", "parityEligible",
        "sourcePlan", "policy", "runs", "runsSha256", "planSha256",
    }:
        raise ScenarioRunnerError("scenario run plan fields differ")
    if value.get("schema") != SCHEMA or value.get("protocol") != PLAN_PROTOCOL \
            or value.get("status") != "PLANNED_NOT_EXECUTED" \
            or value.get("parityEligible") is not False:
        raise ScenarioRunnerError("scenario run plan escaped fail-closed planning")
    expected_source = {
        "contract": batch_plan["contract"],
        "manifestSha256": batch_plan["manifestSha256"],
        "fileSha256": sha256_file(DEFAULT_BATCH_PLAN),
    }
    expected_policy = {
        "channels": list(CHANNELS),
        "producers": list(PRODUCERS),
        "requiredChannel": "semantic",
        "rawArtifactsMustBeDistinct": True,
        "promotionAuthority": "EXTERNAL_VALIDATORS_ONLY",
        "maximumResult": "CANDIDATE_MATCH",
    }
    if value.get("edition") != batch_plan["edition"] \
            or value.get("sourcePlan") != expected_source \
            or value.get("policy") != expected_policy:
        raise ScenarioRunnerError("scenario run plan source/policy differs")
    unhashed = {key: item for key, item in value.items() if key != "planSha256"}
    if value.get("planSha256") != canonical_sha256(unhashed):
        raise ScenarioRunnerError("scenario run plan hash differs")
    jobs = {
        job["id"]: (batch["id"], job)
        for batch in batch_plan["batches"] for job in batch["jobs"]
    }
    seen = set()
    for run in value.get("runs", []):
        found = jobs.get(run.get("jobId")) if isinstance(run, dict) else None
        if found is None:
            raise ScenarioRunnerError("scenario run differs from checked job")
        batch_id, job = found
        expected_fields = {
            "schema": SCHEMA,
            "id": f"SCENARIO_RUN:{job['jobSha256']}",
            "batchId": batch_id,
            "jobId": job["id"],
            "jobSha256": job["jobSha256"],
            "claimId": job["claimId"],
            "evidenceClass": job["evidenceClass"],
            "scenarioId": job["scenario"]["scenarioId"],
            "scenarioSha256": job["scenarioSha256"],
            "subjectSha256": job["subjectSha256"],
            "expectationSha256": job["expectationSha256"],
            "captureSlices": job["captureSlices"],
            "promotionAllowed": False,
        }
        if any(run.get(key) != item for key, item in expected_fields.items()) \
                or run.get("id") in seen or run.get("promotionAllowed") is not False:
            raise ScenarioRunnerError("scenario run differs from checked job")
        seen.add(run["id"])
        expected_channels = [{
            "channel": channel,
            "required": channel == "semantic",
            "producerAdapters": {
                producer: sorted(
                    adapter for adapter, producers in ADAPTERS[channel].items()
                    if producer in producers
                )
                for producer in PRODUCERS
            },
            "missingProducerPolicy": "FAIL_CLOSED_NOT_COMPARABLE",
        } for channel in CHANNELS]
        if run.get("channels") != expected_channels:
            raise ScenarioRunnerError("scenario run channel order differs")
    expected_runs_hash = canonical_sha256([
        {"id": run["id"], "jobSha256": run["jobSha256"]}
        for run in value["runs"]
    ])
    if not seen or value.get("runsSha256") != expected_runs_hash:
        raise ScenarioRunnerError("scenario run inventory hash differs")
    return {"runs": len(seen), "channels": len(seen) * len(CHANNELS)}


def _identity(job: dict[str, Any], batch_plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "edition": batch_plan["edition"],
        "claimId": job["claimId"],
        "evidenceClass": job["evidenceClass"],
        "sourceHashes": {
            "sceneDispatchContract": batch_plan["sources"]["sceneDispatchContract"]["sha256"],
            "udsSceneScripts": batch_plan["sources"]["udsSceneScripts"]["sha256"],
            "executableUdspSceneScripts": (
                batch_plan["sources"]["executableUdspSceneScripts"]["sha256"]
            ),
        },
        "subjectSha256": job["subjectSha256"],
        "expectationSha256": job["expectationSha256"],
    }


def _normalize_semantic(
    path: Path, producer: str, job: dict[str, Any], batch_plan: dict[str, Any],
    entry: dict[str, Any],
) -> dict[str, Any]:
    document = _load_json(path, "semantic raw document")
    executable_bytes = DEFAULT_EXECUTABLE.read_bytes()
    executable = json.loads(executable_bytes)
    ledger = _load_json(DEFAULT_LEDGER, "semantic coverage ledger")
    expectation = next(
        row["expectation"] for row in ledger["records"]
        if row["id"] == job["claimId"]
    )
    provenance = entry.get("expectedCaptureProvenance")
    normalizer = (
        udsp_semantic_oracle.normalize_native_trace
        if producer == "NATIVE" else udsp_semantic_oracle.normalize_web_trace
    )
    return normalizer(
        document, executable, _identity(job, batch_plan),
        executable_source_bytes=executable_bytes,
        expected_expectation=expectation,
        expected_capture_provenance=provenance,
    )


def _normalize_flight_trace(path: Path, producer: str) -> dict[str, Any]:
    trace = flight_trace_differential.load_trace(path)
    expected_kind = producer.lower()
    if trace["capture_kind"] != expected_kind:
        raise ScenarioRunnerError("flight frame trace producer differs")
    return trace


def _normalize_framebuffer_manifest(
    path: Path, producer: str, evidence_root: Path,
) -> dict[str, Any]:
    evidence_root = evidence_root.resolve()
    _manifest_path, rgba, size = verify_flight_runtime_contract._framebuffer_manifest(
        evidence_root, path.relative_to(evidence_root).as_posix(),
        f"{producer.lower()} framebuffer",
    )
    return {
        "width": size[0],
        "height": size[1],
        "canonicalFormat": "rgba8",
        "canonicalRgbaSha256": hashlib.sha256(rgba).hexdigest(),
    }


def _normalize_artifact(
    *, channel: str, adapter: str, producer: str, path: Path,
    evidence_root: Path, job: dict[str, Any], batch_plan: dict[str, Any],
    entry: dict[str, Any],
) -> dict[str, Any]:
    if adapter == "semantic-document":
        return _normalize_semantic(path, producer, job, batch_plan, entry)
    if adapter == "flight-frame-trace":
        return _normalize_flight_trace(path, producer)
    if adapter == "native-semantic-log":
        return native_scenario_artifacts.parse_semantic_log(path, require_complete=True)
    if adapter == "native-body-trace":
        return native_body_trace.validate_trace(path)
    if adapter == "natural-transition":
        return natural_transition_trace.load_capture(
            path, f"{producer.lower()}-gameplay",
        )
    if adapter == "framebuffer-manifest":
        return _normalize_framebuffer_manifest(path, producer, evidence_root)
    if adapter == "native-framebuffer-metadata":
        metadata = native_scenario_artifacts.load_framebuffer_metadata(
            path, root=evidence_root,
        )
        raw = path.with_suffix(".raw").read_bytes()
        rgba = native_scenario_artifacts.canonicalize_native_framebuffer(metadata, raw)
        return {
            "width": metadata["width"],
            "height": metadata["height"],
            "canonicalFormat": "rgba8",
            "canonicalRgbaSha256": hashlib.sha256(rgba).hexdigest(),
        }
    raise ScenarioRunnerError(f"unsupported capture adapter: {adapter}")


def import_captures(
    run_plan: dict[str, Any], manifest: Any, *, evidence_root: Path,
    batch_plan: dict[str, Any],
) -> dict[str, Any]:
    """Validate and normalize hash-bound artifacts without promoting parity."""

    validate_run_plan(run_plan, batch_plan)
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "protocol", "planSha256", "artifacts",
    } or manifest.get("schema") != SCHEMA or manifest.get("protocol") != IMPORT_PROTOCOL \
            or manifest.get("planSha256") != run_plan["planSha256"] \
            or not isinstance(manifest.get("artifacts"), list):
        raise ScenarioRunnerError("capture import manifest fields differ")
    declared_paths = [
        entry.get("path") if isinstance(entry, dict) else None
        for entry in manifest["artifacts"]
    ]
    if len(declared_paths) != len(set(declared_paths)):
        raise ScenarioRunnerError("capture artifacts may not be reused across slots")
    jobs = {job["id"]: job for job in _jobs(batch_plan)}
    runs = {run["id"]: run for run in run_plan["runs"]}
    seen_slots = set()
    seen_paths = set()
    normalized = []
    for entry in manifest["artifacts"]:
        required = {"runId", "producer", "channel", "adapter", "path", "sha256"}
        optional = {"expectedCaptureProvenance"}
        if not isinstance(entry, dict) or set(entry) - required - optional \
                or not required <= set(entry):
            raise ScenarioRunnerError("capture import entry fields differ")
        run = runs.get(entry["runId"])
        producer = entry["producer"]
        channel = entry["channel"]
        adapter = entry["adapter"]
        if run is None or producer not in PRODUCERS or channel not in CHANNELS \
                or adapter not in ADAPTERS[channel] \
                or producer not in ADAPTERS[channel][adapter]:
            raise ScenarioRunnerError("capture import slot is unsupported")
        if "expectedCaptureProvenance" in entry and adapter != "semantic-document":
            raise ScenarioRunnerError(
                "capture provenance override is semantic-document-only"
            )
        slot = (entry["runId"], producer, channel)
        if slot in seen_slots:
            raise ScenarioRunnerError("capture import contains a duplicate slot")
        seen_slots.add(slot)
        path = _inside(evidence_root, entry["path"], "capture artifact")
        if path in seen_paths:
            raise ScenarioRunnerError("capture artifacts may not be reused across slots")
        seen_paths.add(path)
        if not _is_sha256(entry["sha256"]) or sha256_file(path) != entry["sha256"]:
            raise ScenarioRunnerError("capture artifact hash differs")
        job = jobs[run["jobId"]]
        payload = _normalize_artifact(
            channel=channel, adapter=adapter, producer=producer, path=path,
            evidence_root=evidence_root, job=job, batch_plan=batch_plan, entry=entry,
        )
        row = {
            "schema": SCHEMA,
            "protocol": NORMALIZED_PROTOCOL,
            "runId": run["id"],
            "jobId": run["jobId"],
            "claimId": run["claimId"],
            "producer": producer,
            "channel": channel,
            "adapter": adapter,
            "raw": {
                "path": entry["path"],
                "sha256": entry["sha256"],
                "size": path.stat().st_size,
            },
            "payload": payload,
            "payloadSha256": canonical_sha256(payload),
            "parityEligible": False,
        }
        normalized.append(row)
    normalized.sort(key=lambda row: (
        row["runId"], CHANNELS.index(row["channel"]), PRODUCERS.index(row["producer"]),
    ))
    required_slots = {
        (run["id"], producer, "semantic")
        for run in run_plan["runs"] for producer in PRODUCERS
    }
    missing_required = sorted(required_slots - seen_slots)
    result = {
        "schema": SCHEMA,
        "protocol": RESULT_PROTOCOL,
        "status": "CANDIDATE_IMPORTED" if not missing_required else "INCOMPLETE",
        "parityEligible": False,
        "planSha256": run_plan["planSha256"],
        "normalized": normalized,
        "missingRequiredSlots": [
            {"runId": run_id, "producer": producer, "channel": channel}
            for run_id, producer, channel in missing_required
        ],
    }
    result["resultSha256"] = canonical_sha256(result)
    return result


def compare_imported(result: dict[str, Any]) -> dict[str, Any]:
    """Compare paired normalized channels, capped at candidate evidence."""

    rows = result.get("normalized") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        raise ScenarioRunnerError("capture result has no normalized rows")
    paired: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for row in rows:
        paired.setdefault((row["runId"], row["channel"]), {})[row["producer"]] = row
    comparisons = []
    for (run_id, channel), producers in sorted(paired.items()):
        if set(producers) != set(PRODUCERS):
            comparisons.append({
                "runId": run_id, "channel": channel,
                "result": "NOT_COMPARABLE_MISSING_PRODUCER",
                "parityEligible": False,
            })
            continue
        native = producers["NATIVE"]
        web = producers["WEB"]
        if native["adapter"] != web["adapter"]:
            comparisons.append({
                "runId": run_id,
                "channel": channel,
                "result": "NOT_COMPARABLE_ADAPTERS_DIFFER",
                "detail": {
                    "nativeAdapter": native["adapter"],
                    "webAdapter": web["adapter"],
                },
                "parityEligible": False,
            })
            continue
        elif channel == "semantic":
            detail = udsp_semantic_oracle.compare_normalized_traces(
                native["payload"], web["payload"],
            )
            match = detail["result"] in {
                "TEST_ONLY_MATCH", "PRODUCTION_MATCH_UNREVIEWED",
            }
        elif native["adapter"] == "natural-transition":
            identity_fields = (
                "edition", "edge", "source_scene", "scene", "entry_path",
                "transition_site", "transition_trigger", "transition_predicate",
            )
            native_identity = {
                field: native["payload"][field] for field in identity_fields
            }
            web_identity = {
                field: web["payload"][field] for field in identity_fields
            }
            match = native_identity == web_identity
            detail = {"native": native_identity, "web": web_identity}
        elif native["adapter"] == "flight-frame-trace":
            report = flight_trace_differential.compare_traces(
                native["payload"], web["payload"],
            )
            match = report.matches
            detail = {
                "scenario": report.scenario,
                "framesCompared": report.frames_compared,
                "firstDivergence": (
                    None if report.divergence is None else {
                        "path": report.divergence.path,
                        "reason": report.divergence.reason,
                        "native": report.divergence.native,
                        "web": report.divergence.web,
                    }
                ),
            }
        else:
            match = native["payloadSha256"] == web["payloadSha256"]
            detail = {
                "nativePayloadSha256": native["payloadSha256"],
                "webPayloadSha256": web["payloadSha256"],
            }
        comparisons.append({
            "runId": run_id,
            "channel": channel,
            "result": "CANDIDATE_MATCH" if match else "DIVERGED",
            "detail": detail,
            "parityEligible": False,
        })
    output = {
        "schema": SCHEMA,
        "protocol": DIFFERENTIAL_PROTOCOL,
        "status": (
            "CANDIDATE_MATCH"
            if comparisons and all(row["result"] == "CANDIDATE_MATCH"
                                   for row in comparisons)
            else "INCOMPLETE_OR_DIVERGED"
        ),
        "parityEligible": False,
        "comparisons": comparisons,
    }
    output["differentialSha256"] = canonical_sha256(output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-plan", type=Path, default=DEFAULT_BATCH_PLAN)
    parser.add_argument("--run-plan", type=Path)
    parser.add_argument("--batch", action="append", default=[])
    parser.add_argument("--claim", action="append", default=[])
    parser.add_argument("--write-plan", type=Path)
    parser.add_argument("--import-manifest", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    batch_plan = load_checked_batch_plan(args.batch_plan)
    run_plan = (
        _load_json(args.run_plan, "scenario run plan")
        if args.run_plan else build_run_plan(
            batch_plan, batch_ids=args.batch, claim_ids=args.claim,
        )
    )
    validate_run_plan(run_plan, batch_plan)
    value: Any = run_plan
    if args.write_plan:
        args.write_plan.write_text(
            json.dumps(run_plan, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    if args.import_manifest:
        if args.evidence_root is None:
            raise ScenarioRunnerError("--evidence-root is required for import")
        value = import_captures(
            run_plan, _load_json(args.import_manifest, "capture import manifest"),
            evidence_root=args.evidence_root, batch_plan=batch_plan,
        )
        value = {"capture": value, "differential": compare_imported(value)}
    if args.output:
        args.output.write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    else:
        print(json.dumps(value, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
