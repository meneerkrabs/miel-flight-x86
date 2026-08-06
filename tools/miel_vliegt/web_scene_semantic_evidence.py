#!/usr/bin/env python3
"""Generate and validate headless web evidence for all scene-semantic jobs.

The producer executes only typed routes that exist in the current web engine:
``SceneDispatchRuntime`` for dispatch/policy claims and a fresh
``UdspSceneRuntime`` for each executable or hash-bound source-lowering claim.
Browser-owned media ports and failed command coverage remain explicit per-slot
blockers. The output is candidate evidence only; it cannot promote native/web
parity.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import (
        scene_semantic_coverage as coverage,
        scene_semantic_evidence_batches as batches,
        scene_semantic_scenario_runner as runner,
        udsp_semantic_oracle as oracle,
    )
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import scene_semantic_coverage as coverage
    import scene_semantic_evidence_batches as batches
    import scene_semantic_scenario_runner as runner
    import udsp_semantic_oracle as oracle


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/web_scene_semantic_evidence_manifest.json"
DEFAULT_ARTIFACT_ROOT = ROOT / "content/miel_vliegt/web_scene_semantic_evidence"
DEFAULT_LEDGER = coverage.DEFAULT_LEDGER
DEFAULT_PLAN = batches.DEFAULT_OUTPUT
DEFAULT_EXECUTABLE = ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json"
DEFAULT_DISPATCH = ROOT / "content/miel_vliegt/scene_dispatch_contract.json"
DEFAULT_SOURCE_ARTIFACT = ROOT / "content/miel_vliegt/uds_scene_scripts.json"
DEFAULT_ASSET_CONTRACT = ROOT / "content/miel_vliegt/flight_scene_asset_contract.json"
NODE_PRODUCER = ROOT / "tools/miel_vliegt/run_web_scene_semantic_evidence.cjs"
WEB_PRODUCER = ROOT / "src/flight/engine/scene/WebSceneSemanticEvidenceProducer.js"
WEB_UDSP_RUNTIME = ROOT / "src/flight/engine/scene/UdspSceneRuntime.js"
WEB_DISPATCH_RUNTIME = ROOT / "src/flight/engine/scene/SceneDispatchRuntime.js"
WEB_DISPATCH_EXECUTOR = (
    ROOT / "src/flight/engine/scene/WebSceneDispatchCaptureExecutor.js"
)
WEB_ACTOR_RUNTIME = (
    ROOT / "src/flight/engine/scene/FlightActorPresentationRuntime.js"
)
WEB_HEADLESS_PORT_OBSERVER = (
    ROOT / "src/flight/engine/scene/HeadlessScenePortObserver.js"
)
WEB_SOURCE_EXECUTION_ROUTE = (
    ROOT / "src/flight/engine/scene/SourceUdspExecutionRoute.js"
)
SCHEMA = 1
PRODUCER_PROTOCOL = "miel-vliegt-headless-web-scene-semantic-producer"
MANIFEST_PROTOCOL = "miel-vliegt-headless-web-scene-semantic-manifest"
ARTIFACT_PROTOCOL = "miel-vliegt-headless-web-scene-semantic-artifact"
CAPTURED = "CAPTURED_CANDIDATE"
BLOCKED = "BLOCKED"
SHA256 = frozenset("0123456789abcdef")


class WebSceneSemanticEvidenceError(ValueError):
    """Raised when web semantic evidence is incomplete, reused or unbound."""


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def javascript_sorted_sha256(value: Any) -> str:
    """Match JSON.stringify after recursively sorting object keys in JS.

    ECMAScript always serializes array-index-looking object keys numerically
    before the remaining insertion-ordered keys, even when the object was
    constructed from a lexicographically sorted key list.
    """

    def array_index(key: str) -> int | None:
        if not key.isdigit() or (len(key) > 1 and key.startswith("0")):
            return None
        value = int(key)
        return value if 0 <= value < 2**32 - 1 and str(value) == key else None

    def normalize(item: Any) -> Any:
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, dict):
            keys = sorted(item)
            indices = sorted(
                ((array_index(key), key) for key in keys if array_index(key) is not None),
                key=lambda pair: pair[0],
            )
            ordinary = [key for key in keys if array_index(key) is None]
            return {
                key: normalize(item[key])
                for _index, key in indices
            } | {
                key: normalize(item[key])
                for key in ordinary
            }
        return item

    return hashlib.sha256(json.dumps(
        normalize(value), ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= SHA256


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("utf-8")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WebSceneSemanticEvidenceError(f"cannot read {label}: {path}") from error
    if not isinstance(value, dict):
        raise WebSceneSemanticEvidenceError(f"{label} must be an object")
    return value


def _source(path: Path, schema: int = 1) -> dict[str, Any]:
    try:
        relative = path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError as error:
        raise WebSceneSemanticEvidenceError("semantic source escapes repository") from error
    return {"path": relative, "sha256": sha256_file(path), "schema": schema}


def _jobs(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [job for batch in plan["batches"] for job in batch["jobs"]]


def _identity(
    job: dict[str, Any], plan: dict[str, Any],
) -> dict[str, Any]:
    return {
        "edition": plan["edition"],
        "claimId": job["claimId"],
        "evidenceClass": job["evidenceClass"],
        "sourceHashes": {
            "sceneDispatchContract": plan["sources"]["sceneDispatchContract"]["sha256"],
            "udsSceneScripts": plan["sources"]["udsSceneScripts"]["sha256"],
            "executableUdspSceneScripts": (
                plan["sources"]["executableUdspSceneScripts"]["sha256"]
            ),
        },
        "subjectSha256": job["subjectSha256"],
        "expectationSha256": job["expectationSha256"],
    }


def _write_content_addressed(
    root: Path, group: str, document: dict[str, Any],
) -> dict[str, Any]:
    data = _json_bytes(document)
    digest = hashlib.sha256(data).hexdigest()
    relative = Path(group) / f"{digest}.json"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != data:
        raise WebSceneSemanticEvidenceError("semantic content-address collision")
    path.write_bytes(data)
    return {
        "path": (Path("content/miel_vliegt/web_scene_semantic_evidence") / relative).as_posix(),
        "sha256": digest,
        "size": len(data),
    }


def _walk_receipt_indices(
    value: Any, *, artifact_key: str, field: str, result: set[int],
) -> None:
    if isinstance(value, list):
        for item in value:
            _walk_receipt_indices(
                item, artifact_key=artifact_key, field=field, result=result,
            )
        return
    if not isinstance(value, dict):
        return
    if value.get("script") == artifact_key and type(value.get(field)) is int:
        result.add(value[field])
    outcome = value.get("outcome")
    if isinstance(outcome, dict):
        _walk_receipt_indices(
            outcome.get("branches"),
            artifact_key=artifact_key, field=field, result=result,
        )
    scheduler = value.get("scheduler")
    if isinstance(scheduler, dict):
        _walk_receipt_indices(
            scheduler.get("children"),
            artifact_key=artifact_key, field=field, result=result,
        )


def _validate_executable_coverage(
    raw: dict[str, Any], job: dict[str, Any],
) -> list[int]:
    observed: set[int] = set()
    _walk_receipt_indices(
        raw.get("receipts"),
        artifact_key=job["scenario"]["artifactKey"],
        field="executableCommandIndex",
        result=observed,
    )
    required = job["scenario"]["coverage"]["requiredExecutableCommandIndices"]
    missing = [index for index in required if index not in observed]
    if missing:
        raise WebSceneSemanticEvidenceError(
            f"captured executable job misses required commands: {job['claimId']}"
        )
    return sorted(observed)


def _validate_source_coverage(
    raw: dict[str, Any], job: dict[str, Any],
) -> tuple[list[int], list[int], list[int]]:
    observed_source: set[int] = set()
    observed_executable: set[int] = set()
    _walk_receipt_indices(
        raw.get("receipts"),
        artifact_key=job["scenario"]["artifactKey"],
        field="sourceCommandIndex",
        result=observed_source,
    )
    _walk_receipt_indices(
        raw.get("receipts"),
        artifact_key=job["scenario"]["artifactKey"],
        field="executableCommandIndex",
        result=observed_executable,
    )
    lowering = raw.get("lowering")
    if not isinstance(lowering, list):
        raise WebSceneSemanticEvidenceError(
            f"captured source job has no lowering: {job['claimId']}"
        )
    lowered_absent = sorted(
        row["sourceCommandIndex"]
        for row in lowering
        if isinstance(row, dict) and row.get("disposition") == "NO_COMMAND_NODE"
    )
    if len(lowered_absent) != len(set(lowered_absent)):
        raise WebSceneSemanticEvidenceError(
            f"captured source job repeats removed commands: {job['claimId']}"
        )
    required = job["scenario"]["coverage"]["requiredSourceCommandIndices"]
    covered = set(observed_source) | set(lowered_absent)
    missing = [index for index in required if index not in covered]
    if missing or sorted(covered) != required:
        raise WebSceneSemanticEvidenceError(
            f"captured source job misses required commands: {job['claimId']}"
        )
    return (
        sorted(observed_source),
        lowered_absent,
        sorted(observed_executable),
    )


def _candidate_identity() -> dict[str, str]:
    digest = sha256_file(WEB_PRODUCER)
    return {
        "candidateVersion": f"headless-{digest[:16]}",
        "captureBundleSha256": digest,
    }


def _expected_sources() -> dict[str, dict[str, Any]]:
    return {
        "semanticCoverage": _source(DEFAULT_LEDGER, coverage.SCHEMA),
        "semanticEvidencePlan": _source(DEFAULT_PLAN, batches.SCHEMA),
        "executableUdspSceneScripts": _source(DEFAULT_EXECUTABLE, 1),
        "sceneDispatchContract": _source(DEFAULT_DISPATCH, 1),
        "udsSceneScripts": _source(DEFAULT_SOURCE_ARTIFACT, 2),
        "flightSceneAssetContract": _source(DEFAULT_ASSET_CONTRACT, 1),
        "scenarioRunner": _source(Path(runner.__file__), runner.SCHEMA),
        "semanticOracle": _source(Path(oracle.__file__), 1),
        "nodeProducer": _source(NODE_PRODUCER, 1),
        "webProducer": _source(WEB_PRODUCER, 1),
        "webUdspRuntime": _source(WEB_UDSP_RUNTIME, 1),
        "webDispatchRuntime": _source(WEB_DISPATCH_RUNTIME, 1),
        "webDispatchExecutor": _source(WEB_DISPATCH_EXECUTOR, 1),
        "webActorRuntime": _source(WEB_ACTOR_RUNTIME, 1),
        "webHeadlessPortObserver": _source(WEB_HEADLESS_PORT_OBSERVER, 1),
        "webSourceExecutionRoute": _source(WEB_SOURCE_EXECUTION_ROUTE, 1),
        "generator": _source(Path(__file__), SCHEMA),
    }


def run_headless_capture(output: Path) -> dict[str, Any]:
    command = [
        "node", str(NODE_PRODUCER),
        "--asset-contract", str(DEFAULT_ASSET_CONTRACT),
        "--executable", str(DEFAULT_EXECUTABLE),
        "--ledger", str(DEFAULT_LEDGER),
        "--manifest", str(DEFAULT_DISPATCH),
        "--output", str(output),
        "--plan", str(DEFAULT_PLAN),
        "--source-artifact", str(DEFAULT_SOURCE_ARTIFACT),
    ]
    try:
        subprocess.run(
            command, cwd=ROOT, check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise WebSceneSemanticEvidenceError(
            f"headless web semantic producer failed: {detail.strip()}"
        ) from error
    return _load_json(output, "headless web semantic capture")


def validate_capture(
    capture: dict[str, Any], plan: dict[str, Any],
) -> dict[str, int]:
    required = {
        "schema", "protocol", "edition", "status", "semanticStatus",
        "parityEligible", "candidateIdentity", "planManifestSha256",
        "counts", "slots", "captureSha256",
    }
    if set(capture) != required or capture.get("schema") != SCHEMA \
            or capture.get("protocol") != PRODUCER_PROTOCOL \
            or capture.get("edition") != plan["edition"] \
            or capture.get("semanticStatus") != "UNPROVEN" \
            or capture.get("parityEligible") is not False \
            or capture.get("candidateIdentity") != _candidate_identity() \
            or capture.get("planManifestSha256") != plan["manifestSha256"]:
        raise WebSceneSemanticEvidenceError("headless semantic capture identity differs")
    unhashed = {
        key: value for key, value in capture.items() if key != "captureSha256"
    }
    if capture.get("captureSha256") != javascript_sorted_sha256(unhashed):
        raise WebSceneSemanticEvidenceError("headless semantic capture hash differs")
    planned_jobs = sorted(_jobs(plan), key=lambda row: row["claimId"])
    slots = capture.get("slots")
    if not isinstance(slots, list) or len(slots) != len(planned_jobs):
        raise WebSceneSemanticEvidenceError("headless semantic slot inventory differs")
    seen_slices: set[str] = set()
    seen_claims: set[str] = set()
    seen_runtime_sessions: set[str] = set()
    seen_event_occurrences: set[str] = set()
    captured = 0
    for job, slot in zip(planned_jobs, slots):
        fields = {
            "schema", "jobId", "jobSha256", "claimId", "evidenceClass",
            "scenarioSha256", "subjectSha256", "expectationSha256",
            "webSliceId", "status", "blocker", "rawDocument", "parityEligible",
        }
        if not isinstance(slot, dict) or set(slot) != fields \
                or slot.get("schema") != SCHEMA \
                or slot.get("parityEligible") is not False:
            raise WebSceneSemanticEvidenceError("headless semantic slot schema differs")
        expected = {
            "jobId": job["id"],
            "jobSha256": job["jobSha256"],
            "claimId": job["claimId"],
            "evidenceClass": job["evidenceClass"],
            "scenarioSha256": job["scenarioSha256"],
            "subjectSha256": job["subjectSha256"],
            "expectationSha256": job["expectationSha256"],
            "webSliceId": next(
                row["sliceId"] for row in job["captureSlices"]
                if row["producer"] == "WEB"
            ),
        }
        if any(slot.get(key) != value for key, value in expected.items()) \
                or slot["claimId"] in seen_claims \
                or slot["webSliceId"] in seen_slices:
            raise WebSceneSemanticEvidenceError(
                f"headless semantic slot binding differs: {job['claimId']}"
            )
        seen_claims.add(slot["claimId"])
        seen_slices.add(slot["webSliceId"])
        if slot["status"] == CAPTURED:
            if slot["blocker"] is not None or not isinstance(slot["rawDocument"], dict):
                raise WebSceneSemanticEvidenceError("captured semantic slot has no raw document")
            raw = slot["rawDocument"]
            expected_protocol = next(
                row["rawProtocol"] for row in job["captureSlices"]
                if row["producer"] == "WEB"
            )
            if raw.get("protocol") != expected_protocol:
                raise WebSceneSemanticEvidenceError(
                    f"captured semantic raw protocol differs: {job['claimId']}"
                )
            if job["evidenceClass"] in {"UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY"}:
                session = raw.get("runtimeSessionSha256")
                occurrences = raw.get("eventOccurrenceIds")
                if not _is_sha256(session) or session in seen_runtime_sessions \
                        or not isinstance(occurrences, list) \
                        or not occurrences \
                        or any(
                            not _is_sha256(item)
                            or item in seen_event_occurrences
                            for item in occurrences
                        ):
                    raise WebSceneSemanticEvidenceError(
                        "captured semantic runtime events are reused"
                    )
                seen_runtime_sessions.add(session)
                seen_event_occurrences.update(occurrences)
            captured += 1
        elif slot["status"] == BLOCKED:
            blocker = slot.get("blocker")
            if slot["rawDocument"] is not None or not isinstance(blocker, dict) \
                    or not isinstance(blocker.get("code"), str) \
                    or not blocker["code"] \
                    or blocker.get("semanticStatus") != "UNPROVEN":
                raise WebSceneSemanticEvidenceError("blocked semantic slot is not explicit")
        else:
            raise WebSceneSemanticEvidenceError("semantic slot escaped fail-closed status")
    counts = capture.get("counts")
    expected_counts = {
        "jobs": len(slots), "captured": captured, "blocked": len(slots) - captured,
    }
    expected_status = "CAPTURED_CANDIDATE" if captured == len(slots) else "PARTIAL_BLOCKED"
    if counts != expected_counts or capture.get("status") != expected_status:
        raise WebSceneSemanticEvidenceError("headless semantic capture counts differ")
    return expected_counts


def build_staged_manifest(
    capture: dict[str, Any], artifact_root: Path,
) -> dict[str, Any]:
    plan = batches.generate()
    batches.validate_plan(plan)
    ledger = _load_json(DEFAULT_LEDGER, "semantic coverage ledger")
    coverage.validate_ledger(ledger)
    run_plan = runner.build_run_plan(plan)
    runner.validate_run_plan(run_plan, plan)
    validate_capture(capture, plan)
    executable_bytes = DEFAULT_EXECUTABLE.read_bytes()
    executable = json.loads(executable_bytes)
    source_artifact_bytes = DEFAULT_SOURCE_ARTIFACT.read_bytes()
    source_artifact = json.loads(source_artifact_bytes)
    records = {record["id"]: record for record in ledger["records"]}
    jobs_by_claim = {job["claimId"]: job for job in _jobs(plan)}
    runs_by_claim = {run["claimId"]: run for run in run_plan["runs"]}
    rows = []
    seen_raw: set[str] = set()
    seen_normalized: set[str] = set()
    seen_artifacts: set[str] = set()
    by_class: Counter[str] = Counter()
    blockers: Counter[str] = Counter()

    for slot in capture["slots"]:
        job = jobs_by_claim[slot["claimId"]]
        run = runs_by_claim[slot["claimId"]]
        common = {
            "schema": SCHEMA,
            "runId": run["id"],
            "jobId": job["id"],
            "jobSha256": job["jobSha256"],
            "claimId": job["claimId"],
            "evidenceClass": job["evidenceClass"],
            "scenarioSha256": job["scenarioSha256"],
            "subjectSha256": job["subjectSha256"],
            "expectationSha256": job["expectationSha256"],
            "webSliceId": slot["webSliceId"],
            "status": slot["status"],
            "parityEligible": False,
        }
        if slot["status"] == BLOCKED:
            by_class[f"{job['evidenceClass']}:{BLOCKED}"] += 1
            blockers[slot["blocker"]["code"]] += 1
            rows.append({
                **common,
                "blocker": copy.deepcopy(slot["blocker"]),
                "artifact": None,
            })
            continue
        raw = slot["rawDocument"]
        record = records[job["claimId"]]
        provenance = None
        if job["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}:
            provenance = coverage.expected_web_dispatch_capture_provenance(
                record, edition=ledger["edition"],
                candidate_identity=capture["candidateIdentity"],
                plan_document=plan,
            )
        try:
            normalized = oracle.normalize_web_trace(
                raw, executable, _identity(job, plan),
                executable_source_bytes=executable_bytes,
                source_artifact=source_artifact,
                source_artifact_bytes=source_artifact_bytes,
                expected_expectation=record["expectation"],
                expected_capture_provenance=provenance,
            )
        except oracle.SemanticOracleError as error:
            if job["evidenceClass"] not in {
                "UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY",
            }:
                raise WebSceneSemanticEvidenceError(
                    f"dispatch capture rejected by semantic oracle: {job['claimId']}"
                ) from error
            blocker = {
                "code": "WEB_SEMANTIC_NORMALIZER_REJECTED",
                "semanticStatus": "UNPROVEN",
                "errorType": type(error).__name__,
                "message": str(error),
            }
            by_class[f"{job['evidenceClass']}:{BLOCKED}"] += 1
            blockers[blocker["code"]] += 1
            rows.append({
                **{**common, "status": BLOCKED},
                "blocker": blocker,
                "artifact": None,
            })
            continue
        observed_executable = []
        observed_source = []
        lowered_absent_source = []
        if job["evidenceClass"] == "UDSP_EXECUTABLE_BODY":
            observed_executable = _validate_executable_coverage(raw, job)
        elif job["evidenceClass"] == "UDSP_SCRIPT_BODY":
            (
                observed_source,
                lowered_absent_source,
                observed_executable,
            ) = _validate_source_coverage(raw, job)
        by_class[f"{job['evidenceClass']}:{CAPTURED}"] += 1
        raw_ref = _write_content_addressed(artifact_root, "raw", raw)
        normalized_ref = _write_content_addressed(
            artifact_root, "normalized", normalized,
        )
        if raw_ref["sha256"] in seen_raw or normalized_ref["sha256"] in seen_normalized:
            raise WebSceneSemanticEvidenceError("semantic artifact is reused across jobs")
        seen_raw.add(raw_ref["sha256"])
        seen_normalized.add(normalized_ref["sha256"])
        artifact = {
            "schema": SCHEMA,
            "protocol": ARTIFACT_PROTOCOL,
            "semanticStatus": "UNPROVEN",
            "parityEligible": False,
            "promotionAllowed": False,
            "nativeComparison": "NOT_RUN",
            "runId": run["id"],
            "jobId": job["id"],
            "jobSha256": job["jobSha256"],
            "claimId": job["claimId"],
            "evidenceClass": job["evidenceClass"],
            "scenarioSha256": job["scenarioSha256"],
            "webSliceId": slot["webSliceId"],
            "rawProtocol": raw["protocol"],
            "runtimeSessionSha256": raw.get("runtimeSessionSha256"),
            "eventOccurrenceIdsSha256": (
                canonical_sha256(raw["eventOccurrenceIds"])
                if "eventOccurrenceIds" in raw else None
            ),
            "observedExecutableCommandIndices": observed_executable,
            "observedSourceCommandIndices": observed_source,
            "loweredAbsentSourceCommandIndices": lowered_absent_source,
            "raw": raw_ref,
            "normalized": normalized_ref,
        }
        artifact_ref = _write_content_addressed(
            artifact_root, "artifacts", artifact,
        )
        if artifact_ref["sha256"] in seen_artifacts:
            raise WebSceneSemanticEvidenceError("semantic job artifact is reused")
        seen_artifacts.add(artifact_ref["sha256"])
        rows.append({**common, "blocker": None, "artifact": artifact_ref})

    manifest = {
        "schema": SCHEMA,
        "protocol": MANIFEST_PROTOCOL,
        "edition": plan["edition"],
        "status": (
            "CAPTURED_CANDIDATE"
            if all(row["status"] == CAPTURED for row in rows)
            else "PARTIAL_BLOCKED"
        ),
        "semanticStatus": "UNPROVEN",
        "parityEligible": False,
        "promotionAllowed": False,
        "nativeComparison": "NOT_RUN",
        "candidateIdentity": copy.deepcopy(capture["candidateIdentity"]),
        "sourcePlan": {
            "manifestSha256": plan["manifestSha256"],
            "fileSha256": sha256_file(DEFAULT_PLAN),
            "scenarioRunPlanSha256": run_plan["planSha256"],
        },
        "sources": _expected_sources(),
        "policy": {
            "browserE2ERequired": False,
            "typedRuntimeOnly": True,
            "sourceAstRuntimeFallback": "FORBIDDEN",
            "sourceArtifactExecution": "HASH_BOUND_DISTINCT_RUNTIME_REQUIRED",
            "syntheticPortCompletion": "FORBIDDEN",
            "artifactReuse": "FORBIDDEN",
            "nativeParityPromotion": "FORBIDDEN",
        },
        "counts": {
            "jobs": len(rows),
            "captured": sum(row["status"] == CAPTURED for row in rows),
            "blocked": sum(row["status"] == BLOCKED for row in rows),
            "byEvidenceClassAndStatus": dict(sorted(by_class.items())),
            "byBlocker": dict(sorted(blockers.items())),
        },
        "records": rows,
    }
    manifest["manifestSha256"] = canonical_sha256(manifest)
    return manifest


def _resolve_ref(reference: dict[str, Any], label: str) -> Path:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256", "size"} \
            or not _is_sha256(reference.get("sha256")) \
            or type(reference.get("size")) is not int or reference["size"] < 1:
        raise WebSceneSemanticEvidenceError(f"{label} reference fields differ")
    path = (ROOT / reference["path"]).resolve()
    try:
        path.relative_to(DEFAULT_ARTIFACT_ROOT.resolve())
    except ValueError as error:
        raise WebSceneSemanticEvidenceError(f"{label} escapes semantic artifact root") from error
    if not path.is_file() or path.stat().st_size != reference["size"] \
            or sha256_file(path) != reference["sha256"]:
        raise WebSceneSemanticEvidenceError(f"{label} bytes differ")
    return path


def validate_manifest(
    manifest: dict[str, Any], *, output: Path = DEFAULT_OUTPUT,
) -> dict[str, Any]:
    required = {
        "schema", "protocol", "edition", "status", "semanticStatus",
        "parityEligible", "promotionAllowed", "nativeComparison",
        "candidateIdentity", "sourcePlan", "sources", "policy", "counts",
        "records", "manifestSha256",
    }
    if set(manifest) != required or manifest.get("schema") != SCHEMA \
            or manifest.get("protocol") != MANIFEST_PROTOCOL \
            or manifest.get("semanticStatus") != "UNPROVEN" \
            or manifest.get("parityEligible") is not False \
            or manifest.get("promotionAllowed") is not False \
            or manifest.get("nativeComparison") != "NOT_RUN" \
            or manifest.get("candidateIdentity") != _candidate_identity():
        raise WebSceneSemanticEvidenceError("web semantic manifest identity differs")
    unhashed = {
        key: value for key, value in manifest.items() if key != "manifestSha256"
    }
    if manifest.get("manifestSha256") != canonical_sha256(unhashed):
        raise WebSceneSemanticEvidenceError("web semantic manifest hash differs")
    plan = batches.generate()
    batches.validate_plan(plan)
    run_plan = runner.build_run_plan(plan)
    runner.validate_run_plan(run_plan, plan)
    expected_source_plan = {
        "manifestSha256": plan["manifestSha256"],
        "fileSha256": sha256_file(DEFAULT_PLAN),
        "scenarioRunPlanSha256": run_plan["planSha256"],
    }
    if manifest.get("edition") != plan["edition"] \
            or manifest.get("sourcePlan") != expected_source_plan:
        raise WebSceneSemanticEvidenceError("web semantic manifest plan binding differs")
    if manifest.get("sources") != _expected_sources():
        raise WebSceneSemanticEvidenceError("web semantic source inventory differs")
    expected_policy = {
        "browserE2ERequired": False,
        "typedRuntimeOnly": True,
        "sourceAstRuntimeFallback": "FORBIDDEN",
        "sourceArtifactExecution": "HASH_BOUND_DISTINCT_RUNTIME_REQUIRED",
        "syntheticPortCompletion": "FORBIDDEN",
        "artifactReuse": "FORBIDDEN",
        "nativeParityPromotion": "FORBIDDEN",
    }
    if manifest.get("policy") != expected_policy:
        raise WebSceneSemanticEvidenceError("web semantic evidence policy differs")
    planned_jobs = sorted(_jobs(plan), key=lambda row: row["claimId"])
    runs = {run["claimId"]: run for run in run_plan["runs"]}
    ledger = _load_json(DEFAULT_LEDGER, "semantic coverage ledger")
    coverage.validate_ledger(ledger)
    ledger_records = {record["id"]: record for record in ledger["records"]}
    executable_bytes = DEFAULT_EXECUTABLE.read_bytes()
    executable = json.loads(executable_bytes)
    source_artifact_bytes = DEFAULT_SOURCE_ARTIFACT.read_bytes()
    source_artifact = json.loads(source_artifact_bytes)
    records = manifest.get("records")
    if not isinstance(records, list) or len(records) != len(planned_jobs):
        raise WebSceneSemanticEvidenceError("web semantic manifest record inventory differs")
    seen_refs: set[str] = set()
    seen_runtime_sessions: set[str] = set()
    seen_event_occurrences: set[str] = set()
    captured = 0
    blockers: Counter[str] = Counter()
    by_class: Counter[str] = Counter()
    referenced_files: set[Path] = set()
    for job, row in zip(planned_jobs, records):
        common_fields = {
            "schema", "runId", "jobId", "jobSha256", "claimId",
            "evidenceClass", "scenarioSha256", "subjectSha256",
            "expectationSha256", "webSliceId", "status", "parityEligible",
            "blocker", "artifact",
        }
        run = runs[job["claimId"]]
        expected = {
            "schema": SCHEMA,
            "runId": run["id"],
            "jobId": job["id"],
            "jobSha256": job["jobSha256"],
            "claimId": job["claimId"],
            "evidenceClass": job["evidenceClass"],
            "scenarioSha256": job["scenarioSha256"],
            "subjectSha256": job["subjectSha256"],
            "expectationSha256": job["expectationSha256"],
            "webSliceId": next(
                item["sliceId"] for item in job["captureSlices"]
                if item["producer"] == "WEB"
            ),
            "parityEligible": False,
        }
        if not isinstance(row, dict) or set(row) != common_fields \
                or any(row.get(key) != value for key, value in expected.items()):
            raise WebSceneSemanticEvidenceError(
                f"web semantic manifest job binding differs: {job['claimId']}"
            )
        by_class[f"{job['evidenceClass']}:{row['status']}"] += 1
        if row["status"] == BLOCKED:
            if row["artifact"] is not None or not isinstance(row["blocker"], dict) \
                    or row["blocker"].get("semanticStatus") != "UNPROVEN":
                raise WebSceneSemanticEvidenceError("blocked web semantic record differs")
            blockers[row["blocker"]["code"]] += 1
            continue
        if row["status"] != CAPTURED or row["blocker"] is not None:
            raise WebSceneSemanticEvidenceError("web semantic record escaped fail-closed status")
        captured += 1
        artifact_path = _resolve_ref(row["artifact"], "job artifact")
        referenced_files.add(artifact_path)
        if row["artifact"]["sha256"] in seen_refs:
            raise WebSceneSemanticEvidenceError("web semantic artifact reference is reused")
        seen_refs.add(row["artifact"]["sha256"])
        artifact = _load_json(artifact_path, "web semantic job artifact")
        artifact_fields = {
            "schema", "protocol", "semanticStatus", "parityEligible",
            "promotionAllowed", "nativeComparison", "runId", "jobId",
            "jobSha256", "claimId", "evidenceClass", "scenarioSha256",
            "webSliceId", "rawProtocol", "runtimeSessionSha256",
            "eventOccurrenceIdsSha256", "observedExecutableCommandIndices",
            "observedSourceCommandIndices",
            "loweredAbsentSourceCommandIndices", "raw", "normalized",
        }
        if set(artifact) != artifact_fields \
                or artifact.get("schema") != SCHEMA \
                or artifact.get("protocol") != ARTIFACT_PROTOCOL \
                or artifact.get("semanticStatus") != "UNPROVEN" \
                or artifact.get("runId") != run["id"] \
                or artifact.get("jobId") != job["id"] \
                or artifact.get("jobSha256") != job["jobSha256"] \
                or artifact.get("claimId") != job["claimId"] \
                or artifact.get("evidenceClass") != job["evidenceClass"] \
                or artifact.get("scenarioSha256") != job["scenarioSha256"] \
                or artifact.get("webSliceId") != row["webSliceId"] \
                or artifact.get("rawProtocol") != next(
                    item["rawProtocol"] for item in job["captureSlices"]
                    if item["producer"] == "WEB"
                ) \
                or artifact.get("parityEligible") is not False \
                or artifact.get("promotionAllowed") is not False \
                or artifact.get("nativeComparison") != "NOT_RUN":
            raise WebSceneSemanticEvidenceError("web semantic job artifact binding differs")
        children = {}
        for label in ("raw", "normalized"):
            child = artifact.get(label)
            child_path = _resolve_ref(child, f"job artifact {label}")
            referenced_files.add(child_path)
            if child["sha256"] in seen_refs:
                raise WebSceneSemanticEvidenceError(
                    "web semantic raw/normalized artifact is reused"
                )
            seen_refs.add(child["sha256"])
            children[label] = _load_json(child_path, f"web semantic {label}")
        record = ledger_records[job["claimId"]]
        if job["evidenceClass"] in {"UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY"}:
            session = children["raw"].get("runtimeSessionSha256")
            occurrences = children["raw"].get("eventOccurrenceIds")
            if not _is_sha256(session) or session in seen_runtime_sessions \
                    or not isinstance(occurrences, list) or not occurrences \
                    or any(
                        not _is_sha256(item) or item in seen_event_occurrences
                        for item in occurrences
                    ):
                raise WebSceneSemanticEvidenceError(
                    "web semantic runtime event occurrence is reused"
                )
            seen_runtime_sessions.add(session)
            seen_event_occurrences.update(occurrences)
        provenance = None
        if job["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}:
            provenance = coverage.expected_web_dispatch_capture_provenance(
                record, edition=ledger["edition"],
                candidate_identity=manifest["candidateIdentity"],
                plan_document=plan,
            )
        try:
            expected_normalized = oracle.normalize_web_trace(
                children["raw"], executable, _identity(job, plan),
                executable_source_bytes=executable_bytes,
                source_artifact=source_artifact,
                source_artifact_bytes=source_artifact_bytes,
                expected_expectation=record["expectation"],
                expected_capture_provenance=provenance,
            )
        except oracle.SemanticOracleError as error:
            raise WebSceneSemanticEvidenceError(
                f"web semantic raw artifact no longer normalizes: {job['claimId']}"
            ) from error
        if children["normalized"] != expected_normalized:
            raise WebSceneSemanticEvidenceError(
                f"web semantic normalized artifact differs: {job['claimId']}"
            )
        expected_executable = []
        expected_source = []
        expected_absent = []
        if job["evidenceClass"] == "UDSP_EXECUTABLE_BODY":
            expected_executable = _validate_executable_coverage(
                children["raw"], job
            )
        elif job["evidenceClass"] == "UDSP_SCRIPT_BODY":
            (
                expected_source,
                expected_absent,
                expected_executable,
            ) = _validate_source_coverage(children["raw"], job)
        expected_session = children["raw"].get("runtimeSessionSha256")
        expected_occurrences_sha = (
            canonical_sha256(children["raw"]["eventOccurrenceIds"])
            if "eventOccurrenceIds" in children["raw"] else None
        )
        if artifact["observedExecutableCommandIndices"] != expected_executable \
                or artifact["observedSourceCommandIndices"] != expected_source \
                or artifact["loweredAbsentSourceCommandIndices"] != expected_absent \
                or artifact["runtimeSessionSha256"] != expected_session \
                or artifact["eventOccurrenceIdsSha256"] \
                != expected_occurrences_sha:
            raise WebSceneSemanticEvidenceError(
                f"web semantic observed coverage differs: {job['claimId']}"
            )
    expected_counts = {
        "jobs": len(records),
        "captured": captured,
        "blocked": len(records) - captured,
        "byEvidenceClassAndStatus": dict(sorted(by_class.items())),
        "byBlocker": dict(sorted(blockers.items())),
    }
    expected_status = "CAPTURED_CANDIDATE" if captured == len(records) else "PARTIAL_BLOCKED"
    if manifest.get("counts") != expected_counts \
            or manifest.get("status") != expected_status:
        raise WebSceneSemanticEvidenceError("web semantic manifest counts differ")
    actual_files = {
        path.resolve() for path in DEFAULT_ARTIFACT_ROOT.rglob("*") if path.is_file()
    }
    if output.resolve() == DEFAULT_OUTPUT.resolve() and actual_files != referenced_files:
        raise WebSceneSemanticEvidenceError("web semantic artifact directory has orphan files")
    return copy.deepcopy(manifest["counts"])


def _replace_tree(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    os.replace(source, destination)


def generate_to(output: Path, artifact_root: Path) -> dict[str, Any]:
    output = output.resolve()
    artifact_root = artifact_root.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact_root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="miel-web-semantic-", dir=output.parent,
    ) as directory:
        temp = Path(directory)
        capture_path = temp / "capture.json"
        staged_artifacts = temp / "artifacts"
        staged_artifacts.mkdir()
        capture = run_headless_capture(capture_path)
        manifest = build_staged_manifest(capture, staged_artifacts)
        staged_manifest = temp / "manifest.json"
        staged_manifest.write_bytes(
            json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
        )
        _replace_tree(staged_artifacts, artifact_root)
        os.replace(staged_manifest, output)
    return manifest


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*") if path.is_file()
    }


def check_regeneration() -> dict[str, Any]:
    tracked = _load_json(DEFAULT_OUTPUT, "tracked web semantic manifest")
    validate_manifest(tracked)
    with tempfile.TemporaryDirectory(prefix="miel-web-semantic-check-") as directory:
        temp = Path(directory)
        output = temp / "manifest.json"
        artifacts = temp / "artifacts"
        capture_path = temp / "capture.json"
        capture = run_headless_capture(capture_path)
        generated = build_staged_manifest(capture, artifacts)
        output.write_bytes(
            json.dumps(generated, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
        )
        if output.read_bytes() != DEFAULT_OUTPUT.read_bytes() \
                or _tree_bytes(artifacts) != _tree_bytes(DEFAULT_ARTIFACT_ROOT):
            raise WebSceneSemanticEvidenceError(
                "tracked web semantic evidence differs from headless regeneration"
            )
    return copy.deepcopy(tracked["counts"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.write and args.check:
        raise WebSceneSemanticEvidenceError("--write and --check are mutually exclusive")
    if args.write:
        manifest = generate_to(DEFAULT_OUTPUT, DEFAULT_ARTIFACT_ROOT)
        counts = manifest["counts"]
    elif args.check:
        counts = check_regeneration()
    else:
        counts = validate_manifest(
            _load_json(DEFAULT_OUTPUT, "web semantic manifest")
        )
    if args.json:
        print(json.dumps(counts, sort_keys=True))
    else:
        print(
            f"web scene semantic evidence: {counts['captured']}/"
            f"{counts['jobs']} captured, {counts['blocked']} fail-closed; "
            "native comparison NOT_RUN"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
