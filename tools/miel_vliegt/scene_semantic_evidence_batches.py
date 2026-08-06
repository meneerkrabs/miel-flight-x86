#!/usr/bin/env python3
"""Generate fail-closed native/web capture batches for semantic claims.

The output is a work plan, never parity evidence.  It binds every planned
capture to one edition, source envelope, claim subject and expectation while
requiring distinct native and web session slices.  Only the semantic coverage
validator may later promote a claim from a real differential receipt.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import scene_semantic_coverage as coverage
    from tools.miel_vliegt import native_dispatch_hook_contract
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import scene_semantic_coverage as coverage
    import native_dispatch_hook_contract


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER = ROOT / "content/miel_vliegt/scene_semantic_coverage.json"
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/scene_semantic_evidence_batches.json"
WEB_DISPATCH_CAPTURE_EXECUTOR = (
    ROOT / "src/flight/engine/scene/WebSceneDispatchCaptureExecutor.js"
)
WEB_DISPATCH_CANDIDATE_BRIDGE = (
    ROOT / "src/flight/engine/scene/WebSceneDispatchCandidateBridge.js"
)
WEB_DISPATCH_RUNTIME = ROOT / "src/flight/engine/scene/SceneDispatchRuntime.js"
SEMANTIC_ORACLE = ROOT / "tools/miel_vliegt/udsp_semantic_oracle.py"
WEB_DISPATCH_CANDIDATE_WRITER = (
    ROOT / "tools/miel_vliegt/web_dispatch_candidate_artifacts.py"
)
WEB_TRANSITION_BUILD = ROOT / "content/miel_vliegt/web_transition_build.json"
SCHEMA = 1
CONTRACT = "miel-vliegt-scene-semantic-evidence-batches"
BATCH_SIZE = 16
TARGET_CLASSES = (
    "UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY", "MISSION_DISPATCH", "LOCATION_POLICY",
)
CLASS_DRIVERS = {
    "UDSP_SCRIPT_BODY": "EXECUTE_SOURCE_UDSP_ARTIFACT_GRAPH",
    "UDSP_EXECUTABLE_BODY": "EXECUTE_UDSP_ARTIFACT_GRAPH",
    "MISSION_DISPATCH": "DISPATCH_MISSION_PHASE_ACTION",
    "LOCATION_POLICY": "SELECT_LOCATION_ROOT_FROM_NATIVE_PREDICATES",
}
CLASS_CAPTURE_CAPABILITIES = {
    "UDSP_SCRIPT_BODY": {
        "status": "PENDING_INDEPENDENT_NATIVE_WEB_DIFFERENTIAL",
        "native": "SOURCE_TO_EXECUTABLE_OCCURRENCE_MAPPING_ENFORCED",
        "web": "SOURCE_TO_EXECUTABLE_OCCURRENCE_MAPPING_ENFORCED",
    },
    "UDSP_EXECUTABLE_BODY": {
        "status": "PENDING_INDEPENDENT_NATIVE_WEB_DIFFERENTIAL",
        "native": "SUPPORTED_HOOK_FACTS_REQUIRED",
        "web": "EXECUTABLE_UDSP_RUNTIME_RECEIPTS_REQUIRED",
    },
    "MISSION_DISPATCH": {
        "status": "BLOCKED_MISSING_NATIVE_MISSION_DISPATCH_PRODUCER",
        "native": "STATIC_HOOK_MAP_COMPLETE_RUNTIME_TRAMPOLINES_AND_TRACE_REQUIRED",
        "web": "SCENE_DISPATCH_PRE_RESULT_POST_RECEIPTS_AVAILABLE",
    },
    "LOCATION_POLICY": {
        "status": "BLOCKED_MISSING_NATIVE_LOCATION_POLICY_PRODUCER",
        "native": "STATIC_HOOK_MAP_COMPLETE_RUNTIME_TRAMPOLINES_AND_TRACE_REQUIRED",
        "web": "SCENE_DISPATCH_PRE_RESULT_POST_RECEIPTS_AVAILABLE",
    },
}
RAW_PROTOCOLS = {
    "NATIVE": "miel-vliegt-native-scene-semantic-raw",
    "WEB": "miel-vliegt-web-scene-semantic-raw",
}
WEB_SOURCE_RAW_PROTOCOL = "miel-vliegt-web-source-scene-semantic-raw"
POLICY_PREDICATES = {
    "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3": ["FINAL_MISSION_STATE_NE_3"],
    "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3": ["FINAL_MISSION_STATE_EQ_3"],
    "ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED": [
        "ROOT_COMPLETE", "REFUEL_ARMED", "REFUEL_UNCONSUMED",
    ],
    "LOCATION_ENTER_FIRST_CHALLENGE": ["LOCATION_ENTER", "FIRST_CHALLENGE"],
    "LOCATION_ENTER_SUBSEQUENT_CHALLENGE": [
        "LOCATION_ENTER", "SUBSEQUENT_CHALLENGE",
    ],
    "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2": [
        "CHALLENGE_ROOT_COMPLETE", "CHALLENGE_RESULT_EQ_2",
    ],
    "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2": [
        "CHALLENGE_ROOT_COMPLETE", "CHALLENGE_RESULT_NE_2",
    ],
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900": [
        "LOCATION_ENTER", "OUTRO_FALSE", "PROJECTED_X_LT_900",
    ],
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_NE_3": [
        "LOCATION_ENTER", "OUTRO_FALSE", "PROJECTED_X_GTE_900",
        "PROJECTED_X_LT_2200", "FINAL_MISSION_STATE_NE_3",
    ],
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_NE_3": [
        "LOCATION_ENTER", "OUTRO_FALSE", "PROJECTED_X_GTE_2200",
        "FINAL_MISSION_STATE_NE_3",
    ],
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_EQ_3": [
        "LOCATION_ENTER", "OUTRO_FALSE", "PROJECTED_X_GTE_900",
        "PROJECTED_X_LT_2200", "FINAL_MISSION_STATE_EQ_3",
    ],
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_EQ_3": [
        "LOCATION_ENTER", "OUTRO_FALSE", "PROJECTED_X_GTE_2200",
        "FINAL_MISSION_STATE_EQ_3",
    ],
    "LOCATION_ENTER_OUTRO_REQUESTED": ["LOCATION_ENTER", "OUTRO_REQUESTED"],
    "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE": [
        "LOCATION_ENTER", "EXPECTED_UDSP_ABSENCE",
    ],
}


class SemanticEvidenceBatchError(ValueError):
    """Raised when a batch plan is not structurally and hash exact."""


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source(path: Path, schema: int) -> dict[str, Any]:
    try:
        relative = path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError as error:
        raise SemanticEvidenceBatchError("batch source escapes repository") from error
    return {"path": relative, "sha256": coverage.sha256_file(path), "schema": schema}


def _scenario(record: dict[str, Any], edition: str) -> dict[str, Any]:
    evidence_class = record["evidenceClass"]
    expectation = copy.deepcopy(record["expectation"])
    common = {
        "schema": 1,
        "driver": CLASS_DRIVERS[evidence_class],
        "artifactKey": expectation.get("artifactKey"),
        "expectedObservation": "CLAIM_BOUND_NORMALIZED_STATE",
    }
    if evidence_class == "UDSP_SCRIPT_BODY":
        count = expectation["counts"]["commands"]
        common["entry"] = {
            "scriptType": expectation["scriptType"],
            "domainId": expectation["domainId"],
            "dispatchId": expectation["dispatchId"],
            "sourceScriptSha256": expectation["scriptSha256"],
        }
        common["coverage"] = {
            "requiredSourceCommandIndices": list(range(count)),
            "commandsSha256": expectation["commandsSha256"],
            "structureSha256": expectation["structureSha256"],
            "pathPolicy": "ALL_REACHABLE_SOURCE_BRANCH_OUTCOME_AND_FAILURE_VARIANTS",
            "executableClaimEventReuseForbidden": True,
            "syntheticCompletionForbidden": True,
        }
    elif evidence_class == "UDSP_EXECUTABLE_BODY":
        count = expectation["counts"]["executableCommandNodes"]
        common["entry"] = {
            "scriptType": expectation["scriptType"],
            "domainId": expectation["domainId"],
            "dispatchId": expectation["dispatchId"],
            "executableScriptSha256": expectation["executableScriptSha256"],
        }
        common["coverage"] = {
            "requiredExecutableCommandIndices": list(range(count)),
            "requiredCommandSha256": expectation["commandSha256"],
            "pathPolicy": "ALL_REACHABLE_BRANCH_OUTCOME_AND_FAILURE_VARIANTS",
            "syntheticCompletionForbidden": True,
        }
    elif evidence_class == "MISSION_DISPATCH":
        common["trigger"] = {
            key: expectation[key]
            for key in (
                "missionKey", "missionId", "missionPhase", "nativeActionOrdinal",
                "opcode", "route", "domainId", "scriptId",
            )
        }
        common["requiredEffects"] = [
            "MISSION_ACTION_SELECTED", "ROUTE_MATCHED", "ARTIFACT_DISPATCHED",
        ]
    else:
        selector = expectation["selector"]
        predicates = POLICY_PREDICATES.get(selector)
        if predicates is None:
            raise SemanticEvidenceBatchError(
                f"unknown location-policy selector: {selector}"
            )
        common["trigger"] = {
            key: expectation[key]
            for key in ("locationId", "domainId", "mode", "policy", "outcome", "selector")
        }
        common["setupPredicates"] = predicates
        common["requiredEffects"] = [
            "EXPECTED_UDSP_ABSENCE_CONFIRMED"
            if expectation["artifactKey"] is None else "EXPECTED_ROOT_ARTIFACT_SELECTED"
        ]
    common["scenarioId"] = "scenario:" + canonical_sha256({
        "edition": edition,
        "claimId": record["id"],
        "driver": common["driver"],
        "scenario": common,
    })
    return common


def _slice_requirement(
    producer: str, record: dict[str, Any], scenario_sha256: str,
) -> dict[str, Any]:
    identity = {
        "producer": producer,
        "claimId": record["id"],
        "subjectSha256": coverage.evidence_subject_sha256(record),
        "scenarioSha256": scenario_sha256,
    }
    return {
        "producer": producer,
        "sliceId": f"{producer.lower()}-slice:{canonical_sha256(identity)}",
        "rawProtocol": (
            WEB_SOURCE_RAW_PROTOCOL
            if producer == "WEB" and record["evidenceClass"] == "UDSP_SCRIPT_BODY"
            else RAW_PROTOCOLS[producer]
        ),
        "mode": "CAPTURED_PRODUCTION_REQUIRED",
        "sessionPolicy": "UNIQUE_EVENT_OCCURRENCES_PER_CLAIM",
        "eventPolicy": "UNIQUE_SESSION_EVENT_OCCURRENCES_CROSS_CLAIM",
        "artifactPolicy": "HASHED_REPOSITORY_RELATIVE_ARTIFACT_REQUIRED",
        "normalization": "INDEPENDENT_RAW_TO_NORMALIZED_RECOMPUTATION_REQUIRED",
    }


def _job(record: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    scenario = _scenario(record, ledger["edition"])
    scenario_sha256 = canonical_sha256(scenario)
    capability = copy.deepcopy(CLASS_CAPTURE_CAPABILITIES[record["evidenceClass"]])
    job = {
        "schema": 1,
        "id": f"SEMANTIC_EVIDENCE_JOB:{record['id']}",
        "claimId": record["id"],
        "evidenceClass": record["evidenceClass"],
        "claimStatusAtPlanning": record["status"],
        "status": capability["status"],
        "captureCapability": capability,
        "subjectSha256": coverage.evidence_subject_sha256(record),
        "expectationSha256": coverage.evidence_expectation_sha256(record),
        "scenarioSha256": scenario_sha256,
        "scenario": scenario,
        "captureSlices": [
            _slice_requirement("NATIVE", record, scenario_sha256),
            _slice_requirement("WEB", record, scenario_sha256),
        ],
        "acceptance": {
            "differentialProtocol": coverage.SEMANTIC_DIFFERENTIAL_PROTOCOL,
            "nativeWebArtifactsDistinct": True,
            "nativeWebSessionsDistinct": True,
            "normalizedObservationsByteEqual": True,
            "productionProvenanceRequired": True,
            "promotionAuthority": "scene_semantic_coverage.validate_ledger",
            "planMayPromoteClaim": False,
        },
    }
    job["jobSha256"] = canonical_sha256(job)
    return job


def build_plan(ledger: dict[str, Any], *, ledger_source: dict[str, Any]) -> dict[str, Any]:
    records_by_class: dict[str, list[dict[str, Any]]] = {
        name: [] for name in TARGET_CLASSES
    }
    for record in ledger["records"]:
        if record["evidenceClass"] in records_by_class:
            records_by_class[record["evidenceClass"]].append(record)
    batches = []
    for evidence_class in TARGET_CLASSES:
        jobs = [_job(record, ledger) for record in sorted(
            records_by_class[evidence_class], key=lambda row: row["id"]
        )]
        for start in range(0, len(jobs), BATCH_SIZE):
            ordinal = start // BATCH_SIZE
            batch_jobs = jobs[start:start + BATCH_SIZE]
            batch = {
                "schema": 1,
                "id": f"{evidence_class.lower()}:{ordinal:03d}",
                "evidenceClass": evidence_class,
                "ordinal": ordinal,
                "status": "PENDING_CAPTURE",
                "jobs": batch_jobs,
            }
            batch["jobsSha256"] = canonical_sha256([
                job["jobSha256"] for job in batch_jobs
            ])
            batches.append(batch)
    counts = {name: len(records_by_class[name]) for name in TARGET_CLASSES}
    plan = {
        "schema": SCHEMA,
        "contract": CONTRACT,
        "edition": ledger["edition"],
        "claim": "CAPTURE_PLAN_ONLY_RUNTIME_SEMANTIC_PARITY_UNPROVEN",
        "sources": {
            "semanticCoverage": ledger_source,
            "generator": _source(Path(__file__), 1),
            "nativeDispatchHookContract": _source(
                native_dispatch_hook_contract.DEFAULT_OUTPUT, 1,
            ),
            "webSceneDispatchCaptureExecutor": _source(
                WEB_DISPATCH_CAPTURE_EXECUTOR, 1,
            ),
            "webSceneDispatchCandidateBridge": _source(
                WEB_DISPATCH_CANDIDATE_BRIDGE, 1,
            ),
            "webSceneDispatchRuntime": _source(WEB_DISPATCH_RUNTIME, 1),
            "semanticOracle": _source(SEMANTIC_ORACLE, 1),
            "webDispatchCandidateArtifactWriter": _source(
                WEB_DISPATCH_CANDIDATE_WRITER, 1,
            ),
            "webTransitionBuild": _source(WEB_TRANSITION_BUILD, 1),
            **copy.deepcopy(ledger["sources"]),
        },
        "policy": {
            "targetEvidenceClasses": list(TARGET_CLASSES),
            "batchSize": BATCH_SIZE,
            "ordering": "EVIDENCE_CLASS_THEN_CLAIM_ID",
            "producerOrder": ["NATIVE", "WEB"],
            "crossClaimSliceReuse": "FORBIDDEN",
            "crossClaimEventReuse": "FORBIDDEN",
            "nativeWebSliceReuse": "FORBIDDEN",
            "initialJobStatus": "DERIVED_FROM_EVIDENCE_CLASS_CAPABILITY",
            "promotion": "FORBIDDEN_BY_PLAN_REQUIRES_VALIDATED_DIFFERENTIAL",
        },
        "counts": {
            "claims": sum(counts.values()),
            "batches": len(batches),
            "byEvidenceClass": counts,
        },
        "batches": batches,
    }
    plan["manifestSha256"] = canonical_sha256(plan)
    return plan


def generate(ledger_path: Path = DEFAULT_LEDGER) -> dict[str, Any]:
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SemanticEvidenceBatchError("cannot read semantic coverage ledger") from error
    try:
        coverage.validate_ledger(ledger)
    except coverage.SemanticCoverageError as error:
        raise SemanticEvidenceBatchError(
            f"semantic coverage ledger is not valid: {error}"
        ) from error
    try:
        native_dispatch_hook_contract.validate_contract(json.loads(
            native_dispatch_hook_contract.DEFAULT_OUTPUT.read_text(encoding="utf-8")
        ))
    except (OSError, json.JSONDecodeError,
            native_dispatch_hook_contract.NativeDispatchHookContractError) as error:
        raise SemanticEvidenceBatchError(
            "native dispatch hook design contract is not valid"
        ) from error
    return build_plan(ledger, ledger_source=_source(ledger_path, coverage.SCHEMA))


def _validate_schema(plan: dict[str, Any]) -> None:
    source_names = {
        "semanticCoverage", "generator", "sceneDispatchContract", "udsSceneScripts",
        "executableUdspSceneScripts", "nativeDispatchHookContract",
        "webSceneDispatchCaptureExecutor",
        "webSceneDispatchCandidateBridge",
        "webSceneDispatchRuntime", "semanticOracle",
        "webDispatchCandidateArtifactWriter",
        "webTransitionBuild",
    }
    sources = plan.get("sources")
    if not isinstance(sources, dict) or set(sources) != source_names:
        raise SemanticEvidenceBatchError("semantic evidence source schema drifted")
    for name, source in sources.items():
        if not isinstance(source, dict) or set(source) != {"path", "sha256", "schema"}:
            raise SemanticEvidenceBatchError(f"semantic evidence source shape drifted: {name}")
        if not isinstance(source["path"], str) or not coverage.SHA256.fullmatch(
            source.get("sha256", "")
        ) or source["schema"] not in {1, 2}:
            raise SemanticEvidenceBatchError(f"semantic evidence source identity drifted: {name}")
    policy = plan.get("policy")
    if not isinstance(policy, dict) or set(policy) != {
        "targetEvidenceClasses", "batchSize", "ordering", "producerOrder",
        "crossClaimSliceReuse", "crossClaimEventReuse", "nativeWebSliceReuse",
        "initialJobStatus", "promotion",
    }:
        raise SemanticEvidenceBatchError("semantic evidence policy schema drifted")
    counts = plan.get("counts")
    if not isinstance(counts, dict) or set(counts) != {
        "claims", "batches", "byEvidenceClass",
    } or not isinstance(counts.get("byEvidenceClass"), dict) \
            or set(counts["byEvidenceClass"]) != set(TARGET_CLASSES):
        raise SemanticEvidenceBatchError("semantic evidence count schema drifted")
    batch_fields = {
        "schema", "id", "evidenceClass", "ordinal", "status", "jobs", "jobsSha256",
    }
    job_fields = {
        "schema", "id", "claimId", "evidenceClass", "claimStatusAtPlanning",
        "status", "captureCapability", "subjectSha256", "expectationSha256", "scenarioSha256",
        "scenario", "captureSlices", "acceptance", "jobSha256",
    }
    slice_fields = {
        "producer", "sliceId", "rawProtocol", "mode", "sessionPolicy",
        "eventPolicy", "artifactPolicy", "normalization",
    }
    acceptance_fields = {
        "differentialProtocol", "nativeWebArtifactsDistinct", "nativeWebSessionsDistinct",
        "normalizedObservationsByteEqual", "productionProvenanceRequired",
        "promotionAuthority", "planMayPromoteClaim",
    }
    scenario_fields = {
        "UDSP_SCRIPT_BODY": {
            "schema", "driver", "artifactKey", "expectedObservation", "entry",
            "coverage", "scenarioId",
        },
        "UDSP_EXECUTABLE_BODY": {
            "schema", "driver", "artifactKey", "expectedObservation", "entry",
            "coverage", "scenarioId",
        },
        "MISSION_DISPATCH": {
            "schema", "driver", "artifactKey", "expectedObservation", "trigger",
            "requiredEffects", "scenarioId",
        },
        "LOCATION_POLICY": {
            "schema", "driver", "artifactKey", "expectedObservation", "trigger",
            "setupPredicates", "requiredEffects", "scenarioId",
        },
    }
    for batch in plan.get("batches", []):
        if not isinstance(batch, dict) or set(batch) != batch_fields \
                or batch.get("schema") != 1 or batch.get("status") != "PENDING_CAPTURE" \
                or batch.get("evidenceClass") not in TARGET_CLASSES \
                or not isinstance(batch.get("jobs"), list) or not batch["jobs"]:
            raise SemanticEvidenceBatchError("semantic evidence batch row schema drifted")
        for job in batch["jobs"]:
            if not isinstance(job, dict) or set(job) != job_fields or job.get("schema") != 1 \
                    or job.get("evidenceClass") != batch["evidenceClass"]:
                raise SemanticEvidenceBatchError("semantic evidence job schema drifted")
            scenario = job.get("scenario")
            if not isinstance(scenario, dict) or set(scenario) != scenario_fields[job["evidenceClass"]] \
                    or scenario.get("schema") != 1:
                raise SemanticEvidenceBatchError(
                    f"semantic evidence scenario schema drifted: {job.get('claimId')}"
                )
            slices = job.get("captureSlices")
            if not isinstance(slices, list) or len(slices) != 2 or any(
                not isinstance(row, dict) or set(row) != slice_fields for row in slices
            ):
                raise SemanticEvidenceBatchError(
                    f"semantic evidence slice schema drifted: {job.get('claimId')}"
                )
            acceptance = job.get("acceptance")
            if not isinstance(acceptance, dict) or set(acceptance) != acceptance_fields:
                raise SemanticEvidenceBatchError(
                    f"semantic evidence acceptance schema drifted: {job.get('claimId')}"
                )
            if job.get("captureCapability") != CLASS_CAPTURE_CAPABILITIES[job["evidenceClass"]] \
                    or job.get("status") != job["captureCapability"]["status"]:
                raise SemanticEvidenceBatchError(
                    f"semantic evidence capture capability drifted: {job.get('claimId')}"
                )


def _validate_hashes(plan: dict[str, Any]) -> None:
    manifest = plan.get("manifestSha256")
    unhashed = {key: value for key, value in plan.items() if key != "manifestSha256"}
    if manifest != canonical_sha256(unhashed):
        raise SemanticEvidenceBatchError("semantic evidence manifest hash drifted")
    seen_claims: set[str] = set()
    seen_slices: set[str] = set()
    for batch in plan.get("batches", []):
        if batch.get("jobsSha256") != canonical_sha256([
            job.get("jobSha256") for job in batch.get("jobs", [])
        ]):
            raise SemanticEvidenceBatchError(f"batch jobs hash drifted: {batch.get('id')}")
        for job in batch.get("jobs", []):
            job_hash = job.get("jobSha256")
            unhashed_job = {key: value for key, value in job.items() if key != "jobSha256"}
            if job_hash != canonical_sha256(unhashed_job):
                raise SemanticEvidenceBatchError(f"job hash drifted: {job.get('claimId')}")
            if job.get("scenarioSha256") != canonical_sha256(job.get("scenario")):
                raise SemanticEvidenceBatchError(
                    f"scenario hash drifted: {job.get('claimId')}"
                )
            claim_id = job.get("claimId")
            if claim_id in seen_claims:
                raise SemanticEvidenceBatchError(f"claim scheduled twice: {claim_id}")
            seen_claims.add(claim_id)
            slices = job.get("captureSlices")
            if not isinstance(slices, list) or [row.get("producer") for row in slices] != [
                "NATIVE", "WEB",
            ]:
                raise SemanticEvidenceBatchError(f"producer slices drifted: {claim_id}")
            slice_ids = [row.get("sliceId") for row in slices]
            if len(set(slice_ids)) != 2 or any(item in seen_slices for item in slice_ids):
                raise SemanticEvidenceBatchError(f"capture slice reused: {claim_id}")
            seen_slices.update(slice_ids)
            if job.get("status") != CLASS_CAPTURE_CAPABILITIES[
                job.get("evidenceClass")
            ]["status"] or job.get("acceptance", {}).get("planMayPromoteClaim") is not False:
                raise SemanticEvidenceBatchError(f"job escaped fail-closed status: {claim_id}")
            if "evidence" in job:
                raise SemanticEvidenceBatchError(f"capture plan carries evidence: {claim_id}")


def validate_plan(
    plan: dict[str, Any], *, ledger_path: Path = DEFAULT_LEDGER,
) -> dict[str, int]:
    required = {
        "schema", "contract", "edition", "claim", "sources", "policy",
        "counts", "batches", "manifestSha256",
    }
    if not isinstance(plan, dict) or set(plan) != required:
        raise SemanticEvidenceBatchError("semantic evidence batch schema drifted")
    if plan.get("schema") != SCHEMA or plan.get("contract") != CONTRACT:
        raise SemanticEvidenceBatchError("semantic evidence batch contract drifted")
    if not isinstance(plan.get("batches"), list):
        raise SemanticEvidenceBatchError("semantic evidence batches must be a list")
    _validate_schema(plan)
    _validate_hashes(plan)
    expected = generate(ledger_path)
    if plan != expected:
        raise SemanticEvidenceBatchError(
            "semantic evidence plan differs from edition-pinned claims"
        )
    return copy.deepcopy(plan["counts"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.write:
        value = generate(args.ledger)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    try:
        plan = json.loads(args.output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SemanticEvidenceBatchError("cannot read semantic evidence batch output") from error
    counts = validate_plan(plan, ledger_path=args.ledger)
    if args.json:
        print(json.dumps(counts, sort_keys=True))
    else:
        print(
            f"semantic evidence batches: {counts['batches']} batches / "
            f"{counts['claims']} claims (capture plan only; parity UNPROVEN)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
