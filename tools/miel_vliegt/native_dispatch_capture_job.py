#!/usr/bin/env python3
"""Compile checked dispatch claims into immutable native capture targets.

This boundary only describes which exact native hook occurrence a controller
must execute.  It does not execute the game and can therefore never produce
parity evidence or promote a semantic claim.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import scene_semantic_evidence_batches as batches
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import scene_semantic_evidence_batches as batches


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN = batches.DEFAULT_OUTPUT
SCHEMA = 1
CONTRACT = "miel-vliegt-native-dispatch-capture-job-compilation"
TARGET_CONTRACT = "miel-vliegt-native-dispatch-capture-job"
STATUS = "NOT_EXECUTED"
TARGET_CLASSES = ("MISSION_DISPATCH", "LOCATION_POLICY")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

# These are the exact outer hook occurrences at which a controller may open
# the producer's one-shot window.  Predicate/terminal probes remain enforced
# by the producer; they are not alternate opening points.
_FUNCTION_ENTRY = "FUNCTION_ENTRY"
_INTEGER_ARGUMENT = "INTEGER_ARGUMENT"
_INLINE_SITE = "INLINE_SITE"
ACTION_CAPTURE_TARGETS: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {
    ("PLAY_SCRIPT", "GROUND"): (
        "ACTION_GROUND",
        {"kind": _INLINE_SITE, "semanticEvent": "MISSION_ACTION_DISPATCH"},
    ),
    ("PLAY_BARNSCRIPT", "BARN"): (
        "ACTION_BARN",
        {"kind": _INLINE_SITE, "semanticEvent": "MISSION_ACTION_DISPATCH"},
    ),
    ("PLAY_SCRIPTMODEFLY", "FLIGHT"): (
        "ACTION_FLIGHT",
        {"kind": _INLINE_SITE, "semanticEvent": "MISSION_ACTION_DISPATCH"},
    ),
    ("PLAY_OUTRO", "LOCATION_POLICY"): (
        "ACTION_OUTRO",
        {"kind": _INLINE_SITE, "semanticEvent": "MISSION_ACTION_DISPATCH"},
    ),
}
SELECTOR_CAPTURE_TARGETS: dict[str, tuple[str, dict[str, Any]]] = {
    "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3": (
        "GENERIC_LOCATION_ENTER",
        {"kind": _FUNCTION_ENTRY, "semanticEvent": "LOCATION_ENTER"},
    ),
    "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3": (
        "GENERIC_LOCATION_ENTER",
        {"kind": _FUNCTION_ENTRY, "semanticEvent": "LOCATION_ENTER"},
    ),
    "ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED": (
        "GROTTE_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "ROOT_COMPLETE",
            "argument": 5,
        },
    ),
    "LOCATION_ENTER_FIRST_CHALLENGE": (
        "RAYMOND_LOCATION_LOAD",
        {"kind": _FUNCTION_ENTRY, "semanticEvent": "LOCATION_ENTER"},
    ),
    "LOCATION_ENTER_SUBSEQUENT_CHALLENGE": (
        "RAYMOND_LOCATION_LOAD",
        {"kind": _FUNCTION_ENTRY, "semanticEvent": "LOCATION_ENTER"},
    ),
    "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2": (
        "RAYMOND_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "CHALLENGE_ROOT_COMPLETE",
            "argument": 6,
        },
    ),
    "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2": (
        "RAYMOND_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "CHALLENGE_ROOT_COMPLETE",
            "argument": 6,
        },
    ),
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900": (
        "EXHIBITION_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "LOCATION_ENTER",
            "argument": 6,
        },
    ),
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_NE_3": (
        "EXHIBITION_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "LOCATION_ENTER",
            "argument": 6,
        },
    ),
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_NE_3": (
        "EXHIBITION_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "LOCATION_ENTER",
            "argument": 6,
        },
    ),
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_EQ_3": (
        "EXHIBITION_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "LOCATION_ENTER",
            "argument": 6,
        },
    ),
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_EQ_3": (
        "EXHIBITION_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "LOCATION_ENTER",
            "argument": 6,
        },
    ),
    "LOCATION_ENTER_OUTRO_REQUESTED": (
        "EXHIBITION_STATE_SETTER",
        {
            "kind": _INTEGER_ARGUMENT,
            "semanticEvent": "LOCATION_ENTER",
            "argument": 6,
        },
    ),
    "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE": (
        "MYGGHANGET_ENTER",
        {"kind": _FUNCTION_ENTRY, "semanticEvent": "LOCATION_ENTER"},
    ),
}

COMPILATION_FIELDS = {
    "schema", "contract", "edition", "status", "parityEligible",
    "sourcePlan", "counts", "targets", "targetsSha256", "compilationSha256",
}
SOURCE_PLAN_FIELDS = {"capturePlanSha256", "manifestSha256"}
COUNT_FIELDS = {"targets", "byEvidenceClass"}
TARGET_FIELDS = {
    "schema", "contract", "status", "parityEligible", "planManifestSha256",
    "capturePlanSha256", "jobId", "jobSha256", "claimId", "claimSha256",
    "subjectSha256", "expectationSha256", "scenarioSha256", "evidenceClass",
    "nativeSliceId", "nativeSliceSha256", "trigger", "targetSha256",
}
MISSION_TRIGGER_FIELDS = {
    "sourcePath", "missionKey", "missionId", "missionPhase",
    "nativeActionOrdinal", "opcode", "route", "domainId", "scriptId",
    "artifactKey", "actionHookFamily", "actionEvent",
}
LOCATION_TRIGGER_FIELDS = {
    "locationId", "domainId", "mode", "policy", "outcome", "selector",
    "setupPredicates", "artifactKey", "selectorHookFamily", "selectorEvent",
}


class NativeDispatchCaptureJobError(ValueError):
    """A capture target cannot be bound exactly to the checked plan."""


def canonical_ascii_bytes(value: Any) -> bytes:
    """Return the sole transport encoding accepted for a compiled target."""

    try:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeDispatchCaptureJobError(
            "capture target is not canonical ASCII JSON"
        ) from error


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_ascii_bytes(value)).hexdigest()


def _load_checked_plan(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        source = path.read_bytes()
        plan = json.loads(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDispatchCaptureJobError("cannot read capture plan") from error
    try:
        batches.validate_plan(plan)
    except batches.SemanticEvidenceBatchError as error:
        raise NativeDispatchCaptureJobError(
            "capture plan differs from the checked edition plan"
        ) from error
    return plan, source


def _native_slice(job: dict[str, Any]) -> tuple[str, str]:
    rows = [
        row for row in job["captureSlices"] if row.get("producer") == "NATIVE"
    ]
    if len(rows) != 1:
        raise NativeDispatchCaptureJobError(
            f"job does not have exactly one native slice: {job.get('id')}"
        )
    slice_id = rows[0].get("sliceId")
    if not isinstance(slice_id, str) or not slice_id.startswith("native-slice:"):
        raise NativeDispatchCaptureJobError(
            f"native slice identity is invalid: {job.get('id')}"
        )
    digest = slice_id.removeprefix("native-slice:")
    if SHA256.fullmatch(digest) is None:
        raise NativeDispatchCaptureJobError(
            f"native slice hash is invalid: {job.get('id')}"
        )
    return slice_id, digest


def _mission_trigger(job: dict[str, Any]) -> dict[str, Any]:
    scenario = job["scenario"]
    source = scenario["trigger"]
    mission_key = source.get("missionKey")
    mission_id = source.get("missionId")
    prefix = f"{mission_id}:"
    if type(mission_id) is not int or mission_id < 0 \
            or not isinstance(mission_key, str) or not mission_key.startswith(prefix):
        raise NativeDispatchCaptureJobError(
            f"mission source identity is invalid: {job.get('id')}"
        )
    source_path = mission_key[len(prefix):]
    if not source_path or not source_path.isascii() or "\\" in source_path \
            or any(part in {"", ".", ".."} for part in Path(source_path).parts):
        raise NativeDispatchCaptureJobError(
            f"mission source path is invalid: {job.get('id')}"
        )
    trigger = {"sourcePath": source_path}
    trigger.update(copy.deepcopy(source))
    trigger["artifactKey"] = scenario["artifactKey"]
    action_target = ACTION_CAPTURE_TARGETS.get((
        trigger.get("opcode"), trigger.get("route"),
    ))
    if action_target is None:
        raise NativeDispatchCaptureJobError(
            f"mission opcode/route is unsupported: {job.get('id')}"
        )
    trigger["actionHookFamily"] = action_target[0]
    trigger["actionEvent"] = copy.deepcopy(action_target[1])
    if set(trigger) != MISSION_TRIGGER_FIELDS:
        raise NativeDispatchCaptureJobError(
            f"mission trigger schema differs: {job.get('id')}"
        )
    return trigger


def _location_trigger(job: dict[str, Any]) -> dict[str, Any]:
    scenario = job["scenario"]
    source = scenario["trigger"]
    selector = source.get("selector")
    capture_target = SELECTOR_CAPTURE_TARGETS.get(selector)
    if capture_target is None:
        raise NativeDispatchCaptureJobError(
            f"location selector is unsupported: {selector!r}"
        )
    trigger = copy.deepcopy(source)
    trigger.update({
        "setupPredicates": copy.deepcopy(scenario["setupPredicates"]),
        "artifactKey": scenario["artifactKey"],
        "selectorHookFamily": capture_target[0],
        "selectorEvent": copy.deepcopy(capture_target[1]),
    })
    if set(trigger) != LOCATION_TRIGGER_FIELDS:
        raise NativeDispatchCaptureJobError(
            f"location trigger schema differs: {job.get('id')}"
        )
    return trigger


def _compile_target(
    job: dict[str, Any], *, plan_manifest_sha256: str, capture_plan_sha256: str,
) -> dict[str, Any]:
    evidence_class = job.get("evidenceClass")
    if evidence_class not in TARGET_CLASSES:
        raise NativeDispatchCaptureJobError(
            f"unsupported dispatch capture class: {evidence_class!r}"
        )
    slice_id, slice_sha256 = _native_slice(job)
    if evidence_class == "MISSION_DISPATCH":
        trigger = _mission_trigger(job)
    else:
        trigger = _location_trigger(job)
    claim_identity = {
        "claimId": job["claimId"],
        "evidenceClass": evidence_class,
        "subjectSha256": job["subjectSha256"],
        "expectationSha256": job["expectationSha256"],
    }
    target = {
        "schema": SCHEMA,
        "contract": TARGET_CONTRACT,
        "status": STATUS,
        "parityEligible": False,
        "planManifestSha256": plan_manifest_sha256,
        "capturePlanSha256": capture_plan_sha256,
        "jobId": job["id"],
        "jobSha256": job["jobSha256"],
        "claimId": job["claimId"],
        "claimSha256": canonical_sha256(claim_identity),
        "subjectSha256": job["subjectSha256"],
        "expectationSha256": job["expectationSha256"],
        "scenarioSha256": job["scenarioSha256"],
        "evidenceClass": evidence_class,
        "nativeSliceId": slice_id,
        "nativeSliceSha256": slice_sha256,
        "trigger": trigger,
    }
    target["targetSha256"] = canonical_sha256(target)
    return target


def compile_targets(plan_path: Path = DEFAULT_PLAN) -> dict[str, Any]:
    """Compile all and only checked dispatch jobs from ``plan_path``."""

    plan, source = _load_checked_plan(plan_path)
    capture_plan_sha256 = hashlib.sha256(source).hexdigest()
    selected = [
        job
        for batch in plan["batches"]
        for job in batch["jobs"]
        if job.get("evidenceClass") in TARGET_CLASSES
    ]
    targets = [
        _compile_target(
            job,
            plan_manifest_sha256=plan["manifestSha256"],
            capture_plan_sha256=capture_plan_sha256,
        )
        for job in selected
    ]
    by_class = {
        evidence_class: sum(
            target["evidenceClass"] == evidence_class for target in targets
        )
        for evidence_class in TARGET_CLASSES
    }
    compilation = {
        "schema": SCHEMA,
        "contract": CONTRACT,
        "edition": plan["edition"],
        "status": STATUS,
        "parityEligible": False,
        "sourcePlan": {
            "capturePlanSha256": capture_plan_sha256,
            "manifestSha256": plan["manifestSha256"],
        },
        "counts": {"targets": len(targets), "byEvidenceClass": by_class},
        "targets": targets,
        "targetsSha256": canonical_sha256([
            target["targetSha256"] for target in targets
        ]),
    }
    compilation["compilationSha256"] = canonical_sha256(compilation)
    return compilation


def _validate_shape(compilation: Any) -> None:
    if not isinstance(compilation, dict) or set(compilation) != COMPILATION_FIELDS:
        raise NativeDispatchCaptureJobError("capture compilation schema differs")
    if compilation.get("schema") != SCHEMA or compilation.get("contract") != CONTRACT:
        raise NativeDispatchCaptureJobError("capture compilation contract differs")
    if compilation.get("status") != STATUS \
            or compilation.get("parityEligible") is not False:
        raise NativeDispatchCaptureJobError("capture compilation escaped NOT_EXECUTED")
    source_plan = compilation.get("sourcePlan")
    if not isinstance(source_plan, dict) or set(source_plan) != SOURCE_PLAN_FIELDS \
            or any(SHA256.fullmatch(source_plan.get(field, "")) is None
                   for field in SOURCE_PLAN_FIELDS):
        raise NativeDispatchCaptureJobError("capture source-plan identity differs")
    counts = compilation.get("counts")
    if not isinstance(counts, dict) or set(counts) != COUNT_FIELDS \
            or not isinstance(counts.get("byEvidenceClass"), dict) \
            or set(counts["byEvidenceClass"]) != set(TARGET_CLASSES):
        raise NativeDispatchCaptureJobError("capture target counts differ")
    targets = compilation.get("targets")
    if not isinstance(targets, list):
        raise NativeDispatchCaptureJobError("capture targets must be a list")
    for target in targets:
        if not isinstance(target, dict) or set(target) != TARGET_FIELDS:
            raise NativeDispatchCaptureJobError("capture target schema differs")
        evidence_class = target.get("evidenceClass")
        expected_trigger_fields = (
            MISSION_TRIGGER_FIELDS
            if evidence_class == "MISSION_DISPATCH" else LOCATION_TRIGGER_FIELDS
        )
        if evidence_class not in TARGET_CLASSES \
                or not isinstance(target.get("trigger"), dict) \
                or set(target["trigger"]) != expected_trigger_fields:
            raise NativeDispatchCaptureJobError("capture target trigger differs")
        if target.get("schema") != SCHEMA or target.get("contract") != TARGET_CONTRACT \
                or target.get("status") != STATUS \
                or target.get("parityEligible") is not False:
            raise NativeDispatchCaptureJobError("capture target escaped NOT_EXECUTED")
        for field in (
            "planManifestSha256", "capturePlanSha256", "jobSha256", "claimSha256",
            "subjectSha256", "expectationSha256", "scenarioSha256",
            "nativeSliceSha256", "targetSha256",
        ):
            if SHA256.fullmatch(target.get(field, "")) is None:
                raise NativeDispatchCaptureJobError(
                    f"capture target hash is invalid: {field}"
                )


def _validate_hashes(compilation: dict[str, Any]) -> None:
    unhashed = {
        key: value for key, value in compilation.items()
        if key != "compilationSha256"
    }
    if compilation["compilationSha256"] != canonical_sha256(unhashed):
        raise NativeDispatchCaptureJobError("capture compilation hash differs")
    seen_jobs: set[str] = set()
    seen_claims: set[str] = set()
    seen_slices: set[str] = set()
    for target in compilation["targets"]:
        unhashed_target = {
            key: value for key, value in target.items() if key != "targetSha256"
        }
        if target["targetSha256"] != canonical_sha256(unhashed_target):
            raise NativeDispatchCaptureJobError(
                f"capture target hash differs: {target.get('jobId')}"
            )
        identities = (
            (seen_jobs, target.get("jobId"), "job"),
            (seen_claims, target.get("claimId"), "claim"),
            (seen_slices, target.get("nativeSliceId"), "native slice"),
        )
        for seen, value, label in identities:
            if not isinstance(value, str) or not value or value in seen:
                raise NativeDispatchCaptureJobError(
                    f"duplicate or invalid capture {label}: {value!r}"
                )
            seen.add(value)
    if compilation["targetsSha256"] != canonical_sha256([
        target["targetSha256"] for target in compilation["targets"]
    ]):
        raise NativeDispatchCaptureJobError("capture target-set hash differs")


def validate_compilation(
    compilation: Any, plan_path: Path = DEFAULT_PLAN,
) -> dict[str, int]:
    """Validate shape, hashes, uniqueness, and exact checked-plan equality."""

    _validate_shape(compilation)
    _validate_hashes(compilation)
    expected = compile_targets(plan_path)
    if compilation != expected:
        raise NativeDispatchCaptureJobError(
            "capture targets differ from checked immutable jobs"
        )
    counts = compilation["counts"]["byEvidenceClass"]
    return {
        "targets": compilation["counts"]["targets"],
        "MISSION_DISPATCH": counts["MISSION_DISPATCH"],
        "LOCATION_POLICY": counts["LOCATION_POLICY"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--write", type=Path)
    parser.add_argument("--check", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.write is not None and args.check is not None:
        parser.error("--write and --check are mutually exclusive")
    if args.check is not None:
        try:
            compilation = json.loads(args.check.read_bytes())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeDispatchCaptureJobError(
                "cannot read capture compilation"
            ) from error
        counts = validate_compilation(compilation, args.plan)
    else:
        compilation = compile_targets(args.plan)
        counts = validate_compilation(compilation, args.plan)
        if args.write is not None:
            args.write.parent.mkdir(parents=True, exist_ok=True)
            args.write.write_bytes(canonical_ascii_bytes(compilation) + b"\n")
    if args.json:
        print(json.dumps(counts, sort_keys=True))
    else:
        print(
            f"native dispatch capture jobs: {counts['targets']} NOT_EXECUTED "
            "targets (parity ineligible)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
