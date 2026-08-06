#!/usr/bin/env python3
"""Generate the exact C allowlist for checked native dispatch capture jobs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from tools.miel_vliegt import native_capture_driver_cohorts as driver_cohorts
    from tools.miel_vliegt import native_dispatch_capture_job as jobs
except ModuleNotFoundError:
    import native_capture_driver_cohorts as driver_cohorts
    import native_dispatch_capture_job as jobs


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = (
    ROOT / "tools/miel_vliegt/hangover/"
    "native_dispatch_capture_targets.generated.h"
)

HOOK_FAMILIES = {
    "ACTION_GROUND": "MVDS_CAPTURE_HOOK_ACTION_GROUND",
    "ACTION_BARN": "MVDS_CAPTURE_HOOK_ACTION_BARN",
    "ACTION_FLIGHT": "MVDS_CAPTURE_HOOK_ACTION_FLIGHT",
    "ACTION_OUTRO": "MVDS_CAPTURE_HOOK_ACTION_OUTRO",
    "GENERIC_LOCATION_ENTER": "MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER",
    "GROTTE_STATE_SETTER": "MVDS_CAPTURE_HOOK_GROTTE_STATE_SETTER",
    "RAYMOND_LOCATION_LOAD": "MVDS_CAPTURE_HOOK_RAYMOND_LOCATION_LOAD",
    "RAYMOND_STATE_SETTER": "MVDS_CAPTURE_HOOK_RAYMOND_STATE_SETTER",
    "EXHIBITION_STATE_SETTER": "MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER",
    "MYGGHANGET_ENTER": "MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER",
}

DRIVER_NONE = "MVDS_CAPTURE_DRIVER_NONE"
DRIVER_GENERIC_LOCATION_CLEAN_V2 = (
        "MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2"
)
DRIVER_BOOTSTRAP_PROFILE_SHA256 = driver_cohorts.DRIVER_BOOTSTRAP_PROFILE_SHA256
DRIVER_SCENARIO_SHA256 = driver_cohorts.DRIVER_SCENARIO_SHA256
DRIVER_INITIAL_USER_SHA256 = driver_cohorts.DRIVER_INITIAL_USER_SHA256


def capture_driver(target: dict) -> str:
    selected = driver_cohorts.cohort_for_target(target)
    if selected is None:
        return DRIVER_NONE
    return selected["cMacro"]


def _c_text(value: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ValueError("capture target text must be non-empty ASCII")
    return json.dumps(value, ensure_ascii=True)


def _common(target: dict) -> list[str]:
    selected = driver_cohorts.cohort_for_target(target)
    driven = selected is not None
    return [
        f".capture_driver = {selected['cMacro'] if driven else DRIVER_NONE}",
        f".driver_mode = {_c_text(selected['mode'] if driven else '-')}",
        f".driver_bootstrap_profile_sha256 = {_c_text(DRIVER_BOOTSTRAP_PROFILE_SHA256 if driven else '-')}",
        f".driver_scenario_sha256 = {_c_text(DRIVER_SCENARIO_SHA256 if driven else '-')}",
        f".driver_initial_user_sha256 = {_c_text(DRIVER_INITIAL_USER_SHA256 if driven else '-')}",
        f".plan_manifest_sha256 = {_c_text(target['planManifestSha256'])}",
        f".capture_plan_sha256 = {_c_text(target['capturePlanSha256'])}",
        f".job_id = {_c_text(target['jobId'])}",
        f".job_sha256 = {_c_text(target['jobSha256'])}",
        f".claim_id = {_c_text(target['claimId'])}",
        f".claim_sha256 = {_c_text(target['claimSha256'])}",
        f".subject_sha256 = {_c_text(target['subjectSha256'])}",
        f".expectation_sha256 = {_c_text(target['expectationSha256'])}",
        f".scenario_sha256 = {_c_text(target['scenarioSha256'])}",
        f".native_slice_sha256 = {_c_text(target['nativeSliceSha256'])}",
        f".target_sha256 = {_c_text(target['targetSha256'])}",
    ]


def _target_row(target: dict) -> str:
    trigger = target["trigger"]
    fields = _common(target)
    if target["evidenceClass"] == "MISSION_DISPATCH":
        fields.insert(0, ".evidence_class = MVDS_EVIDENCE_MISSION_DISPATCH")
        mission = [
            f".source_path = {_c_text(trigger['sourcePath'])}",
            f".mission_key = {_c_text(trigger['missionKey'])}",
            f".mission_id = {trigger['missionId']}u",
            f".mission_phase = {_c_text(trigger['missionPhase'])}",
            f".native_action_ordinal = {trigger['nativeActionOrdinal']}u",
            f".opcode = {_c_text(trigger['opcode'])}",
            f".route = MVDS_ROUTE_{trigger['route']}",
            f".hook_family = {HOOK_FAMILIES[trigger['actionHookFamily']]}",
        ]
        fields.append(".trigger = { .mission = { " + ", ".join(mission) + " } }")
    else:
        fields.insert(0, ".evidence_class = MVDS_EVIDENCE_LOCATION_POLICY")
        event_argument = trigger["selectorEvent"].get("argument", -1)
        location = [
            f".location_id = {trigger['locationId']}u",
            f".selector = {_c_text(trigger['selector'])}",
            f".mode = {_c_text(trigger['mode'])}",
            f".hook_family = {HOOK_FAMILIES[trigger['selectorHookFamily']]}",
            f".event_argument = {event_argument}",
        ]
        fields.append(".trigger = { .location = { " + ", ".join(location) + " } }")
    return "    { " + ", ".join(fields) + " },"


def generate_header() -> str:
    compilation = jobs.compile_targets()
    counts = jobs.validate_compilation(compilation)
    if counts != {
        "targets": 155, "MISSION_DISPATCH": 113, "LOCATION_POLICY": 42,
    }:
        raise ValueError("capture target population differs")
    driver_counts: dict[str, int] = {}
    for target in compilation["targets"]:
        macro = capture_driver(target)
        if macro != DRIVER_NONE:
            driver_counts[macro] = driver_counts.get(macro, 0) + 1
    expected_counts = {
        cohort["cMacro"]: cohort["expectedTargetCount"]
        for cohort in driver_cohorts.COHORTS
    }
    if driver_counts != expected_counts:
        raise ValueError("driver cohort population differs")
    rows = "\n".join(_target_row(target) for target in compilation["targets"])
    return (
        "/* Generated by native_dispatch_capture_target_header.py. */\n"
        "#ifndef MIEL_VLIEGT_NATIVE_DISPATCH_CAPTURE_TARGETS_GENERATED_H\n"
        "#define MIEL_VLIEGT_NATIVE_DISPATCH_CAPTURE_TARGETS_GENERATED_H\n\n"
        "#define MVDS_CAPTURE_TARGET_COUNT 155u\n"
        "static const MvdsCaptureTarget MVDS_CAPTURE_TARGETS[] = {\n"
        f"{rows}\n"
        "};\n\n"
        "#endif\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generate_header()
    if args.check:
        if not args.output.is_file() or args.output.read_text(
            encoding="ascii",
        ) != expected:
            raise ValueError("generated capture target header differs")
        print(f"PASS {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="ascii")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
