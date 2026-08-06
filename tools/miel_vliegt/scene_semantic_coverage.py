#!/usr/bin/env python3
"""Fail-closed semantic coverage ledger for the flight scene engine.

This gate deliberately separates four claims which are easy to conflate: the
parsed body of a UDSP location or character script, its edition-dependent native parser
lowering, a mission action dispatching that script, and the native location
policy selecting a root.  Static structure is an inventory, not runtime
parity; generated records therefore start UNPROVEN.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.miel_vliegt import udsp_semantic_oracle
except ModuleNotFoundError:  # Direct script execution from tools/miel_vliegt.
    import udsp_semantic_oracle


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DISPATCH = ROOT / "content/miel_vliegt/scene_dispatch_contract.json"
DEFAULT_UDSP = ROOT / "content/miel_vliegt/uds_scene_scripts.json"
DEFAULT_EXECUTABLE = ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json"
DEFAULT_LEDGER = ROOT / "content/miel_vliegt/scene_semantic_coverage.json"
SEMANTIC_EVIDENCE_BATCH_PLAN = (
    ROOT / "content/miel_vliegt/scene_semantic_evidence_batches.json"
)
WEB_DISPATCH_CAPTURE_EXECUTOR = (
    ROOT / "src/flight/engine/scene/WebSceneDispatchCaptureExecutor.js"
)
WEB_DISPATCH_CANDIDATE_BRIDGE = (
    ROOT / "src/flight/engine/scene/WebSceneDispatchCandidateBridge.js"
)
WEB_DISPATCH_CANDIDATE_WRITER = (
    ROOT / "tools/miel_vliegt/web_dispatch_candidate_artifacts.py"
)

SCHEMA = 1
CONTRACT = "miel-vliegt-scene-semantic-coverage"
CLASSES = (
    "UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY", "MISSION_DISPATCH", "LOCATION_POLICY",
)
STATUS = {"UNPROVEN", "PROVEN"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CANDIDATE_VERSION_LINE = re.compile(
    r"Miel Monteur [^()\r\n]+ \([^,()\r\n]+,[ \t]*([A-Za-z0-9._-]+)\)"
)
HEX_POINTER = re.compile(r"^0x[0-9a-fA-F]{8,16}$")
SEMANTIC_TRACE_PROTOCOL = "miel-vliegt-scene-semantic-trace"
SEMANTIC_SESSION_PROTOCOL = "miel-vliegt-scene-semantic-session"
SEMANTIC_DIFFERENTIAL_PROTOCOL = "miel-vliegt-scene-semantic-differential"
SEMANTIC_TRACE_FIELDS = {
    "schema", "protocol", "producer", "claimId", "evidenceClass",
    "edition", "sourceHashes", "subjectSha256", "expectationSha256",
    "producerProvenance", "observations",
}
SEMANTIC_SLICED_TRACE_FIELDS = (
    SEMANTIC_TRACE_FIELDS - {"observations"}
) | {"sessionSlice"}
SEMANTIC_SESSION_FIELDS = {
    "schema", "protocol", "producer", "edition", "sourceHashes", "events",
}
SEMANTIC_SESSION_EVENT_FIELDS = {"schema", "record", "sequence", "state"}
SEMANTIC_SESSION_SLICE_FIELDS = {
    "session", "claimId", "subjectSha256", "expectationSha256",
    "eventIndices", "eventHashes", "sliceSha256",
}
SEMANTIC_OBSERVATION_FIELDS = {
    "schema", "record", "sequence", "claimId", "evidenceClass",
    "subjectSha256", "expectationSha256", "state",
}
SEMANTIC_DIFFERENTIAL_FIELDS = {
    "schema", "protocol", "result", "evidenceId", "evidenceClass",
    "claimId", "edition", "sourceHashes", "subjectSha256",
    "expectationSha256", "nativeTrace", "webTrace",
    "observationsSha256",
}
TRACE_REFERENCE_FIELDS = {"path", "sha256"}
PRODUCER_PROVENANCE_PROTOCOL = "miel-vliegt-scene-semantic-producer-provenance"
PRODUCER_PROVENANCE_COMMON_FIELDS = {
    "schema", "protocol", "producer", "mode", "result", "claimId", "evidenceClass",
    "edition", "sourceHashes", "subjectSha256", "expectationSha256",
    "observationsSha256", "captureProtocol",
}
NATIVE_PROVENANCE_FIELDS = PRODUCER_PROVENANCE_COMMON_FIELDS | {
    "executableSha256", "nativeCommandContract", "observerHook",
    "observerLauncher", "captureReceipt",
}
WEB_PROVENANCE_FIELDS = PRODUCER_PROVENANCE_COMMON_FIELDS | {
    "webBuild", "runtimeProducer", "captureReceipt",
}
NATIVE_CAPTURE_PROTOCOL = "miel-vliegt-native-scene-semantic-capture"
WEB_CAPTURE_PROTOCOL = "miel-vliegt-web-scene-semantic-capture"
CAPTURE_COMMON_FIELDS = {
    "schema", "protocol", "result", "captureStatus", "producer", "edition",
    "claimId", "evidenceClass", "sourceHashes", "subjectSha256",
    "expectationSha256", "observationsSha256", "rawTrace",
    "rawTraceProtocol",
}
NATIVE_CAPTURE_FIELDS = CAPTURE_COMMON_FIELDS | {
    "executableSha256", "nativeCommandContract", "observerHook",
    "observerLauncherSource", "observerDll", "launcherBinary",
}
WEB_CAPTURE_FIELDS = CAPTURE_COMMON_FIELDS | {"webBuild", "runtimeProducer"}
WEB_DISPATCH_CAPTURE_FIELDS = WEB_CAPTURE_FIELDS | {"candidateBuild"}
WEB_DISPATCH_CANDIDATE_BUILD_PROTOCOL = "miel-vliegt-web-dispatch-candidate-build"
WEB_DISPATCH_CANDIDATE_BUILD_FIELDS = {
    "schema", "protocol", "semanticStatus", "parityEligible",
    "productionProvenance",
    "candidateVersion", "captureBundleSha256", "versionTextSha256",
    "webTransitionBuildSha256", "captureBundle", "versionText",
    "webTransitionBuild", "semanticLedgerSha256", "semanticPlanSha256",
    "semanticLedger", "semanticPlan",
}
NATIVE_OBSERVER_HOOK = ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
NATIVE_OBSERVER_LAUNCHER = ROOT / "tools/miel_vliegt/hangover/native_observer_launcher.c"
WEB_BUILD_RECEIPT = ROOT / "content/miel_vliegt/web_transition_build.json"
WEB_RUNTIME_PRODUCER = ROOT / "src/flight/engine/scene/UdspSceneRuntime.js"
WEB_DISPATCH_RUNTIME_PRODUCER = ROOT / "src/flight/engine/scene/SceneDispatchRuntime.js"
SEMANTIC_ORACLE_SOURCE = Path(udsp_semantic_oracle.__file__).resolve()
RAW_POINTER_FIELDS = {
    "address", "callback", "caller", "composite", "context", "dispatcher",
    "entry", "handler_case", "next", "node", "object", "object_vtable",
    "parent_current", "parser_case", "pointer", "root", "vtable",
}
EXPECTED_ROUTES = {
    "GROUND": {"opcode": "PLAY_SCRIPT", "enqueue": "PREPEND", "start": "LOCATION_SELECTION"},
    "BARN": {"opcode": "PLAY_BARNSCRIPT", "enqueue": "APPEND", "start": "IMMEDIATE_IF_IDLE"},
    "FLIGHT": {"opcode": "PLAY_SCRIPTMODEFLY", "enqueue": "REPLACE", "start": "IMMEDIATE"},
}
SPECIAL_POLICIES = {
    "grotte_grundlig": ("GROTTE_REFUEL", ("nooneathome", "allfinished"), ("refuel",)),
    "raymond_rajser": (
        "RAYMOND_CHALLENGE", (),
        ("challenge_first", "challenge", "mulle_win", "mulle_lose"),
    ),
    "varldsutstallning": (
        "EXHIBITION_SELECTOR", (),
        (
            "judge", "nooneathome_emma", "nooneathome_circus",
            "allfinished_emma", "allfinished_circus", "outro",
        ),
    ),
    "mygghanget": ("BESPOKE_NO_UDSP", (), ()),
}
POLICY_SELECTORS = {
    "GENERIC": {
        "nooneathome": "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3",
        "allfinished": "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3",
    },
    "GROTTE_REFUEL": {
        "nooneathome": "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3",
        "allfinished": "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3",
        "refuel": "ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED",
    },
    "RAYMOND_CHALLENGE": {
        "challenge_first": "LOCATION_ENTER_FIRST_CHALLENGE",
        "challenge": "LOCATION_ENTER_SUBSEQUENT_CHALLENGE",
        "mulle_win": "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2",
        "mulle_lose": "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2",
    },
    "EXHIBITION_SELECTOR": {
        "judge": "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900",
        "nooneathome_emma": (
            "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_"
            "AND_FINAL_MISSION_STATE_NE_3"
        ),
        "nooneathome_circus": (
            "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_"
            "AND_FINAL_MISSION_STATE_NE_3"
        ),
        "allfinished_emma": (
            "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_"
            "AND_FINAL_MISSION_STATE_EQ_3"
        ),
        "allfinished_circus": (
            "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_"
            "AND_FINAL_MISSION_STATE_EQ_3"
        ),
        "outro": "LOCATION_ENTER_OUTRO_REQUESTED",
    },
    "BESPOKE_NO_UDSP": {
        "bespoke_native_state_machine": "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE",
    },
}
EXPECTED_ABSENCES = [
    {
        "domainId": "mygghanget", "dispatchId": None,
        "kind": "LOCATION_SCRIPT_DOMAIN", "reason": "BESPOKE_NATIVE_STATE_MACHINE",
    },
    {
        "domainId": "raymond_rajser", "dispatchId": "allfinished",
        "kind": "LOCATION_SCRIPT", "reason": "SPECIALIZED_CHALLENGE_POLICY",
    },
    {
        "domainId": "varldsutstallning", "dispatchId": "allfinished",
        "kind": "LOCATION_SCRIPT", "reason": "SUFFIXED_EXHIBITION_FINAL_ROOTS",
    },
]
EXECUTABLE_COUNT_FIELDS = {
    "scripts", "rawCommandNodes", "executableCommandNodes", "removedCommandNodes",
    "sourceCharacterSounds", "removedZeroTakeCharacterSounds",
    "removedDirectParserDiscards", "oneTakeCharacterSounds",
    "multipleTakeCharacterSounds", "nativeOpcode5Nodes", "nativeOpcode6Nodes",
}


class SemanticCoverageError(ValueError):
    """Raised when a coverage input or ledger is not structurally exact."""


def parse_web_candidate_version_text(value: str) -> str:
    newline = value.find("\n")
    if newline < 0:
        raise SemanticCoverageError("web dispatch candidate line ending is invalid")
    first_line = value[:newline]
    if first_line.endswith("\r"):
        first_line = first_line[:-1]
    if "\r" in first_line:
        raise SemanticCoverageError("web dispatch candidate line ending is invalid")
    match = CANDIDATE_VERSION_LINE.fullmatch(first_line)
    if not match or not match.group(1) or match.group(1) == "dev":
        raise SemanticCoverageError("web dispatch candidate version is invalid")
    return match.group(1)


def web_runtime_producer(record: dict[str, Any]) -> Path:
    evidence_class = record.get("evidenceClass") if isinstance(record, dict) else None
    if evidence_class in {"UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY"}:
        return WEB_RUNTIME_PRODUCER
    if evidence_class in {"MISSION_DISPATCH", "LOCATION_POLICY"}:
        return WEB_DISPATCH_RUNTIME_PRODUCER
    raise SemanticCoverageError(f"unknown web semantic producer class: {evidence_class}")


def expected_web_dispatch_capture_provenance(
    record: dict[str, Any], *, edition: str,
    candidate_identity: dict[str, Any] | None = None,
    plan_document: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Derive dispatch raw provenance from the checked, source-bound batch plan."""

    if record.get("evidenceClass") not in {"MISSION_DISPATCH", "LOCATION_POLICY"}:
        return None
    if not isinstance(candidate_identity, dict) \
            or set(candidate_identity) != {"candidateVersion", "captureBundleSha256"} \
            or not isinstance(candidate_identity.get("candidateVersion"), str) \
            or not candidate_identity["candidateVersion"] \
            or not SHA256.fullmatch(candidate_identity.get("captureBundleSha256", "")):
        raise SemanticCoverageError("dispatch candidate build identity is required")
    if plan_document is None:
        try:
            plan = json.loads(SEMANTIC_EVIDENCE_BATCH_PLAN.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SemanticCoverageError("semantic evidence batch plan cannot be loaded") from error
    else:
        plan = copy.deepcopy(plan_document)
    required = {
        "schema", "contract", "edition", "claim", "sources", "policy",
        "counts", "batches", "manifestSha256",
    }
    if not isinstance(plan, dict) or set(plan) != required \
            or plan.get("schema") != 1 \
            or plan.get("contract") != "miel-vliegt-scene-semantic-evidence-batches" \
            or plan.get("edition") != edition \
            or plan.get("manifestSha256") != _canonical_sha({
                key: value for key, value in plan.items() if key != "manifestSha256"
            }):
        raise SemanticCoverageError("semantic evidence batch plan identity differs")
    source_paths = {
        "webSceneDispatchCaptureExecutor": WEB_DISPATCH_CAPTURE_EXECUTOR,
        "webSceneDispatchCandidateBridge": WEB_DISPATCH_CANDIDATE_BRIDGE,
        "webSceneDispatchRuntime": WEB_DISPATCH_RUNTIME_PRODUCER,
        "semanticOracle": SEMANTIC_ORACLE_SOURCE,
        "webDispatchCandidateArtifactWriter": WEB_DISPATCH_CANDIDATE_WRITER,
        "webTransitionBuild": WEB_BUILD_RECEIPT,
    }
    sources = plan.get("sources")
    for name, path in source_paths.items():
        source = sources.get(name) if isinstance(sources, dict) else None
        if not isinstance(source, dict) or set(source) != {"path", "sha256", "schema"} \
                or source.get("path") != _repo_path(path) \
                or source.get("sha256") != sha256_file(path):
            raise SemanticCoverageError(
                f"semantic evidence batch source differs: {name}"
            )
    jobs = [
        job for batch in plan.get("batches", [])
        if isinstance(batch, dict) and isinstance(batch.get("jobs"), list)
        for job in batch["jobs"]
        if isinstance(job, dict) and job.get("claimId") == record.get("id")
    ]
    if len(jobs) != 1:
        raise SemanticCoverageError("dispatch claim has no unique semantic capture job")
    job = jobs[0]
    if job.get("evidenceClass") != record.get("evidenceClass") \
            or job.get("subjectSha256") != evidence_subject_sha256(record) \
            or job.get("expectationSha256") != evidence_expectation_sha256(record) \
            or job.get("jobSha256") != _canonical_sha({
                key: value for key, value in job.items() if key != "jobSha256"
            }):
        raise SemanticCoverageError("dispatch semantic capture job identity differs")
    web_slices = [
        row for row in job.get("captureSlices", [])
        if isinstance(row, dict) and row.get("producer") == "WEB"
    ]
    if len(web_slices) != 1 \
            or web_slices[0].get("rawProtocol") != udsp_semantic_oracle.WEB_RAW_PROTOCOL:
        raise SemanticCoverageError("dispatch semantic web capture slice differs")
    return {
        "schema": 1,
        "planManifestSha256": plan["manifestSha256"],
        "jobSha256": job["jobSha256"],
        "webSliceId": web_slices[0].get("sliceId"),
        "executorSha256": sources["webSceneDispatchCaptureExecutor"]["sha256"],
        "runtimeSha256": sources["webSceneDispatchRuntime"]["sha256"],
        "oracleSha256": sources["semanticOracle"]["sha256"],
        **copy.deepcopy(candidate_identity),
    }


@dataclass(frozen=True)
class CoverageReport:
    edition: str
    counts: dict[str, int]
    proven: dict[str, int]
    unproven: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def complete(self) -> bool:
        return sum(self.unproven.values()) == 0


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evidence_expectation_sha256(record: dict[str, Any]) -> str:
    """Hash the exact generated expectation a semantic proof must satisfy."""

    return _canonical_sha(record["expectation"])


def evidence_subject_sha256(record: dict[str, Any]) -> str:
    """Hash the claim identity independently from a proof artifact."""

    return _canonical_sha({
        "claimId": record["id"],
        "evidenceClass": record["evidenceClass"],
        "expectationSha256": evidence_expectation_sha256(record),
    })


def semantic_observations_sha256(observations: list[dict[str, Any]]) -> str:
    return _canonical_sha(observations)


def _repo_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError as error:
        raise SemanticCoverageError(f"source is outside repository: {path}") from error


def _load(path: Path, schema: int, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SemanticCoverageError(f"cannot read {label}: {path}") from error
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise SemanticCoverageError(f"{label} must use schema {schema}")
    return value


def _source(path: Path, schema: int) -> dict[str, Any]:
    return {"path": _repo_path(path), "sha256": sha256_file(path), "schema": schema}


def _record(evidence_class: str, claim_id: str, expectation: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": claim_id,
        "evidenceClass": evidence_class,
        "status": "UNPROVEN",
        "evidence": [],
        "expectation": expectation,
    }


def _raw_scripts(udsp: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    scripts = udsp.get("scripts")
    if not isinstance(scripts, list):
        raise SemanticCoverageError("UDSP source has no scripts inventory")
    for script in scripts:
        if not isinstance(script, dict):
            raise SemanticCoverageError("UDSP source has an invalid script")
        domain = script.get("domain_id")
        dispatch = script.get("dispatch_id")
        digest = script.get("sha256")
        path = script.get("path")
        if not all(isinstance(value, str) and value for value in (domain, dispatch, path)):
            raise SemanticCoverageError("UDSP script has an invalid identity")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise SemanticCoverageError("UDSP script has an invalid hash")
        if path in rows:
            raise SemanticCoverageError(f"duplicate UDSP script path: {path}")
        rows[path] = script
    counts = udsp.get("counts", {})
    declared = counts.get("location_scripts", 0) + counts.get("character_scripts", 0)
    if declared != len(rows):
        raise SemanticCoverageError("UDSP script count drifted")
    return rows


def _script_artifacts(udsp: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for script in _raw_scripts(udsp).values():
        script_type = script.get("type")
        if script_type not in {"LOCATION_SCRIPT", "CHARACTER_SCRIPT"}:
            raise SemanticCoverageError(f"unknown UDSP script type: {script_type}")
        key = f"{script_type}:{script['domain_id']}/{script['dispatch_id']}"
        if key in rows:
            raise SemanticCoverageError(f"duplicate UDSP script artifact: {key}")
        rows[key] = script
    declared = sum(
        udsp.get("counts", {}).get(name, 0)
        for name in ("location_scripts", "character_scripts")
    )
    if declared != len(rows):
        raise SemanticCoverageError("UDSP script artifact count drifted")
    return rows


def _location_scripts(udsp: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = {
        key: script for key, script in _script_artifacts(udsp).items()
        if script["type"] == "LOCATION_SCRIPT"
    }
    if len(rows) != udsp.get("counts", {}).get("location_scripts"):
        raise SemanticCoverageError("UDSP location-script count drifted")
    return rows


def _validate_source_pins(executable: dict[str, Any]) -> None:
    sources = executable.get("sources")
    if not isinstance(sources, dict) or set(sources) != {
        "scripts", "assets", "nativeCommands", "generator",
    }:
        raise SemanticCoverageError("executable UDSP source pins drifted")
    for label, source in sources.items():
        if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
            raise SemanticCoverageError(f"executable UDSP source pin is invalid: {label}")
        path, digest = source["path"], source["sha256"]
        if not isinstance(path, str) or not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise SemanticCoverageError(f"executable UDSP source pin is invalid: {label}")
        source_path = (ROOT / path).resolve()
        try:
            source_path.relative_to(ROOT.resolve())
        except ValueError as error:
            raise SemanticCoverageError(f"executable UDSP source escapes repository: {label}") from error
        if not source_path.is_file() or sha256_file(source_path) != digest:
            raise SemanticCoverageError(f"executable UDSP source hash drifted: {label}")


def _load_lowering_sources(
    executable: dict[str, Any],
) -> tuple[
    dict[tuple[str, int, str], list[dict[str, Any]]],
    dict[int, list[dict[str, Any]]],
    dict[str, tuple[int, str]],
]:
    sources = executable["sources"]
    assets = _load(ROOT / sources["assets"]["path"], 1, "flight scene assets")
    native = _load(ROOT / sources["nativeCommands"]["path"], 1, "native UDSP commands")
    if assets.get("contract") != "miel-vliegt-flight-scene-assets" \
            or assets.get("edition") != executable.get("edition"):
        raise SemanticCoverageError("executable UDSP asset edition/contract drifted")
    sound_index: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
    barn_index: dict[int, list[dict[str, Any]]] = {}
    barn_bank = assets.get("resolution", {}).get("barnBank")
    if not isinstance(barn_bank, str) or not barn_bank:
        raise SemanticCoverageError("flight scene asset barn bank drifted")
    for row in assets.get("media", []):
        if not isinstance(row, dict):
            continue
        if row.get("opcode") == "PLAY_MULLEBARNSOUND":
            number = row.get("scriptNumber")
            variants = row.get("variants")
            if row.get("owner") != "barn" or row.get("bank") != barn_bank \
                    or row.get("status") != "RESOLVED" or not isinstance(number, int) \
                    or not isinstance(variants, list) or not variants or number in barn_index:
                raise SemanticCoverageError("flight scene barn-media identity drifted")
            barn_index[number] = variants
            continue
        if row.get("opcode") != "PLAY_CHARACTER_SOUND":
            continue
        owner, number, bank = row.get("owner"), row.get("scriptNumber"), row.get("bank")
        variants = row.get("variants")
        if not isinstance(owner, str) or not isinstance(number, int) \
                or not isinstance(bank, str) or not isinstance(variants, list):
            raise SemanticCoverageError("flight scene sound-media identity drifted")
        key = (owner.lower(), number, bank.lower())
        if key in sound_index:
            raise SemanticCoverageError(f"duplicate flight scene sound media: {key}")
        sound_index[key] = variants
    opcode_index: dict[str, tuple[int, str]] = {}
    for row in native.get("commands", []):
        name = row.get("name") if isinstance(row, dict) else None
        opcode = row.get("id") if isinstance(row, dict) else None
        behavior = row.get("parser_behavior") if isinstance(row, dict) else None
        if not isinstance(name, str) or not isinstance(opcode, int) or not isinstance(behavior, str) \
                or name in opcode_index:
            raise SemanticCoverageError("native UDSP opcode inventory drifted")
        opcode_index[name] = (opcode, behavior)
    if len(opcode_index) != 15:
        raise SemanticCoverageError("native UDSP opcode inventory drifted")
    return sound_index, barn_index, opcode_index


def _sound_media_key(arguments: Any, key: str) -> tuple[str, int, str]:
    if not isinstance(arguments, list) or len(arguments) != 4:
        raise SemanticCoverageError(f"character-sound arguments drifted: {key}")
    owner, number, bank = arguments[:3]
    if not isinstance(owner, str) or not isinstance(number, int) or not isinstance(bank, str):
        raise SemanticCoverageError(f"character-sound media identity drifted: {key}")
    return owner.lower(), number, bank.lower()


def _lower_expected_structure(
    structure: Any, source_to_executable: dict[int, int | None], *, path: str,
) -> dict[str, Any]:
    if not isinstance(structure, dict) or set(structure) != {"node", "repeat", "children"} \
            or not isinstance(structure["children"], list):
        raise SemanticCoverageError(f"raw UDSP structure drifted: {path}")
    children = []
    for child in structure["children"]:
        if isinstance(child, dict) and set(child) == {"command"}:
            source_index = child["command"]
            if source_index not in source_to_executable:
                raise SemanticCoverageError(
                    f"raw UDSP structure references unknown command: {path}#{source_index}"
                )
            executable_index = source_to_executable[source_index]
            if executable_index is not None:
                children.append({
                    "command": executable_index,
                    "sourceCommand": source_index,
                })
        elif isinstance(child, dict):
            children.append(_lower_expected_structure(
                child, source_to_executable, path=path,
            ))
        else:
            raise SemanticCoverageError(f"raw UDSP structure child drifted: {path}")
    return {
        "node": structure["node"],
        "repeat": structure["repeat"],
        "children": children,
    }


def _validate_lowered_sound(
    command: dict[str, Any], key: str,
    sound_index: dict[tuple[str, int, str], list[dict[str, Any]]],
) -> None:
    media_key = _sound_media_key(command.get("arguments"), key)
    if media_key not in sound_index:
        raise SemanticCoverageError(f"character-sound media is absent: {key}")
    expected_takes = sound_index[media_key]
    native_opcode = command.get("nativeOpcode")
    asset_key = command.get("assetKey")
    takes = command.get("takes")
    if len(expected_takes) == 1:
        expected_key = expected_takes[0].get("key")
        if native_opcode != 5 or asset_key != expected_key or "takes" in command:
            raise SemanticCoverageError(f"one-take lowering drifted: {key}")
        return
    expected = [
        {"take": row.get("take"), "assetKey": row.get("key")} for row in expected_takes
    ]
    if len(expected) < 2 or native_opcode != 6 or asset_key is not None or takes != expected:
        raise SemanticCoverageError(f"multi-take lowering drifted: {key}")
    take_numbers = [row.get("take") if isinstance(row, dict) else None for row in takes]
    asset_keys = [row.get("assetKey") if isinstance(row, dict) else None for row in takes]
    if (
        any(not isinstance(take, int) or not 1 <= take < 100 for take in take_numbers)
        or take_numbers != sorted(set(take_numbers))
        or any(not isinstance(value, str) or not value for value in asset_keys)
        or len(asset_keys) != len(set(asset_keys))
    ):
        raise SemanticCoverageError(f"multi-take ordering drifted: {key}")


def _validate_lowered_barn(
    command: dict[str, Any], key: str,
    barn_index: dict[int, list[dict[str, Any]]],
) -> None:
    arguments = command.get("arguments")
    if not isinstance(arguments, list) or len(arguments) != 2 \
            or not isinstance(arguments[0], int):
        raise SemanticCoverageError(f"barn-sound arguments drifted: {key}")
    expected_takes = barn_index.get(arguments[0])
    expected = [
        {"take": row.get("take"), "assetKey": row.get("key")}
        for row in expected_takes or []
    ]
    if not expected or command.get("nativeOpcode") != 14 \
            or command.get("takes") != expected or "assetKey" in command:
        raise SemanticCoverageError(f"barn take lowering drifted: {key}")
    take_numbers = [row.get("take") for row in expected]
    asset_keys = [row.get("assetKey") for row in expected]
    if (
        any(not isinstance(take, int) or not 1 <= take < 100 for take in take_numbers)
        or take_numbers != sorted(set(take_numbers))
        or any(not isinstance(value, str) or not value for value in asset_keys)
        or len(asset_keys) != len(set(asset_keys))
    ):
        raise SemanticCoverageError(f"barn take lowering drifted: {key}")


def _executable_scripts(
    executable: dict[str, Any], udsp: dict[str, Any], *,
    udsp_source: dict[str, Any], edition: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    if executable.get("contract") != "miel-vliegt-executable-udsp-scene-scripts":
        raise SemanticCoverageError("unexpected executable UDSP contract")
    if executable.get("claim") != "STATIC_NATIVE_PARSER_LOWERING_EXACT_FOR_PINNED_EDITION_ASSETS":
        raise SemanticCoverageError("executable UDSP contract escaped static-only claim")
    if executable.get("edition") != edition:
        raise SemanticCoverageError("executable UDSP edition differs from dispatch edition")
    declared_counts = executable.get("counts")
    if not isinstance(declared_counts, dict) or set(declared_counts) != EXECUTABLE_COUNT_FIELDS:
        raise SemanticCoverageError("executable UDSP aggregate lowering count shape drifted")
    _validate_source_pins(executable)
    script_pin = executable["sources"]["scripts"]
    if script_pin != {
        "path": udsp_source["path"], "sha256": udsp_source["sha256"],
    }:
        raise SemanticCoverageError("raw/executable UDSP source identity mismatch")

    identities = executable.get("sourceIdentities")
    if not isinstance(identities, dict) or set(identities) != {
        "rawUdspArchiveSha256", "nativeExecutableSha256", "editionDataArchiveSha256",
        "editionSoundsArchiveSha256", "nativeVoiceExecutableSha256",
    } or any(not isinstance(value, str) or not SHA256.fullmatch(value) for value in identities.values()):
        raise SemanticCoverageError("executable UDSP source identities drifted")
    raw_archive = udsp.get("source", {}).get("sha256")
    if (
        identities["rawUdspArchiveSha256"] != raw_archive
        or identities["editionDataArchiveSha256"] != raw_archive
        or identities["nativeExecutableSha256"] != identities["nativeVoiceExecutableSha256"]
    ):
        raise SemanticCoverageError("raw/executable archive or native identity mismatch")

    sound_index, barn_index, opcode_index = _load_lowering_sources(executable)
    raw_by_path = _raw_scripts(udsp)
    lowered = executable.get("scripts")
    if not isinstance(lowered, list) or len(lowered) != len(raw_by_path):
        raise SemanticCoverageError("executable UDSP script inventory drifted")
    removed = executable.get("removedCommands")
    if not isinstance(removed, list):
        raise SemanticCoverageError("executable UDSP removed-command inventory drifted")
    removed_by_path: dict[str, list[dict[str, Any]]] = {}
    for row in removed:
        path = row.get("path") if isinstance(row, dict) else None
        if path not in raw_by_path:
            raise SemanticCoverageError(f"removed command targets unknown script: {path}")
        removed_by_path.setdefault(path, []).append(row)

    result: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    total_raw = total_executable = total_removed = 0
    for script in lowered:
        if not isinstance(script, dict):
            raise SemanticCoverageError("invalid executable UDSP script")
        path = script.get("path")
        if path in seen_paths or path not in raw_by_path:
            raise SemanticCoverageError(f"duplicate or unknown executable UDSP script: {path}")
        seen_paths.add(path)
        raw = raw_by_path[path]
        identity = (
            script.get("type"), script.get("domainId"), script.get("dispatchId"),
            script.get("sourceSha256"),
        )
        expected_identity = (
            raw.get("type"), raw.get("domain_id"), raw.get("dispatch_id"), raw.get("sha256"),
        )
        if identity != expected_identity:
            raise SemanticCoverageError(f"raw/executable script identity mismatch: {path}")
        commands = script.get("commands")
        structure = script.get("structure")
        counts = script.get("counts")
        raw_commands = raw.get("commands")
        removed_rows = removed_by_path.get(path, [])
        if not all(isinstance(value, list) for value in (commands, raw_commands)) \
                or not isinstance(structure, dict) or not isinstance(counts, dict):
            raise SemanticCoverageError(f"executable UDSP script structure drifted: {path}")
        expected_counts = {
            "rawCommandNodes": len(raw_commands),
            "executableCommandNodes": len(commands),
            "removedCommandNodes": len(removed_rows),
        }
        if counts != expected_counts or counts["rawCommandNodes"] != (
            counts["executableCommandNodes"] + counts["removedCommandNodes"]
        ):
            raise SemanticCoverageError(f"raw/executable command counts drifted: {path}")

        source_indices: list[int] = []
        for index, command in enumerate(commands):
            if not isinstance(command, dict):
                raise SemanticCoverageError(f"invalid executable command: {path}#{index}")
            executable_index = command.get("executableCommandIndex")
            source_index = command.get("sourceCommandIndex")
            if executable_index != index or not isinstance(source_index, int) \
                    or not 0 <= source_index < len(raw_commands):
                raise SemanticCoverageError(f"executable command index drifted: {path}#{index}")
            source = raw_commands[source_index]
            for lowered_field, raw_field in (
                ("sourceOpcode", "opcode"), ("arguments", "arguments"),
                ("sourceNode", "node"), ("loop", "loop"),
            ):
                if command.get(lowered_field) != source.get(raw_field):
                    raise SemanticCoverageError(f"raw/executable command drifted: {path}#{source_index}")
            if command.get("sourceOpcode") == "PLAY_CHARACTER_SOUND":
                _validate_lowered_sound(
                    command, f"{path}#{source_index}", sound_index,
                )
            elif command.get("sourceOpcode") == "PLAY_MULLEBARNSOUND":
                _validate_lowered_barn(
                    command, f"{path}#{source_index}", barn_index,
                )
            else:
                native_opcode = opcode_index.get(command.get("sourceOpcode"))
                if native_opcode is None or native_opcode[1] != "CONSTRUCT_NODE" \
                        or command.get("nativeOpcode") != native_opcode[0]:
                    raise SemanticCoverageError(
                        f"native opcode lowering drifted: {path}#{source_index}"
                    )
            source_indices.append(source_index)

        removed_indices: list[int] = []
        for row in removed_rows:
            source_index = row.get("sourceCommandIndex")
            if not isinstance(source_index, int) or not 0 <= source_index < len(raw_commands):
                raise SemanticCoverageError(f"removed command index drifted: {path}")
            source = raw_commands[source_index]
            if any(row.get(field) != source.get(source_field) for field, source_field in (
                ("sourceOpcode", "opcode"), ("arguments", "arguments"),
                ("sourceNode", "node"), ("loop", "loop"),
            )):
                raise SemanticCoverageError(f"removed command source drifted: {path}#{source_index}")
            if row.get("reason") != "ABSENT_NO_COMMAND_NODE" \
                    or row.get("sourceOpcode") != "PLAY_CHARACTER_SOUND":
                raise SemanticCoverageError(f"removed command lowering drifted: {path}#{source_index}")
            media_key = _sound_media_key(row.get("arguments"), f"{path}#{source_index}")
            if media_key not in sound_index or sound_index[media_key]:
                raise SemanticCoverageError(f"removed sound take lowering drifted: {path}#{source_index}")
            removed_indices.append(source_index)
        if sorted(source_indices + removed_indices) != list(range(len(raw_commands))) \
                or len(source_indices) != len(set(source_indices)) \
                or len(removed_indices) != len(set(removed_indices)):
            raise SemanticCoverageError(f"raw/executable source-index partition drifted: {path}")
        source_to_executable = {source_index: None for source_index in removed_indices}
        source_to_executable.update({
            command["sourceCommandIndex"]: command["executableCommandIndex"]
            for command in commands
        })
        expected_structure = _lower_expected_structure(
            raw.get("structure"), source_to_executable, path=path,
        )
        if structure != expected_structure:
            raise SemanticCoverageError(f"raw/executable structure lowering drifted: {path}")

        total_raw += len(raw_commands)
        total_executable += len(commands)
        total_removed += len(removed_rows)
        key = f"{script['type']}:{script['domainId']}/{script['dispatchId']}"
        if key in result:
            raise SemanticCoverageError(f"duplicate executable script artifact: {key}")
        result[key] = script

    if seen_paths != set(raw_by_path):
        raise SemanticCoverageError("all-script raw/executable lowering totals drifted")
    all_raw_commands = [
        command for script in raw_by_path.values() for command in script.get("commands", [])
    ]
    all_executable_commands = [
        command for script in lowered for command in script.get("commands", [])
    ]
    native_counts = Counter(command.get("nativeOpcode") for command in all_executable_commands)
    removal_reasons = Counter(row.get("reason") for row in removed)
    observed_counts = {
        "scripts": len(lowered),
        "rawCommandNodes": total_raw,
        "executableCommandNodes": total_executable,
        "removedCommandNodes": total_removed,
        "sourceCharacterSounds": sum(
            command.get("opcode") == "PLAY_CHARACTER_SOUND" for command in all_raw_commands
        ),
        "removedZeroTakeCharacterSounds": removal_reasons["ABSENT_NO_COMMAND_NODE"],
        "removedDirectParserDiscards": removal_reasons["DISCARD_DIRECT_OPCODE_NATIVE_PARSER"],
        "oneTakeCharacterSounds": native_counts[5],
        "multipleTakeCharacterSounds": native_counts[6],
        "nativeOpcode5Nodes": native_counts[5],
        "nativeOpcode6Nodes": native_counts[6],
    }
    if total_raw != total_executable + total_removed or declared_counts != observed_counts:
        raise SemanticCoverageError("executable UDSP aggregate lowering counts drifted")
    if len(result) != len(raw_by_path):
        raise SemanticCoverageError("executable script artifact count drifted")
    return result, removed_by_path


def _body_records(scripts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for key, script in sorted(scripts.items()):
        counts = script.get("counts")
        commands = script.get("commands")
        structure = script.get("structure")
        if not isinstance(counts, dict) or not isinstance(commands, list) or not isinstance(structure, dict):
            raise SemanticCoverageError(f"UDSP script lacks exact structure: {key}")
        if counts.get("commands") != len(commands):
            raise SemanticCoverageError(f"UDSP command count drifted: {key}")
        records.append(_record("UDSP_SCRIPT_BODY", f"UDSP_SCRIPT_BODY:{key}", {
            "artifactKey": key,
            "scriptType": script.get("type"),
            "path": script.get("path"),
            "domainId": script.get("domain_id"),
            "dispatchId": script.get("dispatch_id"),
            "scriptSha256": script.get("sha256"),
            "counts": copy.deepcopy(counts),
            "commandsSha256": _canonical_sha(commands),
            "structureSha256": _canonical_sha(structure),
        }))
    return records


def _executable_body_records(
    scripts: dict[str, dict[str, Any]],
    removed_by_path: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    records = []
    for key, script in sorted(scripts.items()):
        commands = script["commands"]
        structure = script["structure"]
        removed = removed_by_path.get(script["path"], [])
        records.append(_record(
            "UDSP_EXECUTABLE_BODY", f"UDSP_EXECUTABLE_BODY:{key}", {
                "artifactKey": key,
                "scriptType": script["type"],
                "path": script["path"],
                "domainId": script["domainId"],
                "dispatchId": script["dispatchId"],
                "sourceScriptSha256": script["sourceSha256"],
                "executableScriptSha256": _canonical_sha(script),
                "counts": copy.deepcopy(script["counts"]),
                "commandSha256": [_canonical_sha(command) for command in commands],
                "commandsSha256": _canonical_sha(commands),
                "structureSha256": _canonical_sha(structure),
                "removedSourceCommandIndices": [
                    row["sourceCommandIndex"] for row in removed
                ],
                "removedCommandsSha256": _canonical_sha(removed),
            },
        ))
    return records


def _dispatch_records(
    dispatch: dict[str, Any], scripts: dict[str, dict[str, Any]],
    executable_scripts: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    actions = dispatch.get("missionActions")
    if not isinstance(actions, list):
        raise SemanticCoverageError("scene dispatch contract has no mission actions")
    records = []
    seen: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            raise SemanticCoverageError("invalid mission dispatch row")
        required = {
            "missionKey", "missionId", "missionPhase", "nativeActionOrdinal",
            "opcode", "route", "domainId", "scriptId", "artifactKey",
        }
        if set(action) != required:
            raise SemanticCoverageError("mission dispatch identity shape drifted")
        expected_route = {
            "PLAY_SCRIPT": "GROUND",
            "PLAY_BARNSCRIPT": "BARN",
            "PLAY_SCRIPTMODEFLY": "FLIGHT",
            "PLAY_OUTRO": "LOCATION_POLICY",
        }.get(action["opcode"])
        if action["route"] != expected_route:
            raise SemanticCoverageError("mission dispatch opcode/route drifted")
        artifact_key = action["artifactKey"]
        if artifact_key not in scripts:
            raise SemanticCoverageError(f"mission dispatch targets unknown artifact: {artifact_key}")
        if artifact_key not in executable_scripts:
            raise SemanticCoverageError(
                f"mission dispatch targets missing executable artifact: {artifact_key}"
            )
        claim_id = (
            f"MISSION_DISPATCH:{action['missionKey']}#{action['missionPhase']}:"
            f"{action['nativeActionOrdinal']}:{action['opcode']}"
        )
        if claim_id in seen:
            raise SemanticCoverageError(f"duplicate mission dispatch identity: {claim_id}")
        seen.add(claim_id)
        expectation = copy.deepcopy(action)
        expectation["scriptSha256"] = scripts[artifact_key]["sha256"]
        records.append(_record("MISSION_DISPATCH", claim_id, expectation))
    return sorted(records, key=lambda row: row["id"])


def _root_outcomes(location: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any] | None]]:
    policy = location.get("policy")
    if policy == "BESPOKE_NO_UDSP":
        outcome = "bespoke_native_state_machine"
        yield outcome, POLICY_SELECTORS[policy][outcome], None
        return
    selectors = POLICY_SELECTORS.get(policy)
    if selectors is None:
        raise SemanticCoverageError(f"unknown location policy: {policy}")
    for field in ("defaultRoot", "finalRoot"):
        root = location.get(field)
        if root is not None:
            outcome = root["dispatchId"]
            yield outcome, selectors[outcome], root
    special = location.get("specialRoots")
    if not isinstance(special, list):
        raise SemanticCoverageError("location policy has no special-roots list")
    for root in special:
        outcome = root["dispatchId"]
        yield outcome, selectors[outcome], root


def _root_ids(location: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    primary = tuple(
        root["dispatchId"]
        for root in (location.get("defaultRoot"), location.get("finalRoot"))
        if isinstance(root, dict)
    )
    special = location.get("specialRoots")
    if not isinstance(special, list) or not all(isinstance(root, dict) for root in special):
        raise SemanticCoverageError("location policy has an invalid special-roots list")
    return primary, tuple(root.get("dispatchId") for root in special)


def _validate_location_policy_shape(location: dict[str, Any]) -> None:
    domain = location.get("domainId")
    policy = location.get("policy")
    primary, special = _root_ids(location)
    expected = SPECIAL_POLICIES.get(domain)
    if expected is None:
        expected = ("GENERIC", ("nooneathome", "allfinished"), ())
    if (policy, primary, special) != expected:
        raise SemanticCoverageError(f"location policy/root inventory drifted: {domain}")


def _policy_records(
    dispatch: dict[str, Any], scripts: dict[str, dict[str, Any]],
    executable_scripts: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    locations = dispatch.get("locations")
    if not isinstance(locations, list) or len(locations) != 18:
        raise SemanticCoverageError("scene dispatch contract must have 18 locations")
    records = []
    claim_ids: set[str] = set()
    locations_seen: set[int] = set()
    domains_seen: set[str] = set()
    for location in locations:
        location_id = location.get("locationId")
        domain = location.get("domainId")
        if location_id in locations_seen or domain in domains_seen:
            raise SemanticCoverageError("duplicate location policy identity")
        locations_seen.add(location_id)
        domains_seen.add(domain)
        _validate_location_policy_shape(location)
        outcomes = list(_root_outcomes(location))
        if not outcomes:
            raise SemanticCoverageError(f"location policy has no outcomes: {domain}")
        for outcome, selector, root in outcomes:
            artifact_key = None if root is None else root.get("artifactKey")
            script_sha = None if root is None else root.get("sha256")
            if root is not None:
                if artifact_key not in scripts:
                    raise SemanticCoverageError(f"location policy targets unknown artifact: {artifact_key}")
                if artifact_key not in executable_scripts:
                    raise SemanticCoverageError(
                        f"location policy targets missing executable artifact: {artifact_key}"
                    )
                if script_sha != scripts[artifact_key]["sha256"]:
                    raise SemanticCoverageError(f"location policy artifact hash drifted: {artifact_key}")
            claim_id = f"LOCATION_POLICY:{domain}:{outcome}"
            if claim_id in claim_ids:
                raise SemanticCoverageError(f"duplicate location policy outcome: {claim_id}")
            claim_ids.add(claim_id)
            records.append(_record("LOCATION_POLICY", claim_id, {
                "locationId": location_id,
                "domainId": domain,
                "mode": location.get("mode"),
                "policy": location.get("policy"),
                "outcome": outcome,
                "selector": selector,
                "artifactKey": artifact_key,
                "scriptSha256": script_sha,
            }))
    return sorted(records, key=lambda row: row["id"])


def build_ledger(
    dispatch: dict[str, Any], udsp: dict[str, Any], executable: dict[str, Any], *,
    dispatch_source: dict[str, Any], udsp_source: dict[str, Any],
    executable_source: dict[str, Any],
) -> dict[str, Any]:
    if dispatch.get("contract") != "miel-vliegt-scene-dispatch":
        raise SemanticCoverageError("unexpected scene dispatch contract")
    if dispatch.get("claim") != "STATIC_DISPATCH_POLICY_RUNTIME_PARITY_UNPROVEN":
        raise SemanticCoverageError("scene dispatch contract escaped fail-closed status")
    if dispatch.get("routes") != EXPECTED_ROUTES:
        raise SemanticCoverageError("scene dispatch routes drifted")
    if dispatch.get("expectedAbsences") != EXPECTED_ABSENCES:
        raise SemanticCoverageError("scene dispatch expected absences drifted")
    edition = dispatch.get("edition")
    if not isinstance(edition, str) or not edition:
        raise SemanticCoverageError("scene dispatch contract has no edition")
    if udsp.get("claim") != "SOURCE_STRUCTURE_EXACT":
        raise SemanticCoverageError("UDSP source is not structurally exact")
    if dispatch.get("sources", {}).get("udsp", {}).get("sha256") != udsp_source["sha256"]:
        raise SemanticCoverageError("dispatch and UDSP source hashes differ")

    all_scripts = _script_artifacts(udsp)
    scripts = {
        key: script for key, script in all_scripts.items()
        if script["type"] == "LOCATION_SCRIPT"
    }
    all_executable_scripts, removed_by_path = _executable_scripts(
        executable, udsp, udsp_source=udsp_source, edition=edition,
    )
    executable_scripts = {
        key: script for key, script in all_executable_scripts.items()
        if script["type"] == "LOCATION_SCRIPT"
    }
    dispatch_artifacts = dispatch.get("artifacts")
    if not isinstance(dispatch_artifacts, list):
        raise SemanticCoverageError("scene dispatch contract has no artifact inventory")
    artifact_map: dict[str, str] = {}
    for artifact in dispatch_artifacts:
        key = artifact.get("artifactKey") if isinstance(artifact, dict) else None
        digest = artifact.get("sha256") if isinstance(artifact, dict) else None
        if key in artifact_map:
            raise SemanticCoverageError(f"duplicate dispatch artifact: {key}")
        artifact_map[key] = digest
    if artifact_map != {key: row["sha256"] for key, row in scripts.items()}:
        raise SemanticCoverageError("dispatch and UDSP artifact inventories differ")
    missing_executable = set(scripts) - set(executable_scripts)
    unknown_executable = set(executable_scripts) - set(scripts)
    if missing_executable or unknown_executable:
        detail = min(missing_executable or unknown_executable)
        raise SemanticCoverageError(f"raw/executable location inventory differs: {detail}")
    for key, script in scripts.items():
        if executable_scripts[key]["sourceSha256"] != script["sha256"]:
            raise SemanticCoverageError(f"raw/executable location hash differs: {key}")
    if set(all_scripts) != set(all_executable_scripts):
        detail = min(set(all_scripts) ^ set(all_executable_scripts))
        raise SemanticCoverageError(f"raw/executable all-script inventory differs: {detail}")
    for key, script in all_scripts.items():
        if all_executable_scripts[key]["sourceSha256"] != script["sha256"]:
            raise SemanticCoverageError(f"raw/executable script hash differs: {key}")

    records = {
        "UDSP_SCRIPT_BODY": _body_records(all_scripts),
        "UDSP_EXECUTABLE_BODY": _executable_body_records(
            all_executable_scripts, removed_by_path,
        ),
        "MISSION_DISPATCH": _dispatch_records(dispatch, scripts, executable_scripts),
        "LOCATION_POLICY": _policy_records(dispatch, scripts, executable_scripts),
    }
    return {
        "schema": SCHEMA,
        "contract": CONTRACT,
        "edition": edition,
        "claim": "RUNTIME_SEMANTIC_PARITY_UNPROVEN",
        "policy": {
            "evidenceClasses": list(CLASSES),
            "initialStatus": "UNPROVEN",
            "crossClaimEvidenceReuse": "FORBIDDEN",
            "promotionRequires": "CLAIM_BOUND_EDITION_AND_SOURCE_HASHED_EVIDENCE",
            "executableLowering": {
                "scope": "ALL_238_UDSP_SCRIPTS_WITH_INDEPENDENT_BODY_CLAIMS",
                "artifactSha256": executable_source["sha256"],
                "counts": copy.deepcopy(executable["counts"]),
                "sources": copy.deepcopy(executable["sources"]),
                "sourceIdentities": copy.deepcopy(executable["sourceIdentities"]),
                "loweringSha256": _canonical_sha(executable.get("lowering")),
                "removedCommandsSha256": _canonical_sha(executable.get("removedCommands")),
            },
        },
        "sources": {
            "sceneDispatchContract": dispatch_source,
            "udsSceneScripts": udsp_source,
            "executableUdspSceneScripts": executable_source,
        },
        "counts": {name: len(records[name]) for name in CLASSES},
        "records": [row for name in CLASSES for row in records[name]],
    }


#: Deterministic-build cache for :func:`generate`.  The ledger is a pure
#: function of the three input files, and ``validate_ledger`` rebuilds it on
#: every call (hundreds of times per manifest test run over identical inputs).
#: Keying on each path's (mtime, size) makes repeat builds of unchanged inputs
#: reuse the cached build; any edit to an input busts its key.  Callers may
#: mutate the ledger in place (promotion marks records), so every call returns
#: an independent deep copy -- still far cheaper than re-parsing three multi-MB
#: JSON inputs and recomputing the full canonical-hash tree each time.
_GENERATE_CACHE: dict[tuple[Any, ...], dict[str, Any]] = {}
_GENERATE_CACHE_LIMIT = 8


def _generate_cache_key(*paths: Path) -> tuple[Any, ...] | None:
    key: list[Any] = []
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            return None
        key.append((str(path), stat.st_mtime_ns, stat.st_size))
    return tuple(key)


def generate(
    dispatch_path: Path = DEFAULT_DISPATCH, udsp_path: Path = DEFAULT_UDSP,
    executable_path: Path = DEFAULT_EXECUTABLE,
) -> dict[str, Any]:
    cache_key = _generate_cache_key(dispatch_path, udsp_path, executable_path)
    if cache_key is not None and cache_key in _GENERATE_CACHE:
        return copy.deepcopy(_GENERATE_CACHE[cache_key])
    dispatch = _load(dispatch_path, 1, "scene dispatch contract")
    udsp = _load(udsp_path, 2, "UDSP scene scripts")
    executable = _load(executable_path, 1, "executable UDSP scene scripts")
    ledger = build_ledger(
        dispatch, udsp, executable,
        dispatch_source=_source(dispatch_path, 1),
        udsp_source=_source(udsp_path, 2),
        executable_source=_source(executable_path, 1),
    )
    if cache_key is not None:
        if len(_GENERATE_CACHE) >= _GENERATE_CACHE_LIMIT:
            _GENERATE_CACHE.clear()
        _GENERATE_CACHE[cache_key] = copy.deepcopy(ledger)
    return ledger


def _evidence_path(relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise SemanticCoverageError(f"invalid {label} path")
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as error:
        raise SemanticCoverageError(f"{label} escapes repository") from error
    return path


def _load_hashed_artifact(relative: Any, digest: Any, label: str) -> dict[str, Any]:
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise SemanticCoverageError(f"invalid {label} hash")
    path = _evidence_path(relative, label)
    if not path.is_file() or sha256_file(path) != digest:
        raise SemanticCoverageError(f"{label} artifact hash mismatch")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SemanticCoverageError(f"cannot read {label}: {relative}") from error
    if not isinstance(value, dict):
        raise SemanticCoverageError(f"{label} is not an object")
    return value


def _reject_raw_pointers(value: Any, path: str = "state", field: str | None = None) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SemanticCoverageError(f"semantic observation has a non-string key: {path}")
            normalized = key.lower()
            if normalized in RAW_POINTER_FIELDS or normalized.endswith(("_address", "_pointer")):
                raise SemanticCoverageError(f"semantic observation contains raw pointer field: {path}.{key}")
            _reject_raw_pointers(item, f"{path}.{key}", normalized)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_raw_pointers(item, f"{path}[{index}]", field)
        return
    if isinstance(value, str) and HEX_POINTER.fullmatch(value) \
            and not (field or "").endswith(("_bits", "bits")):
        raise SemanticCoverageError(f"semantic observation contains raw pointer value: {path}")
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise SemanticCoverageError(f"semantic observation has a non-JSON value: {path}")


def _validate_observations(
    observations: Any, *, record: dict[str, Any], subject_sha256: str,
    expectation_sha256: str, label: str,
) -> list[dict[str, Any]]:
    if not isinstance(observations, list) or not observations:
        raise SemanticCoverageError(f"{label} semantic observations are empty")
    for sequence, observation in enumerate(observations):
        if not isinstance(observation, dict) or set(observation) != SEMANTIC_OBSERVATION_FIELDS:
            raise SemanticCoverageError(f"{label} semantic observation has an invalid shape")
        if observation.get("schema") != 1 \
                or observation.get("record") != "semantic_observation" \
                or observation.get("sequence") != sequence:
            raise SemanticCoverageError(f"{label} semantic observation sequence is invalid")
        if observation.get("claimId") != record["id"] \
                or observation.get("evidenceClass") != record["evidenceClass"] \
                or observation.get("subjectSha256") != subject_sha256 \
                or observation.get("expectationSha256") != expectation_sha256:
            raise SemanticCoverageError(f"{label} semantic observation identity mismatch")
        state = observation.get("state")
        if not isinstance(state, dict) or not state:
            raise SemanticCoverageError(f"{label} semantic observation state is empty")
        _reject_raw_pointers(state)
    return observations


def _validate_semantic_trace(
    trace: dict[str, Any], *, producer: str, record: dict[str, Any],
    edition: str, source_hashes: dict[str, str], subject_sha256: str,
    expectation_sha256: str, allow_test_provenance: bool,
    provenance_paths: set[Path], provenance_hashes: set[str],
    capture_paths: set[Path], capture_hashes: set[str],
    native_command_contract: dict[str, str], native_executable_sha256: str,
    executable_artifact: dict[str, Any], executable_source_bytes: bytes,
    session_occurrences: set[tuple[str, Path, str, int, str]],
) -> tuple[list[dict[str, Any]], tuple[Path, str] | None]:
    if isinstance(trace, dict) and "producerProvenance" not in trace:
        raise SemanticCoverageError(
            f"{producer.lower()} semantic trace has no producer provenance"
        )
    if frozenset(trace) not in {frozenset(SEMANTIC_TRACE_FIELDS), frozenset(SEMANTIC_SLICED_TRACE_FIELDS)} \
            or trace.get("schema") != 1 \
            or trace.get("protocol") != SEMANTIC_TRACE_PROTOCOL:
        raise SemanticCoverageError(f"{producer.lower()} semantic trace has an invalid schema")
    expected = {
        "producer": producer,
        "claimId": record["id"],
        "evidenceClass": record["evidenceClass"],
        "edition": edition,
        "sourceHashes": source_hashes,
        "subjectSha256": subject_sha256,
        "expectationSha256": expectation_sha256,
    }
    if any(trace.get(field) != value for field, value in expected.items()):
        raise SemanticCoverageError(f"{producer.lower()} semantic trace metadata mismatch")
    session_identity = None
    if "sessionSlice" in trace:
        observations, session_identity = _validate_session_slice(
            trace["sessionSlice"], producer=producer, record=record,
            edition=edition, source_hashes=source_hashes,
            subject_sha256=subject_sha256,
            expectation_sha256=expectation_sha256,
            session_occurrences=session_occurrences,
        )
    else:
        observations = _validate_observations(
            trace.get("observations"), record=record,
            subject_sha256=subject_sha256,
            expectation_sha256=expectation_sha256,
            label=producer.lower(),
        )
    _validate_producer_provenance(
        trace.get("producerProvenance"), producer=producer, record=record,
        edition=edition, source_hashes=source_hashes,
        subject_sha256=subject_sha256, expectation_sha256=expectation_sha256,
        observations=observations, allow_test_provenance=allow_test_provenance,
        provenance_paths=provenance_paths, provenance_hashes=provenance_hashes,
        capture_paths=capture_paths, capture_hashes=capture_hashes,
        native_command_contract=native_command_contract,
        native_executable_sha256=native_executable_sha256,
        executable_artifact=executable_artifact,
        executable_source_bytes=executable_source_bytes,
    )
    return observations, session_identity


def _validate_session_slice(
    session_slice: Any, *, producer: str, record: dict[str, Any], edition: str,
    source_hashes: dict[str, str], subject_sha256: str,
    expectation_sha256: str,
    session_occurrences: set[tuple[str, Path, str, int, str]],
) -> tuple[list[dict[str, Any]], tuple[Path, str]]:
    if not isinstance(session_slice, dict) \
            or set(session_slice) != SEMANTIC_SESSION_SLICE_FIELDS:
        raise SemanticCoverageError(f"{producer.lower()} semantic session slice has an invalid schema")
    identity = {
        "claimId": record["id"],
        "subjectSha256": subject_sha256,
        "expectationSha256": expectation_sha256,
        "eventIndices": session_slice.get("eventIndices"),
        "eventHashes": session_slice.get("eventHashes"),
    }
    if any(session_slice.get(field) != value for field, value in identity.items()):
        raise SemanticCoverageError(f"{producer.lower()} semantic session slice identity mismatch")
    indices = session_slice.get("eventIndices")
    hashes = session_slice.get("eventHashes")
    if not isinstance(indices, list) or not indices \
            or any(type(index) is not int or index < 0 for index in indices) \
            or indices != sorted(set(indices)) \
            or not isinstance(hashes, list) or len(hashes) != len(indices) \
            or any(not isinstance(digest, str) or not SHA256.fullmatch(digest) for digest in hashes):
        raise SemanticCoverageError(f"{producer.lower()} semantic session slice events are invalid")
    if session_slice.get("sliceSha256") != _canonical_sha(identity):
        raise SemanticCoverageError(f"{producer.lower()} semantic session slice hash mismatch")
    session_path, session_digest = _validate_artifact_reference(
        session_slice.get("session"), f"{producer.lower()} semantic session"
    )
    session = _load_hashed_artifact(
        session_slice["session"]["path"], session_digest,
        f"{producer.lower()} semantic session",
    )
    if not isinstance(session, dict) or set(session) != SEMANTIC_SESSION_FIELDS \
            or session.get("schema") != 1 \
            or session.get("protocol") != SEMANTIC_SESSION_PROTOCOL \
            or session.get("producer") != producer \
            or session.get("edition") != edition \
            or session.get("sourceHashes") != source_hashes:
        raise SemanticCoverageError(f"{producer.lower()} semantic session metadata mismatch")
    events = session.get("events")
    if not isinstance(events, list) or not events:
        raise SemanticCoverageError(f"{producer.lower()} semantic session events are empty")
    for sequence, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != SEMANTIC_SESSION_EVENT_FIELDS \
                or event.get("schema") != 1 \
                or event.get("record") != "semantic_session_event" \
                or event.get("sequence") != sequence \
                or not isinstance(event.get("state"), dict) or not event["state"]:
            raise SemanticCoverageError(f"{producer.lower()} semantic session event is invalid")
        _reject_raw_pointers(event["state"])
    observations = []
    for sequence, (event_index, event_hash) in enumerate(zip(indices, hashes)):
        if event_index >= len(events) or _canonical_sha(events[event_index]) != event_hash:
            raise SemanticCoverageError(f"{producer.lower()} semantic session slice event hash mismatch")
        occurrence = (producer, session_path, session_digest, event_index, event_hash)
        if occurrence in session_occurrences:
            raise SemanticCoverageError(
                f"semantic session occurrence reused across claims: {record['id']}"
            )
        session_occurrences.add(occurrence)
        observations.append({
            "schema": 1,
            "record": "semantic_observation",
            "sequence": sequence,
            "claimId": record["id"],
            "evidenceClass": record["evidenceClass"],
            "subjectSha256": subject_sha256,
            "expectationSha256": expectation_sha256,
            "state": copy.deepcopy(events[event_index]["state"]),
        })
    return observations, (session_path, session_digest)


def _validate_exact_source_reference(reference: Any, expected_path: Path, label: str) -> None:
    if not isinstance(reference, dict) or set(reference) != TRACE_REFERENCE_FIELDS:
        raise SemanticCoverageError(f"invalid {label} provenance reference")
    expected_relative = _repo_path(expected_path)
    if reference.get("path") != expected_relative:
        raise SemanticCoverageError(f"{label} provenance path mismatch")
    if not expected_path.is_file() or reference.get("sha256") != sha256_file(expected_path):
        raise SemanticCoverageError(f"{label} provenance hash mismatch")


def _validate_artifact_reference(
    reference: Any, label: str, *, require_pe: bool = False,
) -> tuple[Path, str]:
    if not isinstance(reference, dict) or set(reference) != TRACE_REFERENCE_FIELDS:
        raise SemanticCoverageError(f"invalid {label} reference")
    path = _evidence_path(reference.get("path"), label)
    digest = reference.get("sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest) \
            or not path.is_file() or sha256_file(path) != digest:
        raise SemanticCoverageError(f"{label} artifact hash mismatch")
    if require_pe and not path.read_bytes().startswith(b"MZ"):
        raise SemanticCoverageError(f"{label} is not a PE artifact")
    return path, digest


def _validate_candidate_build_child(
    reference: Any, *, build_path: Path, label: str,
) -> tuple[Path, str]:
    if not isinstance(reference, dict) or set(reference) != TRACE_REFERENCE_FIELDS:
        raise SemanticCoverageError(f"invalid {label} reference")
    relative = reference.get("path")
    if not isinstance(relative, str) or not relative or "\\" in relative \
            or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise SemanticCoverageError(f"invalid {label} path")
    candidates = [ROOT / relative, build_path.parent / relative]
    matches = [
        path.resolve() for path in candidates
        if path.is_file() and sha256_file(path) == reference.get("sha256")
    ]
    if len(set(matches)) != 1 or not SHA256.fullmatch(reference.get("sha256", "")):
        raise SemanticCoverageError(f"{label} artifact hash mismatch")
    return matches[0], reference["sha256"]


def _validate_web_dispatch_candidate_build(
    reference: Any,
) -> tuple[dict[str, str], dict[str, Any]]:
    build_path, digest = _validate_artifact_reference(
        reference, "web dispatch candidate build"
    )
    build = _load_hashed_artifact(
        reference["path"], digest, "web dispatch candidate build"
    )
    if not isinstance(build, dict) or set(build) != WEB_DISPATCH_CANDIDATE_BUILD_FIELDS \
            or build.get("schema") != 1 \
            or build.get("protocol") != WEB_DISPATCH_CANDIDATE_BUILD_PROTOCOL \
            or build.get("semanticStatus") != "UNPROVEN" \
            or build.get("parityEligible") is not False \
            or build.get("productionProvenance") \
            != "CANDIDATE_ONLY_NO_SOURCE_TO_BUNDLE_ATTESTATION":
        raise SemanticCoverageError("web dispatch candidate build schema differs")
    bundle_path, bundle_sha = _validate_candidate_build_child(
        build.get("captureBundle"), build_path=build_path,
        label="web dispatch candidate bundle",
    )
    version_path, version_sha = _validate_candidate_build_child(
        build.get("versionText"), build_path=build_path,
        label="web dispatch candidate version",
    )
    _web_build_path, web_build_sha = _validate_candidate_build_child(
        build.get("webTransitionBuild"), build_path=build_path,
        label="web dispatch candidate source build",
    )
    ledger_path, ledger_sha = _validate_candidate_build_child(
        build.get("semanticLedger"), build_path=build_path,
        label="web dispatch semantic ledger",
    )
    plan_path, plan_sha = _validate_candidate_build_child(
        build.get("semanticPlan"), build_path=build_path,
        label="web dispatch semantic plan",
    )
    if bundle_sha != build.get("captureBundleSha256") \
            or version_sha != build.get("versionTextSha256") \
            or web_build_sha != build.get("webTransitionBuildSha256") \
            or ledger_sha != build.get("semanticLedgerSha256") \
            or plan_sha != build.get("semanticPlanSha256"):
        raise SemanticCoverageError("web dispatch candidate build hash differs")
    try:
        version_text = version_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise SemanticCoverageError("web dispatch candidate version is invalid") from error
    candidate_version = build.get("candidateVersion")
    try:
        parsed_version = parse_web_candidate_version_text(version_text)
    except SemanticCoverageError as error:
        raise SemanticCoverageError("web dispatch candidate version differs") from error
    if parsed_version != candidate_version \
            or not isinstance(candidate_version, str) or not candidate_version:
        raise SemanticCoverageError("web dispatch candidate version differs")
    if not bundle_path.is_file():  # Covered by the hash check; documents intent.
        raise SemanticCoverageError("web dispatch candidate bundle is unavailable")
    try:
        captured_ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        captured_plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SemanticCoverageError("web dispatch candidate plan is invalid") from error
    if not isinstance(captured_ledger, dict) or not isinstance(captured_plan, dict) \
            or captured_plan.get("sources", {}).get("semanticCoverage", {}).get("sha256") \
            != ledger_sha:
        raise SemanticCoverageError("web dispatch candidate plan/ledger binding differs")
    return {
        "candidateVersion": candidate_version,
        "captureBundleSha256": bundle_sha,
    }, captured_plan


def _validate_capture_receipt(
    reference: Any, *, producer: str, record: dict[str, Any], edition: str,
    source_hashes: dict[str, str], subject_sha256: str,
    expectation_sha256: str, observations: list[dict[str, Any]],
    provenance: dict[str, Any], capture_paths: set[Path],
    capture_hashes: set[str], native_command_contract: dict[str, str],
    native_executable_sha256: str, executable_artifact: dict[str, Any],
    executable_source_bytes: bytes,
) -> list[dict[str, Any]]:
    path, digest = _validate_artifact_reference(
        reference, f"{producer.lower()} capture receipt"
    )
    if path in capture_paths or digest in capture_hashes:
        raise SemanticCoverageError(f"capture receipt reused across claims: {record['id']}")
    capture_paths.add(path)
    capture_hashes.add(digest)
    receipt = _load_hashed_artifact(
        reference["path"], digest, f"{producer.lower()} capture receipt"
    )
    protocol = NATIVE_CAPTURE_PROTOCOL if producer == "NATIVE" else WEB_CAPTURE_PROTOCOL
    expected = {
        "schema": 1,
        "protocol": protocol,
        "result": "PASS",
        "captureStatus": "PRODUCTION_COMPLETE",
        "producer": producer,
        "edition": edition,
        "claimId": record["id"],
        "evidenceClass": record["evidenceClass"],
        "sourceHashes": source_hashes,
        "subjectSha256": subject_sha256,
        "expectationSha256": expectation_sha256,
        "observationsSha256": semantic_observations_sha256(observations),
    }
    if any(receipt.get(field) != value for field, value in expected.items()):
        raise SemanticCoverageError(f"{producer.lower()} capture receipt metadata mismatch")
    dispatch_web = producer == "WEB" and record["evidenceClass"] in {
        "MISSION_DISPATCH", "LOCATION_POLICY",
    }
    expected_fields = NATIVE_CAPTURE_FIELDS if producer == "NATIVE" else (
        WEB_DISPATCH_CAPTURE_FIELDS if dispatch_web else WEB_CAPTURE_FIELDS
    )
    raw_protocol = f"miel-vliegt-{producer.lower()}-scene-semantic-raw"
    if set(receipt) != expected_fields or receipt.get("rawTraceProtocol") != raw_protocol:
        raise SemanticCoverageError(f"{producer.lower()} capture receipt has an invalid schema")
    raw_path, raw_digest = _validate_artifact_reference(
        receipt.get("rawTrace"), f"{producer.lower()} raw semantic trace"
    )
    if raw_path in capture_paths or raw_digest in capture_hashes:
        raise SemanticCoverageError(f"raw capture reused across claims: {record['id']}")
    capture_paths.add(raw_path)
    capture_hashes.add(raw_digest)
    raw = _load_hashed_artifact(
        receipt["rawTrace"]["path"], raw_digest,
        f"{producer.lower()} raw semantic trace",
    )
    expected_raw_identity = {
        "edition": edition,
        "claimId": record["id"],
        "evidenceClass": record["evidenceClass"],
        "sourceHashes": source_hashes,
        "subjectSha256": subject_sha256,
        "expectationSha256": expectation_sha256,
    }
    if producer == "WEB":
        candidate_build = (
            _validate_web_dispatch_candidate_build(receipt.get("candidateBuild"))
            if dispatch_web else (None, None)
        )
        candidate_identity, captured_plan = candidate_build
        if dispatch_web:
            # The candidate stores both hashes, but an unsigned manifest does
            # not prove that webpack produced this exact bundle from those
            # sources.  Keep normalization useful while promotion stays shut.
            raise SemanticCoverageError(
                "web dispatch candidate-only capture cannot promote without "
                "source-to-bundle attestation"
            )
        try:
            normalized = udsp_semantic_oracle.normalize_web_trace(
                raw, executable_artifact, expected_raw_identity,
                executable_source_bytes=executable_source_bytes,
                expected_expectation=record["expectation"],
                expected_capture_provenance=(
                    expected_web_dispatch_capture_provenance(
                        record, edition=edition,
                        candidate_identity=candidate_identity,
                        plan_document=captured_plan,
                    )
                ),
            )
        except udsp_semantic_oracle.SemanticOracleError as error:
            raise SemanticCoverageError(
                f"web raw-to-normalized semantic verification failed: {error}"
            ) from error
        if normalized["observations"] != observations:
            raise SemanticCoverageError("web raw-to-normalized observations differ")
    else:
        try:
            normalized = udsp_semantic_oracle.normalize_native_trace(
                raw, executable_artifact, expected_raw_identity,
                executable_source_bytes=executable_source_bytes,
                expected_expectation=record["expectation"],
            )
        except udsp_semantic_oracle.SemanticOracleUnsupported as error:
            raise SemanticCoverageError(
                f"native raw-to-normalized semantic unsupported: {error}"
            ) from error
        except udsp_semantic_oracle.SemanticOracleError as error:
            raise SemanticCoverageError(
                f"native raw-to-normalized semantic verification failed: {error}"
            ) from error
        if normalized["observations"] != observations:
            raise SemanticCoverageError("native raw-to-normalized observations differ")
    if producer == "NATIVE":
        if receipt.get("executableSha256") != native_executable_sha256:
            raise SemanticCoverageError("native capture executable hash mismatch")
        _validate_native_command_contract(
            receipt.get("nativeCommandContract"), native_command_contract,
            native_executable_sha256,
        )
        if receipt.get("observerHook") != provenance.get("observerHook") \
                or receipt.get("observerLauncherSource") != provenance.get("observerLauncher"):
            raise SemanticCoverageError("native capture source provenance mismatch")
        _validate_exact_source_reference(
            receipt.get("observerHook"), NATIVE_OBSERVER_HOOK, "native capture observer hook"
        )
        _validate_exact_source_reference(
            receipt.get("observerLauncherSource"), NATIVE_OBSERVER_LAUNCHER,
            "native capture observer launcher source",
        )
        dll_path, dll_digest = _validate_artifact_reference(
            receipt.get("observerDll"), "native capture observer DLL", require_pe=True
        )
        launcher_path, launcher_digest = _validate_artifact_reference(
            receipt.get("launcherBinary"), "native capture launcher binary", require_pe=True
        )
        if dll_path == launcher_path or dll_digest == launcher_digest:
            raise SemanticCoverageError("native capture binaries are not independent artifacts")
        return normalized["observations"]
    if receipt.get("webBuild") != provenance.get("webBuild") \
            or receipt.get("runtimeProducer") != provenance.get("runtimeProducer"):
        raise SemanticCoverageError("web capture source provenance mismatch")
    _validate_exact_source_reference(receipt.get("webBuild"), WEB_BUILD_RECEIPT, "web capture build")
    _validate_exact_source_reference(
        receipt.get("runtimeProducer"), web_runtime_producer(record),
        "web capture runtime producer",
    )
    return normalized["observations"]


def _validate_native_command_contract(
    reference: Any, expected_reference: dict[str, str],
    native_executable_sha256: str,
) -> None:
    if reference != expected_reference:
        raise SemanticCoverageError("native producer contract reference mismatch")
    contract = _load_hashed_artifact(
        reference.get("path"), reference.get("sha256"), "native producer contract"
    )
    digest = contract.get("source", {}).get("executable_sha256")
    if contract.get("claim") != "STATIC_CONTROL_FLOW_COMPLETE_SEMANTICS_PARTIAL" \
            or digest != native_executable_sha256:
        raise SemanticCoverageError("native producer contract is not exact")


def _validate_producer_provenance(
    reference: Any, *, producer: str, record: dict[str, Any], edition: str,
    source_hashes: dict[str, str], subject_sha256: str,
    expectation_sha256: str, observations: list[dict[str, Any]],
    allow_test_provenance: bool, provenance_paths: set[Path],
    provenance_hashes: set[str],
    capture_paths: set[Path], capture_hashes: set[str],
    native_command_contract: dict[str, str], native_executable_sha256: str,
    executable_artifact: dict[str, Any], executable_source_bytes: bytes,
) -> None:
    if not isinstance(reference, dict) or set(reference) != TRACE_REFERENCE_FIELDS:
        raise SemanticCoverageError(
            f"{producer.lower()} semantic trace has no exact producer provenance"
        )
    path = _evidence_path(reference.get("path"), f"{producer.lower()} producer provenance")
    digest = reference.get("sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise SemanticCoverageError(f"invalid {producer.lower()} producer provenance hash")
    if path in provenance_paths or digest in provenance_hashes:
        raise SemanticCoverageError(f"producer provenance reused across claims: {record['id']}")
    provenance_paths.add(path)
    provenance_hashes.add(digest)
    receipt = _load_hashed_artifact(
        reference["path"], digest, f"{producer.lower()} producer provenance"
    )
    common = {
        "schema": 1,
        "protocol": PRODUCER_PROVENANCE_PROTOCOL,
        "producer": producer,
        "result": "PASS",
        "claimId": record["id"],
        "evidenceClass": record["evidenceClass"],
        "edition": edition,
        "sourceHashes": source_hashes,
        "subjectSha256": subject_sha256,
        "expectationSha256": expectation_sha256,
        "observationsSha256": semantic_observations_sha256(observations),
    }
    if any(receipt.get(field) != value for field, value in common.items()):
        raise SemanticCoverageError(f"{producer.lower()} producer provenance metadata mismatch")
    mode = receipt.get("mode")
    if mode == "TEST_FIXTURE":
        if not allow_test_provenance or set(receipt) != PRODUCER_PROVENANCE_COMMON_FIELDS \
                or receipt.get("captureProtocol") != "UNIT_TEST_ONLY":
            raise SemanticCoverageError("test-only producer provenance is not parity evidence")
        return
    if producer == "NATIVE":
        if set(receipt) != NATIVE_PROVENANCE_FIELDS or mode != "CAPTURED" \
                or receipt.get("captureProtocol") != NATIVE_CAPTURE_PROTOCOL:
            raise SemanticCoverageError("native producer provenance has an invalid schema")
        if receipt.get("executableSha256") != native_executable_sha256:
            raise SemanticCoverageError("native producer executable hash mismatch")
        _validate_native_command_contract(
            receipt.get("nativeCommandContract"), native_command_contract,
            native_executable_sha256,
        )
        _validate_exact_source_reference(
            receipt.get("observerHook"), NATIVE_OBSERVER_HOOK, "native observer hook"
        )
        _validate_exact_source_reference(
            receipt.get("observerLauncher"), NATIVE_OBSERVER_LAUNCHER,
            "native observer launcher",
        )
        recomputed = _validate_capture_receipt(
            receipt.get("captureReceipt"), producer=producer, record=record,
            edition=edition, source_hashes=source_hashes,
            subject_sha256=subject_sha256, expectation_sha256=expectation_sha256,
            observations=observations, provenance=receipt,
            capture_paths=capture_paths, capture_hashes=capture_hashes,
            native_command_contract=native_command_contract,
            native_executable_sha256=native_executable_sha256,
            executable_artifact=executable_artifact,
            executable_source_bytes=executable_source_bytes,
        )
        if recomputed != observations:
            raise SemanticCoverageError("native capture observations were not recomputed")
        return
    if producer == "WEB":
        if set(receipt) != WEB_PROVENANCE_FIELDS or mode != "CAPTURED" \
                or receipt.get("captureProtocol") != WEB_CAPTURE_PROTOCOL:
            raise SemanticCoverageError("web producer provenance has an invalid schema")
        _validate_exact_source_reference(
            receipt.get("webBuild"), WEB_BUILD_RECEIPT, "web build"
        )
        _validate_exact_source_reference(
            receipt.get("runtimeProducer"), web_runtime_producer(record),
            "web runtime producer",
        )
        recomputed = _validate_capture_receipt(
            receipt.get("captureReceipt"), producer=producer, record=record,
            edition=edition, source_hashes=source_hashes,
            subject_sha256=subject_sha256, expectation_sha256=expectation_sha256,
            observations=observations, provenance=receipt,
            capture_paths=capture_paths, capture_hashes=capture_hashes,
            native_command_contract=native_command_contract,
            native_executable_sha256=native_executable_sha256,
            executable_artifact=executable_artifact,
            executable_source_bytes=executable_source_bytes,
        )
        if recomputed != observations:
            raise SemanticCoverageError("web capture observations were not recomputed")
        return
    raise SemanticCoverageError(f"unknown semantic trace producer: {producer}")


def _validate_evidence(
    record: dict[str, Any], *, edition: str, source_hashes: dict[str, str],
    evidence_ids: set[str], evidence_hashes: set[str],
    trace_paths: set[Path], trace_hashes: set[str],
    provenance_paths: set[Path], provenance_hashes: set[str],
    capture_paths: set[Path], capture_hashes: set[str],
    native_command_contract: dict[str, str], native_executable_sha256: str,
    executable_artifact: dict[str, Any], executable_source_bytes: bytes,
    allow_test_provenance: bool,
    session_occurrences: set[tuple[str, Path, str, int, str]],
) -> None:
    evidence = record.get("evidence")
    status = record.get("status")
    if status not in STATUS or not isinstance(evidence, list):
        raise SemanticCoverageError(f"invalid claim status/evidence: {record.get('id')}")
    if status == "UNPROVEN" and evidence:
        raise SemanticCoverageError(f"unproven claim carries evidence: {record['id']}")
    if status == "PROVEN" and not evidence:
        raise SemanticCoverageError(f"proven claim has no evidence: {record['id']}")
    if status == "PROVEN" and len(evidence) != 1:
        raise SemanticCoverageError(
            f"proven claim requires one unique differential receipt: {record['id']}"
        )
    subject_sha256 = evidence_subject_sha256(record)
    expectation_sha256 = evidence_expectation_sha256(record)
    for item in evidence:
        required = {
            "evidenceId", "path", "sha256", "evidenceClass", "claimId",
            "edition", "sourceHashes", "subjectSha256", "expectationSha256",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise SemanticCoverageError(f"invalid evidence shape: {record['id']}")
        if item["evidenceClass"] != record["evidenceClass"]:
            raise SemanticCoverageError(f"evidence class mismatch: {record['id']}")
        if item["claimId"] != record["id"]:
            raise SemanticCoverageError(f"evidence claim mismatch: {record['id']}")
        if item["edition"] != edition:
            raise SemanticCoverageError(f"evidence edition mismatch: {record['id']}")
        if item["sourceHashes"] != source_hashes:
            raise SemanticCoverageError(f"evidence source hash mismatch: {record['id']}")
        if item["subjectSha256"] != subject_sha256:
            raise SemanticCoverageError(f"evidence subject hash mismatch: {record['id']}")
        if item["expectationSha256"] != expectation_sha256:
            raise SemanticCoverageError(f"evidence expectation hash mismatch: {record['id']}")
        evidence_id, digest = item["evidenceId"], item["sha256"]
        if (not isinstance(evidence_id, str) or not evidence_id or
                not isinstance(digest, str) or not SHA256.fullmatch(digest)):
            raise SemanticCoverageError(f"invalid evidence identity: {record['id']}")
        if evidence_id in evidence_ids or digest in evidence_hashes:
            raise SemanticCoverageError(f"evidence reused across claims: {evidence_id}")
        evidence_ids.add(evidence_id)
        evidence_hashes.add(digest)
        receipt = _load_hashed_artifact(
            item["path"], digest, f"evidence artifact for {record['id']}"
        )
        if set(receipt) != SEMANTIC_DIFFERENTIAL_FIELDS \
                or receipt.get("schema") != 1 \
                or receipt.get("protocol") != SEMANTIC_DIFFERENTIAL_PROTOCOL:
            raise SemanticCoverageError(
                f"semantic differential receipt has an invalid schema: {record['id']}"
            )
        for field in (
            "evidenceId", "evidenceClass", "claimId", "edition",
            "sourceHashes", "subjectSha256", "expectationSha256",
        ):
            if receipt.get(field) != item[field]:
                raise SemanticCoverageError(f"evidence artifact metadata mismatch: {record['id']}")
        if receipt.get("result") != "PASS":
            raise SemanticCoverageError(f"semantic differential is not PASS: {record['id']}")
        references = []
        for field, producer in (("nativeTrace", "NATIVE"), ("webTrace", "WEB")):
            reference = receipt.get(field)
            if not isinstance(reference, dict) or set(reference) != TRACE_REFERENCE_FIELDS:
                raise SemanticCoverageError(
                    f"semantic differential receipt has no exact {field}: {record['id']}"
                )
            path = _evidence_path(reference.get("path"), f"{producer.lower()} semantic trace")
            trace_digest = reference.get("sha256")
            if not isinstance(trace_digest, str) or not SHA256.fullmatch(trace_digest):
                raise SemanticCoverageError(f"invalid {producer.lower()} semantic trace hash")
            references.append((field, producer, reference, path, trace_digest))
        if references[0][3] == references[1][3] or references[0][4] == references[1][4]:
            raise SemanticCoverageError(
                f"native and web semantic traces are not independent: {record['id']}"
            )
        for _, _, _, path, trace_digest in references:
            if path in trace_paths or trace_digest in trace_hashes:
                raise SemanticCoverageError(
                    f"semantic trace reused across claims: {record['id']}"
                )
            trace_paths.add(path)
            trace_hashes.add(trace_digest)
        observations_by_producer = {}
        sessions_by_producer = {}
        for _, producer, reference, _, trace_digest in references:
            trace = _load_hashed_artifact(
                reference["path"], trace_digest, f"{producer.lower()} semantic trace"
            )
            observations, session_identity = _validate_semantic_trace(
                trace, producer=producer, record=record, edition=edition,
                source_hashes=source_hashes, subject_sha256=subject_sha256,
                expectation_sha256=expectation_sha256,
                allow_test_provenance=allow_test_provenance,
                provenance_paths=provenance_paths,
                provenance_hashes=provenance_hashes,
                capture_paths=capture_paths, capture_hashes=capture_hashes,
                native_command_contract=native_command_contract,
                native_executable_sha256=native_executable_sha256,
                executable_artifact=executable_artifact,
                executable_source_bytes=executable_source_bytes,
                session_occurrences=session_occurrences,
            )
            observations_by_producer[producer] = observations
            sessions_by_producer[producer] = session_identity
        native_session = sessions_by_producer["NATIVE"]
        web_session = sessions_by_producer["WEB"]
        if (native_session is None) != (web_session is None):
            raise SemanticCoverageError(
                f"native and web semantic trace envelopes differ: {record['id']}"
            )
        if native_session is not None and native_session == web_session:
            raise SemanticCoverageError(
                f"native and web semantic sessions are not independent: {record['id']}"
            )
        native_observations = observations_by_producer["NATIVE"]
        web_observations = observations_by_producer["WEB"]
        if native_observations != web_observations:
            raise SemanticCoverageError(
                f"native and web semantic observations differ: {record['id']}"
            )
        if not allow_test_provenance:
            _validate_runtime_claim_coverage(
                record, native_observations, executable_artifact,
            )
        observations_sha256 = semantic_observations_sha256(native_observations)
        if receipt.get("observationsSha256") != observations_sha256:
            raise SemanticCoverageError(
                f"semantic differential observation hash mismatch: {record['id']}"
            )


def _normalized_commands(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for observation in observations:
        state = observation.get("state") if isinstance(observation, dict) else None
        if not isinstance(state, dict):
            continue
        command = state.get("command")
        if isinstance(command, dict):
            commands.append(command)
        branches = state.get("branches")
        if isinstance(branches, list):
            commands.extend(
                branch["command"] for branch in branches
                if isinstance(branch, dict) and isinstance(branch.get("command"), dict)
            )
    return commands


def _validate_runtime_claim_coverage(
    record: dict[str, Any], observations: list[dict[str, Any]],
    executable_artifact: dict[str, Any],
) -> None:
    """Require observations to prove the claim, not merely match each other."""

    evidence_class = record.get("evidenceClass")
    if evidence_class in {"MISSION_DISPATCH", "LOCATION_POLICY"}:
        states = [
            observation.get("state") for observation in observations
            if isinstance(observation, dict)
        ]
        expectation = record.get("expectation")
        if len(states) != 1 or not isinstance(states[0], dict) \
                or not isinstance(expectation, dict) \
                or states[0].get("variant") != evidence_class:
            raise SemanticCoverageError(
                f"semantic dispatch observations do not cover the claim: {record.get('id')}"
            )
        state = states[0]
        effect = state.get("effect")
        if not isinstance(effect, dict) or effect.get("artifactKey") != expectation.get("artifactKey"):
            raise SemanticCoverageError(
                f"semantic dispatch effect differs from the claim: {record.get('id')}"
            )
        if evidence_class == "MISSION_DISPATCH":
            if state.get("trigger") != {
                key: expectation[key]
                for key in ("missionKey", "missionPhase", "nativeActionOrdinal")
            } or effect.get("route") != expectation.get("route"):
                raise SemanticCoverageError(
                    f"semantic mission dispatch identity differs: {record.get('id')}"
                )
        elif state.get("trigger") != {
            "locationId": expectation.get("locationId"),
            "selector": expectation.get("selector"),
        } or effect.get("outcome") != expectation.get("outcome"):
            raise SemanticCoverageError(
                f"semantic location policy identity differs: {record.get('id')}"
            )
        return
    if evidence_class not in {"UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY"}:
        raise SemanticCoverageError(
            f"production semantic normalizer is missing for {evidence_class}: {record.get('id')}"
        )
    expectation = record.get("expectation")
    artifact_key = expectation.get("artifactKey") if isinstance(expectation, dict) else None
    scripts = executable_artifact.get("scripts")
    matches = [
        script for script in scripts if isinstance(script, dict) and
        f"{script.get('type')}:{script.get('domainId')}/{script.get('dispatchId')}" == artifact_key
    ] if isinstance(scripts, list) else []
    if len(matches) != 1:
        raise SemanticCoverageError(f"claim executable artifact is not unique: {record.get('id')}")
    script = matches[0]
    executable_commands = script.get("commands")
    counts = script.get("counts")
    if not isinstance(executable_commands, list) or not isinstance(counts, dict):
        raise SemanticCoverageError(f"claim executable artifact is incomplete: {record.get('id')}")
    expected = {
        (
            command.get("executableCommandIndex"),
            command.get("sourceCommandIndex"),
            udsp_semantic_oracle.canonical_sha256(command),
        )
        for command in executable_commands if isinstance(command, dict)
    }
    if len(expected) != len(executable_commands):
        raise SemanticCoverageError(f"claim executable command identity is ambiguous: {record.get('id')}")
    observed = {
        (
            command.get("executableCommandIndex"),
            command.get("sourceCommandIndex"),
            command.get("commandSha256"),
        )
        for command in _normalized_commands(observations)
    }
    if not expected.issubset(observed):
        raise SemanticCoverageError(f"semantic observations do not cover the claim: {record.get('id')}")
    if evidence_class == "UDSP_SCRIPT_BODY":
        source_counts = expectation.get("counts")
        raw_count = counts.get("rawCommandNodes")
        executable_count = counts.get("executableCommandNodes")
        removed_count = counts.get("removedCommandNodes")
        source_indices = {command.get("sourceCommandIndex") for command in executable_commands}
        if not isinstance(source_counts, dict) or source_counts.get("commands") != raw_count \
                or executable_count != len(executable_commands) \
                or not all(isinstance(value, int) for value in (
                    raw_count, executable_count, removed_count,
                )) \
                or raw_count != executable_count + removed_count \
                or len(source_indices) != executable_count \
                or not source_indices.issubset(set(range(raw_count))):
            raise SemanticCoverageError(
                f"source-to-executable command coverage differs: {record.get('id')}"
            )


def validate_ledger(
    ledger: dict[str, Any], *, dispatch_path: Path = DEFAULT_DISPATCH,
    udsp_path: Path = DEFAULT_UDSP, executable_path: Path = DEFAULT_EXECUTABLE,
    verify_sources: bool = True, allow_test_provenance: bool = False,
) -> CoverageReport:
    expected = generate(dispatch_path, udsp_path, executable_path)
    required = {"schema", "contract", "edition", "claim", "policy", "sources", "counts", "records"}
    if not isinstance(ledger, dict) or set(ledger) != required:
        raise SemanticCoverageError("semantic coverage ledger shape drifted")
    for field in required - {"records"}:
        if ledger.get(field) != expected[field]:
            raise SemanticCoverageError(f"semantic coverage {field} drifted")
    if verify_sources:
        for source in ledger["sources"].values():
            path = (ROOT / source["path"]).resolve()
            try:
                path.relative_to(ROOT.resolve())
            except ValueError as error:
                raise SemanticCoverageError("semantic coverage source escapes repository") from error
            if not path.is_file() or sha256_file(path) != source["sha256"]:
                raise SemanticCoverageError(f"pinned source hash drifted: {source['path']}")

    expected_rows = {row["id"]: row for row in expected["records"]}
    actual_rows: dict[str, dict[str, Any]] = {}
    records = ledger.get("records")
    if not isinstance(records, list):
        raise SemanticCoverageError("semantic coverage records must be a list")
    for row in records:
        claim_id = row.get("id") if isinstance(row, dict) else None
        if claim_id in actual_rows:
            raise SemanticCoverageError(f"duplicate semantic coverage claim: {claim_id}")
        if claim_id not in expected_rows:
            raise SemanticCoverageError(f"unknown semantic coverage claim: {claim_id}")
        if set(row) != {"id", "evidenceClass", "status", "evidence", "expectation"}:
            raise SemanticCoverageError(f"semantic coverage record shape drifted: {claim_id}")
        expected_row = expected_rows[claim_id]
        for field in ("id", "evidenceClass", "expectation"):
            if row[field] != expected_row[field]:
                raise SemanticCoverageError(f"semantic coverage expectation drifted: {claim_id}")
        actual_rows[claim_id] = row
    missing = set(expected_rows) - set(actual_rows)
    if missing:
        raise SemanticCoverageError(f"missing semantic coverage claim: {min(missing)}")

    source_hashes = {
        "sceneDispatchContract": ledger["sources"]["sceneDispatchContract"]["sha256"],
        "udsSceneScripts": ledger["sources"]["udsSceneScripts"]["sha256"],
        "executableUdspSceneScripts": ledger["sources"]["executableUdspSceneScripts"]["sha256"],
    }
    evidence_ids: set[str] = set()
    evidence_hashes: set[str] = set()
    trace_paths: set[Path] = set()
    trace_hashes: set[str] = set()
    provenance_paths: set[Path] = set()
    provenance_hashes: set[str] = set()
    capture_paths: set[Path] = set()
    capture_hashes: set[str] = set()
    session_occurrences: set[tuple[str, Path, str, int, str]] = set()
    lowering = ledger["policy"]["executableLowering"]
    native_command_contract = lowering["sources"]["nativeCommands"]
    native_executable_sha256 = lowering["sourceIdentities"]["nativeExecutableSha256"]
    executable_source = ledger["sources"]["executableUdspSceneScripts"]
    executable_artifact = _load_hashed_artifact(
        executable_source["path"], executable_source["sha256"],
        "executable UDSP semantic source",
    )
    executable_source_bytes = (ROOT / executable_source["path"]).read_bytes()
    for row in records:
        _validate_evidence(
            row, edition=ledger["edition"], source_hashes=source_hashes,
            evidence_ids=evidence_ids, evidence_hashes=evidence_hashes,
            trace_paths=trace_paths, trace_hashes=trace_hashes,
            provenance_paths=provenance_paths,
            provenance_hashes=provenance_hashes,
            capture_paths=capture_paths, capture_hashes=capture_hashes,
            native_command_contract=native_command_contract,
            native_executable_sha256=native_executable_sha256,
            executable_artifact=executable_artifact,
            executable_source_bytes=executable_source_bytes,
            allow_test_provenance=allow_test_provenance,
            session_occurrences=session_occurrences,
        )

    counts = {name: 0 for name in CLASSES}
    proven = {name: 0 for name in CLASSES}
    for row in records:
        evidence_class = row["evidenceClass"]
        counts[evidence_class] += 1
        proven[evidence_class] += int(row["status"] == "PROVEN")
    if counts != ledger["counts"]:
        raise SemanticCoverageError("semantic coverage class counts drifted")
    return CoverageReport(
        ledger["edition"], counts, proven,
        {name: counts[name] - proven[name] for name in CLASSES},
    )


def load_and_validate(
    ledger_path: Path = DEFAULT_LEDGER, *, dispatch_path: Path = DEFAULT_DISPATCH,
    udsp_path: Path = DEFAULT_UDSP, executable_path: Path = DEFAULT_EXECUTABLE,
) -> CoverageReport:
    ledger = _load(ledger_path, SCHEMA, "scene semantic coverage ledger")
    return validate_ledger(
        ledger, dispatch_path=dispatch_path, udsp_path=udsp_path,
        executable_path=executable_path,
    )


def _format_report(report: CoverageReport) -> str:
    lines = [f"edition: {report.edition}", f"claims: {report.total}"]
    for name in CLASSES:
        lines.append(
            f"{name}: {report.proven[name]}/{report.counts[name]} PROVEN "
            f"({report.unproven[name]} UNPROVEN)"
        )
    lines.append(f"runtime semantic parity: {'PROVEN' if report.complete else 'UNPROVEN'}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dispatch", type=Path, default=DEFAULT_DISPATCH)
    parser.add_argument("--udsp", type=Path, default=DEFAULT_UDSP)
    parser.add_argument("--executable", type=Path, default=DEFAULT_EXECUTABLE)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--write", action="store_true", help="regenerate the fail-closed ledger")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()

    if args.write:
        value = generate(args.dispatch, args.udsp, args.executable)
        args.ledger.parent.mkdir(parents=True, exist_ok=True)
        args.ledger.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report = load_and_validate(
        args.ledger, dispatch_path=args.dispatch, udsp_path=args.udsp,
        executable_path=args.executable,
    )
    if args.json:
        print(json.dumps({
            "edition": report.edition, "counts": report.counts,
            "proven": report.proven, "unproven": report.unproven,
            "complete": report.complete,
        }, sort_keys=True))
    else:
        print(_format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
