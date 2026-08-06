#!/usr/bin/env python3
"""Strict normalization boundary for native and web UDSP semantic traces.

The normalizer accepts facts emitted by the runtime, binds every command back
to the edition's executable UDSP artifact, and emits a pointer-free comparison
shape.  It never upgrades a semantic match to production parity. Incomplete
native hooks are rejected before their event labels are inspected; a complete
hook must expose the exact script, command, scheduler and lifecycle facts from
which the normalized state is independently derived.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import struct
from typing import Any

try:
    from tools.miel_vliegt import authenticated_evidence
except ModuleNotFoundError:
    import authenticated_evidence


SHA256 = re.compile(r"^[0-9a-f]{64}$")
HEX_POINTER = re.compile(r"^0x[0-9a-fA-F]{8,16}$")
F32_BITS = re.compile(r"^0x[0-9a-f]{8}$")
WEB_RAW_PROTOCOL = "miel-vliegt-web-scene-semantic-raw"
WEB_SOURCE_RAW_PROTOCOL = "miel-vliegt-web-source-scene-semantic-raw"
NATIVE_RAW_PROTOCOL = "miel-vliegt-native-scene-semantic-raw"
NORMALIZED_TRACE_PROTOCOL = "miel-vliegt-udsp-semantic-normalized-trace"
NORMALIZED_STATE_PROTOCOL = "miel-vliegt-udsp-semantic-state"
DIFFERENTIAL_PROTOCOL = "miel-vliegt-udsp-semantic-differential"
CANONICAL_HASH_PROTOCOL = "miel-json-ieee754-canonical-v1"
EVIDENCE_MODES = {"TEST_ONLY", "PRODUCTION"}
PRODUCTION_UDSP_EVIDENCE_CLASSES = {
    "UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY",
}
PRODUCTION_DISPATCH_EVIDENCE_CLASSES = {"MISSION_DISPATCH", "LOCATION_POLICY"}
RUNTIME_STATES = {"WAITING", "RUNNING", "COMPLETE", "FAILED"}
VARIANTS = {"COMMAND", "NODE_PARALLEL", "SCHEDULER_ONLY", "FAILURE"}
SOURCE_HASH_FIELDS = {
    "sceneDispatchContract", "udsSceneScripts", "executableUdspSceneScripts",
}
IDENTITY_FIELDS = {
    "edition", "claimId", "evidenceClass", "sourceHashes",
    "subjectSha256", "expectationSha256",
}
RAW_POINTER_FIELDS = {
    "address", "callback_address", "caller", "composite", "context",
    "dispatcher", "entry_address", "handler_case", "next", "node_pointer",
    "object", "object_vtable", "parent_current", "parser_case", "pointer",
    "root_pointer", "vtable",
}
DOCUMENT_COMMON_FIELDS = {
    "schema", "protocol", "evidenceMode", "producer", "edition", "claimId",
    "evidenceClass", "semanticCaseId", "sourceHashes", "subjectSha256",
    "expectationSha256", "artifactKey", "executableScriptSha256",
}
WEB_DOCUMENT_FIELDS = DOCUMENT_COMMON_FIELDS | {"receipts"}
WEB_EXECUTION_FIELDS = {
    "executionRoute", "runtimeSessionSha256", "eventOccurrenceIds",
}
AUTHENTICATED_EVIDENCE_FIELD = "authenticatedEvidence"
WEB_EXECUTABLE_DOCUMENT_FIELDS = WEB_DOCUMENT_FIELDS | WEB_EXECUTION_FIELDS
WEB_SOURCE_DOCUMENT_FIELDS = WEB_EXECUTABLE_DOCUMENT_FIELDS | {
    "sourceScriptSha256", "sourceScriptDocumentSha256",
    "loweringSha256", "lowering",
}
DISPATCH_CAPTURE_PROVENANCE_FIELDS = {
    "schema", "planManifestSha256", "jobSha256", "webSliceId",
    "executorSha256", "runtimeSha256", "oracleSha256",
    "candidateVersion", "captureBundleSha256",
}
WEB_DISPATCH_DOCUMENT_FIELDS = WEB_DOCUMENT_FIELDS | {"captureProvenance"}
NATIVE_DOCUMENT_FIELDS = DOCUMENT_COMMON_FIELDS | {
    "supportStatus", "hookCapabilities", "events",
}
NATIVE_DISPATCH_CAPTURE_PROVENANCE_FIELDS = {
    "schema", "planSha256", "planManifestSha256", "jobId", "jobSha256",
    "nativeSliceId", "nativeSliceSha256", "observerBinarySha256",
    "observerBuildReceiptSha256", "producerBuildSha256",
    "nativeProcessId", "captureSessionId",
}
NATIVE_CAPABILITY_FIELDS = {
    "scriptKey", "executableCommandIndex", "sourceCommandIndex", "opcode",
    "callAncestry", "scheduler", "clock", "delta", "randomSamples",
    "outcome", "failure",
}
NATIVE_DISPATCH_CAPABILITY_FIELDS = {
    "triggerIdentity", "selectorPredicates", "route", "artifact",
    "stateBefore", "stateAfter",
}
NATIVE_SUPPORTED_STATUS = "SUPPORTED_HOOK_FACTS"
SUCCESS_RECEIPT_FIELDS = {
    "schema", "sequence", "semanticStatus", "script", "ancestry", "depth",
    "commandIndex", "executableCommandIndex", "sourceCommandIndex", "opcode",
    "scheduler", "before", "after", "clock", "delta", "randomSamples",
    "outcome",
}
FAILURE_RECEIPT_FIELDS = {
    "schema", "sequence", "semanticStatus", "script", "ancestry", "depth",
    "commandIndex", "executableCommandIndex", "sourceCommandIndex", "opcode",
    "before", "after", "clock", "randomSamples", "outcome", "failure",
}
NATIVE_SUCCESS_EVENT_FIELDS = (
    SUCCESS_RECEIPT_FIELDS - {"semanticStatus", "script"}
) | {"event", "scriptKey"}
NATIVE_FAILURE_EVENT_FIELDS = (
    FAILURE_RECEIPT_FIELDS - {"semanticStatus", "script"}
) | {"event", "scriptKey"}
SCHEDULER_FIELDS = {"node", "repeat", "complete", "resetCount", "parents"}
PARENT_FIELDS = {"node", "repeat", "childIndex"}
BRANCH_FIELDS = {
    "script", "ancestry", "depth", "commandIndex", "executableCommandIndex",
    "sourceCommandIndex", "opcode", "node", "loop", "complete", "resetCount",
    "parents", "randomSamples", "outcome",
}
COMMAND_FIELDS = {
    "opcode", "nativeOpcode", "executableCommandIndex", "sourceCommandIndex",
    "commandSha256",
}
NORMALIZED_TRACE_FIELDS = {
    "schema", "protocol", "producer", "evidenceMode", "edition", "claimId",
    "evidenceClass", "semanticCaseId", "sourceHashes", "subjectSha256",
    "expectationSha256", "artifactKey", "executableScriptSha256", "observations",
}
NORMALIZED_OBSERVATION_FIELDS = {
    "schema", "record", "sequence", "claimId", "evidenceClass",
    "subjectSha256", "expectationSha256", "state",
}
NORMALIZED_STATE_FIELDS = {
    "protocol", "variant", "artifactKey", "executableScriptSha256", "depth",
    "callAncestry", "command", "parentPath", "beforeState", "afterState",
    "timing", "f32Bits", "rng", "callbacks", "sideEffects", "branches",
    "failure",
}
NORMALIZED_BRANCH_FIELDS = {
    "artifactKey", "executableScriptSha256", "depth", "callAncestry",
    "command", "parentPath", "afterState", "f32Bits", "rng", "callbacks",
    "sideEffects",
}
NORMALIZED_DISPATCH_STATE_FIELDS = {
    "protocol", "variant", "trigger", "predicates", "effect",
}
DISPATCH_RECEIPT_FIELDS = {
    "schema", "sequence", "semanticStatus", "event", "before", "result", "after",
}


class SemanticOracleError(ValueError):
    """Raised when a raw or normalized semantic document is not exact."""


class SemanticOracleUnsupported(SemanticOracleError):
    """Raised when a producer cannot emit the facts required to normalize."""


def canonical_sha256(value: Any) -> str:
    """Hash JSON values through an explicit cross-language number contract.

    JSON's text form is not a canonical numeric representation: JavaScript
    and Python serialize negative zero, integer-valued doubles and exponents
    differently.  Every number is therefore represented by its IEEE-754
    binary64 bits before sorted-key JSON serialization.
    """

    def normalize(item: Any) -> Any:
        if type(item) is bool or item is None or isinstance(item, str):
            return item
        if _is_number(item):
            bits = struct.unpack(">Q", struct.pack(">d", float(item)))[0]
            return {"$numberF64": f"0x{bits:016x}"}
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise SemanticOracleError("canonical JSON object key is not a string")
            return {key: normalize(item[key]) for key in sorted(item)}
        raise SemanticOracleError("canonical hash input is not JSON")

    encoded = json.dumps(
        normalize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_number(value: Any) -> bool:
    return (_is_int(value) or type(value) is float) and math.isfinite(value)


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise SemanticOracleError(f"{label} is not sha256")
    return value


def _reject_raw_pointers(value: Any, path: str = "$", field: str | None = None) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SemanticOracleError(f"non-string semantic key at {path}")
            normalized = key.lower()
            if normalized in RAW_POINTER_FIELDS or normalized.endswith(("_address", "_pointer")):
                raise SemanticOracleError(f"raw pointer field at {path}.{key}")
            _reject_raw_pointers(item, f"{path}.{key}", normalized)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_raw_pointers(item, f"{path}[{index}]", field)
        return
    if isinstance(value, str) and HEX_POINTER.fullmatch(value) \
            and not (field or "").endswith(("bits", "_bits")):
        raise SemanticOracleError(f"raw pointer value at {path}")
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise SemanticOracleError(f"non-JSON semantic value at {path}")


def _validate_identity(document: dict[str, Any], producer: str) -> None:
    if document.get("producer") != producer:
        raise SemanticOracleError(f"semantic producer is not {producer}")
    mode = document.get("evidenceMode")
    if mode not in EVIDENCE_MODES:
        raise SemanticOracleError("semantic evidence mode is invalid")
    for field in ("edition", "claimId", "evidenceClass"):
        if not isinstance(document.get(field), str) or not document[field]:
            raise SemanticOracleError(f"semantic {field} is invalid")
    semantic_case_id = document.get("semanticCaseId")
    if mode == "TEST_ONLY":
        if not isinstance(semantic_case_id, str) or not semantic_case_id:
            raise SemanticOracleError("test-only semanticCaseId is invalid")
        if not semantic_case_id.startswith(f"{document['edition']}:"):
            raise SemanticOracleError("test-only semanticCaseId is not edition-scoped")
        expected_claim = f"UDSP_SEMANTIC_CASE:{semantic_case_id}"
        if document["evidenceClass"] != "UDSP_SEMANTIC_CASE" \
                or document["claimId"] != expected_claim:
            raise SemanticOracleError("test-only semantic case claim is invalid")
        if not isinstance(document.get("artifactKey"), str) or not document["artifactKey"]:
            raise SemanticOracleError("test-only semantic artifact is invalid")
        _require_sha(document.get("executableScriptSha256"), "semantic executable script hash")
    else:
        evidence_class = document.get("evidenceClass")
        if evidence_class in PRODUCTION_UDSP_EVIDENCE_CLASSES:
            artifact_key = document.get("artifactKey")
            expected_claim = f"{evidence_class}:{artifact_key}"
            if not isinstance(artifact_key, str) or not artifact_key \
                    or document["claimId"] != expected_claim:
                raise SemanticOracleError("production semantic claim is not UDSP-body bound")
            _require_sha(document.get("executableScriptSha256"), "semantic executable script hash")
        elif evidence_class in PRODUCTION_DISPATCH_EVIDENCE_CLASSES:
            if not document["claimId"].startswith(f"{evidence_class}:"):
                raise SemanticOracleError("production semantic claim is not dispatch bound")
            artifact_key = document.get("artifactKey")
            executable_sha = document.get("executableScriptSha256")
            if artifact_key is None:
                if evidence_class != "LOCATION_POLICY" or executable_sha is not None:
                    raise SemanticOracleError("dispatch semantic absence binding is invalid")
            else:
                if not isinstance(artifact_key, str) or not artifact_key:
                    raise SemanticOracleError("dispatch semantic artifact is invalid")
                _require_sha(executable_sha, "semantic executable script hash")
        else:
            raise SemanticOracleError("production semantic evidence class is unsupported")
        if semantic_case_id is not None:
            raise SemanticOracleError("production semanticCaseId must be null")
    source_hashes = document.get("sourceHashes")
    if not isinstance(source_hashes, dict) or set(source_hashes) != SOURCE_HASH_FIELDS:
        raise SemanticOracleError("semantic source hashes have an invalid shape")
    for label, digest in source_hashes.items():
        _require_sha(digest, f"semantic source hash {label}")
    _require_sha(document.get("subjectSha256"), "semantic subject hash")
    _require_sha(document.get("expectationSha256"), "semantic expectation hash")


def _validate_expected_identity(
    document: dict[str, Any], expected_identity: dict[str, Any] | None,
) -> None:
    if expected_identity is None:
        if document.get("evidenceMode") == "PRODUCTION":
            raise SemanticOracleError("production semantic trace requires expected ledger identity")
        return
    if not isinstance(expected_identity, dict) or set(expected_identity) != IDENTITY_FIELDS:
        raise SemanticOracleError("expected semantic identity has an invalid shape")
    for field in IDENTITY_FIELDS:
        if document.get(field) != expected_identity[field]:
            raise SemanticOracleError(f"semantic identity mismatch: {field}")


def _validate_web_dispatch_capture_provenance(
    document: dict[str, Any], expected: dict[str, Any] | None,
) -> None:
    provenance = document.get("captureProvenance")
    if not isinstance(expected, dict) or set(expected) != DISPATCH_CAPTURE_PROVENANCE_FIELDS:
        raise SemanticOracleError(
            "production dispatch trace requires expected capture provenance"
        )
    if not isinstance(provenance, dict) \
            or set(provenance) != DISPATCH_CAPTURE_PROVENANCE_FIELDS:
        raise SemanticOracleError("dispatch capture provenance fields differ")
    if provenance.get("schema") != 1 \
            or not isinstance(provenance.get("webSliceId"), str) \
            or not provenance["webSliceId"].startswith("web-slice:") \
            or not isinstance(provenance.get("candidateVersion"), str) \
            or not provenance["candidateVersion"]:
        raise SemanticOracleError("dispatch capture provenance identity differs")
    for field in (
        "planManifestSha256", "jobSha256", "executorSha256",
        "runtimeSha256", "oracleSha256",
        "captureBundleSha256",
    ):
        _require_sha(provenance.get(field), f"dispatch capture provenance {field}")
    if provenance != expected:
        raise SemanticOracleError("dispatch capture provenance differs from expected")


def _script_index(executable: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(executable, dict) or executable.get("schema") != 1 \
            or executable.get("contract") != "miel-vliegt-executable-udsp-scene-scripts" \
            or not isinstance(executable.get("scripts"), list):
        raise SemanticOracleError("executable UDSP artifact is invalid")
    result = {}
    for script in executable["scripts"]:
        if not isinstance(script, dict):
            raise SemanticOracleError("executable UDSP script is invalid")
        try:
            key = f"{script['type']}:{script['domainId']}/{script['dispatchId']}"
        except KeyError as error:
            raise SemanticOracleError("executable UDSP script identity is invalid") from error
        if key in result:
            raise SemanticOracleError(f"duplicate executable UDSP script: {key}")
        result[key] = script
    return result


def _validate_production_executable_binding(
    document: dict[str, Any], executable: dict[str, Any],
    executable_source_bytes: bytes | None,
) -> None:
    if document["evidenceMode"] != "PRODUCTION":
        return
    if not isinstance(executable_source_bytes, bytes):
        raise SemanticOracleError("production executable artifact is not source-bound")
    if hashlib.sha256(executable_source_bytes).hexdigest() \
            != document["sourceHashes"]["executableUdspSceneScripts"]:
        raise SemanticOracleError("production executable source hash differs")
    try:
        source_document = json.loads(executable_source_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SemanticOracleError("production executable source is invalid JSON") from error
    if source_document != executable:
        raise SemanticOracleError("production executable source and artifact differ")
    sources = executable.get("sources") if isinstance(executable, dict) else None
    script_source = sources.get("scripts") if isinstance(sources, dict) else None
    if executable.get("edition") != document["edition"] \
            or executable.get("claim") != "STATIC_NATIVE_PARSER_LOWERING_EXACT_FOR_PINNED_EDITION_ASSETS" \
            or not isinstance(script_source, dict) \
            or set(script_source) != {"path", "sha256"} \
            or script_source.get("path") != "content/miel_vliegt/uds_scene_scripts.json" \
            or script_source.get("sha256") != document["sourceHashes"]["udsSceneScripts"] \
            or not isinstance(executable.get("sourceIdentities"), dict) \
            or not isinstance(executable.get("lowering"), dict):
        raise SemanticOracleError("production executable artifact is not source-bound")


def _sorted_json_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _source_script_index(
    source_artifact: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    if source_artifact.get("schema") != 2 \
            or source_artifact.get("claim") != "SOURCE_STRUCTURE_EXACT" \
            or not isinstance(source_artifact.get("scripts"), list):
        raise SemanticOracleError("source UDSP artifact identity differs")
    result = {}
    for script in source_artifact["scripts"]:
        if not isinstance(script, dict):
            raise SemanticOracleError("source UDSP script differs")
        try:
            key = (
                f"{script['type']}:{script['domain_id']}/{script['dispatch_id']}"
            )
        except KeyError as error:
            raise SemanticOracleError("source UDSP script identity differs") from error
        if key in result:
            raise SemanticOracleError(f"duplicate source UDSP script: {key}")
        result[key] = script
    return result


def _source_modifier(arguments: Any) -> str | None:
    modifiers = {
        "NONE", "LOOP", "LOOP_TIMES", "LOOP_RANDOMTIMES",
        "WAIT_RANDOM", "WAIT", "FINISHDIRECT",
    }
    if not isinstance(arguments, list):
        raise SemanticOracleError("source UDSP command arguments differ")
    found = [
        value for value in arguments
        if isinstance(value, str) and value in modifiers
    ]
    if len(found) > 1:
        raise SemanticOracleError("source UDSP command modifier is ambiguous")
    return found[0] if found else None


def _lower_source_structure(
    structure: Any, mapping: dict[int, int | None],
) -> dict[str, Any]:
    if not isinstance(structure, dict) \
            or set(structure) != {"node", "repeat", "children"} \
            or not isinstance(structure["children"], list):
        raise SemanticOracleError("source UDSP structure differs")
    children = []
    for child in structure["children"]:
        if not isinstance(child, dict):
            raise SemanticOracleError("source UDSP structure child differs")
        if set(child) == {"command"}:
            source_index = child["command"]
            if not _is_int(source_index) or source_index not in mapping:
                raise SemanticOracleError("source UDSP command reference differs")
            executable_index = mapping[source_index]
            if executable_index is not None:
                children.append({
                    "command": executable_index,
                    "sourceCommand": source_index,
                })
        else:
            children.append(_lower_source_structure(child, mapping))
    return {
        "node": structure["node"],
        "repeat": structure["repeat"],
        "children": children,
    }


def _expected_source_lowering(
    source_script: dict[str, Any],
    executable_script: dict[str, Any],
    executable: dict[str, Any],
) -> list[dict[str, Any]]:
    commands = source_script.get("commands")
    executable_commands = executable_script.get("commands")
    removals = [
        row for row in executable.get("removedCommands", [])
        if isinstance(row, dict) and row.get("path") == source_script.get("path")
    ]
    if not isinstance(commands, list) or not isinstance(executable_commands, list):
        raise SemanticOracleError("source/executable command inventory differs")
    executable_by_source = {}
    for executable_index, command in enumerate(executable_commands):
        if not isinstance(command, dict) \
                or command.get("executableCommandIndex") != executable_index \
                or not _is_int(command.get("sourceCommandIndex")) \
                or command["sourceCommandIndex"] in executable_by_source:
            raise SemanticOracleError("executable source-command mapping differs")
        executable_by_source[command["sourceCommandIndex"]] = (
            executable_index, command
        )
    removal_by_source = {}
    for removal in removals:
        source_index = removal.get("sourceCommandIndex")
        if not _is_int(source_index) or source_index in removal_by_source:
            raise SemanticOracleError("removed source-command mapping differs")
        removal_by_source[source_index] = removal
    mapping: dict[int, int | None] = {}
    lowering = []
    for source_index, command in enumerate(commands):
        if not isinstance(command, dict) \
                or set(command) != {"opcode", "arity", "node", "loop", "arguments"} \
                or command.get("arity") != len(command.get("arguments", [])):
            raise SemanticOracleError("source UDSP command fields differ")
        executable_match = executable_by_source.get(source_index)
        removal = removal_by_source.get(source_index)
        if int(executable_match is not None) + int(removal is not None) != 1:
            raise SemanticOracleError("source command has no unique lowering")
        source_hash = canonical_sha256(command)
        if executable_match is not None:
            executable_index, lowered = executable_match
            if lowered.get("sourceOpcode") != command["opcode"] \
                    or lowered.get("sourceNode") != command["node"] \
                    or lowered.get("loop") is not command["loop"] \
                    or lowered.get("arguments") != command["arguments"] \
                    or lowered.get("modifier") != _source_modifier(
                        command["arguments"]
                    ) \
                    or not _is_int(lowered.get("nativeOpcode")):
                raise SemanticOracleError("source command lowering identity differs")
            mapping[source_index] = executable_index
            lowering.append({
                "sourceCommandIndex": source_index,
                "sourceOpcode": command["opcode"],
                "sourceCommandSha256": source_hash,
                "disposition": "EXECUTABLE_COMMAND",
                "executableCommandIndex": executable_index,
                "nativeOpcode": lowered["nativeOpcode"],
                "executableCommandSha256": canonical_sha256(lowered),
                "reason": None,
            })
        else:
            expected_removed = {
                "path": source_script.get("path"),
                "sourceCommandIndex": source_index,
                "sourceNode": command["node"],
                "loop": command["loop"],
                "sourceOpcode": command["opcode"],
                "arguments": command["arguments"],
                "reason": removal.get("reason"),
            }
            if removal != expected_removed \
                    or removal.get("reason") not in {
                        "ABSENT_NO_COMMAND_NODE",
                        "DISCARD_DIRECT_OPCODE_NATIVE_PARSER",
                    }:
                raise SemanticOracleError("source command removal identity differs")
            mapping[source_index] = None
            lowering.append({
                "sourceCommandIndex": source_index,
                "sourceOpcode": command["opcode"],
                "sourceCommandSha256": source_hash,
                "disposition": "NO_COMMAND_NODE",
                "executableCommandIndex": None,
                "nativeOpcode": None,
                "executableCommandSha256": None,
                "reason": removal["reason"],
            })
    if len(executable_by_source) + len(removal_by_source) != len(commands) \
            or _lower_source_structure(source_script.get("structure"), mapping) \
            != executable_script.get("structure"):
        raise SemanticOracleError("source lowering partition/structure differs")
    return lowering


def _validate_execution_occurrences(
    document: dict[str, Any], receipts: list[dict[str, Any]],
    expected_route: str,
) -> None:
    if document.get("executionRoute") != expected_route:
        raise SemanticOracleError("web runtime execution route differs")
    expected_session = canonical_sha256({
        "protocol": "miel-vliegt-web-scene-runtime-session",
        "route": expected_route,
        "claimId": document["claimId"],
        "subjectSha256": document["subjectSha256"],
        "expectationSha256": document["expectationSha256"],
        "executableScriptSha256": document["executableScriptSha256"],
    })
    if document.get("runtimeSessionSha256") != expected_session:
        raise SemanticOracleError("web runtime session binding differs")
    expected_occurrences = [
        canonical_sha256({
            "protocol": "miel-vliegt-web-scene-event-occurrence",
            "runtimeSessionSha256": expected_session,
            "sequence": sequence,
            "receiptSha256": canonical_sha256(receipt),
        })
        for sequence, receipt in enumerate(receipts)
    ]
    if document.get("eventOccurrenceIds") != expected_occurrences \
            or len(set(expected_occurrences)) != len(expected_occurrences):
        raise SemanticOracleError("web runtime event occurrence binding differs")


def _validate_authenticated_evidence(
    document: dict[str, Any], receipts: list[dict[str, Any]],
    *,
    expected_producer_build_sha256: str | None,
    expected_audio_asset_sha256: dict[str, str] | None,
) -> None:
    records = document.get(AUTHENTICATED_EVIDENCE_FIELD, [])
    if not isinstance(records, list):
        raise SemanticOracleError("authenticated evidence sidecar is not an array")
    used_envelopes: set[str] = set()
    used_payloads: set[str] = set()
    used_occurrences: set[str] = set()
    expected = {
        "producer": document["producer"],
        "edition": document["edition"],
        "claimId": document["claimId"],
        "evidenceClass": document["evidenceClass"],
        "subjectSha256": document["subjectSha256"],
        "expectationSha256": document["expectationSha256"],
        "runtimeSessionSha256": document["runtimeSessionSha256"],
    }
    if records:
        if not isinstance(expected_producer_build_sha256, str) \
                or SHA256.fullmatch(expected_producer_build_sha256) is None:
            raise SemanticOracleError(
                "authenticated evidence producer build expectation is missing"
            )
        if not isinstance(expected_audio_asset_sha256, dict):
            raise SemanticOracleError(
                "authenticated evidence asset source expectation is missing"
            )
        expected["producerBuildSha256"] = expected_producer_build_sha256
    try:
        for record in records:
            authenticated_evidence.validate_record(
                record,
                expected=expected,
                event_occurrence_ids=document["eventOccurrenceIds"],
                receipts=receipts,
                used_envelopes=used_envelopes,
                used_payloads=used_payloads,
                used_occurrences=used_occurrences,
                asset_source_sha256_by_key=expected_audio_asset_sha256,
            )
    except authenticated_evidence.AuthenticatedEvidenceError as error:
        raise SemanticOracleError(str(error)) from error
    try:
        occurrence_events = authenticated_evidence.runtime_occurrence_events(
            document["eventOccurrenceIds"], receipts,
        )
    except authenticated_evidence.AuthenticatedEvidenceError as error:
        raise SemanticOracleError(str(error)) from error
    completed_media_occurrences = {
        row["occurrenceId"]
        for row in occurrence_events
        if isinstance(row["event"], dict)
        and row["event"].get("opcode") in {
            "PLAY_CHARACTER_SOUND", "PLAY_MULLEBARNSOUND",
            "PLAY_RADIO", "PLAY_SOUND",
        }
        and (
            row["event"].get("scheduler", {}).get("complete")
            if isinstance(row["event"].get("scheduler"), dict)
            else row["event"].get("complete")
        ) is True
        and isinstance(row["event"].get("outcome"), dict)
        and row["event"]["outcome"].get("port") == row["event"].get("opcode")
    }
    if used_occurrences != completed_media_occurrences:
        raise SemanticOracleError(
            "completed media commands and authenticated callback evidence differ"
        )


def _validate_production_source_binding(
    document: dict[str, Any],
    source_artifact: dict[str, Any] | None,
    source_artifact_bytes: bytes | None,
    executable: dict[str, Any],
    expected_expectation: dict[str, Any] | None,
) -> None:
    if not isinstance(source_artifact, dict) \
            or not isinstance(source_artifact_bytes, bytes):
        raise SemanticOracleError("production source artifact is not source-bound")
    if hashlib.sha256(source_artifact_bytes).hexdigest() \
            != document["sourceHashes"]["udsSceneScripts"]:
        raise SemanticOracleError("production source artifact hash differs")
    try:
        parsed = json.loads(source_artifact_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SemanticOracleError("production source artifact is invalid JSON") from error
    if parsed != source_artifact:
        raise SemanticOracleError("production source bytes and artifact differ")
    source_scripts = _source_script_index(source_artifact)
    executable_scripts = _script_index(executable)
    key = document["artifactKey"]
    source_script = source_scripts.get(key)
    executable_script = executable_scripts.get(key)
    if source_script is None or executable_script is None \
            or source_script.get("path") != executable_script.get("path") \
            or source_script.get("sha256") != executable_script.get("sourceSha256") \
            or source_script.get("type") != executable_script.get("type") \
            or source_script.get("domain_id") != executable_script.get("domainId") \
            or source_script.get("dispatch_id") != executable_script.get("dispatchId") \
            or source_script.get("name") != executable_script.get("name"):
        raise SemanticOracleError("production source script binding differs")
    if document.get("sourceScriptSha256") != source_script.get("sha256") \
            or document.get("sourceScriptDocumentSha256") \
            != canonical_sha256(source_script):
        raise SemanticOracleError("production source script hash differs")
    if not isinstance(expected_expectation, dict) \
            or expected_expectation.get("artifactKey") != key \
            or expected_expectation.get("scriptSha256") != source_script.get("sha256") \
            or expected_expectation.get("commandsSha256") \
            != _sorted_json_sha256(source_script.get("commands")) \
            or expected_expectation.get("structureSha256") \
            != _sorted_json_sha256(source_script.get("structure")):
        raise SemanticOracleError("production source expectation binding differs")
    lowering = _expected_source_lowering(
        source_script, executable_script, executable
    )
    if document.get("lowering") != lowering \
            or document.get("loweringSha256") != canonical_sha256(lowering):
        raise SemanticOracleError("production source lowering differs")


def _parent_path(structure: Any, command_index: int, parents=()) -> list[dict[str, Any]] | None:
    if not isinstance(structure, dict) or set(structure) != {"node", "repeat", "children"} \
            or not isinstance(structure["children"], list) or type(structure["repeat"]) is not bool \
            or (structure["node"] is not None and not _is_int(structure["node"])):
        raise SemanticOracleError("executable script structure is invalid")
    for child_index, child in enumerate(structure["children"]):
        parent = {
            "node": structure["node"], "repeat": structure["repeat"],
            "childIndex": child_index,
        }
        if not isinstance(child, dict):
            raise SemanticOracleError("executable script child is invalid")
        if set(child) == {"command", "sourceCommand"}:
            if child.get("command") == command_index:
                return [*parents, parent]
            continue
        found = _parent_path(child, command_index, (*parents, parent))
        if found is not None:
            return found
    return None


def _command_for(
    script: dict[str, Any], command_index: Any,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    commands = script.get("commands")
    if not isinstance(commands, list) or not _is_int(command_index) \
            or not 0 <= command_index < len(commands):
        raise SemanticOracleError("executable command index is invalid")
    command = commands[command_index]
    if not isinstance(command, dict) or command.get("executableCommandIndex") != command_index:
        raise SemanticOracleError("executable command identity is invalid")
    path = _parent_path(script.get("structure"), command_index)
    if not path:
        raise SemanticOracleError("executable command parent path is absent")
    identity = {
        "opcode": command.get("sourceOpcode"),
        "nativeOpcode": command.get("nativeOpcode"),
        "executableCommandIndex": command_index,
        "sourceCommandIndex": command.get("sourceCommandIndex"),
        "commandSha256": canonical_sha256(command),
    }
    if not isinstance(identity["opcode"], str) or not _is_int(identity["nativeOpcode"]) \
            or not _is_int(identity["sourceCommandIndex"]):
        raise SemanticOracleError("executable command metadata is invalid")
    return command, identity, path


def _float32_bits(value: Any, label: str) -> str:
    if not _is_number(value):
        raise SemanticOracleError(f"{label} is not a finite number")
    try:
        packed = struct.pack("<f", float(value))
    except OverflowError as error:
        raise SemanticOracleError(f"{label} is outside float32") from error
    return f"0x{struct.unpack('<I', packed)[0]:08x}"


def _require_float32_value(value: Any, label: str) -> str:
    bits = _float32_bits(value, label)
    decoded = struct.unpack("<f", struct.pack("<I", int(bits[2:], 16)))[0]
    if decoded != float(value):
        raise SemanticOracleError(f"{label} is not an exact float32 value")
    return bits


def _validate_ancestry(
    ancestry: Any, depth: Any, script_key: str, entry_key: str,
) -> list[str]:
    if not isinstance(ancestry, list) or not ancestry \
            or any(not isinstance(item, str) or not item for item in ancestry) \
            or len(set(ancestry)) != len(ancestry) \
            or ancestry[0] != entry_key or ancestry[-1] != script_key \
            or not _is_int(depth) or depth != len(ancestry) - 1:
        raise SemanticOracleError("web receipt call ancestry differs")
    return copy.deepcopy(ancestry)


def _validate_parent_records(parents: Any) -> None:
    if not isinstance(parents, list) or not parents:
        raise SemanticOracleError("web receipt parent path is empty")
    for parent in parents:
        if not isinstance(parent, dict) or set(parent) != PARENT_FIELDS \
                or (parent.get("node") is not None and not _is_int(parent.get("node"))) \
                or type(parent.get("repeat")) is not bool \
                or not _is_int(parent.get("childIndex")) or parent["childIndex"] < 0:
            raise SemanticOracleError("web receipt parent path fields differ")


def _normalized_parent_path(path: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _validate_parent_records(path)
    return [
        {"nodeId": row["node"], "repeat": row["repeat"], "childIndex": row["childIndex"]}
        for row in path
    ]


def _rng_samples(samples: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(samples, list) or len(samples) > 64:
        raise SemanticOracleError("semantic RNG samples are invalid")
    normalized = []
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or set(sample) != {"sequence", "kind", "value"} \
                or not _is_int(sample.get("sequence")) or sample["sequence"] != index:
            raise SemanticOracleError(f"semantic RNG sample {index} fields differ")
        kind = sample.get("kind")
        value = sample.get("value")
        if kind == "NATIVE_RAND_U15":
            if not _is_int(value) or not 0 <= value <= 32767:
                raise SemanticOracleError(f"semantic native RNG sample {index} is invalid")
        elif kind == "UNIT_INTERVAL_NUMBER":
            if not _is_number(value) or not 0 <= value < 1:
                raise SemanticOracleError(f"semantic unit RNG sample {index} is invalid")
        else:
            raise SemanticOracleError(f"semantic RNG sample {index} kind is invalid")
        normalized.append(copy.deepcopy(sample))
    return {"samples": normalized}


def _callbacks(value: Any, path: str = "$.outcome") -> list[dict[str, Any]]:
    result = []
    if isinstance(value, dict):
        for key in sorted(value):
            item = value[key]
            child_path = f"{path}.{key}"
            if "callback" in key.lower() or key == "advancesOn":
                result.append({"path": child_path, "value": copy.deepcopy(item)})
            result.extend(_callbacks(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_callbacks(item, f"{path}[{index}]"))
    return result


def _without_callback_or_f32_duplicates(value: Any, path: str = "$.outcome") -> Any:
    if isinstance(value, dict):
        result = {}
        for key in sorted(value):
            child_path = f"{path}.{key}"
            if "callback" in key.lower() or key == "advancesOn":
                continue
            if child_path in {
                "$.outcome.wait.duration", "$.outcome.wait.initialTimer",
                "$.outcome.wait.timer",
            }:
                continue
            result[key] = _without_callback_or_f32_duplicates(value[key], child_path)
        return result
    if isinstance(value, list):
        return [
            _without_callback_or_f32_duplicates(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    return copy.deepcopy(value)


def _outcome_transcripts(
    outcome: Any, timing_delta: Any,
) -> tuple[list[dict[str, str]], list[dict[str, Any]], list[dict[str, Any]]]:
    _reject_raw_pointers(outcome, "$.outcome")
    f32_bits = []
    if isinstance(outcome, dict) and isinstance(outcome.get("wait"), dict):
        wait = outcome["wait"]
        for field in ("delta", "duration", "initialTimer", "timer"):
            if field not in wait:
                raise SemanticOracleError(f"WAIT outcome lacks {field}")
            bits = _require_float32_value(wait[field], f"WAIT outcome {field}")
            if field == "delta" and bits != _require_float32_value(
                timing_delta, "receipt timing delta"
            ):
                raise SemanticOracleError("WAIT delta differs from receipt timing")
            f32_bits.append({
                "path": f"$.outcome.wait.{field}",
                "bits": bits,
            })
    callbacks = _callbacks(outcome)
    side_effects = [] if outcome is None else [{
        "sequence": 0,
        "kind": "OUTCOME",
        "value": _without_callback_or_f32_duplicates(outcome),
    }]
    return f32_bits, callbacks, side_effects


def _script_and_command(
    scripts: dict[str, dict[str, Any]], script_key: str, command_index: Any,
    *, source_index: Any, opcode: Any, parent_path: Any,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    script = scripts.get(script_key)
    if script is None:
        raise SemanticOracleError(f"web receipt script is unknown: {script_key}")
    command, identity, expected_path = _command_for(script, command_index)
    if source_index != identity["sourceCommandIndex"] or opcode != identity["opcode"]:
        raise SemanticOracleError("web receipt command identity differs")
    if parent_path != expected_path:
        raise SemanticOracleError("web receipt parent path differs")
    return script, identity, expected_path


def _after_state(
    status: Any, complete: Any, reset_count: Any, *, allow_unknown_runtime: bool = False,
) -> dict[str, Any]:
    if (status not in RUNTIME_STATES and not (allow_unknown_runtime and status is None)) \
            or type(complete) is not bool \
            or not _is_int(reset_count) or reset_count < 0:
        raise SemanticOracleError("web receipt after-state differs")
    return {
        "runtimeStatus": status,
        "schedulerComplete": complete,
        "schedulerResetCount": reset_count,
    }


def _normalize_branch(
    branch: Any, scripts: dict[str, dict[str, Any]], entry_key: str,
    timing_delta: Any,
) -> dict[str, Any]:
    if not isinstance(branch, dict) or set(branch) != BRANCH_FIELDS:
        raise SemanticOracleError("web NODE_PARALLEL branch fields differ")
    script_key = branch.get("script")
    ancestry = _validate_ancestry(branch.get("ancestry"), branch.get("depth"), script_key, entry_key)
    script = scripts.get(script_key)
    if script is None:
        raise SemanticOracleError(f"web receipt script is unknown: {script_key}")
    _, command, _ = _command_for(
        script, branch.get("executableCommandIndex")
    )
    expected_path = _parent_path(
        script.get("structure"), branch.get("executableCommandIndex")
    )
    if branch.get("sourceCommandIndex") != command["sourceCommandIndex"] \
            or branch.get("opcode") != command["opcode"]:
        raise SemanticOracleError("web NODE_PARALLEL command identity differs")
    path = branch.get("parents")
    _validate_parent_records(path)
    if path != expected_path:
        raise SemanticOracleError("web NODE_PARALLEL parent path differs")
    if branch.get("commandIndex") != command["executableCommandIndex"]:
        raise SemanticOracleError("web NODE_PARALLEL command index differs")
    f32_bits, callbacks, effects = _outcome_transcripts(
        branch.get("outcome"), timing_delta
    )
    return {
        "artifactKey": script_key,
        "executableScriptSha256": canonical_sha256(script),
        "depth": branch["depth"],
        "callAncestry": ancestry,
        "command": command,
        "parentPath": _normalized_parent_path(path),
        "afterState": _after_state(
            None, branch.get("complete"), branch.get("resetCount"),
            allow_unknown_runtime=True,
        ),
        "f32Bits": f32_bits,
        "rng": _rng_samples(branch.get("randomSamples")),
        "callbacks": callbacks,
        "sideEffects": effects,
    }


def _base_state(
    *, variant: str, artifact_key: str, script_sha: str, depth: int,
    ancestry: list[str], command: dict[str, Any] | None,
    parent_path: list[dict[str, Any]], before: str, after: dict[str, Any],
    clock: Any, delta: Any, f32_bits: list[dict[str, str]], rng: dict[str, Any],
    callbacks: list[dict[str, Any]], effects: list[dict[str, Any]],
    branches: list[dict[str, Any]] | None = None, failure: Any = None,
) -> dict[str, Any]:
    if before not in RUNTIME_STATES \
            or (not _is_number(clock) and not (variant == "FAILURE" and clock is None)) \
            or (delta is not None and not _is_number(delta)):
        raise SemanticOracleError("web receipt timing/state differs")
    if delta is not None:
        _require_float32_value(delta, "receipt timing delta")
    state = {
        "protocol": NORMALIZED_STATE_PROTOCOL,
        "variant": variant,
        "artifactKey": artifact_key,
        "executableScriptSha256": script_sha,
        "depth": depth,
        "callAncestry": ancestry,
        "command": command,
        "parentPath": parent_path,
        "beforeState": {"runtimeStatus": before},
        "afterState": after,
        "timing": {"clock": clock, "delta": delta},
        "f32Bits": f32_bits,
        "rng": rng,
        "callbacks": callbacks,
        "sideEffects": effects,
        "branches": branches,
        "failure": failure,
    }
    _validate_normalized_state(state)
    return state


def _normalize_success_receipt(
    receipt: dict[str, Any], document: dict[str, Any],
    scripts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if set(receipt) != SUCCESS_RECEIPT_FIELDS:
        raise SemanticOracleError("web UdspSceneRuntime success receipt fields differ")
    entry_key = document["artifactKey"]
    if receipt.get("opcode") == "NODE_PARALLEL":
        if any(receipt.get(field) is not None for field in (
            "commandIndex", "executableCommandIndex", "sourceCommandIndex",
        )) or not isinstance(receipt.get("scheduler"), dict) \
                or set(receipt["scheduler"]) != {"children"} \
                or not isinstance(receipt.get("outcome"), dict) \
                or set(receipt["outcome"]) != {"branches"} \
                or receipt["scheduler"]["children"] != receipt["outcome"]["branches"]:
            raise SemanticOracleError("web NODE_PARALLEL envelope differs")
        ancestry = _validate_ancestry(
            receipt.get("ancestry"), receipt.get("depth"), receipt.get("script"), entry_key
        )
        branches = [
            _normalize_branch(branch, scripts, entry_key, receipt.get("delta"))
            for branch in receipt["outcome"]["branches"]
        ]
        flattened = [
            {**sample, "sequence": sequence}
            for sequence, sample in enumerate(
                sample
                for branch in receipt["outcome"]["branches"]
                for sample in branch["randomSamples"]
            )
        ]
        if receipt.get("randomSamples") != flattened:
            raise SemanticOracleError("web NODE_PARALLEL RNG envelope differs")
        script = scripts.get(receipt["script"])
        if script is None:
            raise SemanticOracleError("web NODE_PARALLEL receipt script is unknown")
        return _base_state(
            variant="NODE_PARALLEL", artifact_key=receipt["script"],
            script_sha=canonical_sha256(script), depth=receipt["depth"], ancestry=ancestry,
            command=None, parent_path=[], before=receipt["before"],
            after={"runtimeStatus": receipt["after"], "schedulerComplete": None,
                   "schedulerResetCount": None},
            clock=receipt["clock"], delta=receipt["delta"], f32_bits=[],
            rng=_rng_samples(receipt["randomSamples"]), callbacks=[], effects=[],
            branches=branches,
        )
    scheduler = receipt.get("scheduler")
    if not isinstance(scheduler, dict) or set(scheduler) != SCHEDULER_FIELDS:
        raise SemanticOracleError("web receipt scheduler fields differ")
    script_key = receipt.get("script")
    ancestry = _validate_ancestry(
        receipt.get("ancestry"), receipt.get("depth"), script_key, entry_key
    )
    if receipt.get("opcode") == "EMPTY_REPEAT_SCHEDULER":
        if any(receipt.get(field) is not None for field in (
            "commandIndex", "executableCommandIndex", "sourceCommandIndex",
        )) or scheduler.get("repeat") is not True \
                or not isinstance(receipt.get("outcome"), dict) \
                or receipt["outcome"].get("kind") != "SCHEDULER_ONLY":
            raise SemanticOracleError("web empty-repeat scheduler envelope differs")
        if script_key not in scripts:
            raise SemanticOracleError("web empty-repeat receipt script is unknown")
        path = _normalized_parent_path(scheduler.get("parents"))
        f32_bits, callbacks, effects = _outcome_transcripts(
            receipt.get("outcome"), receipt.get("delta")
        )
        return _base_state(
            variant="SCHEDULER_ONLY", artifact_key=script_key,
            script_sha=canonical_sha256(scripts[script_key]), depth=receipt["depth"],
            ancestry=ancestry, command=None, parent_path=path,
            before=receipt["before"], after=_after_state(
                receipt["after"], scheduler.get("complete"), scheduler.get("resetCount")
            ), clock=receipt["clock"], delta=receipt["delta"],
            f32_bits=f32_bits, rng=_rng_samples(receipt["randomSamples"]),
            callbacks=callbacks, effects=effects,
        )
    script, command, expected_path = _script_and_command(
        scripts, script_key, receipt.get("executableCommandIndex"),
        source_index=receipt.get("sourceCommandIndex"), opcode=receipt.get("opcode"),
        parent_path=scheduler.get("parents"),
    )
    if receipt.get("commandIndex") != command["executableCommandIndex"] \
            or scheduler.get("node") != script["commands"][command["executableCommandIndex"]].get("sourceNode") \
            or scheduler.get("repeat") is not script["commands"][command["executableCommandIndex"]].get("loop"):
        raise SemanticOracleError("web receipt command scheduler differs")
    f32_bits, callbacks, effects = _outcome_transcripts(
        receipt.get("outcome"), receipt.get("delta")
    )
    return _base_state(
        variant="COMMAND", artifact_key=script_key,
        script_sha=canonical_sha256(script), depth=receipt["depth"], ancestry=ancestry,
        command=command, parent_path=_normalized_parent_path(expected_path),
        before=receipt["before"], after=_after_state(
            receipt["after"], scheduler.get("complete"), scheduler.get("resetCount")
        ), clock=receipt["clock"], delta=receipt["delta"], f32_bits=f32_bits,
        rng=_rng_samples(receipt["randomSamples"]), callbacks=callbacks, effects=effects,
    )


def _normalize_failure_receipt(
    receipt: dict[str, Any], document: dict[str, Any],
    scripts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if set(receipt) != FAILURE_RECEIPT_FIELDS or receipt.get("after") != "FAILED" \
            or receipt.get("outcome") is not None:
        raise SemanticOracleError("web UdspSceneRuntime failure receipt fields differ")
    script_key = receipt.get("script")
    ancestry = _validate_ancestry(
        receipt.get("ancestry"), receipt.get("depth"), script_key, document["artifactKey"]
    )
    script = scripts.get(script_key)
    if script is None:
        raise SemanticOracleError("web failure receipt script is unknown")
    indices = (
        receipt.get("commandIndex"), receipt.get("executableCommandIndex"),
        receipt.get("sourceCommandIndex"), receipt.get("opcode"),
    )
    command = None
    path = []
    if any(value is not None for value in indices):
        if any(value is None for value in indices):
            raise SemanticOracleError("web failure command identity is partial")
        _, command, expected_path = _script_and_command(
            scripts, script_key, receipt["executableCommandIndex"],
            source_index=receipt["sourceCommandIndex"], opcode=receipt["opcode"],
            parent_path=_parent_path(script["structure"], receipt["executableCommandIndex"]),
        )
        if receipt["commandIndex"] != command["executableCommandIndex"]:
            raise SemanticOracleError("web failure command index differs")
        path = _normalized_parent_path(expected_path)
    failure = receipt.get("failure")
    if not isinstance(failure, dict) or set(failure) != {"code", "message", "details"} \
            or not isinstance(failure.get("code"), str) or not failure["code"] \
            or not isinstance(failure.get("message"), str):
        raise SemanticOracleError("web failure payload differs")
    _reject_raw_pointers(failure, "$.failure")
    return _base_state(
        variant="FAILURE", artifact_key=script_key,
        script_sha=canonical_sha256(script), depth=receipt["depth"], ancestry=ancestry,
        command=command, parent_path=path, before=receipt["before"],
        after={"runtimeStatus": "FAILED", "schedulerComplete": None,
               "schedulerResetCount": None},
        clock=receipt["clock"], delta=None, f32_bits=[],
        rng=_rng_samples(receipt["randomSamples"]), callbacks=[], effects=[],
        failure=copy.deepcopy(failure),
    )


def _validate_normalized_parent_path(value: Any, *, allow_empty: bool) -> None:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise SemanticOracleError("normalized parent path fields differ")
    for row in value:
        if not isinstance(row, dict) or set(row) != {"nodeId", "repeat", "childIndex"} \
                or (row.get("nodeId") is not None and not _is_int(row.get("nodeId"))) \
                or type(row.get("repeat")) is not bool \
                or not _is_int(row.get("childIndex")) or row["childIndex"] < 0:
            raise SemanticOracleError("normalized parent path fields differ")


def _validate_transcripts(state: dict[str, Any]) -> None:
    f32_bits = state.get("f32Bits")
    if not isinstance(f32_bits, list):
        raise SemanticOracleError("normalized float32 transcript fields differ")
    previous = None
    for item in f32_bits:
        if not isinstance(item, dict) or set(item) != {"path", "bits"} \
                or not isinstance(item.get("path"), str) or not item["path"].startswith("$.") \
                or not isinstance(item.get("bits"), str) or not F32_BITS.fullmatch(item["bits"]) \
                or (previous is not None and item["path"] <= previous):
            raise SemanticOracleError("normalized float32 transcript order/fields differ")
        previous = item["path"]
    rng = state.get("rng")
    if not isinstance(rng, dict) or set(rng) != {"samples"}:
        raise SemanticOracleError("normalized RNG transcript fields differ")
    _rng_samples(rng["samples"])
    callbacks = state.get("callbacks")
    if not isinstance(callbacks, list):
        raise SemanticOracleError("normalized callback transcript fields differ")
    previous = None
    for item in callbacks:
        if not isinstance(item, dict) or set(item) != {"path", "value"} \
                or not isinstance(item.get("path"), str) or not item["path"].startswith("$.outcome") \
                or (previous is not None and item["path"] <= previous):
            raise SemanticOracleError("normalized callback transcript order/fields differ")
        previous = item["path"]
    effects = state.get("sideEffects")
    if not isinstance(effects, list) or len(effects) > 1 or any(
        not isinstance(item, dict) or set(item) != {"sequence", "kind", "value"}
        or not _is_int(item.get("sequence")) or item["sequence"] != index
        or item.get("kind") != "OUTCOME"
        for index, item in enumerate(effects)
    ):
        raise SemanticOracleError("normalized side-effect transcript fields differ")


def _validate_normalized_state(state: Any) -> None:
    _reject_raw_pointers(state)
    if isinstance(state, dict) and set(state) == NORMALIZED_DISPATCH_STATE_FIELDS:
        if state.get("protocol") != "miel-vliegt-scene-dispatch-semantic-state" \
                or state.get("variant") not in PRODUCTION_DISPATCH_EVIDENCE_CLASSES \
                or not isinstance(state.get("trigger"), dict) \
                or not isinstance(state.get("predicates"), list) \
                or any(not isinstance(value, str) or not value for value in state["predicates"]) \
                or len(state["predicates"]) != len(set(state["predicates"])) \
                or not isinstance(state.get("effect"), dict):
            raise SemanticOracleError("normalized dispatch state fields differ")
        if state["variant"] == "MISSION_DISPATCH":
            if set(state["trigger"]) != {"missionKey", "missionPhase", "nativeActionOrdinal"} \
                    or state["predicates"] != [] \
                    or set(state["effect"]) != {"selection", "route", "artifactKey"} \
                    or state["effect"].get("selection") != "MISSION_ACTION_SELECTED":
                raise SemanticOracleError("normalized mission dispatch state differs")
        elif set(state["trigger"]) != {"locationId", "selector"} \
                or not state["predicates"] \
                or set(state["effect"]) != {"selection", "outcome", "artifactKey"} \
                or state["effect"].get("selection") not in {
                    "EXPECTED_ROOT_ARTIFACT_SELECTED", "EXPECTED_UDSP_ABSENCE_CONFIRMED",
                }:
            raise SemanticOracleError("normalized location policy state differs")
        return
    if not isinstance(state, dict) or set(state) != NORMALIZED_STATE_FIELDS \
            or state.get("protocol") != NORMALIZED_STATE_PROTOCOL \
            or state.get("variant") not in VARIANTS:
        raise SemanticOracleError("normalized semantic state fields differ")
    if not isinstance(state.get("artifactKey"), str) or not state["artifactKey"]:
        raise SemanticOracleError("normalized semantic artifactKey is invalid")
    _require_sha(state.get("executableScriptSha256"), "normalized executable script hash")
    ancestry = state.get("callAncestry")
    if not isinstance(ancestry, list) or not ancestry or ancestry[-1] != state["artifactKey"] \
            or len(set(ancestry)) != len(ancestry) or state.get("depth") != len(ancestry) - 1:
        raise SemanticOracleError("normalized call ancestry differs")
    command = state.get("command")
    if command is not None:
        if not isinstance(command, dict) or set(command) != COMMAND_FIELDS \
                or not isinstance(command.get("opcode"), str) \
                or not _is_int(command.get("nativeOpcode")) \
                or not _is_int(command.get("executableCommandIndex")) \
                or not _is_int(command.get("sourceCommandIndex")):
            raise SemanticOracleError("normalized command fields differ")
        _require_sha(command.get("commandSha256"), "normalized command hash")
    variant = state["variant"]
    if (variant == "COMMAND" and command is None) \
            or (variant in {"NODE_PARALLEL", "SCHEDULER_ONLY"} and command is not None):
        raise SemanticOracleError("normalized command/variant differs")
    _validate_normalized_parent_path(
        state.get("parentPath"), allow_empty=variant in {"NODE_PARALLEL", "FAILURE"}
    )
    before = state.get("beforeState")
    after = state.get("afterState")
    if not isinstance(before, dict) or set(before) != {"runtimeStatus"} \
            or before.get("runtimeStatus") not in RUNTIME_STATES \
            or not isinstance(after, dict) \
            or set(after) != {"runtimeStatus", "schedulerComplete", "schedulerResetCount"} \
            or after.get("runtimeStatus") not in RUNTIME_STATES:
        raise SemanticOracleError("normalized before/after state fields differ")
    scheduler_values = (after.get("schedulerComplete"), after.get("schedulerResetCount"))
    if variant in {"NODE_PARALLEL", "FAILURE"}:
        if scheduler_values != (None, None):
            raise SemanticOracleError("normalized envelope scheduler state differs")
    elif type(scheduler_values[0]) is not bool or not _is_int(scheduler_values[1]) \
            or scheduler_values[1] < 0:
        raise SemanticOracleError("normalized scheduler state differs")
    if variant == "FAILURE" and after.get("runtimeStatus") != "FAILED":
        raise SemanticOracleError("normalized failure runtime status differs")
    timing = state.get("timing")
    if not isinstance(timing, dict) or set(timing) != {"clock", "delta"} \
            or (not _is_number(timing.get("clock"))
                and not (variant == "FAILURE" and timing.get("clock") is None)) \
            or (timing.get("delta") is not None and not _is_number(timing.get("delta"))):
        raise SemanticOracleError("normalized timing fields differ")
    _validate_transcripts(state)
    branches = state.get("branches")
    if variant == "NODE_PARALLEL":
        if not isinstance(branches, list) or len(branches) < 2:
            raise SemanticOracleError("normalized NODE_PARALLEL branches differ")
        for branch in branches:
            if not isinstance(branch, dict) or set(branch) != NORMALIZED_BRANCH_FIELDS:
                raise SemanticOracleError("normalized NODE_PARALLEL branch fields differ")
            if not isinstance(branch.get("artifactKey"), str) or not branch["artifactKey"]:
                raise SemanticOracleError("normalized NODE_PARALLEL branch artifact differs")
            _require_sha(
                branch.get("executableScriptSha256"),
                "normalized NODE_PARALLEL executable script hash",
            )
            branch_ancestry = branch.get("callAncestry")
            if not isinstance(branch_ancestry, list) or not branch_ancestry \
                    or branch_ancestry[-1] != branch["artifactKey"] \
                    or len(set(branch_ancestry)) != len(branch_ancestry) \
                    or branch.get("depth") != len(branch_ancestry) - 1:
                raise SemanticOracleError("normalized NODE_PARALLEL branch ancestry differs")
            branch_command = branch.get("command")
            if not isinstance(branch_command, dict) or set(branch_command) != COMMAND_FIELDS \
                    or not isinstance(branch_command.get("opcode"), str) \
                    or not _is_int(branch_command.get("nativeOpcode")) \
                    or not _is_int(branch_command.get("executableCommandIndex")) \
                    or not _is_int(branch_command.get("sourceCommandIndex")):
                raise SemanticOracleError("normalized NODE_PARALLEL branch command differs")
            _require_sha(
                branch_command.get("commandSha256"),
                "normalized NODE_PARALLEL command hash",
            )
            _validate_normalized_parent_path(branch.get("parentPath"), allow_empty=False)
            branch_after = branch.get("afterState")
            if not isinstance(branch_after, dict) \
                    or set(branch_after) != {
                        "runtimeStatus", "schedulerComplete", "schedulerResetCount",
                    } or branch_after.get("runtimeStatus") is not None \
                    or type(branch_after.get("schedulerComplete")) is not bool \
                    or not _is_int(branch_after.get("schedulerResetCount")) \
                    or branch_after["schedulerResetCount"] < 0:
                raise SemanticOracleError("normalized NODE_PARALLEL branch state differs")
            _validate_transcripts(branch)
    elif branches is not None:
        raise SemanticOracleError("normalized non-parallel branches differ")
    failure = state.get("failure")
    if variant == "FAILURE":
        if not isinstance(failure, dict) or set(failure) != {"code", "message", "details"} \
                or not isinstance(failure.get("code"), str) or not failure["code"] \
                or not isinstance(failure.get("message"), str):
            raise SemanticOracleError("normalized failure fields differ")
    elif failure is not None:
        raise SemanticOracleError("normalized non-failure payload differs")


def _normalized_observation(
    document: dict[str, Any], sequence: int, state: dict[str, Any],
) -> dict[str, Any]:
    _validate_normalized_state(state)
    return {
        "schema": 1,
        "record": "semantic_observation",
        "sequence": sequence,
        "claimId": document["claimId"],
        "evidenceClass": document["evidenceClass"],
        "subjectSha256": document["subjectSha256"],
        "expectationSha256": document["expectationSha256"],
        "state": state,
    }


def _trace(
    document: dict[str, Any], producer: str, observations: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": 1,
        "protocol": NORMALIZED_TRACE_PROTOCOL,
        "producer": producer,
        "evidenceMode": document["evidenceMode"],
        "edition": document["edition"],
        "claimId": document["claimId"],
        "evidenceClass": document["evidenceClass"],
        "semanticCaseId": document["semanticCaseId"],
        "sourceHashes": copy.deepcopy(document["sourceHashes"]),
        "subjectSha256": document["subjectSha256"],
        "expectationSha256": document["expectationSha256"],
        "artifactKey": document["artifactKey"],
        "executableScriptSha256": document["executableScriptSha256"],
        "observations": observations,
    }


def _dispatch_state(
    document: dict[str, Any], expectation: dict[str, Any], receipt: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != DISPATCH_RECEIPT_FIELDS \
            or receipt.get("schema") != 1 \
            or receipt.get("semanticStatus") != "UNPROVEN" \
            or not _is_int(receipt.get("sequence")) or receipt["sequence"] < 1:
        raise SemanticOracleError("scene dispatch receipt fields differ")
    event = receipt.get("event")
    before = receipt.get("before")
    result = receipt.get("result")
    after = receipt.get("after")
    for value, label in ((event, "event"), (before, "before"), (result, "result"), (after, "after")):
        if not isinstance(value, dict):
            raise SemanticOracleError(f"scene dispatch {label} is invalid")
    sequence = receipt["sequence"]
    if before.get("sequence") != sequence - 1 or after.get("sequence") != sequence \
            or result.get("sequence") != sequence:
        raise SemanticOracleError("scene dispatch receipt sequence differs")
    evidence_class = document["evidenceClass"]
    if evidence_class == "MISSION_DISPATCH":
        trigger = {
            key: expectation[key]
            for key in ("missionKey", "missionPhase", "nativeActionOrdinal")
        }
        if event != {"trigger": "MISSION_ACTION", **trigger} \
                or result.get("trigger") != "MISSION_ACTION" \
                or result.get("route") != expectation.get("route") \
                or result.get("artifactKey") != expectation.get("artifactKey") \
                or result.get("duplicate") is not False:
            raise SemanticOracleError("mission dispatch receipt differs from expectation")
        expected_action = {
            "GROUND": "PREPENDED", "BARN": "STARTED", "FLIGHT": "STARTED",
            "LOCATION_POLICY": "ARMED",
        }.get(expectation.get("route"))
        if result.get("action") != expected_action:
            raise SemanticOracleError("mission dispatch effect differs from clean scenario")
        mission_key = (
            f"{expectation['missionKey']}|{expectation['missionPhase']}|"
            f"{expectation['nativeActionOrdinal']}"
        )
        applied = after.get("appliedMissionActions")
        if not isinstance(applied, dict) or applied.get(mission_key) != {
            key: result[key] for key in result if key not in {"schema", "sequence", "trigger"}
        }:
            raise SemanticOracleError("mission dispatch durable state differs")
        return {
            "protocol": "miel-vliegt-scene-dispatch-semantic-state",
            "variant": evidence_class,
            "trigger": trigger,
            "predicates": [],
            "effect": {
                "selection": "MISSION_ACTION_SELECTED",
                "route": expectation["route"],
                "artifactKey": expectation["artifactKey"],
            },
        }
    if evidence_class != "LOCATION_POLICY":
        raise SemanticOracleError("scene dispatch evidence class is unsupported")
    selector = expectation.get("selector")
    location_id = expectation.get("locationId")
    artifact_key = expectation.get("artifactKey")
    if result.get("route") != "GROUND" or result.get("locationId") != location_id \
            or result.get("artifactKey") != artifact_key:
        raise SemanticOracleError("location policy selected the wrong root")
    predicates: list[str] = []
    if selector.startswith("LOCATION_ENTER_"):
        if event != {"trigger": "LOCATION_ENTER", "locationId": location_id}:
            raise SemanticOracleError("location policy entry trigger differs")
        predicates.append("LOCATION_ENTER")
    else:
        if event != {
            "trigger": "DERIVED_STATE", "kind": "ROOT_COMPLETE",
            "route": "GROUND", "locationId": location_id,
        }:
            raise SemanticOracleError("location policy completion trigger differs")
        predicates.append("ROOT_COMPLETE")
    final_state = before.get("finalMissionState")
    exhibition = before.get("exhibition")
    raymond = before.get("raymond")
    grotte = before.get("grotte")
    checks = {
        "FINAL_MISSION_STATE_NE_3": final_state != 3,
        "FINAL_MISSION_STATE_EQ_3": final_state == 3,
        "FIRST_CHALLENGE": isinstance(raymond, dict) and raymond.get("firstChallenge") is True,
        "SUBSEQUENT_CHALLENGE": isinstance(raymond, dict) and raymond.get("firstChallenge") is False,
        "CHALLENGE_RESULT_EQ_2": isinstance(raymond, dict) and raymond.get("challengeResult") == 2,
        "CHALLENGE_RESULT_NE_2": isinstance(raymond, dict) and raymond.get("challengeResult") != 2,
        "REFUEL_ARMED": isinstance(grotte, dict) and grotte.get("refuelArmed") is True,
        "REFUEL_UNCONSUMED": isinstance(grotte, dict) and grotte.get("refuelConsumed") is False,
        "OUTRO_FALSE": isinstance(exhibition, dict) and exhibition.get("outroRequested") is False,
        "OUTRO_REQUESTED": isinstance(exhibition, dict) and exhibition.get("outroRequested") is True,
        "PROJECTED_X_LT_900": isinstance(exhibition, dict) and _is_number(exhibition.get("projectedMapX")) and exhibition["projectedMapX"] < 900,
        "PROJECTED_X_GTE_900": isinstance(exhibition, dict) and _is_number(exhibition.get("projectedMapX")) and exhibition["projectedMapX"] >= 900,
        "PROJECTED_X_LT_2200": isinstance(exhibition, dict) and _is_number(exhibition.get("projectedMapX")) and exhibition["projectedMapX"] < 2200,
        "PROJECTED_X_GTE_2200": isinstance(exhibition, dict) and _is_number(exhibition.get("projectedMapX")) and exhibition["projectedMapX"] >= 2200,
        "EXPECTED_UDSP_ABSENCE": artifact_key is None and result.get("action") == "EXPECTED_ABSENCE",
    }
    selector_predicates = {
        "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3": ["FINAL_MISSION_STATE_NE_3"],
        "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3": ["FINAL_MISSION_STATE_EQ_3"],
        "ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED": ["REFUEL_ARMED", "REFUEL_UNCONSUMED"],
        "LOCATION_ENTER_FIRST_CHALLENGE": ["FIRST_CHALLENGE"],
        "LOCATION_ENTER_SUBSEQUENT_CHALLENGE": ["SUBSEQUENT_CHALLENGE"],
        "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2": ["CHALLENGE_RESULT_EQ_2"],
        "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2": ["CHALLENGE_RESULT_NE_2"],
        "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900": ["OUTRO_FALSE", "PROJECTED_X_LT_900"],
        "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_NE_3": ["OUTRO_FALSE", "PROJECTED_X_GTE_900", "PROJECTED_X_LT_2200", "FINAL_MISSION_STATE_NE_3"],
        "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_NE_3": ["OUTRO_FALSE", "PROJECTED_X_GTE_2200", "FINAL_MISSION_STATE_NE_3"],
        "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_EQ_3": ["OUTRO_FALSE", "PROJECTED_X_GTE_900", "PROJECTED_X_LT_2200", "FINAL_MISSION_STATE_EQ_3"],
        "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_EQ_3": ["OUTRO_FALSE", "PROJECTED_X_GTE_2200", "FINAL_MISSION_STATE_EQ_3"],
        "LOCATION_ENTER_OUTRO_REQUESTED": ["OUTRO_REQUESTED"],
        "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE": ["EXPECTED_UDSP_ABSENCE"],
    }.get(selector)
    if selector_predicates is None or any(not checks[name] for name in selector_predicates):
        raise SemanticOracleError("location policy selector predicates differ")
    predicates.extend(selector_predicates)
    active = after.get("locations", {}).get(str(location_id))
    if not isinstance(active, dict) or active.get("activeRoot") != artifact_key:
        raise SemanticOracleError("location policy durable state differs")
    return {
        "protocol": "miel-vliegt-scene-dispatch-semantic-state",
        "variant": evidence_class,
        "trigger": {"locationId": location_id, "selector": selector},
        "predicates": predicates,
        "effect": {
            "selection": "EXPECTED_UDSP_ABSENCE_CONFIRMED" if artifact_key is None else "EXPECTED_ROOT_ARTIFACT_SELECTED",
            "outcome": expectation["outcome"],
            "artifactKey": artifact_key,
        },
    }


def _normalize_dispatch_trace(
    document: dict[str, Any], producer: str, expected_expectation: dict[str, Any] | None,
    executable: dict[str, Any], executable_source_bytes: bytes | None,
) -> dict[str, Any]:
    if document["evidenceMode"] != "PRODUCTION" or not isinstance(expected_expectation, dict):
        raise SemanticOracleError("dispatch semantic trace requires a production expectation")
    _validate_production_executable_binding(
        document, executable, executable_source_bytes,
    )
    if document.get("artifactKey") != expected_expectation.get("artifactKey"):
        raise SemanticOracleError("dispatch semantic artifact differs from expectation")
    artifact_key = document.get("artifactKey")
    if artifact_key is not None:
        script = _script_index(executable).get(artifact_key)
        if script is None or canonical_sha256(script) != document.get("executableScriptSha256"):
            raise SemanticOracleError("dispatch executable script binding differs")
    receipts = document.get("receipts") if producer == "WEB" else document.get("events")
    if not isinstance(receipts, list) or not receipts:
        raise SemanticOracleError("dispatch semantic receipts are empty")
    evidence_class = document["evidenceClass"]
    if evidence_class == "MISSION_DISPATCH":
        expected_event = {
            "trigger": "MISSION_ACTION",
            **{
                key: expected_expectation[key]
                for key in ("missionKey", "missionPhase", "nativeActionOrdinal")
            },
        }
    else:
        selector = expected_expectation.get("selector", "")
        location_id = expected_expectation.get("locationId")
        expected_event = (
            {"trigger": "LOCATION_ENTER", "locationId": location_id}
            if selector.startswith("LOCATION_ENTER_") else
            {
                "trigger": "DERIVED_STATE", "kind": "ROOT_COMPLETE",
                "route": "GROUND", "locationId": location_id,
            }
        )
    candidates = [
        receipt for receipt in receipts
        if isinstance(receipt, dict) and receipt.get("event") == expected_event
    ]
    if len(candidates) != 1:
        raise SemanticOracleError("dispatch semantic claim does not select exactly one receipt")
    state = _dispatch_state(document, expected_expectation, candidates[0])
    return _trace(document, producer, [_normalized_observation(document, 0, state)])


def normalize_web_trace(
    document: dict[str, Any], executable: dict[str, Any],
    expected_identity: dict[str, Any] | None = None,
    *, executable_source_bytes: bytes | None = None,
    source_artifact: dict[str, Any] | None = None,
    source_artifact_bytes: bytes | None = None,
    expected_expectation: dict[str, Any] | None = None,
    expected_capture_provenance: dict[str, Any] | None = None,
    expected_authenticated_producer_build_sha256: str | None = None,
    expected_audio_asset_sha256: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Normalize actual schema-1 :class:`UdspSceneRuntime` receipts."""

    dispatch = isinstance(document, dict) \
        and document.get("evidenceClass") in PRODUCTION_DISPATCH_EVIDENCE_CLASSES
    source_route = isinstance(document, dict) \
        and document.get("protocol") == WEB_SOURCE_RAW_PROTOCOL
    production_body = isinstance(document, dict) \
        and document.get("evidenceMode") == "PRODUCTION" \
        and document.get("evidenceClass") in PRODUCTION_UDSP_EVIDENCE_CLASSES
    expected_fields = (
        WEB_DISPATCH_DOCUMENT_FIELDS
        if dispatch
        else WEB_SOURCE_DOCUMENT_FIELDS
        if source_route
        else WEB_EXECUTABLE_DOCUMENT_FIELDS
        if production_body
        else WEB_DOCUMENT_FIELDS
    )
    if production_body and isinstance(document, dict) \
            and AUTHENTICATED_EVIDENCE_FIELD in document:
        expected_fields = expected_fields | {AUTHENTICATED_EVIDENCE_FIELD}
    expected_protocol = (
        WEB_SOURCE_RAW_PROTOCOL if source_route else WEB_RAW_PROTOCOL
    )
    if not isinstance(document, dict) or set(document) != expected_fields \
            or document.get("schema") != 1 \
            or document.get("protocol") != expected_protocol:
        raise SemanticOracleError("web semantic document fields differ")
    _validate_identity(document, "WEB")
    _validate_expected_identity(document, expected_identity)
    if document["evidenceClass"] in PRODUCTION_DISPATCH_EVIDENCE_CLASSES:
        _validate_web_dispatch_capture_provenance(
            document, expected_capture_provenance,
        )
        _reject_raw_pointers(document)
        return _normalize_dispatch_trace(
            document, "WEB", expected_expectation, executable, executable_source_bytes,
        )
    _validate_production_executable_binding(
        document, executable, executable_source_bytes
    )
    if source_route:
        if document["evidenceClass"] != "UDSP_SCRIPT_BODY":
            raise SemanticOracleError(
                "web source protocol is not a source-body claim"
            )
        _validate_production_source_binding(
            document,
            source_artifact,
            source_artifact_bytes,
            executable,
            expected_expectation,
        )
    elif document["evidenceMode"] == "PRODUCTION" \
            and document["evidenceClass"] != "UDSP_EXECUTABLE_BODY":
        raise SemanticOracleError(
            "web executable protocol is not an executable-body claim"
        )
    _reject_raw_pointers(document)
    scripts = _script_index(executable)
    entry_script = scripts.get(document["artifactKey"])
    if entry_script is None:
        raise SemanticOracleError("web semantic artifactKey is unknown")
    if canonical_sha256(entry_script) != document["executableScriptSha256"]:
        raise SemanticOracleError("web executable script hash mismatch")
    receipts = document.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        raise SemanticOracleError("web semantic receipts are empty")
    if document["evidenceMode"] == "PRODUCTION":
        _validate_execution_occurrences(
            document,
            receipts,
            "SOURCE_ARTIFACT_LOWERED_RUNTIME"
            if source_route else "EXECUTABLE_ARTIFACT_RUNTIME",
        )
        _validate_authenticated_evidence(
            document,
            receipts,
            expected_producer_build_sha256=(
                expected_authenticated_producer_build_sha256
            ),
            expected_audio_asset_sha256=expected_audio_asset_sha256,
        )
    observations = []
    for sequence, receipt in enumerate(receipts):
        if not isinstance(receipt, dict) or receipt.get("schema") != 1 \
                or not _is_int(receipt.get("sequence")) \
                or receipt["sequence"] != sequence + 1 \
                or receipt.get("semanticStatus") != "UNPROVEN":
            raise SemanticOracleError("web UdspSceneRuntime receipt identity differs")
        state = (
            _normalize_failure_receipt(receipt, document, scripts)
            if "failure" in receipt
            else _normalize_success_receipt(receipt, document, scripts)
        )
        observations.append(_normalized_observation(document, sequence, state))
    return _trace(document, "WEB", observations)


def normalize_native_trace(
    document: dict[str, Any], executable: dict[str, Any],
    expected_identity: dict[str, Any] | None = None,
    *, executable_source_bytes: bytes | None = None,
    expected_expectation: dict[str, Any] | None = None,
    expected_capture_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize independently observed native command lifecycle facts."""

    expected_fields = NATIVE_DOCUMENT_FIELDS | (
        {"captureProvenance"}
        if isinstance(document, dict) and
        document.get("evidenceClass") in PRODUCTION_DISPATCH_EVIDENCE_CLASSES
        else set()
    )
    if not isinstance(document, dict) or set(document) != expected_fields \
            or document.get("schema") != 1 or document.get("protocol") != NATIVE_RAW_PROTOCOL:
        raise SemanticOracleError("native semantic document fields differ")
    _validate_identity(document, "NATIVE")
    _validate_expected_identity(document, expected_identity)
    if document["evidenceClass"] in PRODUCTION_DISPATCH_EVIDENCE_CLASSES:
        provenance = document.get("captureProvenance")
        if not isinstance(provenance, dict) \
                or set(provenance) != NATIVE_DISPATCH_CAPTURE_PROVENANCE_FIELDS \
                or provenance != expected_capture_provenance:
            raise SemanticOracleError("native dispatch capture provenance differs")
        if provenance.get("schema") != 1 \
                or not isinstance(provenance.get("jobId"), str) \
                or type(provenance.get("nativeProcessId")) is not int \
                or provenance["nativeProcessId"] <= 0 \
                or not isinstance(provenance.get("captureSessionId"),str) \
                or re.fullmatch(r"mvds-[0-9a-f]{32}",
                                provenance["captureSessionId"]) is None \
                or provenance.get("nativeSliceId") != \
                f"native-slice:{provenance.get('nativeSliceSha256')}":
            raise SemanticOracleError("native dispatch capture provenance is invalid")
        for field in NATIVE_DISPATCH_CAPTURE_PROVENANCE_FIELDS - {
            "schema", "jobId", "nativeSliceId", "nativeProcessId",
            "captureSessionId",
        }:
            _require_sha(provenance.get(field), f"native dispatch provenance {field}")
        _reject_raw_pointers(document)
        capabilities = document.get("hookCapabilities")
        if not isinstance(capabilities, dict) \
                or set(capabilities) != NATIVE_DISPATCH_CAPABILITY_FIELDS \
                or any(type(value) is not bool for value in capabilities.values()):
            raise SemanticOracleError("native dispatch hook capability receipt fields differ")
        missing = sorted(name for name, available in capabilities.items() if not available)
        if missing:
            if document.get("supportStatus") != "UNSUPPORTED_HOOK_FACTS":
                raise SemanticOracleError("native dispatch support status differs")
            raise SemanticOracleUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:" + ",".join(missing)
            )
        if document.get("supportStatus") != NATIVE_SUPPORTED_STATUS:
            raise SemanticOracleError("native dispatch support status differs")
        return _normalize_dispatch_trace(
            document, "NATIVE", expected_expectation, executable, executable_source_bytes,
        )
    _validate_production_executable_binding(
        document, executable, executable_source_bytes
    )
    _reject_raw_pointers(document)
    capabilities = document.get("hookCapabilities")
    if not isinstance(capabilities, dict) or set(capabilities) != NATIVE_CAPABILITY_FIELDS \
            or any(type(value) is not bool for value in capabilities.values()):
        raise SemanticOracleError("native hook capability receipt fields differ")
    missing = sorted(name for name, available in capabilities.items() if not available)
    events = document.get("events")
    if not isinstance(events, list):
        raise SemanticOracleError("native raw events are invalid")
    if missing:
        if document.get("supportStatus") != "UNSUPPORTED_HOOK_FACTS":
            raise SemanticOracleError("native hook support status differs from capabilities")
        # Incomplete hooks remain fail-closed and their event labels are never
        # inspected, so a producer cannot smuggle a normalized result through
        # an unsupported capability receipt.
        raise SemanticOracleUnsupported(
            "UNSUPPORTED_HOOK_FACTS:" + ",".join(missing)
        )
    if document.get("supportStatus") != NATIVE_SUPPORTED_STATUS or not events:
        raise SemanticOracleError("native hook support status differs from capabilities")
    scripts = _script_index(executable)
    entry_script = scripts.get(document["artifactKey"])
    if entry_script is None:
        raise SemanticOracleError("native semantic artifactKey is unknown")
    if canonical_sha256(entry_script) != document["executableScriptSha256"]:
        raise SemanticOracleError("native executable script hash mismatch")
    observations = []
    for sequence, event in enumerate(events):
        if not isinstance(event, dict) or event.get("sequence") != sequence + 1:
            raise SemanticOracleError("native semantic event sequence differs")
        event_kind = event.get("event")
        expected_fields = (
            NATIVE_FAILURE_EVENT_FIELDS
            if event_kind == "COMMAND_FAILURE" else NATIVE_SUCCESS_EVENT_FIELDS
            if event_kind == "COMMAND" else None
        )
        if expected_fields is None or set(event) != expected_fields:
            raise SemanticOracleError("native semantic event fields differ")
        receipt = copy.deepcopy(event)
        receipt.pop("event")
        receipt["script"] = receipt.pop("scriptKey")
        receipt["semanticStatus"] = "UNPROVEN"
        state = (
            _normalize_failure_receipt(receipt, document, scripts)
            if event_kind == "COMMAND_FAILURE"
            else _normalize_success_receipt(receipt, document, scripts)
        )
        observations.append(_normalized_observation(document, sequence, state))
    return _trace(document, "NATIVE", observations)


def _validate_normalized_trace(trace: Any) -> None:
    if not isinstance(trace, dict) or set(trace) != NORMALIZED_TRACE_FIELDS \
            or trace.get("schema") != 1 or trace.get("protocol") != NORMALIZED_TRACE_PROTOCOL:
        raise SemanticOracleError("normalized trace fields differ")
    _validate_identity(trace, trace.get("producer"))
    if trace.get("producer") not in {"NATIVE", "WEB"}:
        raise SemanticOracleError("normalized trace producer is invalid")
    observations = trace.get("observations")
    if not isinstance(observations, list) or not observations:
        raise SemanticOracleError("normalized observations are empty")
    for sequence, observation in enumerate(observations):
        if not isinstance(observation, dict) or set(observation) != NORMALIZED_OBSERVATION_FIELDS \
                or observation.get("schema") != 1 \
                or observation.get("record") != "semantic_observation" \
                or observation.get("sequence") != sequence:
            raise SemanticOracleError("normalized observation fields differ")
        if any(observation.get(field) != trace[field] for field in (
            "claimId", "evidenceClass", "subjectSha256", "expectationSha256",
        )):
            raise SemanticOracleError("normalized observation identity differs")
        _validate_normalized_state(observation.get("state"))


def _first_divergence(native: Any, web: Any, path: str = "$.observations") -> dict[str, Any] | None:
    if type(native) is not type(web):
        return {"path": path, "native": native, "web": web}
    if isinstance(native, dict):
        for key in sorted(set(native) | set(web)):
            if key not in native or key not in web:
                return {
                    "path": f"{path}.{key}",
                    "native": native.get(key, {"missing": True}),
                    "web": web.get(key, {"missing": True}),
                }
            found = _first_divergence(native[key], web[key], f"{path}.{key}")
            if found is not None:
                return found
        return None
    if isinstance(native, list):
        for index in range(max(len(native), len(web))):
            if index >= len(native) or index >= len(web):
                return {
                    "path": f"{path}[{index}]",
                    "native": native[index] if index < len(native) else {"missing": True},
                    "web": web[index] if index < len(web) else {"missing": True},
                }
            found = _first_divergence(native[index], web[index], f"{path}[{index}]")
            if found is not None:
                return found
        return None
    if native != web:
        return {"path": path, "native": native, "web": web}
    return None


def compare_normalized_traces(
    native: dict[str, Any], web: dict[str, Any],
) -> dict[str, Any]:
    """Compare normalized traces without claiming release-eligible parity."""

    _validate_normalized_trace(native)
    _validate_normalized_trace(web)
    if native["producer"] != "NATIVE" or web["producer"] != "WEB":
        raise SemanticOracleError("differential inputs have wrong producers")
    for field in NORMALIZED_TRACE_FIELDS - {"producer", "observations"}:
        if native[field] != web[field]:
            raise SemanticOracleError(f"differential trace identity differs: {field}")
    divergence = _first_divergence(native["observations"], web["observations"])
    matched = divergence is None
    return {
        "schema": 1,
        "protocol": DIFFERENTIAL_PROTOCOL,
        "result": (
            "TEST_ONLY_MATCH" if matched and native["evidenceMode"] == "TEST_ONLY"
            else "PRODUCTION_MATCH_UNREVIEWED" if matched else "DIFFER"
        ),
        "parityEligible": False,
        "evidenceMode": native["evidenceMode"],
        "claimId": native["claimId"],
        "edition": native["edition"],
        "sourceHashes": copy.deepcopy(native["sourceHashes"]),
        "nativeTraceSha256": canonical_sha256(native),
        "webTraceSha256": canonical_sha256(web),
        "observationCount": len(native["observations"]) if matched else None,
        "firstDivergence": divergence,
    }
