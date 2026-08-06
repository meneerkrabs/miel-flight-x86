#!/usr/bin/env python3
"""Fail-closed parser for native dispatch semantic producer records.

The Win32 producer emits receipts only; this host boundary binds each receipt
to the generated coverage ledger and executable UDSP artifact.  A compile, a
static hook map, or an event without the complete runtime CAPABILITY record can
never become ``SUPPORTED_HOOK_FACTS``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.miel_vliegt import scene_semantic_evidence_batches as batches
    from tools.miel_vliegt import scene_semantic_coverage as coverage
    from tools.miel_vliegt import udsp_semantic_oracle as oracle
    from tools.miel_vliegt import native_dispatch_capture_job as capture_jobs
    from tools.miel_vliegt.native_dispatch_hook_contract import (
        EDITION,
        EXECUTABLE_SHA256,
        SELECTORS,
        producer_build_sha256,
    )
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import scene_semantic_evidence_batches as batches
    import scene_semantic_coverage as coverage
    import udsp_semantic_oracle as oracle
    import native_dispatch_capture_job as capture_jobs
    from native_dispatch_hook_contract import (
        EDITION, EXECUTABLE_SHA256, SELECTORS, producer_build_sha256,
    )


WIRE_PREFIX = "MVDS "
WIRE_PROTOCOL = "miel-vliegt-native-dispatch-semantic-wire"
HOOK_NAMES = (
    "MISSION_FILE_PARSE", "MISSION_INSERT", "MISSION_ACTION_EXECUTE",
    "ACTION_GROUND", "ACTION_BARN", "ACTION_FLIGHT", "ACTION_OUTRO",
    "ACTION_OUTRO_COMMIT", "UDSP_ROOT_FACTORY", "GENERIC_LOCATION_ENTER",
    "GENERIC_FINAL_MISSION_PRESENT", "GENERIC_FINAL_TRUE",
    "GROTTE_STATE_SETTER", "GROTTE_REFUEL_BRANCH",
    "RAYMOND_LOCATION_LOAD", "RAYMOND_FIRST_BRANCH", "RAYMOND_STATE_SETTER",
    "RAYMOND_RESULT_BRANCH", "EXHIBITION_STATE_SETTER", "EXHIBITION_PROJECTION",
    "EXHIBITION_LT_900", "EXHIBITION_LT_900_SELECTED", "EXHIBITION_LT_2200",
    "EXHIBITION_LT_2200_SELECTED", "EXHIBITION_LT_2200_FINAL_TRUE",
    "EXHIBITION_GTE_2200", "EXHIBITION_GTE_2200_FINAL_TRUE",
    "EXHIBITION_FINAL_FALSE",
    "EXHIBITION_OUTRO", "MYGGHANGET_ENTER",
)
HOOK_COUNT = len(HOOK_NAMES)
FORWARDED_ROUTE_HOOKS = (
    "SCENE_DISPATCH_GROUND", "SCENE_DISPATCH_BARN", "SCENE_DISPATCH_FLIGHT",
)
DISPATCH_CAPABILITIES = {
    "triggerIdentity", "selectorPredicates", "route", "artifact",
    "stateBefore", "stateAfter",
}
CAPABILITY_FIELDS = {
    "schema", "protocol", "record", "executableSha256", "runtimeCapture",
    "routeForwarding", "engineThread", "installedHookCount", "capabilities",
    "installedHookMask", "installedHooks",
    "forwardedRouteHooks",
    "producerBuildSha256",
    "capturePlanJobId", "nativeSliceSha256", "observerBinarySha256",
    "observerBuildReceiptSha256",
    "nativeProcessId", "captureSessionId",
    "targetSha256", "jobSha256", "claimId", "claimSha256",
    "subjectSha256", "expectationSha256", "scenarioSha256",
    "capturePlanSha256", "planManifestSha256", "evidenceClass",
}
EVENT_COMMON_FIELDS = {
    "schema", "protocol", "record", "executableSha256", "thread",
    "nativeProcessId", "captureSessionId", "evidenceClass", "receipt",
}
CAPTURE_BINDING_FIELDS = {
    "capturePlanJobId", "nativeSliceSha256", "observerBinarySha256",
    "observerBuildReceiptSha256",
    "capturePlanPath", "capturePlanSha256", "observerBinaryPath",
    "observerBuildReceiptPath",
}
CAPABILITY_PROVENANCE_FIELDS = {
    "capturePlanJobId", "nativeSliceSha256", "observerBinarySha256",
    "observerBuildReceiptSha256",
}
TARGET_CAPABILITY_FIELDS = {
    "targetSha256", "jobSha256", "claimId", "claimSha256",
    "subjectSha256", "expectationSha256", "scenarioSha256",
    "capturePlanSha256", "planManifestSha256", "evidenceClass",
}
BUILD_RECEIPT_FIELDS = {
    "schema", "protocol", "capturePlanJobId", "nativeSliceSha256",
    "observerBinarySha256", "producerBuildSha256",
}
DRIVER_BUILD_RECEIPT_FIELDS = BUILD_RECEIPT_FIELDS | {
    "captureDriverFoundation",
}
DRIVER_BUILD_FOUNDATION = {
    "profile": "NATIVE_DISPATCH_DRIVER_V2",
    "profileSha256":
        "72925be976520350aec44c45861e5f0af1bcaaef0f33fe605f42d6d415c0cd68",
    "scenarioSha256":
        "1435350feab7bfe92840bc8be305f13a6daf539173674e0b1bab8553c7b9b165",
    "initialUserSha256":
        "7019275a9489a2d078f2cb38425f852dd2c019295e401ba4a58cbd67566555d6",
}
BUILD_RECEIPT_PROTOCOL = "miel-vliegt-native-dispatch-observer-build-receipt"
SHA256 = re.compile(r"[0-9a-f]{64}")
CAPTURE_SESSION_ID = re.compile(r"mvds-[0-9a-f]{32}")
F32_BITS = re.compile(r"0x[0-9a-f]{8}")
UNTRUSTED_EVIDENCE_MODE = "UNTRUSTED_CANDIDATE"
NATIVE_TRACE_REQUIRED = "NATIVE_TRACE_REQUIRED"


def required_semantic_hooks(target: dict[str, Any]) -> tuple[str, ...]:
    """Return the ordered, exact producer detours for one compiled target."""

    trigger = target.get("trigger")
    if not isinstance(trigger, dict):
        raise NativeDispatchWireError("capture target trigger differs")
    if target.get("evidenceClass") == "MISSION_DISPATCH":
        family = trigger.get("actionHookFamily")
        if family not in {
            "ACTION_GROUND", "ACTION_BARN", "ACTION_FLIGHT", "ACTION_OUTRO",
        }:
            raise NativeDispatchWireError("mission action hook family differs")
        required = {
            "MISSION_FILE_PARSE", "MISSION_INSERT", "MISSION_ACTION_EXECUTE",
            "UDSP_ROOT_FACTORY", family,
        }
        if family == "ACTION_OUTRO":
            required.add("ACTION_OUTRO_COMMIT")
    elif target.get("evidenceClass") == "LOCATION_POLICY":
        selector = trigger.get("selector")
        spec = SELECTORS.get(selector) if isinstance(selector, str) else None
        if not isinstance(spec, dict) or not isinstance(spec.get("probes"), list):
            raise NativeDispatchWireError("location selector hook plan differs")
        required = {name for name in spec["probes"] if name in HOOK_NAMES}
    else:
        raise NativeDispatchWireError("capture target evidence class differs")
    ordered = tuple(name for name in HOOK_NAMES if name in required)
    if not ordered or set(ordered) != required:
        raise NativeDispatchWireError("capture target hook plan is incomplete")
    return ordered


def target_uses_exact_location_driver(target: dict[str, Any]) -> bool:
    trigger = target.get("trigger")
    return isinstance(trigger, dict) \
        and target.get("evidenceClass") == "LOCATION_POLICY" \
        and trigger.get("selector") == "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3" \
        and trigger.get("selectorHookFamily") == "GENERIC_LOCATION_ENTER"


def forwarded_route_hooks_for_target(target: dict[str, Any]) -> tuple[str, ...]:
    return () if target_uses_exact_location_driver(target) else FORWARDED_ROUTE_HOOKS


def semantic_hook_mask(hooks: Iterable[str]) -> str:
    selected = set(hooks)
    if not selected.issubset(HOOK_NAMES):
        raise NativeDispatchWireError("semantic hook mask contains an unknown hook")
    mask = sum(1 << index for index, name in enumerate(HOOK_NAMES)
               if name in selected)
    return f"0x{mask:08x}"


class NativeDispatchWireError(ValueError):
    """The runtime stream cannot support an exact semantic claim."""


class NativeDispatchWireUnsupported(NativeDispatchWireError):
    """No complete runtime capability receipt was observed."""


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        source = path.read_bytes()
        value = json.loads(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDispatchWireError(f"cannot load {label}: {path}") from error
    if not isinstance(value, dict):
        raise NativeDispatchWireError(f"{label} is not an object")
    return value, source


def _resolve_artifact_path(value: str, evidence_root: Path = coverage.ROOT) -> Path:
    path = Path(value)
    root = evidence_root.resolve()
    if not root.is_dir():
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:EVIDENCE_ROOT_UNAVAILABLE"
        )
    if path.is_absolute() or "\\" in value or not value \
            or any(part in {"", ".", ".."} for part in path.parts):
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:ARTIFACT_PATH_NOT_REPOSITORY_RELATIVE"
        )
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:ARTIFACT_PATH_ESCAPES_REPOSITORY"
        ) from error
    return resolved


def _artifact_bytes(
    path_text: str, expected_sha: str, label: str, evidence_root: Path,
) -> bytes:
    path = _resolve_artifact_path(path_text,evidence_root)
    try:
        source = path.read_bytes()
    except OSError as error:
        raise NativeDispatchWireUnsupported(
            f"UNSUPPORTED_DISPATCH_HOOK_FACTS:{label}_UNAVAILABLE"
        ) from error
    if hashlib.sha256(source).hexdigest() != expected_sha:
        raise NativeDispatchWireUnsupported(
            f"UNSUPPORTED_DISPATCH_HOOK_FACTS:{label}_HASH_DIFFERS"
        )
    return source


def _validate_capture_binding(
    value: Any, evidence_root: Path,
) -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != CAPTURE_BINDING_FIELDS:
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:BINARY_BUILD_RECEIPT_REQUIRED"
        )
    job = value.get("capturePlanJobId")
    if not isinstance(job, str) or not job or not job.isascii() \
            or any(not (char.isalnum() or char in "_./:-#") for char in job):
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPTURE_PLAN_JOB_INVALID"
        )
    for field in CAPABILITY_PROVENANCE_FIELDS - {"capturePlanJobId"} | {"capturePlanSha256"}:
        if not isinstance(value.get(field), str) or SHA256.fullmatch(value[field]) is None:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:BINARY_BUILD_RECEIPT_INVALID"
            )
    for field in ("capturePlanPath", "observerBinaryPath", "observerBuildReceiptPath"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:PROVENANCE_ARTIFACT_PATH_INVALID"
            )
    plan_source = _artifact_bytes(
        value["capturePlanPath"], value["capturePlanSha256"], "CAPTURE_PLAN",
        evidence_root,
    )
    try:
        plan = json.loads(plan_source)
        batches.validate_plan(plan)
    except (json.JSONDecodeError, batches.SemanticEvidenceBatchError) as error:
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPTURE_PLAN_INVALID"
        ) from error
    jobs = [
        job for batch in plan["batches"] for job in batch["jobs"]
        if job.get("id") == value["capturePlanJobId"]
    ]
    if len(jobs) != 1:
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPTURE_PLAN_JOB_NOT_UNIQUE"
        )
    job = jobs[0]
    native_slices = [
        row for row in job.get("captureSlices", []) if row.get("producer") == "NATIVE"
    ]
    expected_slice_id = f"native-slice:{value['nativeSliceSha256']}"
    if len(native_slices) != 1 or native_slices[0].get("sliceId") != expected_slice_id:
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:NATIVE_SLICE_DIFFERS"
        )
    _artifact_bytes(
        value["observerBinaryPath"], value["observerBinarySha256"], "OBSERVER_BINARY",
        evidence_root,
    )
    receipt_source = _artifact_bytes(
        value["observerBuildReceiptPath"], value["observerBuildReceiptSha256"],
        "OBSERVER_BUILD_RECEIPT", evidence_root,
    )
    try:
        receipt = json.loads(receipt_source)
    except json.JSONDecodeError as error:
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:OBSERVER_BUILD_RECEIPT_INVALID"
        ) from error
    expected_receipt = {
        "schema": 1,
        "protocol": BUILD_RECEIPT_PROTOCOL,
        "capturePlanJobId": value["capturePlanJobId"],
        "nativeSliceSha256": value["nativeSliceSha256"],
        "observerBinarySha256": value["observerBinarySha256"],
        "producerBuildSha256": producer_build_sha256(),
    }
    if isinstance(receipt, dict) and "captureDriverFoundation" in receipt:
        expected_receipt["captureDriverFoundation"] = DRIVER_BUILD_FOUNDATION
    if not isinstance(receipt, dict) \
            or (set(receipt) != BUILD_RECEIPT_FIELDS and
                set(receipt) != DRIVER_BUILD_RECEIPT_FIELDS) \
            or receipt != expected_receipt:
        raise NativeDispatchWireUnsupported(
            "UNSUPPORTED_DISPATCH_HOOK_FACTS:OBSERVER_BUILD_RECEIPT_INVALID"
        )
    return value, job, plan


def _reject_json_constant(value: str) -> None:
    raise NativeDispatchWireError(f"MVDS JSON constant is forbidden: {value}")


def _normalize_f32_bits(event: dict[str, Any]) -> None:
    if event.get("evidenceClass") != "LOCATION_POLICY":
        return
    receipt = event.get("receipt")
    before = receipt.get("before") if isinstance(receipt, dict) else None
    exhibition = before.get("exhibition") if isinstance(before, dict) else None
    if not isinstance(exhibition, dict) or "projectedMapXBits" not in exhibition \
            or "projectedMapX" in exhibition:
        return
    encoded = exhibition.pop("projectedMapXBits")
    if encoded is None:
        exhibition["projectedMapX"] = None
        return
    if not isinstance(encoded, str) or F32_BITS.fullmatch(encoded) is None:
        raise NativeDispatchWireError("projectedMapXBits is not canonical f32 bits")
    value = struct.unpack("<f", int(encoded[2:], 16).to_bytes(4, "little"))[0]
    if not math.isfinite(value):
        raise NativeDispatchWireError("projectedMapXBits is non-finite")
    exhibition["projectedMapX"] = value


def _script_index(executable: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for script in executable.get("scripts", []):
        if not isinstance(script, dict):
            raise NativeDispatchWireError("executable script inventory is invalid")
        try:
            key = f"{script['type']}:{script['domainId']}/{script['dispatchId']}"
        except KeyError as error:
            raise NativeDispatchWireError("executable script identity is invalid") from error
        if key in result:
            raise NativeDispatchWireError(f"duplicate executable script: {key}")
        result[key] = script
    return result


def _source_hashes(ledger: dict[str, Any]) -> dict[str, str]:
    sources = ledger.get("sources")
    if not isinstance(sources, dict):
        raise NativeDispatchWireError("coverage source pins are absent")
    try:
        return {
            name: sources[name]["sha256"]
            for name in (
                "sceneDispatchContract", "udsSceneScripts",
                "executableUdspSceneScripts",
            )
        }
    except (KeyError, TypeError) as error:
        raise NativeDispatchWireError("coverage source pins are invalid") from error


def _expected_identity(
    ledger: dict[str, Any], record: dict[str, Any],
) -> dict[str, Any]:
    return {
        "edition": ledger["edition"],
        "claimId": record["id"],
        "evidenceClass": record["evidenceClass"],
        "sourceHashes": _source_hashes(ledger),
        "subjectSha256": coverage.evidence_subject_sha256(record),
        "expectationSha256": coverage.evidence_expectation_sha256(record),
    }


def _event_identity(event: dict[str, Any]) -> tuple[Any, ...]:
    receipt = event.get("receipt")
    if not isinstance(receipt, dict):
        raise NativeDispatchWireError("EVENT receipt is invalid")
    trigger = receipt.get("event")
    result = receipt.get("result")
    if not isinstance(trigger, dict) or not isinstance(result, dict):
        raise NativeDispatchWireError("EVENT trigger/result is invalid")
    evidence_class = event.get("evidenceClass")
    if evidence_class == "MISSION_DISPATCH":
        return (
            evidence_class, trigger.get("missionKey"),
            trigger.get("missionPhase"), trigger.get("nativeActionOrdinal"),
            result.get("route"), result.get("artifactKey"),
        )
    if evidence_class == "LOCATION_POLICY":
        return (
            evidence_class, event.get("selector"), result.get("locationId"),
            result.get("artifactKey"),
        )
    raise NativeDispatchWireError("EVENT evidenceClass is unsupported")


def _expectation_identity(record: dict[str, Any]) -> tuple[Any, ...]:
    expectation = record["expectation"]
    evidence_class = record["evidenceClass"]
    if evidence_class == "MISSION_DISPATCH":
        return (
            evidence_class, expectation.get("missionKey"),
            expectation.get("missionPhase"),
            expectation.get("nativeActionOrdinal"), expectation.get("route"),
            expectation.get("artifactKey"),
        )
    return (
        evidence_class, expectation.get("selector"), expectation.get("locationId"),
        expectation.get("artifactKey"),
    )


class NativeDispatchWireParser:
    """Incremental parser that accepts noisy observer stdout safely."""

    def __init__(
        self,
        *,
        ledger_path: Path = coverage.DEFAULT_LEDGER,
        executable_path: Path = coverage.DEFAULT_EXECUTABLE,
        capture_binding: dict[str, str] | None = None,
        evidence_root: Path = coverage.ROOT,
    ) -> None:
        self.ledger, _ = _load_json(ledger_path, "semantic coverage ledger")
        self.executable, self.executable_bytes = _load_json(
            executable_path, "executable UDSP artifact",
        )
        if self.ledger.get("edition") != EDITION:
            raise NativeDispatchWireError("semantic coverage edition drifted")
        self.scripts = _script_index(self.executable)
        records = self.ledger.get("records")
        if not isinstance(records, list):
            raise NativeDispatchWireError("semantic coverage records are absent")
        self.records = [
            row for row in records
            if isinstance(row, dict)
            and row.get("evidenceClass") in {"MISSION_DISPATCH", "LOCATION_POLICY"}
        ]
        self.capability: dict[str, Any] | None = None
        self.documents: list[dict[str, Any]] = []
        self.last_sequence = 0
        self.capture_binding = None
        self.capture_job = None
        self.capture_plan = None
        self.capture_target = None
        self.evidence_root = evidence_root
        if capture_binding is not None:
            self.capture_binding, self.capture_job, self.capture_plan = \
                _validate_capture_binding(capture_binding,evidence_root)
            compilation = capture_jobs.compile_targets(
                _resolve_artifact_path(
                    self.capture_binding["capturePlanPath"],evidence_root,
                )
            )
            targets = [
                target for target in compilation["targets"]
                if target.get("jobId") == self.capture_binding["capturePlanJobId"]
            ]
            if len(targets) != 1:
                raise NativeDispatchWireUnsupported(
                    "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPTURE_TARGET_NOT_UNIQUE"
                )
            self.capture_target = targets[0]

    def feed_line(self, line: str) -> dict[str, Any] | None:
        if not isinstance(line, str):
            raise NativeDispatchWireError("wire line is not text")
        if not line.startswith(WIRE_PREFIX):
            return None
        payload = line[len(WIRE_PREFIX):]
        try:
            payload.encode("ascii", errors="strict")
            record = json.loads(payload, parse_constant=_reject_json_constant)
        except UnicodeEncodeError as error:
            raise NativeDispatchWireError("MVDS record must be ASCII") from error
        except json.JSONDecodeError as error:
            raise NativeDispatchWireError("MVDS record is invalid JSON") from error
        if not isinstance(record, dict) or record.get("schema") != 1 \
                or record.get("protocol") != WIRE_PROTOCOL:
            raise NativeDispatchWireError("MVDS record identity differs")
        kind = record.get("record")
        if kind == "CAPABILITY":
            self._accept_capability(record)
            return None
        if kind == "EVENT":
            document = self._accept_event(record)
            self.documents.append(document)
            return document
        raise NativeDispatchWireError("MVDS record kind is unsupported")

    def _accept_capability(self, record: dict[str, Any]) -> None:
        if self.capability is not None or self.documents:
            raise NativeDispatchWireError("CAPABILITY must occur exactly once before EVENT")
        if set(record) != CAPABILITY_FIELDS:
            raise NativeDispatchWireError("CAPABILITY fields differ")
        target = self.capture_target
        if target is None:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:BINARY_BUILD_RECEIPT_REQUIRED"
            )
        expected_hooks = required_semantic_hooks(target)
        expected_routes = forwarded_route_hooks_for_target(target)
        expected_route_forwarding = bool(expected_routes)
        capabilities = record.get("capabilities")
        if not isinstance(capabilities, dict) \
                or set(capabilities) != DISPATCH_CAPABILITIES \
                or any(capabilities.get(name) is not True
                       for name in DISPATCH_CAPABILITIES - {"route"}) \
                or capabilities.get("route") is not expected_route_forwarding \
                or record.get("executableSha256") != EXECUTABLE_SHA256 \
                or record.get("producerBuildSha256") != producer_build_sha256() \
                or record.get("runtimeCapture") is not True \
                or record.get("routeForwarding") is not expected_route_forwarding \
                or type(record.get("engineThread")) is not int \
                or record["engineThread"] <= 0 \
                or type(record.get("nativeProcessId")) is not int \
                or record["nativeProcessId"] <= 0 \
                or not isinstance(record.get("captureSessionId"),str) \
                or CAPTURE_SESSION_ID.fullmatch(record["captureSessionId"]) is None \
                or record.get("installedHookCount") != len(expected_hooks) \
                or record.get("installedHookMask") != semantic_hook_mask(expected_hooks):
            raise NativeDispatchWireUnsupported("UNSUPPORTED_DISPATCH_HOOK_FACTS")
        if record.get("installedHooks") != list(expected_hooks):
            raise NativeDispatchWireUnsupported("UNSUPPORTED_DISPATCH_HOOK_FACTS")
        if record.get("forwardedRouteHooks") != list(expected_routes):
            raise NativeDispatchWireUnsupported("UNSUPPORTED_DISPATCH_HOOK_FACTS")
        if self.capture_binding is None:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:BINARY_BUILD_RECEIPT_REQUIRED"
            )
        if any(record.get(field) != self.capture_binding[field]
               for field in CAPABILITY_PROVENANCE_FIELDS):
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPTURE_PROVENANCE_DIFFERS"
            )
        expected_target_fields = {
            "targetSha256": target["targetSha256"],
            "jobSha256": target["jobSha256"],
            "claimId": target["claimId"],
            "claimSha256": target["claimSha256"],
            "subjectSha256": target["subjectSha256"],
            "expectationSha256": target["expectationSha256"],
            "scenarioSha256": target["scenarioSha256"],
            "capturePlanSha256": target["capturePlanSha256"],
            "planManifestSha256": target["planManifestSha256"],
            "evidenceClass": target["evidenceClass"],
        }
        if any(record.get(field) != expected_target_fields[field]
               for field in TARGET_CAPABILITY_FIELDS):
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPTURE_TARGET_DIFFERS"
            )
        self.capability = record

    def _accept_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.capability is None:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPABILITY_NOT_OBSERVED"
            )
        expected_fields = EVENT_COMMON_FIELDS | (
            {"selector"} if event.get("evidenceClass") == "LOCATION_POLICY" else set()
        )
        if set(event) != expected_fields \
                or event.get("executableSha256") != EXECUTABLE_SHA256 \
                or event.get("thread") != self.capability["engineThread"] \
                or event.get("nativeProcessId") != self.capability["nativeProcessId"] \
                or event.get("captureSessionId") != self.capability["captureSessionId"]:
            raise NativeDispatchWireError("EVENT envelope differs from capability")
        _normalize_f32_bits(event)
        receipt = event.get("receipt")
        sequence = receipt.get("sequence") if isinstance(receipt, dict) else None
        if type(sequence) is not int or sequence != self.last_sequence + 1:
            raise NativeDispatchWireError("EVENT sequence is not contiguous")
        self.last_sequence = sequence
        identity = _event_identity(event)
        matches = [row for row in self.records if _expectation_identity(row) == identity]
        if len(matches) != 1:
            raise NativeDispatchWireError(
                f"EVENT does not select exactly one coverage expectation: {identity!r}"
            )
        record = matches[0]
        expectation = record["expectation"]
        artifact_key = expectation.get("artifactKey")
        script = self.scripts.get(artifact_key) if artifact_key is not None else None
        if artifact_key is not None and script is None:
            raise NativeDispatchWireError("EVENT artifact is absent from executable scripts")
        expected_identity = _expected_identity(self.ledger, record)
        job = self.capture_job
        if not isinstance(job, dict) or job.get("claimId") != record["id"] \
                or job.get("evidenceClass") != record["evidenceClass"] \
                or job.get("subjectSha256") != expected_identity["subjectSha256"] \
                or job.get("expectationSha256") != expected_identity["expectationSha256"]:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:EVENT_JOB_IDENTITY_DIFFERS"
            )
        if self.documents:
            raise NativeDispatchWireError("capture-plan job accepts exactly one EVENT")
        capture_provenance = {
            "schema": 1,
            "planSha256": self.capture_binding["capturePlanSha256"],
            "planManifestSha256": self.capture_plan["manifestSha256"],
            "jobId": job["id"],
            "jobSha256": job["jobSha256"],
            "nativeSliceId": f"native-slice:{self.capture_binding['nativeSliceSha256']}",
            "nativeSliceSha256": self.capture_binding["nativeSliceSha256"],
            "observerBinarySha256": self.capture_binding["observerBinarySha256"],
            "observerBuildReceiptSha256": self.capture_binding["observerBuildReceiptSha256"],
            "producerBuildSha256": producer_build_sha256(),
            "nativeProcessId": self.capability["nativeProcessId"],
            "captureSessionId": self.capability["captureSessionId"],
        }
        validation_document = {
            "schema": 1,
            "protocol": oracle.NATIVE_RAW_PROTOCOL,
            "evidenceMode": "PRODUCTION",
            "producer": "NATIVE",
            "edition": self.ledger["edition"],
            "claimId": record["id"],
            "evidenceClass": record["evidenceClass"],
            "semanticCaseId": None,
            "sourceHashes": expected_identity["sourceHashes"],
            "subjectSha256": expected_identity["subjectSha256"],
            "expectationSha256": expected_identity["expectationSha256"],
            "artifactKey": artifact_key,
            "executableScriptSha256": (
                oracle.canonical_sha256(script) if script is not None else None
            ),
            "supportStatus": oracle.NATIVE_SUPPORTED_STATUS,
            "hookCapabilities": {
                name: True for name in sorted(oracle.NATIVE_DISPATCH_CAPABILITY_FIELDS)
            },
            "events": [receipt],
            "captureProvenance": capture_provenance,
        }
        # This is an executable validation boundary, not merely a shape check.
        # It exercises selector predicates, durable state and source pins before
        # a SUPPORTED document is returned to a caller.
        oracle.normalize_native_trace(
            validation_document,
            self.executable,
            expected_identity,
            executable_source_bytes=self.executable_bytes,
            expected_expectation=expectation,
            expected_capture_provenance=capture_provenance,
        )
        # Repository-local hashes and a caller-authored build receipt establish
        # internal consistency, not capture trust.  This repository currently
        # has no trusted runner/signature attestation that binds the fresh
        # process/session and raw output hash.  Therefore this boundary may
        # return a diagnostically validated candidate, but can never synthesize
        # PRODUCTION/SUPPORTED_HOOK_FACTS from those local artifacts.
        document = dict(validation_document)
        document["evidenceMode"] = UNTRUSTED_EVIDENCE_MODE
        document["supportStatus"] = NATIVE_TRACE_REQUIRED
        document["parityEligible"] = False
        return document

    def finish(self) -> list[dict[str, Any]]:
        if self.capability is None:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:CAPABILITY_NOT_OBSERVED"
            )
        if len(self.documents) != 1:
            raise NativeDispatchWireUnsupported(
                "UNSUPPORTED_DISPATCH_HOOK_FACTS:EXACTLY_ONE_JOB_EVENT_REQUIRED"
            )
        return list(self.documents)


def parse_lines(
    lines: Iterable[str],
    *,
    ledger_path: Path = coverage.DEFAULT_LEDGER,
    executable_path: Path = coverage.DEFAULT_EXECUTABLE,
    capture_binding: dict[str, str] | None = None,
    evidence_root: Path = coverage.ROOT,
) -> list[dict[str, Any]]:
    parser = NativeDispatchWireParser(
        ledger_path=ledger_path, executable_path=executable_path,
        capture_binding=capture_binding, evidence_root=evidence_root,
    )
    for line in lines:
        parser.feed_line(line)
    return parser.finish()


def main() -> int:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("capture", type=Path)
    argument_parser.add_argument("--output", type=Path)
    argument_parser.add_argument("--capture-binding", type=Path, required=True)
    arguments = argument_parser.parse_args()
    binding, _ = _load_json(arguments.capture_binding, "capture provenance binding")
    documents = parse_lines(
        arguments.capture.read_text(encoding="ascii", errors="strict").splitlines(),
        capture_binding=binding,
    )
    encoded = json.dumps(documents, indent=2, ensure_ascii=True) + "\n"
    if arguments.output is None:
        print(encoded, end="")
    else:
        arguments.output.write_text(encoded, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
