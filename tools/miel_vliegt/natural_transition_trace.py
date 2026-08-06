#!/usr/bin/env python3
"""Canonical, capture-bound natural scene-transition evidence.

A transition attestation is useful only when it is derived from a complete
runtime capture.  This module is the single parser used by the differential
tool and the release ledger, so their acceptance rules cannot drift.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.web_transition_build import validate_manifest
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from web_transition_build import validate_manifest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "content/miel_vliegt/native_scene_transitions.json"
WEB_RUNTIME_CONTRACT_PATH = ROOT / "content/miel_vliegt/web_scene_transition_runtime.json"
PROTOCOL = "miel-vliegt-natural-transition-trace"
RECEIPT_PROTOCOL = "miel-scene-transition-differential"
VERSION = 3
EDITION = "flight/nl/miel-vliegt-de-wereld-rond"
SCOPE = "NATURAL_TRANSITION"
NATIVE_RAW_PROTOCOL = "miel-vliegt-native-natural-transition"
WEB_RAW_PROTOCOL = "miel-web-scene-transition-runtime"
NATIVE_HOOK_BUILD = "native-observer-natural-v1"
NATIVE_SOURCE_KEYS = {
    "schema", "protocol", "record", "edge", "transition_site",
    "sequence", "tick", "thread_id", "scenario", "executable_sha256",
    "hook_build", "observer_dll_sha256",
}
NATIVE_SESSION_KEYS = {
    "schema", "protocol", "record", "scenario", "executable_sha256",
    "hook_build", "observer_dll_sha256", "result", "thread_id",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
CAPTURE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}")
SITE = re.compile(r"0x[0-9a-f]{8}")
JS_MAX_SAFE_INTEGER = (1 << 53) - 1

WEB_BUILD_MANIFEST = validate_manifest()
WEB_BUILD_SHA256 = WEB_BUILD_MANIFEST["build_sha256"]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_contract() -> tuple[dict[str, dict[str, Any]], str]:
    try:
        value = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("native scene-transition contract is unavailable") from error
    rows = value.get("edges")
    locations = value.get("location_edges")
    executable = value.get("source", {}).get("executable_sha256")
    if type(value.get("schema")) is not int or value.get("schema") != 1 \
            or not isinstance(rows, list) \
            or len(rows) != 12 or not isinstance(locations, list) \
            or len(locations) != 18 or not SHA256.fullmatch(executable or ""):
        raise RuntimeError("native scene-transition contract has an unsupported shape")
    combined = list(rows)
    for location in locations:
        if not isinstance(location, dict) or set(location) != {
            "location", "landing", "departure",
        }:
            raise RuntimeError("native location-transition contract is incomplete")
        combined.extend((location["landing"], location["departure"]))
    required = {
        "id", "source", "source_type", "target", "target_type", "trigger",
        "address", "predicate", "evidence_status", "natural", "parity_eligible",
    }
    edges: dict[str, dict[str, Any]] = {}
    for row in combined:
        if not isinstance(row, dict) or not required <= set(row) \
                or set(row) - required - {
                    "alternate_addresses", "site_role", "commit_address", "owner_address",
                } \
                or row.get("natural") is not True:
            raise RuntimeError("native natural-transition row is invalid")
        edge = row.get("id")
        if not isinstance(edge, str) or not edge or edge in edges:
            raise RuntimeError("native natural-transition edge identity is invalid")
        sites = [row.get("address"), *row.get("alternate_addresses", [])]
        if any(not SITE.fullmatch(str(site).lower()) for site in sites):
            raise RuntimeError(f"native transition edge has an invalid site: {edge}")
        edges[edge] = row
    if len(edges) != 48:
        raise RuntimeError(f"expected 48 natural transition edges, got {len(edges)}")
    return edges, executable


EDGES, NATIVE_EXECUTABLE_SHA256 = _load_contract()


def _load_web_runtime_contract() -> dict[str, tuple[int, set[str]]]:
    try:
        value = json.loads(WEB_RUNTIME_CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("web scene-transition runtime contract is unavailable") from error
    if set(value or {}) != {"schema", "protocol", "evidence_scope", "records"} \
            or type(value.get("schema")) is not int or value.get("schema") != 1 \
            or value.get("protocol") != WEB_RAW_PROTOCOL \
            or value.get("evidence_scope") != SCOPE \
            or not isinstance(value.get("records"), list) \
            or len(value["records"]) != 3:
        raise RuntimeError("web scene-transition runtime contract is invalid")
    contract: dict[str, tuple[int, set[str]]] = {}
    for sequence, row in enumerate(value["records"]):
        if not isinstance(row, dict) or set(row) != {"record", "sequence", "keys"} \
                or type(row.get("sequence")) is not int \
                or row.get("sequence") != sequence \
                or not isinstance(row.get("record"), str) \
                or not isinstance(row.get("keys"), list) \
                or any(not isinstance(key, str) for key in row["keys"]) \
                or len(set(row["keys"])) != len(row["keys"]) \
                or row["record"] in contract:
            raise RuntimeError("web scene-transition runtime record contract is invalid")
        contract[row["record"]] = (sequence, set(row["keys"]))
    if tuple(contract) != ("session.start", "scene_transition", "session.complete"):
        raise RuntimeError("web scene-transition runtime records are incomplete")
    return contract


WEB_RUNTIME_RECORDS = _load_web_runtime_contract()


def canonical_identity(edge: str, transition_site: str | None = None) -> dict[str, Any]:
    row = EDGES.get(edge)
    if row is None:
        raise ValueError(f"unknown natural transition edge: {edge!r}")
    sites = tuple(str(site).lower() for site in (
        row["address"], *row.get("alternate_addresses", []),
    ))
    site = str(transition_site or sites[0]).lower()
    if site not in sites:
        raise ValueError(f"transition site differs from canonical edge: {edge}")
    bootstrap = row["source_type"] == "bootstrap"
    return {
        "edition": EDITION,
        "edge": edge,
        "source_scene": None if bootstrap else row["source"],
        "scene": row["target"],
        "entry_path": "startup" if bootstrap else "gameplay-transition",
        "transition_site": site,
        "transition_trigger": row["trigger"],
        "transition_predicate": row["predicate"],
    }


def _strict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label}: invalid natural transition trace")
    return value


def _same_json_scalar(actual: Any, expected: Any) -> bool:
    """Compare a JSON scalar without Python's bool/int coercion."""
    return type(actual) is type(expected) and actual == expected


def _read_json_lines(path: Path) -> list[tuple[str, dict[str, Any]]]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as error:
        raise ValueError(f"{path}: cannot read natural transition trace") from error
    records: list[tuple[str, dict[str, Any]]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        prefix = ""
        payload = line
        if len(line) > 4 and line[:4] in {"MVO ", "MVT ", "MVD "}:
            prefix, payload = line[:3], line[4:]
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid natural transition JSON") from error
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: natural transition record is not an object")
        records.append((prefix, value))
    return records


def _reject_disqualified(records: list[tuple[str, dict[str, Any]]], label: str) -> None:
    body_protocols = {
        "miel-vliegt-native-body-dispatch", "miel-vliegt-native-body-lifecycle",
    }
    for _, record in records:
        if record.get("debug_entry") is True \
                or record.get("debug_skip_used") is True \
                or record.get("evidence_scope") == "BODY_ONLY" \
                or record.get("protocol") in body_protocols \
                or record.get("record") in {"engine_mode", "body_phase", "body_lifecycle"} \
                or record.get("command") == "engine_mode":
            raise ValueError(f"{label}: debug/BODY capture cannot prove a natural transition")


def _validate_raw_native(
    records: list[tuple[str, dict[str, Any]]], start: dict[str, Any],
    transition: dict[str, Any], label: str,
) -> None:
    loaded = False
    completed = False
    session_complete = False
    source_matches = 0
    source_total = 0
    natural_starts: list[int] = []
    natural_completes: list[int] = []
    source_indices: list[int] = []
    natural_start_total = 0
    natural_complete_total = 0
    natural_unknown_total = 0
    observer_dll_sha256: str | None = None
    scenario = start["scenario"]
    native_identity = {
        "schema": VERSION,
        "protocol": NATIVE_RAW_PROTOCOL,
        "scenario": scenario,
        "executable_sha256": NATIVE_EXECUTABLE_SHA256,
        "hook_build": NATIVE_HOOK_BUILD,
    }
    for record_index, (prefix, record) in enumerate(records):
        if prefix == "MVO" and record.get("protocol") == "miel-vliegt-native-observer-hook":
            loaded = loaded or record.get("status") == "LOADED"
            completed = completed or record.get("status") == "SCENARIO_COMPLETE"
        if prefix == "MVT" and record.get("record") == "session" \
                and record.get("channel") == "session.complete":
            values = record.get("values", {})
            session_complete = values.get("scenario") == scenario
        natural_record = record.get("record")
        if prefix == "MVD" and record.get("protocol") == NATIVE_RAW_PROTOCOL \
                and natural_record not in {
                    "natural_session_start", "scene_transition_source",
                    "natural_session_complete",
                }:
            natural_unknown_total += 1
        if prefix == "MVD" and record.get("protocol") == NATIVE_RAW_PROTOCOL \
                and natural_record in {
                    "natural_session_start", "natural_session_complete",
                }:
            valid_session = set(record) == NATIVE_SESSION_KEYS \
                and all(_same_json_scalar(record.get(key), value)
                        for key, value in native_identity.items()) \
                and SHA256.fullmatch(record.get("observer_dll_sha256", "")) \
                and isinstance(record.get("thread_id"), int) \
                and not isinstance(record.get("thread_id"), bool) \
                and record["thread_id"] > 0
            if natural_record == "natural_session_start":
                natural_start_total += 1
            if natural_record == "natural_session_complete":
                natural_complete_total += 1
            if natural_record == "natural_session_start" \
                    and valid_session and record.get("result") == "ACTIVE":
                if observer_dll_sha256 is None:
                    observer_dll_sha256 = record["observer_dll_sha256"]
                if record.get("observer_dll_sha256") == observer_dll_sha256:
                    natural_starts.append(record_index)
            if natural_record == "natural_session_complete" \
                    and valid_session and record.get("result") == "PASS" \
                    and record.get("observer_dll_sha256") == observer_dll_sha256:
                natural_completes.append(record_index)
        if prefix == "MVD" and record.get("protocol") == NATIVE_RAW_PROTOCOL \
                and record.get("record") == "scene_transition_source":
            source_total += 1
            expected = {
                "edge": transition["edge"],
                "transition_site": transition["transition_site"],
                "sequence": transition["sequence"],
                "tick": transition["tick"],
            }
            if set(record) == NATIVE_SOURCE_KEYS \
                    and type(record.get("schema")) is int \
                    and record.get("schema") == VERSION \
                    and all(_same_json_scalar(record.get(key), value)
                            for key, value in native_identity.items()) \
                    and record.get("observer_dll_sha256") == observer_dll_sha256 \
                    and all(_same_json_scalar(record.get(key), value)
                            for key, value in expected.items()) \
                    and isinstance(record.get("thread_id"), int) \
                    and not isinstance(record.get("thread_id"), bool) \
                    and record["thread_id"] > 0:
                source_matches += 1
                source_indices.append(record_index)
    if not loaded or not completed or not session_complete \
            or source_total != 1 or source_matches != 1 \
            or natural_start_total != 1 or natural_complete_total != 1 \
            or natural_unknown_total != 0 \
            or len(natural_starts) != 1 or len(natural_completes) != 1 \
            or not (natural_starts[0] < source_indices[0] < natural_completes[0]):
        raise ValueError(f"{label}: native transition requires one complete observer session")


def _validate_raw_web(
    records: list[tuple[str, dict[str, Any]]], start: dict[str, Any],
    transition: dict[str, Any], label: str,
) -> None:
    if any(prefix for prefix, _ in records):
        raise ValueError(f"{label}: web transition capture has native log prefixes")
    if len(records) != 3:
        raise ValueError(f"{label}: web transition requires one complete runtime session")
    session_start, event, session_complete = (record for _, record in records)
    if set(session_start) != WEB_RUNTIME_RECORDS["session.start"][1] \
            or set(event) != WEB_RUNTIME_RECORDS["scene_transition"][1] \
            or set(session_complete) != WEB_RUNTIME_RECORDS["session.complete"][1]:
        raise ValueError(f"{label}: web transition runtime record shape is invalid")
    common = {
        "schema": 1,
        "protocol": WEB_RAW_PROTOCOL,
        "capture_id": start["capture_id"],
        "scenario": start["scenario"],
        "build_sha256": WEB_BUILD_SHA256,
        "debug_entry": False,
        "evidence_scope": SCOPE,
    }
    sequences = [record.get("sequence") for record in (
        session_start, event, session_complete,
    )]
    if any(isinstance(sequence, bool) or not isinstance(sequence, int)
           for sequence in sequences) \
            or any(any(not _same_json_scalar(record.get(key), value)
                       for key, value in common.items())
           for record in (session_start, event, session_complete)) \
            or session_start.get("record") != "session.start" \
            or event.get("record") != "scene_transition" \
            or session_complete.get("record") != "session.complete" \
            or session_complete.get("result") != "PASS" \
            or sequences != [0, 1, 2]:
        raise ValueError(f"{label}: web transition runtime session identity is invalid")
    ticks = [record.get("tick") for record in (session_start, event, session_complete)]
    if any(isinstance(tick, bool) or not isinstance(tick, int) \
           or tick < 0 or tick > JS_MAX_SAFE_INTEGER
           for tick in ticks) or ticks != sorted(ticks):
        raise ValueError(f"{label}: web transition runtime ticks are invalid")
    canonical = canonical_identity(transition["edge"], transition["transition_site"])
    row = EDGES[transition["edge"]]
    expected_event = {
        "edge": canonical["edge"],
        "source_scene": canonical["source_scene"],
        "scene": canonical["scene"],
        "transition_site": canonical["transition_site"],
        "transition_trigger": canonical["transition_trigger"],
        "transition_predicate": canonical["transition_predicate"],
        "native_edge": canonical["edge"],
        "native_transition_site": canonical["transition_site"],
        "classification": "EXACT_NATIVE_CONTRACT_EDGE",
        "parity_eligible": row["parity_eligible"] is True,
        "sequence": transition["sequence"],
        "tick": transition["tick"],
    }
    if any(not _same_json_scalar(event.get(key), value)
           for key, value in expected_event.items()):
        raise ValueError(f"{label}: web transition differs from the canonical runtime event")


def _resolve_raw_trace(path: Path, start: dict[str, Any]) -> Path:
    raw = start["raw_trace"]
    relative = raw.get("path") if isinstance(raw, dict) else None
    expected_hash = raw.get("sha256") if isinstance(raw, dict) else None
    if set(raw or {}) != {"path", "sha256"} \
            or not isinstance(relative, str) or not relative \
            or Path(relative).is_absolute() or not SHA256.fullmatch(expected_hash or ""):
        raise ValueError(f"{path}: invalid raw trace provenance")
    resolved = (path.parent / relative).resolve()
    try:
        resolved.relative_to(path.parent.resolve())
    except ValueError as error:
        raise ValueError(f"{path}: raw trace provenance escapes capture directory") from error
    if not resolved.is_file() or sha256_file(resolved) != expected_hash:
        raise ValueError(f"{path}: raw trace provenance is missing or drifted")
    return resolved


def load_capture(path: Path, expected_driver: str | None = None) -> dict[str, Any]:
    """Validate one normalized transition plus its complete raw runtime session."""
    records = _read_json_lines(path)
    _reject_disqualified(records, str(path))
    if len(records) != 3 or any(prefix for prefix, _ in records):
        raise ValueError(f"{path}: transition attestation requires start/event/complete")
    start, transition, complete = (record for _, record in records)
    _strict(start, {
        "schema", "protocol", "record", "edition", "entry_driver", "capture_id",
        "scenario", "producer", "subject_sha256", "raw_trace", "debug_entry",
        "evidence_scope",
    }, str(path))
    _strict(transition, {
        "schema", "protocol", "record", "edition", "edge", "source_scene", "scene",
        "entry_path", "entry_driver", "transition_site", "transition_trigger",
        "transition_predicate", "capture_id", "sequence", "tick", "debug_entry",
        "evidence_scope",
    }, str(path))
    _strict(complete, {
        "schema", "protocol", "record", "edition", "entry_driver", "capture_id",
        "final_sequence", "result", "debug_entry", "evidence_scope",
    }, str(path))
    common = (start, transition, complete)
    if any(type(record.get("schema")) is not int \
           or record.get("schema") != VERSION or record.get("protocol") != PROTOCOL
           or record.get("edition") != EDITION or record.get("debug_entry") is not False
           or record.get("evidence_scope") != SCOPE for record in common):
        raise ValueError(f"{path}: invalid natural transition trace")
    driver = start.get("entry_driver")
    if driver not in {"native-gameplay", "web-gameplay"} \
            or (expected_driver is not None and driver != expected_driver) \
            or any(record.get("entry_driver") != driver for record in common):
        raise ValueError(f"{path}: natural transition trace has the wrong driver")
    if start.get("record") != "capture_start" or transition.get("record") != "scene_transition" \
            or complete.get("record") != "capture_complete" \
            or complete.get("result") != "PASS":
        raise ValueError(f"{path}: transition capture is incomplete")
    capture_id = start.get("capture_id")
    if not CAPTURE_ID.fullmatch(capture_id or "") \
            or transition.get("capture_id") != capture_id \
            or complete.get("capture_id") != capture_id:
        raise ValueError(f"{path}: transition capture identity is invalid")
    if not isinstance(start.get("scenario"), str) or not start["scenario"] \
            or start.get("producer") != (
                "native-observer-hook" if driver == "native-gameplay" else "web-scene-manager"
            ) or not SHA256.fullmatch(start.get("subject_sha256", "")):
        raise ValueError(f"{path}: transition capture provenance is invalid")
    if driver == "native-gameplay" \
            and start["subject_sha256"] != NATIVE_EXECUTABLE_SHA256:
        raise ValueError(f"{path}: native transition executable differs from pinned source")
    if driver == "web-gameplay" and start["subject_sha256"] != WEB_BUILD_SHA256:
        raise ValueError(f"{path}: web transition producer differs from pinned build")
    sequence = transition.get("sequence")
    tick = transition.get("tick")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence != 1 \
            or isinstance(tick, bool) or not isinstance(tick, int) \
            or tick < 0 or tick > JS_MAX_SAFE_INTEGER \
            or type(complete.get("final_sequence")) is not int \
            or complete.get("final_sequence") != 2:
        raise ValueError(f"{path}: transition sequence/tick is invalid")
    expected = canonical_identity(transition.get("edge"), transition.get("transition_site"))
    if {key: transition.get(key) for key in expected} != expected:
        raise ValueError(f"{path}: natural transition trace differs from canonical edge")
    raw_path = _resolve_raw_trace(path, start)
    raw_records = _read_json_lines(raw_path)
    _reject_disqualified(raw_records, str(raw_path))
    if driver == "native-gameplay":
        _validate_raw_native(raw_records, start, transition, str(raw_path))
    else:
        _validate_raw_web(raw_records, start, transition, str(raw_path))
    return {
        **transition,
        "scenario": start["scenario"],
        "producer": start["producer"],
        "subject_sha256": start["subject_sha256"],
        "raw_trace_sha256": start["raw_trace"]["sha256"],
        "semantic_trace_sha256": sha256_file(path),
    }


RECEIPT_KEYS = {
    "schema", "protocol", "edition", "edge", "source_scene", "scene", "entry_path",
    "transition_site", "transition_trigger", "transition_predicate", "evidence_scope",
    "native_capture_id", "web_capture_id", "native_subject_sha256",
    "web_subject_sha256", "native_raw_trace_sha256", "web_raw_trace_sha256",
    "native_trace_sha256", "web_trace_sha256", "result",
}


def compare(native_path: Path, web_path: Path) -> dict[str, Any]:
    native = load_capture(native_path, "native-gameplay")
    web = load_capture(web_path, "web-gameplay")
    identity_keys = (
        "edition", "edge", "source_scene", "scene", "entry_path", "transition_site",
        "transition_trigger", "transition_predicate",
    )
    identity = {key: native[key] for key in identity_keys}
    if identity != {key: web[key] for key in identity_keys}:
        raise ValueError("natural transition edge differs between native and web evidence")
    return {
        "schema": VERSION,
        "protocol": RECEIPT_PROTOCOL,
        **identity,
        "evidence_scope": SCOPE,
        "native_capture_id": native["capture_id"],
        "web_capture_id": web["capture_id"],
        "native_subject_sha256": native["subject_sha256"],
        "web_subject_sha256": web["subject_sha256"],
        "native_raw_trace_sha256": native["raw_trace_sha256"],
        "web_raw_trace_sha256": web["raw_trace_sha256"],
        "native_trace_sha256": native["semantic_trace_sha256"],
        "web_trace_sha256": web["semantic_trace_sha256"],
        "result": "PASS",
    }


def validate_receipt(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS \
            or type(receipt.get("schema")) is not int \
            or receipt.get("schema") != VERSION \
            or receipt.get("protocol") != RECEIPT_PROTOCOL \
            or receipt.get("evidence_scope") != SCOPE or receipt.get("result") != "PASS" \
            or any(not SHA256.fullmatch(receipt.get(key, "")) for key in (
                "native_subject_sha256", "web_subject_sha256", "native_raw_trace_sha256",
                "web_raw_trace_sha256", "native_trace_sha256", "web_trace_sha256",
            )) or not CAPTURE_ID.fullmatch(receipt.get("native_capture_id", "")) \
            or not CAPTURE_ID.fullmatch(receipt.get("web_capture_id", "")):
        raise ValueError("invalid natural transition differential receipt")
    expected = canonical_identity(receipt.get("edge"), receipt.get("transition_site"))
    if {key: receipt.get(key) for key in expected} != expected:
        raise ValueError("natural transition receipt differs from canonical edge")
    if receipt["native_subject_sha256"] != NATIVE_EXECUTABLE_SHA256:
        raise ValueError("natural transition receipt has the wrong native executable")
    if receipt["web_subject_sha256"] != WEB_BUILD_SHA256:
        raise ValueError("natural transition receipt has the wrong web transition build")
    return dict(receipt)
