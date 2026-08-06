#!/usr/bin/env python3
"""Validate the source-bound scene inventory and edition parity coverage.

Inventory evidence and parity evidence are deliberately separate.  A scene
found in a Director graph or native executable is known to exist, but is not
therefore proven equivalent in the web port.  The default CLI is a release
gate: every inventoried scene body and every natural flight-transition edge
must have a hash-bound PASS differential receipt, otherwise it exits non-zero.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.miel_vliegt import natural_transition_trace
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    import natural_transition_trace


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER = Path(__file__).with_name("scene_coverage_ledger.json")
SHA256_LENGTH = 64
BODY_TRACE_PROTOCOL = "miel-vliegt-mode-body-trace"
BODY_DIFFERENTIAL_PROTOCOL = "miel-scene-differential"
BODY_COMPARATOR = "mode-body-exact-v1"
BODY_LIFECYCLE_PHASES = ("load", "open", "tick", "render", "close", "unload")
BODY_COMPARISON_POLICY = {
    "lifecycle": "EXACT_ORDERED_STATES",
    "render_checkpoints": "EXACT_CANONICAL_RGBA_SHA256",
}
BODY_COVERAGE_REQUIREMENT = {
    "required_lifecycle_phases": list(BODY_LIFECYCLE_PHASES),
    "render_checkpoint_policy": "AT_LEAST_ONE_CANONICAL_RGBA8_AT_RENDER_PHASE",
}
BODY_UNPROVEN_BLOCKER = (
    "MISSING_PAIRED_REVIEWED_NATIVE_AND_WEB_BODY_TRACES_AND_EXACT_PASS_DIFFERENTIAL"
)


class SceneCoverageError(ValueError):
    """Raised when the ledger or one of its pinned sources is invalid."""


class SceneCoverageGap(SceneCoverageError):
    """Raised by the release gate while any scene remains unproven."""


@dataclass(frozen=True)
class CoverageReport:
    editions: int
    expectations: int
    proven: int
    unproven: int
    unknown: int
    inventory_unproven: int
    flight_expectations: int
    flight_transition_expectations: int
    body_parity_proven: int
    body_parity_unproven: int
    body_parity_unknown: int
    natural_transition_parity_proven: int
    natural_transition_parity_unproven: int
    natural_transition_parity_unknown: int
    release_ready: bool
    gaps: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": 2,
            "protocol": "miel-scene-coverage-report",
            "editions": self.editions,
            "expectations": self.expectations,
            "proven": self.proven,
            "unproven": self.unproven,
            "unknown": self.unknown,
            "inventory_unproven": self.inventory_unproven,
            "flight_gates": {
                "BODY_PARITY": {
                    "expectations": self.flight_expectations,
                    "proven": self.body_parity_proven,
                    "unproven": self.body_parity_unproven,
                    "unknown": self.body_parity_unknown,
                },
                "NATURAL_TRANSITION_PARITY": {
                    "expectations": self.flight_transition_expectations,
                    "proven": self.natural_transition_parity_proven,
                    "unproven": self.natural_transition_parity_unproven,
                    "unknown": self.natural_transition_parity_unknown,
                },
            },
            "release_ready": self.release_ready,
            "gaps": list(self.gaps),
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = _canonical_bytes(value)
    return hashlib.sha256(encoded).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise SceneCoverageError("mode BODY evidence is not canonical JSON") from error


def _load_mode_body_trace(path: Path, label: str) -> dict[str, Any]:
    try:
        trace = _load_json(path, label)
    except SceneCoverageError as error:
        raise SceneCoverageError(f"invalid mode BODY trace: {label}") from error
    required = {
        "schema", "protocol", "producer", "edition", "scene", "capture_id",
        "subject_sha256", "result", "lifecycle", "render_checkpoints", "coverage",
    }
    if set(trace) != required or trace.get("schema") != 1 \
            or trace.get("protocol") != BODY_TRACE_PROTOCOL \
            or trace.get("producer") not in {"NATIVE", "WEB"} \
            or trace.get("result") != "PASS" \
            or not isinstance(trace.get("edition"), str) or not trace["edition"] \
            or not isinstance(trace.get("scene"), str) or not trace["scene"] \
            or not isinstance(trace.get("capture_id"), str) or not trace["capture_id"] \
            or not _is_sha256(trace.get("subject_sha256")):
        raise SceneCoverageError(f"invalid mode BODY trace: {label}")

    lifecycle = trace.get("lifecycle")
    if not isinstance(lifecycle, list) or len(lifecycle) != len(BODY_LIFECYCLE_PHASES):
        raise SceneCoverageError(f"mode BODY trace lacks all six lifecycle phases: {label}")
    ticks = []
    for sequence, (event, phase) in enumerate(zip(lifecycle, BODY_LIFECYCLE_PHASES)):
        if not isinstance(event, dict) or set(event) != {
            "sequence", "tick", "phase", "state",
        } or event.get("sequence") != sequence or event.get("phase") != phase \
                or not isinstance(event.get("tick"), int) or event["tick"] < 0 \
                or not isinstance(event.get("state"), dict) or not event["state"]:
            raise SceneCoverageError(f"mode BODY trace lacks all six lifecycle phases: {label}")
        ticks.append(event["tick"])
    if ticks != sorted(ticks):
        raise SceneCoverageError(f"mode BODY lifecycle ticks are not monotonic: {label}")

    checkpoints = trace.get("render_checkpoints")
    if not isinstance(checkpoints, list) or not checkpoints:
        raise SceneCoverageError(f"mode BODY trace lacks a render checkpoint: {label}")
    checkpoint_ids = []
    render_tick = lifecycle[BODY_LIFECYCLE_PHASES.index("render")]["tick"]
    for checkpoint in checkpoints:
        if not isinstance(checkpoint, dict) or set(checkpoint) != {
            "id", "tick", "width", "height", "canonical_rgba_sha256",
        } or not isinstance(checkpoint.get("id"), str) or not checkpoint["id"] \
                or checkpoint.get("tick") != render_tick \
                or not isinstance(checkpoint.get("width"), int) or checkpoint["width"] <= 0 \
                or not isinstance(checkpoint.get("height"), int) or checkpoint["height"] <= 0 \
                or not _is_sha256(checkpoint.get("canonical_rgba_sha256")):
            raise SceneCoverageError(f"invalid mode BODY render checkpoint: {label}")
        checkpoint_ids.append(checkpoint["id"])
    if len(checkpoint_ids) != len(set(checkpoint_ids)):
        raise SceneCoverageError(f"duplicate mode BODY render checkpoint: {label}")

    expected_coverage = {
        "required_lifecycle_phases": list(BODY_LIFECYCLE_PHASES),
        "observed_lifecycle_phases": [event["phase"] for event in lifecycle],
        "render_checkpoint_ids": checkpoint_ids,
    }
    if trace.get("coverage") != expected_coverage:
        raise SceneCoverageError(f"mode BODY coverage vector differs: {label}")
    return trace


def _body_comparable(trace: dict[str, Any]) -> dict[str, Any]:
    return {
        "edition": trace["edition"],
        "scene": trace["scene"],
        "result": trace["result"],
        "lifecycle": trace["lifecycle"],
        "render_checkpoints": trace["render_checkpoints"],
        "coverage": trace["coverage"],
    }


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SceneCoverageError(f"cannot load {label}: {path}") from error


def _pinned_source(record: object, label: str) -> tuple[Path, Any]:
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "authority"}:
        raise SceneCoverageError(f"{label} source fields differ from the contract")
    relative = record["path"]
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise SceneCoverageError(f"{label} has an invalid source path")
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as error:
        raise SceneCoverageError(f"{label} source escapes the repository") from error
    if not path.is_file():
        raise SceneCoverageError(f"{label} source is missing: {relative}")
    expected = record["sha256"]
    if not _is_sha256(expected) or _sha256(path) != expected:
        raise SceneCoverageError(f"{label} source hash drifted: {relative}")
    if record["authority"] not in {
        "inventory", "edition-registry", "subsystem-only", "web-parity-build",
    }:
        raise SceneCoverageError(f"{label} has an invalid authority")
    return path, _load_json(path, label)


def _walk_native_strings(value: Any) -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        text = value.get("value")
        address = value.get("address")
        if isinstance(text, str) and text.startswith("mode_") and isinstance(address, str):
            yield text, address
        for child in value.values():
            yield from _walk_native_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_native_strings(child)


def _native_modes(index: Any) -> dict[str, str]:
    if not isinstance(index, dict) or index.get("schema") != 1:
        raise SceneCoverageError("unsupported native function index")
    modes: dict[str, str] = {}
    for name, address in _walk_native_strings(index):
        previous = modes.setdefault(name, address)
        if previous != address:
            raise SceneCoverageError(f"native mode has conflicting addresses: {name}")
    if not modes:
        raise SceneCoverageError("native function index has no mode inventory")
    return modes


def _inventory_ids(record: object, label: str) -> tuple[str, ...]:
    if not isinstance(record, dict) or set(record) != {"kind", "ids", "exact_editions"}:
        raise SceneCoverageError(f"{label} inventory fields differ from the contract")
    values = record["ids"]
    if not isinstance(values, list) or not values or any(
        not isinstance(value, str) or not value for value in values
    ):
        raise SceneCoverageError(f"{label} inventory must contain non-empty string IDs")
    if values != sorted(set(values)):
        raise SceneCoverageError(f"{label} inventory IDs must be unique and sorted")
    exact_editions = record["exact_editions"]
    if not isinstance(exact_editions, list) or exact_editions != sorted(set(exact_editions)) \
            or any(not isinstance(value, str) or not value for value in exact_editions):
        raise SceneCoverageError(f"{label} exact edition scope must be unique and sorted")
    return tuple(values)


def _negative_body_claims(
    source_record: dict[str, Any], body_contract: dict[str, Any],
) -> list[dict[str, Any]]:
    """Derive explicit negative claims from the authoritative native modes."""

    rows = body_contract.get("modes")
    executable_sha256 = body_contract.get("source", {}).get("executable_sha256")
    if not isinstance(rows, list) or not rows or not _is_sha256(executable_sha256):
        raise SceneCoverageError("native mode body inventory is unavailable")
    if not isinstance(source_record, dict) or set(source_record) != {
        "path", "sha256", "authority",
    } or source_record.get("authority") != "inventory" \
            or not _is_sha256(source_record.get("sha256")):
        raise SceneCoverageError("native mode body source identity is unavailable")

    claims = []
    modes: set[str] = set()
    mode_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SceneCoverageError("native mode body row is invalid")
        mode = row.get("mode")
        mode_id = row.get("id")
        mode_type = row.get("mode_type")
        if not isinstance(mode, str) or not mode.startswith("mode_") \
                or not isinstance(mode_id, str) or not mode_id \
                or mode_type not in {"core", "location"} \
                or mode in modes or mode_id in mode_ids:
            raise SceneCoverageError("native mode body identities are not unique")
        modes.add(mode)
        mode_ids.add(mode_id)
        claims.append({
            "scene": mode,
            "subject": {
                "mode_id": mode_id,
                "mode": mode,
                "mode_type": mode_type,
                "source": {
                    "path": source_record["path"],
                    "sha256": source_record["sha256"],
                    "executable_sha256": executable_sha256,
                },
                "body_sha256": _canonical_sha256(row),
            },
            "coverage": copy.deepcopy(BODY_COVERAGE_REQUIREMENT),
            "gates": {
                "BODY_PARITY": {
                    "status": "UNPROVEN",
                    "evidence": [],
                    "blocker": BODY_UNPROVEN_BLOCKER,
                },
            },
        })
    return sorted(claims, key=lambda claim: claim["scene"])


def generate_negative_body_claims(
    ledger: dict[str, Any], body_contract: dict[str, Any],
) -> dict[str, Any]:
    """Populate every flight edition from its native mode inventory."""

    generated = copy.deepcopy(ledger)
    source_record = generated.get("sources", {}).get("flight_native_mode_bodies")
    claims = _negative_body_claims(source_record, body_contract)
    inventory = generated.get("inventories", {}).get("flight", {}).get("ids")
    if inventory != [claim["scene"] for claim in claims]:
        raise SceneCoverageError("generated BODY claims differ from flight inventory")
    editions = generated.get("editions")
    if not isinstance(editions, dict):
        raise SceneCoverageError("ledger editions must be an object")
    flight_editions = [
        edition for edition in editions.values()
        if isinstance(edition, dict) and edition.get("game") == "flight"
    ]
    if not flight_editions:
        raise SceneCoverageError("ledger has no flight edition for BODY claims")
    for edition in flight_editions:
        edition["claims"] = copy.deepcopy(claims)
    return generated


def regenerate_negative_body_claims(path: Path = DEFAULT_LEDGER) -> dict[str, Any]:
    """Rewrite the canonical ledger with source-derived negative BODY claims."""

    ledger = _load_json(path, "scene coverage ledger")
    sources = ledger.get("sources")
    if not isinstance(sources, dict):
        raise SceneCoverageError("scene coverage source identities are unavailable")
    generated_sources = (
        "edition_registry", "flight_native_mode_bodies",
        "flight_web_transition_build",
    )
    source_paths: dict[str, Path] = {}
    for name in generated_sources:
        source_record = sources.get(name)
        if not isinstance(source_record, dict) \
                or not isinstance(source_record.get("path"), str):
            raise SceneCoverageError(f"{name} source identity is unavailable")
        source_path = (ROOT / source_record["path"]).resolve()
        try:
            source_path.relative_to(ROOT.resolve())
        except ValueError as error:
            raise SceneCoverageError(f"{name} source escapes the repository") from error
        if not source_path.is_file():
            raise SceneCoverageError(f"{name} source is missing")
        source_record["sha256"] = _sha256(source_path)
        source_paths[name] = source_path
    body_contract = _load_json(
        source_paths["flight_native_mode_bodies"], "native mode body inventory",
    )
    generated = generate_negative_body_claims(ledger, body_contract)
    path.write_text(
        json.dumps(generated, ensure_ascii=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return generated


def _validate_flight_static_contracts(
    sources: dict[str, Any], native_modes: dict[str, str]
) -> dict[str, dict[str, Any]]:
    """Bind scene coverage to reviewed bodies and natural transition topology."""

    bodies = sources["flight_native_mode_bodies"]
    transitions = sources["flight_native_scene_transitions"]
    web_transition_build = sources["flight_web_transition_build"]
    executable_sha256 = sources["flight_native_function_index"].get(
        "source", {}
    ).get("sha256")
    if bodies.get("schema") != 1 \
            or bodies.get("claim") != "STATIC_MODE_BODY_MAP_COMPLETE_RUNTIME_UNPROVEN" \
            or bodies.get("source", {}).get("executable_sha256") != executable_sha256:
        raise SceneCoverageError("unsupported native mode body coverage contract")
    if web_transition_build != natural_transition_trace.WEB_BUILD_MANIFEST:
        raise SceneCoverageError("unsupported web transition build contract")
    body_rows = bodies.get("modes")
    if not isinstance(body_rows, list) or len(body_rows) != 22:
        raise SceneCoverageError("native mode body coverage must contain exactly 22 modes")
    body_modes = [row.get("mode") for row in body_rows]
    if len(set(body_modes)) != 22 or set(body_modes) != set(native_modes):
        raise SceneCoverageError("native mode body coverage differs from executable inventory")
    lifecycle_phases = {"load", "open", "tick", "render", "close", "unload"}
    for row in body_rows:
        if row.get("runtime_body_equivalence") != "UNPROVEN" \
                or row.get("parity_eligible") is not False:
            raise SceneCoverageError(
                "mode body contract contains an unearned runtime claim"
            )
        if not isinstance(row.get("lifecycle"), dict) \
                or set(row["lifecycle"]) != lifecycle_phases:
            raise SceneCoverageError("native mode body lifecycle coverage is incomplete")

    if transitions.get("schema") != 1 \
            or transitions.get("source", {}).get("executable_sha256") != executable_sha256:
        raise SceneCoverageError("unsupported native scene transition coverage contract")
    transition_rows = transitions.get("modes")
    if not isinstance(transition_rows, list) or len(transition_rows) != 22 \
            or {row.get("mode") for row in transition_rows} != set(native_modes):
        raise SceneCoverageError("native transition modes differ from executable inventory")
    direct_edges = transitions.get("edges")
    location_edges = transitions.get("location_edges")
    if not isinstance(direct_edges, list) or len(direct_edges) != 12 \
            or not isinstance(location_edges, list) or len(location_edges) != 18 \
            or any(set(row) != {"location", "landing", "departure"} for row in location_edges):
        raise SceneCoverageError("native natural transition topology is incomplete")
    natural_edges = [
        *direct_edges,
        *(edge for row in location_edges for edge in (row["landing"], row["departure"])),
    ]
    edge_ids = [edge.get("id") for edge in natural_edges]
    if len(natural_edges) != 48 or any(
        edge.get("source_type") == "mode" and edge.get("source") not in native_modes
        or edge.get("target_type") == "mode" and edge.get("target") not in native_modes
        for edge in natural_edges
    ):
        raise SceneCoverageError("native natural transition topology escaped mode inventory")
    if any(not isinstance(edge_id, str) or not edge_id for edge_id in edge_ids) \
            or len(set(edge_ids)) != 48:
        raise SceneCoverageError("native natural transition edge identities are incomplete")
    terminal = next(
        (edge for edge in natural_edges if edge["id"] == "credits.terminal"), None,
    )
    if terminal is None or {
        "source": terminal.get("source"),
        "source_type": terminal.get("source_type"),
        "target": terminal.get("target"),
        "target_type": terminal.get("target_type"),
    } != {
        "source": "mode_credits",
        "source_type": "mode",
        "target": "__terminal__",
        "target_type": "terminal",
    }:
        raise SceneCoverageError("credits terminal transition is absent or malformed")
    return {edge["id"]: edge for edge in natural_edges}


def _validate_inventory(
    ledger: dict[str, Any], sources: dict[str, Any]
) -> tuple[
    dict[str, tuple[str, ...]],
    dict[str, frozenset[str]],
    dict[str, dict[str, Any]],
]:
    inventories = ledger.get("inventories")
    if not isinstance(inventories, dict) or set(inventories) != {"car", "boat", "flight"}:
        raise SceneCoverageError("ledger must declare car, boat and flight inventories")

    scene_graph = sources["director_scene_graph"]
    if not isinstance(scene_graph, dict):
        raise SceneCoverageError("Director scene graph must be an object")
    expected_director = {
        game: tuple(sorted(scene_graph.get(game, {}))) for game in ("car", "boat")
    }
    for game in ("car", "boat"):
        record = inventories[game]
        actual = _inventory_ids(record, game)
        if record["kind"] != "director-movie" or actual != expected_director[game]:
            raise SceneCoverageError(f"{game} inventory differs from the pinned Director graph")

    native_modes = _native_modes(sources["flight_native_function_index"])
    flight_transition_edges = _validate_flight_static_contracts(sources, native_modes)
    flight = inventories["flight"]
    actual_flight = _inventory_ids(flight, "flight")
    if flight["kind"] != "native-mode" or actual_flight != tuple(sorted(native_modes)):
        raise SceneCoverageError("flight inventory differs from the pinned executable mode strings")

    probe = sources["flight_native_scene_probe"]
    if not isinstance(probe, dict) or probe.get("schema") != 1:
        raise SceneCoverageError("unsupported native scene probe")
    if index_sha := sources["flight_native_function_index"].get("source", {}).get("sha256"):
        if index_sha != probe.get("source", {}).get("executable_sha256"):
            raise SceneCoverageError("flight inventories refer to different executables")
    else:
        raise SceneCoverageError("native function index has no executable identity")
    probe_modes = {
        scene["mode"]: scene["mode_address"] for scene in probe.get("scenes", [])
    }
    probe_modes.update({
        target["mode"]: target["mode_address"] for target in probe.get("startup_targets", [])
    })
    transition = probe.get("engine", {}).get("startup_mode_transition", {})
    probe_modes[transition.get("original_mode")] = transition.get("original_mode_address")
    for name, address in probe_modes.items():
        if native_modes.get(name) != address:
            raise SceneCoverageError(f"native scene probe disagrees with executable inventory: {name}")

    ids = {
        "car": expected_director["car"],
        "boat": expected_director["boat"],
        "flight": tuple(sorted(native_modes)),
    }
    exact_editions = {
        game: frozenset(inventories[game]["exact_editions"])
        for game in ("car", "boat", "flight")
    }
    return ids, exact_editions, flight_transition_edges


def _registry_editions(registry: Any) -> dict[str, dict[str, str]]:
    if not isinstance(registry, dict) or registry.get("schema_version") != 1:
        raise SceneCoverageError("unsupported edition registry")
    result: dict[str, dict[str, str]] = {}
    for edition_id, edition in registry.get("editions", {}).items():
        game = edition.get("game")
        language = edition.get("language")
        if game not in {"car", "boat"} or not isinstance(language, str):
            raise SceneCoverageError(f"unsupported registered edition identity: {edition_id}")
        result[edition_id] = {"game": game, "language": language}
    return result


def _validate_editions(ledger: dict[str, Any], registry: Any) -> dict[str, dict[str, Any]]:
    editions = ledger.get("editions")
    if not isinstance(editions, dict):
        raise SceneCoverageError("ledger editions must be an object")
    expected = _registry_editions(registry)
    standalone = ledger.get("standalone_editions")
    expected_standalone = {
        "flight/nl/miel-vliegt-de-wereld-rond": {"game": "flight", "language": "nl"}
    }
    if standalone != expected_standalone:
        raise SceneCoverageError("standalone flight edition differs from native source identity")
    for edition_id, identity in standalone.items():
        if not isinstance(identity, dict) or set(identity) != {"game", "language"}:
            raise SceneCoverageError(f"invalid standalone edition: {edition_id}")
        if identity["game"] != "flight" or not isinstance(identity["language"], str):
            raise SceneCoverageError(f"invalid standalone flight edition: {edition_id}")
        expected[edition_id] = identity
    if set(editions) != set(expected):
        missing = sorted(set(expected) - set(editions))
        extra = sorted(set(editions) - set(expected))
        raise SceneCoverageError(f"edition coverage matrix drifted; missing={missing}, extra={extra}")
    for edition_id, identity in expected.items():
        record = editions[edition_id]
        if not isinstance(record, dict) or set(record) != {"game", "language", "claims"}:
            raise SceneCoverageError(f"invalid edition coverage record: {edition_id}")
        if record["game"] != identity["game"] or record["language"] != identity["language"]:
            raise SceneCoverageError(f"edition identity drifted: {edition_id}")
        if not isinstance(record["claims"], list):
            raise SceneCoverageError(f"edition claims must be a list: {edition_id}")
    return editions


def _validate_evidence_catalog(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog = ledger.get("parity_evidence")
    if not isinstance(catalog, dict):
        raise SceneCoverageError("parity evidence catalog must be an object")
    allowed = {
        "native-trace", "web-trace", "differential-receipt",
        "native-transition-trace", "web-transition-trace",
        "transition-differential-receipt",
    }
    validated: dict[str, dict[str, Any]] = {}
    for evidence_id, record in catalog.items():
        if not isinstance(evidence_id, str) or not evidence_id:
            raise SceneCoverageError("parity evidence has an invalid ID")
        if not isinstance(record, dict) or set(record) != {"kind", "path", "sha256"}:
            raise SceneCoverageError(f"invalid parity evidence record: {evidence_id}")
        if record["kind"] not in allowed or not _is_sha256(record["sha256"]):
            raise SceneCoverageError(f"invalid parity evidence identity: {evidence_id}")
        if not isinstance(record["path"], str) or not record["path"] \
                or Path(record["path"]).is_absolute():
            raise SceneCoverageError(f"invalid parity evidence path: {evidence_id}")
        path = (ROOT / record["path"]).resolve()
        try:
            path.relative_to(ROOT.resolve())
        except (TypeError, ValueError) as error:
            raise SceneCoverageError(f"parity evidence escapes the repository: {evidence_id}") from error
        if not path.is_file() or _sha256(path) != record["sha256"]:
            raise SceneCoverageError(f"parity evidence is missing or drifted: {evidence_id}")
        checked = dict(record)
        if record["kind"] in {"native-trace", "web-trace"}:
            body_trace = _load_mode_body_trace(path, evidence_id)
            expected_producer = "NATIVE" if record["kind"] == "native-trace" else "WEB"
            expected_subject = (
                natural_transition_trace.NATIVE_EXECUTABLE_SHA256
                if expected_producer == "NATIVE"
                else natural_transition_trace.WEB_BUILD_SHA256
            )
            if body_trace["producer"] != expected_producer \
                    or body_trace["subject_sha256"] != expected_subject:
                raise SceneCoverageError(
                    f"mode BODY trace producer/source differs: {evidence_id}"
                )
            checked["body_trace"] = body_trace
        elif record["kind"] == "differential-receipt":
            receipt = _load_json(path, evidence_id)
            required = {
                "schema", "protocol", "edition", "scene", "native_trace_sha256",
                "web_trace_sha256", "comparator", "comparison_policy",
                "comparison_policy_sha256", "result",
            }
            if not isinstance(receipt, dict) or set(receipt) != required \
                    or receipt.get("schema") != 2 \
                    or receipt.get("protocol") != BODY_DIFFERENTIAL_PROTOCOL \
                    or receipt.get("result") != "PASS" \
                    or receipt.get("comparator") != BODY_COMPARATOR \
                    or receipt.get("comparison_policy") != BODY_COMPARISON_POLICY \
                    or receipt.get("comparison_policy_sha256") \
                    != _canonical_sha256(BODY_COMPARISON_POLICY) \
                    or not _is_sha256(receipt.get("native_trace_sha256")) \
                    or not _is_sha256(receipt.get("web_trace_sha256")):
                raise SceneCoverageError(f"differential receipt is not PASS: {evidence_id}")
            checked["receipt"] = receipt
        elif record["kind"] in {"native-transition-trace", "web-transition-trace"}:
            transition = _load_natural_transition(path, evidence_id)
            expected_driver = (
                "native-gameplay" if record["kind"] == "native-transition-trace"
                else "web-gameplay"
            )
            if transition["entry_driver"] != expected_driver:
                raise SceneCoverageError(
                    f"natural transition trace has the wrong driver: {evidence_id}"
                )
            checked["transition"] = transition
        elif record["kind"] == "transition-differential-receipt":
            receipt = _load_json(path, evidence_id)
            try:
                receipt = natural_transition_trace.validate_receipt(receipt)
            except ValueError as error:
                raise SceneCoverageError(
                    f"natural transition differential receipt is not PASS: {evidence_id}"
                ) from error
            checked["receipt"] = receipt
        validated[evidence_id] = checked
    return validated


def _load_natural_transition(path: Path, label: str) -> dict[str, Any]:
    try:
        return natural_transition_trace.load_capture(path)
    except ValueError as error:
        raise SceneCoverageError(f"invalid natural transition trace: {label}: {error}") from error


def _validate_proof_triplet(
    *, edition_id: str, scene: str, refs: list[str], evidence: dict[str, dict[str, Any]],
    required_kinds: set[str], gate: str,
) -> None:
    kinds = {evidence[ref]["kind"] for ref in refs}
    if kinds != required_kinds or len(refs) != len(required_kinds):
        if gate == "BODY_PARITY":
            detail = "native, web and PASS differential evidence"
        else:
            detail = "natural native, web and PASS transition differential evidence"
        raise SceneCoverageError(f"{gate} requires {detail}: {edition_id}:{scene}")
    by_kind = {evidence[ref]["kind"]: evidence[ref] for ref in refs}
    native_kind = "native-trace"
    web_kind = "web-trace"
    receipt_kind = "differential-receipt"
    if by_kind[native_kind]["path"] == by_kind[web_kind]["path"]:
        raise SceneCoverageError(
            f"native and web evidence must be independent: {edition_id}:{scene}"
        )
    receipt = by_kind[receipt_kind]["receipt"]
    native_trace = by_kind[native_kind].get("body_trace")
    web_trace = by_kind[web_kind].get("body_trace")
    if not isinstance(native_trace, dict) or not isinstance(web_trace, dict):
        raise SceneCoverageError(f"BODY_PARITY lacks parsed traces: {edition_id}:{scene}")
    if native_trace["capture_id"] == web_trace["capture_id"]:
        raise SceneCoverageError(
            f"native and web BODY captures must be independent: {edition_id}:{scene}"
        )
    if any(trace["edition"] != edition_id or trace["scene"] != scene
           for trace in (native_trace, web_trace)):
        raise SceneCoverageError(
            f"mode BODY trace provenance differs from claim: {edition_id}:{scene}"
        )
    if receipt["edition"] != edition_id or receipt["scene"] != scene \
            or receipt["native_trace_sha256"] != by_kind[native_kind]["sha256"] \
            or receipt["web_trace_sha256"] != by_kind[web_kind]["sha256"]:
        raise SceneCoverageError(
            f"differential receipt provenance differs from claim: {edition_id}:{scene}"
        )
    if _canonical_bytes(_body_comparable(native_trace)) \
            != _canonical_bytes(_body_comparable(web_trace)):
        raise SceneCoverageError(
            f"recomputed mode BODY differential differs: {edition_id}:{scene}"
        )


def _validate_transition_proof_triplet(
    *, edition_id: str, edge_id: str, edge: dict[str, Any], refs: list[str],
    evidence: dict[str, dict[str, Any]],
) -> None:
    required_kinds = {
        "native-transition-trace", "web-transition-trace",
        "transition-differential-receipt",
    }
    kinds = {evidence[ref]["kind"] for ref in refs}
    if kinds != required_kinds or len(refs) != len(required_kinds):
        raise SceneCoverageError(
            "NATURAL_TRANSITION_PARITY requires natural native, web and PASS "
            f"transition differential evidence: {edition_id}:{edge_id}"
        )
    by_kind = {evidence[ref]["kind"]: evidence[ref] for ref in refs}
    native = by_kind["native-transition-trace"]
    web = by_kind["web-transition-trace"]
    receipt = by_kind["transition-differential-receipt"]["receipt"]
    if native["path"] == web["path"]:
        raise SceneCoverageError(
            f"native and web transition evidence must be independent: {edition_id}:{edge_id}"
        )
    try:
        expected = natural_transition_trace.canonical_identity(
            edge_id, receipt.get("transition_site"),
        )
    except ValueError as error:
        raise SceneCoverageError(
            f"natural transition receipt differs from canonical edge: {edition_id}:{edge_id}"
        ) from error
    expected["edition"] = edition_id
    observed_receipt = {key: receipt.get(key) for key in expected}
    if observed_receipt != expected \
            or receipt.get("native_trace_sha256") != native["sha256"] \
            or receipt.get("web_trace_sha256") != web["sha256"]:
        raise SceneCoverageError(
            f"natural transition receipt differs from canonical edge: {edition_id}:{edge_id}"
        )
    if receipt.get("native_capture_id") != native["transition"]["capture_id"] \
            or receipt.get("web_capture_id") != web["transition"]["capture_id"] \
            or receipt.get("native_subject_sha256") != native["transition"]["subject_sha256"] \
            or receipt.get("web_subject_sha256") != web["transition"]["subject_sha256"] \
            or receipt.get("native_raw_trace_sha256") \
            != native["transition"]["raw_trace_sha256"] \
            or receipt.get("web_raw_trace_sha256") != web["transition"]["raw_trace_sha256"]:
        raise SceneCoverageError(
            f"natural transition receipt capture differs from evidence: {edition_id}:{edge_id}"
        )
    for kind in ("native-transition-trace", "web-transition-trace"):
        transition = by_kind[kind]["transition"]
        observed = {key: transition.get(key) for key in expected}
        if observed != expected:
            raise SceneCoverageError(
                f"natural transition trace differs from canonical edge: {edition_id}:{edge_id}"
            )


def _transition_evidence_edge(record: dict[str, Any]) -> str | None:
    if record["kind"] in {"native-transition-trace", "web-transition-trace"}:
        return record["transition"]["edge"]
    if record["kind"] == "transition-differential-receipt":
        return record["receipt"]["edge"]
    return None


def _validate_flight_transition_claims(
    ledger: dict[str, Any], editions: dict[str, dict[str, Any]],
    exact_inventory_editions: dict[str, frozenset[str]],
    edges: dict[str, dict[str, Any]], evidence: dict[str, dict[str, Any]],
) -> tuple[int, int, int, tuple[str, ...]]:
    matrices = ledger.get("flight_transition_claims")
    flight_editions = {
        edition_id for edition_id, edition in editions.items()
        if edition["game"] == "flight"
    }
    if not isinstance(matrices, dict) or set(matrices) != flight_editions:
        raise SceneCoverageError("flight transition edition matrix differs from inventory")
    for evidence_id, record in evidence.items():
        edge_id = _transition_evidence_edge(record)
        if edge_id is not None and edge_id not in edges:
            raise SceneCoverageError(
                f"transition evidence names an unknown edge: {evidence_id}:{edge_id}"
            )
    native_capture_owner: dict[str, str] = {}
    native_raw_owner: dict[str, str] = {}
    web_capture_owner: dict[str, str] = {}
    web_raw_owner: dict[str, str] = {}
    for evidence_id, record in evidence.items():
        if record["kind"] not in {
            "native-transition-trace", "web-transition-trace",
        }:
            continue
        transition = record["transition"]
        is_native = record["kind"] == "native-transition-trace"
        capture_owners = native_capture_owner if is_native else web_capture_owner
        raw_owners = native_raw_owner if is_native else web_raw_owner
        label = "native" if is_native else "web"
        capture_id = transition["capture_id"]
        owner = capture_owners.setdefault(capture_id, transition["edge"])
        if owner != transition["edge"]:
            raise SceneCoverageError(
                f"{label} capture cannot prove multiple natural edges: "
                f"{evidence_id}:{capture_id}:{owner}:{transition['edge']}"
            )
        raw_hash = transition["raw_trace_sha256"]
        raw_owner = raw_owners.setdefault(raw_hash, transition["edge"])
        if raw_owner != transition["edge"]:
            raise SceneCoverageError(
                f"{label} raw capture cannot prove multiple natural edges: "
                f"{evidence_id}:{raw_hash}:{raw_owner}:{transition['edge']}"
            )

    proven = 0
    unproven = 0
    unknown = 0
    gaps: list[str] = []
    expected_ids = set(edges)
    for edition_id in sorted(flight_editions):
        rows = matrices[edition_id]
        if not isinstance(rows, list):
            raise SceneCoverageError(
                f"flight transition claims must be a list: {edition_id}"
            )
        claims: dict[str, dict[str, Any]] = {}
        evidence_owner: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("edge"), str) \
                    or not isinstance(row.get("evidence"), list):
                continue
            for ref in set(row["evidence"]):
                owner = evidence_owner.setdefault(ref, row["edge"])
                if owner != row["edge"]:
                    raise SceneCoverageError(
                        "duplicate flight transition evidence reference: "
                        f"{edition_id}:{row['edge']}:{ref}"
                    )
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"edge", "status", "evidence"}:
                raise SceneCoverageError(
                    f"invalid flight transition claim: {edition_id}"
                )
            edge_id = row["edge"]
            if edge_id not in expected_ids:
                raise SceneCoverageError(
                    f"flight transition claim names an unknown edge: {edition_id}:{edge_id}"
                )
            if edge_id in claims:
                raise SceneCoverageError(
                    f"duplicate flight transition claim: {edition_id}:{edge_id}"
                )
            if row["status"] not in {"UNPROVEN", "PARITY_PROVEN"}:
                raise SceneCoverageError(
                    f"invalid flight transition status: {edition_id}:{edge_id}"
                )
            refs = row["evidence"]
            if not isinstance(refs, list) or len(refs) != len(set(refs)) \
                    or any(ref not in evidence for ref in refs):
                raise SceneCoverageError(
                    f"invalid flight transition evidence: {edition_id}:{edge_id}"
                )
            if row["status"] == "PARITY_PROVEN":
                if edition_id not in exact_inventory_editions["flight"]:
                    raise SceneCoverageError(
                        "NATURAL_TRANSITION_PARITY requires an exact edition inventory: "
                        f"{edition_id}:{edge_id}"
                    )
                _validate_transition_proof_triplet(
                    edition_id=edition_id,
                    edge_id=edge_id,
                    edge=edges[edge_id],
                    refs=refs,
                    evidence=evidence,
                )
                proven += 1
            elif refs:
                raise SceneCoverageError(
                    "UNPROVEN NATURAL_TRANSITION_PARITY must not imply evidence: "
                    f"{edition_id}:{edge_id}"
                )
            else:
                unproven += 1
                gaps.append(
                    f"UNPROVEN_NATURAL_TRANSITION_PARITY:{edition_id}:{edge_id}"
                )
            claims[edge_id] = row
        missing = sorted(expected_ids - set(claims))
        if missing:
            unknown += len(missing)
            raise SceneCoverageError(
                f"flight transition claim matrix is missing edges: {edition_id}:{','.join(missing)}"
            )
        if len(claims) != len(edges):
            raise SceneCoverageError(
                f"flight transition claim matrix does not contain exactly {len(edges)} edges: "
                f"{edition_id}"
            )
    return proven, unproven, unknown, tuple(gaps)


def validate_ledger(path: Path = DEFAULT_LEDGER) -> CoverageReport:
    ledger = _load_json(path, "scene coverage ledger")
    required_ledger_fields = {
        "schema", "protocol", "policy", "sources", "inventories",
        "standalone_editions", "parity_evidence", "editions",
        "flight_transition_claims",
    }
    if not isinstance(ledger, dict) or set(ledger) != required_ledger_fields \
            or ledger.get("schema") != 2 \
            or ledger.get("protocol") != "miel-scene-coverage-ledger":
        raise SceneCoverageError("unsupported scene coverage ledger")
    source_records = ledger.get("sources")
    required_sources = {
        "edition_registry", "director_scene_graph", "flight_native_function_index",
        "flight_native_scene_probe", "flight_native_mode_bodies",
        "flight_native_scene_transitions", "flight_web_transition_build",
        "flight_parity_ledger", "flight_checkpoints",
    }
    if not isinstance(source_records, dict) or set(source_records) != required_sources:
        raise SceneCoverageError("scene coverage source set differs from the contract")
    loaded_sources = {
        name: _pinned_source(record, name)[1] for name, record in source_records.items()
    }
    if source_records["edition_registry"]["authority"] != "edition-registry":
        raise SceneCoverageError("edition registry has the wrong authority")
    if any(source_records[name]["authority"] != "inventory" for name in (
        "director_scene_graph", "flight_native_function_index", "flight_native_scene_probe",
        "flight_native_mode_bodies", "flight_native_scene_transitions",
    )):
        raise SceneCoverageError("scene inventories require inventory authority")
    if any(source_records[name]["authority"] != "subsystem-only" for name in (
        "flight_parity_ledger", "flight_checkpoints",
    )):
        raise SceneCoverageError("flight checkpoints must remain subsystem-only evidence")
    if source_records["flight_web_transition_build"]["authority"] != "web-parity-build":
        raise SceneCoverageError("web transition build has the wrong authority")

    inventories, exact_inventory_editions, flight_transition_edges = \
        _validate_inventory(ledger, loaded_sources)
    editions = _validate_editions(ledger, loaded_sources["edition_registry"])
    scoped_editions = set().union(*exact_inventory_editions.values())
    if not scoped_editions.issubset(editions):
        raise SceneCoverageError("an exact inventory names an unknown edition")
    for game, edition_ids in exact_inventory_editions.items():
        if any(editions[edition_id]["game"] != game for edition_id in edition_ids):
            raise SceneCoverageError(f"{game} exact inventory contains another game's edition")
    evidence = _validate_evidence_catalog(ledger)
    body_evidence_kinds = {"native-trace", "web-trace", "differential-receipt"}
    (
        natural_transition_parity_proven,
        natural_transition_parity_unproven,
        natural_transition_parity_unknown,
        transition_gaps,
    ) = _validate_flight_transition_claims(
        ledger,
        editions,
        exact_inventory_editions,
        flight_transition_edges,
        evidence,
    )
    flight_transition_matrix_proven = (
        natural_transition_parity_proven == len(flight_transition_edges)
        and natural_transition_parity_unproven == 0
        and natural_transition_parity_unknown == 0
    )
    expected_body_claims = {
        claim["scene"]: claim
        for claim in _negative_body_claims(
            source_records["flight_native_mode_bodies"],
            loaded_sources["flight_native_mode_bodies"],
        )
    }

    proven = 0
    unproven = 0
    unknown = 0
    inventory_unproven = 0
    body_parity_proven = 0
    body_parity_unproven = 0
    body_parity_unknown = 0
    gaps: list[str] = list(transition_gaps)
    for edition_id, edition in sorted(editions.items()):
        inventory_is_exact = edition_id in exact_inventory_editions[edition["game"]]
        if not inventory_is_exact:
            inventory_unproven += 1
            gaps.append(f"UNPROVEN_INVENTORY:{edition_id}")
        expected_scenes = set(inventories[edition["game"]])
        claims: dict[str, dict[str, Any]] = {}
        for claim in edition["claims"]:
            if not isinstance(claim, dict) or "scene" not in claim:
                raise SceneCoverageError(f"invalid scene claim in {edition_id}")
            scene = claim["scene"]
            if scene not in expected_scenes:
                raise SceneCoverageError(f"unknown scene claim: {edition_id}:{scene}")
            if scene in claims:
                raise SceneCoverageError(f"duplicate scene claim: {edition_id}:{scene}")
            if edition["game"] == "flight":
                if set(claim) != {"scene", "subject", "coverage", "gates"} \
                        or not isinstance(claim["gates"], dict) \
                        or set(claim["gates"]) != {"BODY_PARITY"}:
                    raise SceneCoverageError(
                        f"flight BODY claim fields differ: {edition_id}:{scene}"
                    )
                expected_claim = expected_body_claims[scene]
                if claim["subject"] != expected_claim["subject"]:
                    raise SceneCoverageError(
                        f"BODY subject identity differs: {edition_id}:{scene}"
                    )
                if claim["coverage"] != BODY_COVERAGE_REQUIREMENT:
                    raise SceneCoverageError(
                        f"BODY coverage vector differs: {edition_id}:{scene}"
                    )
                gate = "BODY_PARITY"
                gate_claim = claim["gates"][gate]
                if not isinstance(gate_claim, dict) \
                        or set(gate_claim) != {"status", "evidence", "blocker"} \
                        or gate_claim["status"] not in {"UNPROVEN", "PARITY_PROVEN"}:
                    raise SceneCoverageError(
                        f"invalid {gate} claim: {edition_id}:{scene}"
                    )
                refs = gate_claim["evidence"]
                if not isinstance(refs, list) or len(refs) != len(set(refs)) \
                        or any(ref not in evidence for ref in refs):
                    raise SceneCoverageError(
                        f"invalid {gate} evidence: {edition_id}:{scene}"
                    )
                if gate_claim["status"] == "PARITY_PROVEN":
                    if gate_claim["blocker"] is not None:
                        raise SceneCoverageError(
                            f"PARITY_PROVEN {gate} retains a blocker: {edition_id}:{scene}"
                        )
                    if not inventory_is_exact:
                        raise SceneCoverageError(
                            f"{gate} requires an exact edition inventory: {edition_id}:{scene}"
                        )
                    _validate_proof_triplet(
                        edition_id=edition_id,
                        scene=scene,
                        refs=refs,
                        evidence=evidence,
                        required_kinds=body_evidence_kinds,
                        gate=gate,
                    )
                elif refs or gate_claim["blocker"] != BODY_UNPROVEN_BLOCKER:
                    raise SceneCoverageError(
                        f"UNPROVEN {gate} needs its explicit blocker and no evidence: "
                        f"{edition_id}:{scene}"
                    )
            else:
                if set(claim) != {"scene", "status", "evidence"}:
                    raise SceneCoverageError(f"invalid scene claim in {edition_id}")
                if claim["status"] not in {"UNPROVEN", "PARITY_PROVEN"}:
                    raise SceneCoverageError(f"invalid scene status: {edition_id}:{scene}")
                refs = claim["evidence"]
                if not isinstance(refs, list) or len(refs) != len(set(refs)) \
                        or any(ref not in evidence for ref in refs):
                    raise SceneCoverageError(f"invalid scene evidence: {edition_id}:{scene}")
                if claim["status"] == "PARITY_PROVEN":
                    if not inventory_is_exact:
                        raise SceneCoverageError(
                            f"PARITY_PROVEN requires an exact edition inventory: {edition_id}:{scene}"
                        )
                    _validate_proof_triplet(
                        edition_id=edition_id,
                        scene=scene,
                        refs=refs,
                        evidence=evidence,
                        required_kinds=body_evidence_kinds,
                        gate="BODY_PARITY",
                    )
                elif refs:
                    raise SceneCoverageError(
                        f"UNPROVEN must not imply evidence: {edition_id}:{scene}"
                    )
            claims[scene] = claim
        if edition["game"] == "flight":
            missing_body_claims = sorted(expected_scenes - set(claims))
            if missing_body_claims:
                raise SceneCoverageError(
                    f"flight body claim matrix is missing modes: {edition_id}:"
                    + ",".join(missing_body_claims)
                )
        for scene in sorted(expected_scenes):
            claim = claims.get(scene)
            key = f"{edition_id}:{scene}"
            if edition["game"] == "flight":
                if claim is None:
                    unknown += 1
                    body_parity_unknown += 1
                    gaps.append(f"UNKNOWN_BODY_PARITY:{key}")
                    continue
                body = claim["gates"]["BODY_PARITY"]["status"]
                if body == "PARITY_PROVEN":
                    body_parity_proven += 1
                    if flight_transition_matrix_proven:
                        proven += 1
                    else:
                        unproven += 1
                else:
                    body_parity_unproven += 1
                    unproven += 1
                    gaps.append(f"UNPROVEN_BODY_PARITY:{key}")
            elif claim is None:
                unknown += 1
                gaps.append(f"UNKNOWN:{key}")
            elif claim["status"] == "UNPROVEN":
                unproven += 1
                gaps.append(f"UNPROVEN:{key}")
            else:
                proven += 1

    expectations = proven + unproven + unknown
    return CoverageReport(
        editions=len(editions),
        expectations=expectations,
        proven=proven,
        unproven=unproven,
        unknown=unknown,
        inventory_unproven=inventory_unproven,
        flight_expectations=len(inventories["flight"]),
        flight_transition_expectations=len(flight_transition_edges),
        body_parity_proven=body_parity_proven,
        body_parity_unproven=body_parity_unproven,
        body_parity_unknown=body_parity_unknown,
        natural_transition_parity_proven=natural_transition_parity_proven,
        natural_transition_parity_unproven=natural_transition_parity_unproven,
        natural_transition_parity_unknown=natural_transition_parity_unknown,
        release_ready=expectations > 0 and not gaps,
        gaps=tuple(gaps),
    )


def enforce_release_coverage(path: Path = DEFAULT_LEDGER) -> CoverageReport:
    report = validate_ledger(path)
    if not report.release_ready:
        raise SceneCoverageGap(
            f"scene parity is incomplete: {report.proven}/{report.expectations} proven, "
            f"{report.unproven} unproven, {report.unknown} unknown; flight natural "
            f"transitions {report.natural_transition_parity_proven}/"
            f"{report.flight_transition_expectations} proven"
        )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument(
        "--inventory-only", action="store_true",
        help="validate pinned inventories and print debt without opening the release gate",
    )
    parser.add_argument(
        "--write", action="store_true",
        help="regenerate explicit negative flight BODY claims from the native inventory",
    )
    parser.add_argument("--report", type=Path, help="write the machine-readable report")
    args = parser.parse_args(argv)
    try:
        if args.write:
            regenerate_negative_body_claims(args.ledger)
        report = validate_ledger(args.ledger)
    except SceneCoverageError as error:
        print(str(error), file=sys.stderr)
        return 1
    encoded = json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not args.inventory_only and not report.release_ready:
        print(
            f"scene parity is incomplete: {report.proven}/{report.expectations} proven",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
