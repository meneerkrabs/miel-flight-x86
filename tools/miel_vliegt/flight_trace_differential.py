#!/usr/bin/env python3
"""Compare captured native/web flight frames and natural scene transitions.

This module never promotes debug/BODY observations or a lone web fixture to
native evidence. It compares two supplied trace artifacts and reports the first
observable divergence. Schema-3 transition receipts are emitted only for one
exact edge from the pinned 48-edge graph.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import natural_transition_trace
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    import natural_transition_trace


PROTOCOL = "miel-vliegt-flight-frame-trace"
VERSION = 2
NATIVE_SEMANTIC_VERSION = 1
NATURAL_TRANSITION_PROTOCOL = natural_transition_trace.PROTOCOL
NATURAL_TRANSITION_DIFFERENTIAL_PROTOCOL = natural_transition_trace.RECEIPT_PROTOCOL
NATURAL_TRANSITION_VERSION = natural_transition_trace.VERSION
FLIGHT_EDITION = natural_transition_trace.EDITION
NATURAL_TRANSITION_SCOPE = natural_transition_trace.SCOPE
ROOT = Path(__file__).resolve().parents[2]
NATIVE_SCENE_TRANSITIONS = ROOT / "content/miel_vliegt/native_scene_transitions.json"
REQUIRED_TRACE_KEYS = {
    "protocol", "version", "capture_kind", "source", "scenario", "frames"
}
REQUIRED_FRAME_KEYS = {"frame", "time_seconds", "inputs", "events"}
OPTIONAL_FRAME_KEYS = {"numeric", "camera", "render"}
WEB_OBSERVATION_SCHEMA = "mulle.flight.frame-observation"
NATIVE_SEMANTIC_PROTOCOL = "miel-vliegt-native-semantic-trace"
TRACE_DOMAINS = frozenset({
    "timing", "controls", "physics", "systems", "collision", "camera",
    "rendering",
})
NATIVE_CONSENSUS_PROTOCOL = "miel-vliegt-native-flight-consensus"
NATIVE_CONTROL_KEYS = ("left", "right", "up", "down", "shift", "control")
NATIVE_SCENARIO_IDS = frozenset({
    "controls-press-hold-release", "taxi-straight", "takeoff-climb",
    "level-flight-turn", "approach-landing", "impact-crash",
    "default-airplane-fixed-camera-frame",
})
NATIVE_SEMANTIC_CHANNELS = frozenset({
    "session.dispatched", "session.navigating", "session.armed", "session.ready",
    "session.complete",
    "rng.seed", "rng.draw", "rng.end",
    "input.focus", "input.transition", "input.sample",
    "clock.tick", "flight.tick", "controls.pre", "controls.post",
    "physics.state", "collision.state", "system.fuel", "camera.commit",
    "render.final", "render.framebuffer",
    "outcome.contact", "outcome.damage", "outcome.crash", "outcome.terrain",
})


NATURAL_TRANSITION_EDGES = natural_transition_trace.EDGES


@dataclass(frozen=True)
class Tolerance:
    absolute: float = 0.0
    relative: float = 0.0


@dataclass(frozen=True)
class Divergence:
    scenario: str
    frame: int | None
    path: str
    reason: str
    native: Any
    web: Any
    tolerance: Tolerance | None = None

    def format(self) -> str:
        location = f"scenario={self.scenario}"
        if self.frame is not None:
            location += f" frame={self.frame}"
        lines = [
            f"DIVERGENCE {location} path={self.path}",
            f"reason: {self.reason}",
            f"native: {_display(self.native)}",
            f"web: {_display(self.web)}",
        ]
        if self.tolerance is not None:
            lines.append(
                "tolerance: "
                f"absolute={self.tolerance.absolute} relative={self.tolerance.relative}"
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class ComparisonReport:
    scenario: str
    frames_compared: int
    divergence: Divergence | None

    @property
    def matches(self) -> bool:
        return self.divergence is None


class TolerancePolicy:
    """Resolve exact, domain and path-specific numeric tolerances."""

    def __init__(
        self,
        default: Tolerance = Tolerance(),
        domains: dict[str, Tolerance] | None = None,
        paths: dict[str, Tolerance] | None = None,
    ):
        self.default = default
        self.domains = domains or {}
        self.paths = paths or {}

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "TolerancePolicy":
        if not isinstance(value, dict) or set(value) - {"default", "domains", "paths"}:
            raise ValueError("tolerance policy supports only default, domains and paths")
        domains = value.get("domains", {})
        paths = value.get("paths", {})
        if not isinstance(domains, dict) or not isinstance(paths, dict):
            raise ValueError("tolerance domains and paths must be objects")
        return cls(
            default=_parse_tolerance(value.get("default", 0.0), "default"),
            domains={key: _parse_tolerance(item, f"domains.{key}") for key, item in domains.items()},
            paths={key: _parse_tolerance(item, f"paths.{key}") for key, item in paths.items()},
        )

    def for_path(self, path: str, domain: str | None) -> Tolerance:
        matches = [pattern for pattern in self.paths if _path_matches(pattern, path)]
        if matches:
            # Prefer the most specific path rule, independent of JSON key order.
            pattern = max(matches, key=lambda item: (len(item.replace("*", "")), len(item)))
            return self.paths[pattern]
        if domain is not None and domain in self.domains:
            return self.domains[domain]
        return self.default


def _path_matches(pattern: str, path: str) -> bool:
    """Match a JSON-style path where every ``*`` is a plain wildcard."""
    expression = re.escape(pattern).replace(r"\*", ".*")
    return re.fullmatch(expression, path) is not None


def _parse_tolerance(value: Any, path: str) -> Tolerance:
    if isinstance(value, bool):
        raise ValueError(f"{path} must be a non-negative tolerance")
    if isinstance(value, (int, float)):
        tolerance = Tolerance(float(value), 0.0)
    elif isinstance(value, dict) and set(value) <= {"absolute", "relative"}:
        tolerance = Tolerance(float(value.get("absolute", 0.0)), float(value.get("relative", 0.0)))
    else:
        raise ValueError(f"{path} must be a number or absolute/relative object")
    if not math.isfinite(tolerance.absolute) or not math.isfinite(tolerance.relative) \
            or tolerance.absolute < 0 or tolerance.relative < 0:
        raise ValueError(f"{path} must contain finite non-negative tolerances")
    return tolerance


def load_tolerance_policy(path: Path | None) -> TolerancePolicy:
    if path is None:
        return TolerancePolicy()
    value = json.loads(path.read_text(encoding="utf-8"))
    return TolerancePolicy.from_mapping(value)


def load_trace(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path}: invalid JSON at line {error.lineno}") from error
    validate_trace(value, str(path))
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_transition_identity(
    edge: str, transition_site: str | None = None,
) -> dict[str, Any]:
    return natural_transition_trace.canonical_identity(edge, transition_site)


def natural_transition_event(
    edge: str, entry_driver: str, *, capture_id: str, sequence: int, tick: int,
    transition_site: str | None = None,
) -> dict[str, Any]:
    """Create one schema-3 event; capture provenance is supplied separately."""
    if entry_driver not in {"native-gameplay", "web-gameplay"}:
        raise ValueError(f"unsupported natural transition driver: {entry_driver!r}")
    return {
        "schema": NATURAL_TRANSITION_VERSION,
        "protocol": NATURAL_TRANSITION_PROTOCOL,
        "record": "scene_transition",
        **_canonical_transition_identity(edge, transition_site),
        "entry_driver": entry_driver,
        "capture_id": capture_id,
        "sequence": sequence,
        "tick": tick,
        "debug_entry": False,
        "evidence_scope": NATURAL_TRANSITION_SCOPE,
    }


def validate_natural_transition_event(
    event: Any, expected_driver: str | None = None, label: str = "transition",
) -> dict[str, Any]:
    """Validate the canonical event fields (the file loader validates provenance)."""
    required = {
        "schema", "protocol", "record", "edition", "edge", "source_scene", "scene",
        "entry_path", "entry_driver", "transition_site", "transition_trigger",
        "transition_predicate", "capture_id", "sequence", "tick", "debug_entry",
        "evidence_scope",
    }
    if not isinstance(event, dict) or set(event) != required \
            or event.get("schema") != NATURAL_TRANSITION_VERSION \
            or event.get("protocol") != NATURAL_TRANSITION_PROTOCOL \
            or event.get("record") != "scene_transition":
        raise ValueError(f"{label}: invalid natural transition trace")
    if event.get("debug_entry") is not False:
        raise ValueError(f"{label}: natural transition evidence cannot use debug entry")
    if event.get("evidence_scope") != NATURAL_TRANSITION_SCOPE:
        raise ValueError(
            f"{label}: BODY_ONLY evidence cannot satisfy natural transition parity"
        )
    driver = event.get("entry_driver")
    if driver not in {"native-gameplay", "web-gameplay"} \
            or (expected_driver is not None and driver != expected_driver):
        raise ValueError(f"{label}: natural transition trace has the wrong driver")
    edge = event.get("edge")
    if not isinstance(edge, str) or not edge:
        raise ValueError(f"{label}: invalid natural transition trace edge")
    if not natural_transition_trace.CAPTURE_ID.fullmatch(event.get("capture_id", "")) \
            or isinstance(event.get("sequence"), bool) \
            or not isinstance(event.get("sequence"), int) or event["sequence"] < 0 \
            or isinstance(event.get("tick"), bool) \
            or not isinstance(event.get("tick"), int) or event["tick"] < 0:
        raise ValueError(f"{label}: invalid capture identity/sequence")
    expected = _canonical_transition_identity(
        edge, event.get("transition_site"),
    )
    observed = {key: event.get(key) for key in expected}
    if observed != expected:
        raise ValueError(f"{label}: natural transition trace differs from canonical edge")
    return dict(event)


def load_natural_transition_file(path: Path, expected_driver: str) -> dict[str, Any]:
    return natural_transition_trace.load_capture(path, expected_driver)


def compare_natural_transition_files(native_path: Path, web_path: Path) -> dict[str, Any]:
    """Return a hash-bound PASS receipt only for the same captured edge/site."""
    return natural_transition_trace.compare(native_path, web_path)


def validate_natural_transition_receipt(receipt: Any) -> dict[str, Any]:
    return natural_transition_trace.validate_receipt(receipt)


def web_observation_to_trace_frame(observation: dict[str, Any], time_seconds: float) -> dict[str, Any]:
    """Bridge the browser observation schema to the neutral trace protocol."""
    if not isinstance(observation, dict) \
            or observation.get("schema") != WEB_OBSERVATION_SCHEMA \
            or observation.get("version") != 1:
        raise ValueError("unsupported web flight frame observation")
    required = {
        "schema", "version", "frameIndex", "input", "timing", "physics",
        "camera", "collisions", "events", "render",
    }
    if set(observation) != required:
        raise ValueError("web flight frame observation has an invalid shape")
    collisions = _canonical_collision_observation(
        observation["collisions"], "web flight frame observation.collisions",
    )
    frame = {
        "frame": observation["frameIndex"],
        "time_seconds": _finite(time_seconds, "time_seconds"),
        "inputs": observation["input"],
        "events": observation["events"],
        "numeric": {
            "timing": observation["timing"],
            "physics": observation["physics"],
            "collisions": collisions,
        },
        "camera": {
            "projection_matrix": observation["camera"]["projectionMatrix"],
            "view_matrix": observation["camera"]["viewMatrix"],
            "vertical_fov_radians": observation["camera"]["verticalFovRadians"],
            "near_clip": observation["camera"]["nearClip"],
            "far_clip": observation["camera"]["farClip"],
            "viewport": observation["camera"]["viewport"],
            "control": _web_camera_control(observation["camera"].get("control")),
        },
        "render": {"diagnostics": {"webgl": observation["render"]}},
    }
    _validate_frame(frame, observation["frameIndex"], "web-observation")
    return frame


def _canonical_collision_observation(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"observed", "contacts"}:
        raise ValueError(f"{label} has an invalid shape")
    if type(value["observed"]) is not bool or not isinstance(value["contacts"], list):
        raise ValueError(f"{label} has invalid availability metadata")
    if not value["observed"] and value["contacts"]:
        raise ValueError(f"{label} has contacts from an unobserved channel")
    required = {
        "kind", "contactPosition", "contactNormal", "relativeVelocity",
        "damage", "landingClassification",
    }
    for index, contact in enumerate(value["contacts"]):
        if not isinstance(contact, dict) or set(contact) != required:
            raise ValueError(f"{label}.contacts[{index}] has an invalid shape")
        if not isinstance(contact["kind"], str) or not contact["kind"] \
                or not isinstance(contact["landingClassification"], str) \
                or not contact["landingClassification"] \
                or not _is_number(contact["damage"]):
            raise ValueError(f"{label}.contacts[{index}] is invalid")
        for field in ("contactPosition", "contactNormal", "relativeVelocity"):
            vector = contact[field]
            if not isinstance(vector, list) or len(vector) != 3 \
                    or any(not _is_number(entry) for entry in vector):
                raise ValueError(
                    f"{label}.contacts[{index}].{field} is invalid",
                )
    return _json_object_clone(value, label)


def _web_camera_control(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("web camera control is invalid")
    if value.get("owner") == "common_location" and set(value) == {"owner", "state"}:
        return dict(value)
    fields = {"owner", "manualCameraEnabled", "moveForward", "moveBackward"}
    if value.get("owner") == "mode_fly" and set(value) == fields:
        return {
            "owner": "mode_fly",
            "manual_camera_enabled": value["manualCameraEnabled"],
            "move_forward": value["moveForward"],
            "move_backward": value["moveBackward"],
        }
    raise ValueError("web camera control is invalid")


def web_observations_to_trace(
    observations: list[dict[str, Any]], source: dict[str, Any], scenario: dict[str, Any],
) -> dict[str, Any]:
    """Package consecutive browser observations without inventing native provenance."""
    if not observations:
        raise ValueError("web observation trace cannot be empty")
    elapsed = 0.0
    frames = []
    for expected, observation in enumerate(observations):
        if observation.get("frameIndex") != expected:
            raise ValueError("web observations must be contiguous from frame zero")
        elapsed += _finite(observation.get("timing", {}).get("deltaSeconds"), "deltaSeconds")
        frames.append(web_observation_to_trace_frame(observation, elapsed))
    trace = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "capture_kind": "web",
        "source": source,
        "scenario": scenario,
        "frames": frames,
    }
    validate_trace(trace, "web-observations")
    return trace


def native_semantic_to_trace(
    semantic: dict[str, Any], source: dict[str, Any], scenario: dict[str, Any],
    framebuffer_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize one completed native MVT session to the neutral frame protocol.

    The bridge only decodes fields emitted by the reviewed observer. It derives
    WebGL view/projection matrices from the proven CcCamera post-render snapshot
    and inclusive native viewport contract. It promotes a canonical RGBA
    checkpoint only when that checkpoint is bound to the exact raw DirectDraw
    semantic record through ``framebuffer_evidence``.
    """
    if not isinstance(semantic, dict):
        raise ValueError("native semantic trace must be an object")
    required = {
        "schema", "protocol", "records", "semantic_sha256", "raw_log_sha256",
        "record_count", "profile", "scenario_id", "session_ready", "complete",
    }
    if not required <= set(semantic):
        raise ValueError("native semantic trace is missing parsed-session provenance")
    if semantic["schema"] != NATIVE_SEMANTIC_VERSION \
            or semantic["protocol"] != NATIVE_SEMANTIC_PROTOCOL:
        raise ValueError("unsupported native semantic trace")
    if semantic["profile"] != "production-session" \
            or semantic["session_ready"] is not True or semantic["complete"] is not True:
        raise ValueError("native semantic trace is not a completed production session")
    records = semantic["records"]
    if not isinstance(records, list) or not records \
            or semantic["record_count"] != len(records):
        raise ValueError("native semantic record count is invalid")
    canonical_semantic = {"schema": NATIVE_SEMANTIC_VERSION,
                          "protocol": NATIVE_SEMANTIC_PROTOCOL,
                          "records": records}
    semantic_sha256 = _canonical_sha256(canonical_semantic)
    if semantic["semantic_sha256"] != semantic_sha256 \
            or not _sha256_string(semantic["raw_log_sha256"]):
        raise ValueError("native semantic provenance hash is invalid")

    source_value = _json_object_clone(source, "native source provenance")
    scenario_value = _json_object_clone(scenario, "native scenario")
    scenario_id = scenario_value.get("id")
    script = scenario_value.get("input_script")
    if scenario_id not in NATIVE_SCENARIO_IDS \
            or scenario_id != semantic["scenario_id"]:
        raise ValueError("native semantic scenario identity differs")
    if not isinstance(script, dict) or isinstance(script.get("tick_count"), bool) \
            or not isinstance(script.get("tick_count"), int) or script["tick_count"] <= 0:
        raise ValueError("native scenario has no positive input tick_count")
    if "semantic_sha256" in source_value \
            and source_value["semantic_sha256"] != semantic_sha256:
        raise ValueError("native source semantic_sha256 conflicts with the MVT session")
    if "raw_log_sha256" in source_value \
            and source_value["raw_log_sha256"] != semantic["raw_log_sha256"]:
        raise ValueError("native source raw_log_sha256 conflicts with the MVT session")
    source_value["semantic_sha256"] = semantic_sha256
    source_value["raw_log_sha256"] = semantic["raw_log_sha256"]
    evidence_tick = None
    evidence_raw_sha256 = None
    evidence_checkpoint = None
    if framebuffer_evidence is not None:
        if not isinstance(framebuffer_evidence, dict) or set(framebuffer_evidence) != {
            "tick", "raw_sha256", "pixel_checkpoint",
        }:
            raise ValueError("native framebuffer evidence has an invalid shape")
        evidence_tick = framebuffer_evidence["tick"]
        evidence_raw_sha256 = framebuffer_evidence["raw_sha256"]
        evidence_checkpoint = framebuffer_evidence["pixel_checkpoint"]
        if isinstance(evidence_tick, bool) or not isinstance(evidence_tick, int) \
                or evidence_tick < 0 or not _sha256_string(evidence_raw_sha256) \
                or _invalid_pixel_checkpoint([{
                    "render": {"pixel_checkpoint": evidence_checkpoint},
                }]) is not None:
            raise ValueError("native framebuffer evidence is not canonical")

    by_tick: dict[int, list[dict[str, Any]]] = {}
    for sequence, record in enumerate(records):
        if not isinstance(record, dict) or record.get("sequence") != sequence:
            raise ValueError("native semantic records are not contiguous")
        channel = record.get("channel")
        if channel not in NATIVE_SEMANTIC_CHANNELS:
            raise ValueError(f"unsupported native semantic channel: {channel!r}")
        tick = record.get("tick")
        if tick is not None and channel not in {"rng.seed", "rng.draw", "rng.end"}:
            if isinstance(tick, bool) or not isinstance(tick, int) or tick < 0:
                raise ValueError(f"native semantic {channel} has an invalid tick")
            by_tick.setdefault(tick, []).append(record)

    tick_count = script["tick_count"]
    clock_ticks = sorted(
        record["tick"] for record in records if record.get("channel") == "clock.tick"
    )
    if clock_ticks != list(range(tick_count)):
        raise ValueError("native clock ticks do not cover the scenario contiguously")

    elapsed = 0.0
    frames: list[dict[str, Any]] = []
    for tick in range(tick_count):
        rows = by_tick.get(tick, [])
        clock = _unique_native_record(rows, "clock.tick", tick)
        flight_tick = _unique_native_record(rows, "flight.tick", tick)
        input_sample = _unique_native_record(rows, "input.sample", tick)
        controls = _unique_native_record(rows, "controls.post", tick)
        physics = _unique_native_record(
            rows, "physics.state", tick, phase="leave", outer=True,
        )
        camera = _unique_native_record(rows, "camera.commit", tick)
        render = _unique_native_record(rows, "render.final", tick)
        collision = _unique_native_record(
            rows, "collision.state", tick, phase="commit", outer=True, required=False,
        )
        framebuffer = _unique_native_record(
            rows, "render.framebuffer", tick, required=False,
        )

        dt = _f32_from_bits(clock["values"].get("scripted_dt_f32_bits"),
                            f"clock.tick[{tick}].scripted")
        flight_dt = _f32_from_bits(flight_tick["values"].get("dt_f32_bits"),
                                   f"flight.tick[{tick}]")
        if _f32_bits(flight_tick["values"].get("dt_f32_bits")) \
                != _f32_bits(clock["values"].get("scripted_dt_f32_bits")):
            raise ValueError(f"native timing transcript differs at tick {tick}")
        elapsed += dt

        inputs = _native_inputs(input_sample, tick)
        controls_value = controls.get("values")
        physics_value = physics.get("values")
        camera_value = camera.get("values")
        if not isinstance(controls_value, dict) or controls_value.get("flight_valid") is not True:
            raise ValueError(f"native controls are invalid at tick {tick}")
        if not isinstance(physics_value, dict) or physics_value.get("state_valid") is not True:
            raise ValueError(f"native physics is invalid at tick {tick}")
        if not isinstance(camera_value, dict) or camera_value.get("camera_valid") is not True \
                or camera_value.get("flight_valid") is not True:
            raise ValueError(f"native camera is invalid at tick {tick}")
        if flight_dt != dt:
            raise ValueError(f"native flight delta differs at tick {tick}")

        numeric = {
            "timing": {"deltaSeconds": dt},
            "controls": _native_controls(controls_value, tick),
            "physics": _native_state(physics_value, tick),
            "systems": _native_systems(physics_value, tick),
            # collision.state is a response-state snapshot, not contact
            # geometry. Keep the channel explicitly unavailable so an empty
            # contact list can never be promoted as observed no-contact.
            "collisions": {"observed": False, "contacts": []},
        }
        if collision is not None:
            collision_value = collision.get("values")
            if not isinstance(collision_value, dict) \
                    or collision_value.get("state_valid") is not True:
                raise ValueError(f"native collision state is invalid at tick {tick}")
            # A pre/post flight state is not contact geometry. Keep the
            # response snapshot for diagnosis while the collision parity gate
            # remains closed until the observer emits native contact evidence.
            numeric["collisionResponse"] = _native_state(collision_value, tick)

        event_rows = [
            row for row in rows if str(row.get("channel", "")).startswith("outcome.")
        ]
        events = [
            {"channel": row["channel"], "values": row["values"]}
            for row in event_rows
        ]
        render_value: dict[str, Any] = {
            "diagnostics": {"native": render.get("values", {})},
        }
        if framebuffer is not None:
            render_value["diagnostics"]["native_framebuffer"] = framebuffer["values"]
            if evidence_tick == tick:
                if framebuffer["values"].get("raw_sha256") != evidence_raw_sha256:
                    raise ValueError("native framebuffer evidence raw hash differs")
                render_value["pixel_checkpoint"] = evidence_checkpoint
        frame = {
            "frame": tick,
            "time_seconds": elapsed,
            "inputs": inputs,
            "events": events,
            "numeric": numeric,
            "camera": _native_camera(camera_value, tick),
            "render": render_value,
        }
        _validate_frame(frame, tick, "native-semantic")
        frames.append(frame)

    trace = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "capture_kind": "native",
        "source": source_value,
        "scenario": scenario_value,
        "frames": frames,
    }
    validate_trace(trace, "native-semantic")
    if framebuffer_evidence is not None and not any(
        frame.get("render", {}).get("pixel_checkpoint") == evidence_checkpoint
        for frame in frames
    ):
        raise ValueError("native framebuffer evidence has no matching semantic record")
    return trace


def native_consensus_to_trace(
    consensus: dict[str, Any], source: dict[str, Any], scenario: dict[str, Any],
) -> dict[str, Any]:
    """Normalize the retained native consensus projection without filling gaps.

    The consensus deliberately excludes the wall-clock-derived damage timer,
    camera commits, framebuffer records and contact geometry. Those fields stay
    absent so domain comparison reports the evidence boundary instead of
    silently manufacturing observations.
    """
    required = {
        "schema", "protocol", "status", "promotion_allowed", "scenario",
        "provenance", "determinism", "coverage", "samples",
    }
    if not isinstance(consensus, dict) or set(consensus) != required \
            or consensus.get("schema") != 1 \
            or consensus.get("protocol") != NATIVE_CONSENSUS_PROTOCOL \
            or consensus.get("status") != "CANDIDATE_PARTIAL_NATIVE_EVIDENCE" \
            or consensus.get("promotion_allowed") is not False:
        raise ValueError("native consensus is not fail-closed candidate evidence")
    source_value = _json_object_clone(source, "native consensus source provenance")
    scenario_value = _json_object_clone(scenario, "native consensus scenario")
    scenario_id = scenario_value.get("id")
    if scenario_id not in NATIVE_SCENARIO_IDS \
            or consensus.get("scenario") != scenario_id:
        raise ValueError("native consensus scenario identity differs")

    provenance = consensus.get("provenance")
    determinism = consensus.get("determinism")
    samples = consensus.get("samples")
    run_count = determinism.get("run_count", 0) if isinstance(determinism, dict) else 0
    runs = provenance.get("runs") if isinstance(provenance, dict) else None
    if not isinstance(provenance, dict) \
            or not _sha256_string(provenance.get("executable_sha256")) \
            or not _sha256_string(provenance.get("observer_dll_sha256")) \
            or not isinstance(determinism, dict) \
            or run_count < 2 or not isinstance(runs, list) \
            or len(runs) != run_count \
            or not isinstance(samples, list) or not samples \
            or determinism.get("sample_count") != len(samples):
        raise ValueError("native consensus provenance or sample count is invalid")
    for run in runs:
        if not isinstance(run, dict) or set(run) != {
            "observer_log_path", "observer_log_sha256",
            "observer_semantic_sha256", "launcher",
        } or not isinstance(run["observer_log_path"], str) \
                or not _sha256_string(run["observer_log_sha256"]) \
                or not _sha256_string(run["observer_semantic_sha256"]):
            raise ValueError("native consensus run provenance is invalid")
        launcher = run["launcher"]
        if not isinstance(launcher, dict) or set(launcher) != {
            "path", "sha256", "executable_sha256", "observer_dll_sha256",
        } or not isinstance(launcher["path"], str) \
                or not _sha256_string(launcher["sha256"]) \
                or launcher["executable_sha256"] != provenance["executable_sha256"] \
                or launcher["observer_dll_sha256"] != provenance["observer_dll_sha256"]:
            raise ValueError("native consensus launcher provenance is invalid")
    projection_sha256 = _canonical_sha256(samples)
    if determinism.get("projection_sha256") != projection_sha256:
        raise ValueError("native consensus projection hash differs")
    if "projection_sha256" in source_value \
            and source_value["projection_sha256"] != projection_sha256:
        raise ValueError("native consensus source projection hash conflicts")
    source_value.update({
        "projection_sha256": projection_sha256,
        "executable_sha256": provenance["executable_sha256"],
        "observer_dll_sha256": provenance["observer_dll_sha256"],
        "evidence_status": consensus["status"],
        "promotion_allowed": False,
    })

    expected_sample_keys = {
        "tick", "clock.tick", "input.sample", "controls.post", "system.fuel",
        "physics.state", "collision.state",
    }
    elapsed = 0.0
    frames: list[dict[str, Any]] = []
    for tick, sample in enumerate(samples):
        if not isinstance(sample, dict) or set(sample) != expected_sample_keys \
                or sample.get("tick") != tick:
            raise ValueError("native consensus samples are not canonical and contiguous")
        clock = sample["clock.tick"]
        physics = sample["physics.state"]
        collision = sample["collision.state"]
        if not isinstance(clock, dict) \
                or set(clock) != {"scripted_dt_f32_bits", "source"} \
                or clock.get("source") != "scenario_transcript" \
                or not isinstance(physics, dict) \
                or set(physics) != {"enter", "leave"} \
                or not isinstance(collision, dict) \
                or set(collision) != {"enter", "commit"}:
            raise ValueError(f"native consensus sample {tick} has an invalid shape")
        dt = _f32_from_bits(
            clock["scripted_dt_f32_bits"],
            f"native consensus clock.tick[{tick}]",
        )
        elapsed += dt
        leave = physics["leave"]
        commit = collision["commit"]
        if not isinstance(leave, dict) or leave.get("phase") != "leave" \
                or leave.get("outer") is not True \
                or not isinstance(commit, dict) or commit.get("phase") != "commit" \
                or commit.get("outer") is not True:
            raise ValueError(f"native consensus state phases differ at tick {tick}")
        frame = {
            "frame": tick,
            "time_seconds": elapsed,
            "inputs": _native_inputs({"values": sample["input.sample"]}, tick),
            "events": [],
            "numeric": {
                "timing": {"deltaSeconds": dt},
                "controls": _native_controls(sample["controls.post"], tick),
                "physics": _native_state(leave, tick),
                "systems": _native_systems(
                    leave, tick, require_damage_gate_timer=False,
                ),
                "collisions": {"observed": False, "contacts": []},
                # The consensus proves a response-state snapshot only. It does
                # not contain contact geometry or landing classification.
                "collisionResponse": _native_state(commit, tick),
            },
            "render": {
                "diagnostics": {
                    "native_consensus_projection": projection_sha256,
                },
            },
        }
        _validate_frame(frame, tick, "native-consensus")
        frames.append(frame)

    trace = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "capture_kind": "native",
        "source": source_value,
        "scenario": scenario_value,
        "frames": frames,
    }
    validate_trace(trace, "native-consensus")
    return trace


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _sha256_string(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _json_object_clone(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{label} must be a non-empty object")
    try:
        clone = json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} must contain JSON values") from error
    _validate_json_tree(clone, label)
    return clone


def _f32_bits(value: Any) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{8}", value) is None:
        raise ValueError("native f32 value must be lowercase 0x + 8 hex digits")
    return int(value[2:], 16)


def _f32_from_bits(value: Any, path: str) -> float:
    number = struct.unpack("<f", struct.pack("<I", _f32_bits(value)))[0]
    if not math.isfinite(number):
        raise ValueError(f"{path} contains a non-finite f32")
    return 0.0 if number == 0.0 else number


def _f32_vector(values: Any, size: int, path: str) -> list[float]:
    if not isinstance(values, list) or len(values) != size:
        raise ValueError(f"{path} must contain {size} native f32 values")
    return [_f32_from_bits(value, f"{path}[{index}]")
            for index, value in enumerate(values)]


def _unique_native_record(
    rows: list[dict[str, Any]], channel: str, tick: int, *,
    phase: str | None = None, outer: bool | None = None, required: bool = True,
) -> dict[str, Any] | None:
    matches = [
        row for row in rows
        if row.get("channel") == channel
        and (phase is None or isinstance(row.get("values"), dict)
             and row["values"].get("phase") == phase)
        and (outer is None or isinstance(row.get("values"), dict)
             and row["values"].get("outer") is outer)
    ]
    if len(matches) > 1 or required and not matches:
        qualifier = f" phase={phase}" if phase is not None else ""
        raise ValueError(
            f"native tick {tick} requires exactly one {channel}{qualifier} record"
        )
    return matches[0] if matches else None


def _native_inputs(record: dict[str, Any], tick: int) -> dict[str, bool]:
    values = record.get("values")
    proof_fields = ("read_valid", "schedule_match", "sample_match", "focus_valid", "valid")
    if not isinstance(values, dict) \
            or any(values.get(field) is not True for field in proof_fields):
        raise ValueError(f"native input proof is incomplete at tick {tick}")
    expected = values.get("expected_mask")
    observed = values.get("observed_mask")
    if not isinstance(expected, str) or re.fullmatch(r"0x[0-9a-f]{2}", expected) is None \
            or expected != observed:
        raise ValueError(f"native input mask differs at tick {tick}")
    mask = int(expected[2:], 16)
    if mask & ~((1 << len(NATIVE_CONTROL_KEYS)) - 1):
        raise ValueError(f"native input mask has unknown bits at tick {tick}")
    return {
        key: bool(mask & (1 << index))
        for index, key in enumerate(NATIVE_CONTROL_KEYS)
    }


def _native_controls(values: dict[str, Any], tick: int) -> dict[str, Any]:
    keys = values.get("keys")
    if not isinstance(keys, dict) or set(keys) != set(NATIVE_CONTROL_KEYS) \
            or any(type(keys[key]) is not int or keys[key] not in {0, 1}
                   for key in NATIVE_CONTROL_KEYS) \
            or type(values.get("controls_enabled")) is not int \
            or values["controls_enabled"] not in {0, 1} \
            or type(values.get("focus_active")) is not bool:
        raise ValueError(f"native control keys are invalid at tick {tick}")
    fields = {
        "analogHorizontal": "analog_horizontal_f32_bits",
        "analogVertical": "analog_vertical_f32_bits",
        "propulsion": "propulsion_f32_bits",
        "propulsionScale": "propulsion_scale_f32_bits",
        "horizontal": "horizontal_f32_bits",
        "vertical": "vertical_f32_bits",
    }
    return {
        "keys": {key: bool(keys[key]) for key in NATIVE_CONTROL_KEYS},
        **{name: _f32_from_bits(values.get(field), f"controls[{tick}].{field}")
           for name, field in fields.items()},
        "enabled": values.get("controls_enabled") == 1,
        "windowFocused": values.get("focus_active") is True,
    }


def _native_state(values: dict[str, Any], tick: int) -> dict[str, Any]:
    orientation_wxyz = _f32_vector(
        values.get("orientation_wxyz_f32_bits"), 4,
        f"state[{tick}].orientation_wxyz_f32_bits",
    )
    return {
        "position": _f32_vector(
            values.get("position_f32_bits"), 3, f"state[{tick}].position_f32_bits",
        ),
        # Web observations use [x,y,z,w]; the observer names its native order.
        "orientation": [*orientation_wxyz[1:], orientation_wxyz[0]],
        "velocity": _f32_vector(
            values.get("velocity_f32_bits"), 3, f"state[{tick}].velocity_f32_bits",
        ),
        "angularVelocity": _f32_vector(
            values.get("angular_velocity_f32_bits"), 3,
            f"state[{tick}].angular_velocity_f32_bits",
        ),
    }


def _native_systems(
    values: dict[str, Any], tick: int, *,
    require_damage_gate_timer: bool = True,
) -> dict[str, Any]:
    fields = {
        "fuel": "fuel_f32_bits",
        "integrity": "integrity_f32_bits",
        "maximumIntegrity": "maximum_integrity_f32_bits",
        "pendingDamage": "pending_damage_f32_bits",
        "damageGateTimer": "damage_gate_timer_f32_bits",
    }
    flag_fields = ("active", "inactive", "floor_enabled")
    if any(type(values.get(field)) is not int or values[field] not in {0, 1}
           for field in flag_fields):
        raise ValueError(f"native system flags are invalid at tick {tick}")
    if not require_damage_gate_timer:
        fields.pop("damageGateTimer")
    return {
        **{name: _f32_from_bits(values.get(field), f"systems[{tick}].{field}")
           for name, field in fields.items()},
        "active": values.get("active") == 1,
        "inactive": values.get("inactive") == 1,
        "floorEnabled": values.get("floor_enabled") == 1,
    }


def _native_camera(values: dict[str, Any], tick: int) -> dict[str, Any]:
    window_endpoints = _f32_vector(
        values.get("window_endpoints_f32_bits"), 4,
        f"camera[{tick}].window_endpoints_f32_bits",
    )
    scaled = _f32_vector(
        values.get("render_scaled_rotation_row_major_f32_bits"), 9,
        f"camera[{tick}].render_scaled_rotation_row_major_f32_bits",
    )
    position = _f32_vector(
        values.get("render_world_position_f32_bits"), 3,
        f"camera[{tick}].render_world_position_f32_bits",
    )
    inverse_scale_squared = _f32_from_bits(
        values.get("render_inverse_scale_squared_f32_bits"),
        f"camera[{tick}].render_inverse_scale_squared",
    )
    linear = [value * inverse_scale_squared for value in scaled]
    near = _f32_from_bits(values.get("near_f32_bits"), f"camera[{tick}].near")
    far = _f32_from_bits(values.get("far_f32_bits"), f"camera[{tick}].far")
    horizontal_degrees = _f32_from_bits(
        values.get("horizontal_fov_degrees_f32_bits"),
        f"camera[{tick}].horizontal_fov_degrees",
    )
    centre = _f32_vector(
        values.get("centre_f32_bits"), 2, f"camera[{tick}].centre_f32_bits",
    )
    focal = _f32_from_bits(
        values.get("focal_pixels_f32_bits"), f"camera[{tick}].focal_pixels",
    )
    left, top, right, bottom = window_endpoints
    span_width = right - left
    span_height = bottom - top
    viewport_width = span_width + 1
    viewport_height = span_height + 1
    if inverse_scale_squared <= 0 or near <= 0 or far <= near \
            or not 1 <= horizontal_degrees <= 175 \
            or span_width <= 0 or span_height <= 0 or focal <= 0:
        raise ValueError(f"native camera projection is invalid at tick {tick}")
    l0, l1, l2 = linear[0:3], linear[3:6], linear[6:9]
    view = [
        l0[0], l1[0], -l2[0], 0.0,
        l0[1], l1[1], -l2[1], 0.0,
        l0[2], l1[2], -l2[2], 0.0,
        -sum(a * b for a, b in zip(l0, position, strict=True)),
        -sum(a * b for a, b in zip(l1, position, strict=True)),
        sum(a * b for a, b in zip(l2, position, strict=True)),
        1.0,
    ]
    projection = [
        2 * focal / viewport_width, 0.0, 0.0, 0.0,
        0.0, 2 * focal / viewport_height, 0.0, 0.0,
        (right + left - 2 * centre[0]) / viewport_width,
        (2 * centre[1] - top - bottom) / viewport_height,
        (far + near) / (near - far), -1.0,
        0.0, 0.0, 2 * far * near / (near - far), 0.0,
    ]
    vertical_fov = 2 * math.atan(viewport_height / (2 * focal))
    owner = values.get("camera_control_owner")
    state = values.get("location_state")
    if owner == "common_location":
        if type(state) is not int or state != 5:
            raise ValueError(f"native camera control is invalid at tick {tick}")
        control = {"owner": owner, "state": state}
    elif owner == "mode_fly":
        control_values = {
            "manual_camera_enabled": values.get("manual_camera_enabled"),
            "move_forward": values.get("move_forward"),
            "move_backward": values.get("move_backward"),
        }
        if any(type(value) is not int or value not in (0, 1)
               for value in control_values.values()):
            raise ValueError(f"native camera control is invalid at tick {tick}")
        control = {
            "owner": owner,
            **{key: bool(value) for key, value in control_values.items()},
        }
    else:
        raise ValueError(f"native camera control is invalid at tick {tick}")
    return {
        "view_matrix": view,
        "projection_matrix": projection,
        "vertical_fov_radians": vertical_fov,
        "near_clip": near,
        "far_clip": far,
        "viewport": {
            "x": left, "y": top,
            "width": viewport_width, "height": viewport_height,
        },
        "control": control,
    }


def validate_trace(trace: Any, label: str = "trace") -> None:
    if not isinstance(trace, dict) or set(trace) != REQUIRED_TRACE_KEYS:
        raise ValueError(f"{label}: invalid trace shape")
    if trace.get("protocol") != PROTOCOL or trace.get("version") != VERSION:
        raise ValueError(f"{label}: unsupported trace protocol")
    if trace.get("capture_kind") not in {"native", "web"}:
        raise ValueError(f"{label}: capture_kind must be native or web")
    if not isinstance(trace["source"], dict) or not trace["source"]:
        raise ValueError(f"{label}: source provenance must be a non-empty object")
    scenario = trace["scenario"]
    if not isinstance(scenario, dict) or not isinstance(scenario.get("id"), str) \
            or not scenario["id"]:
        raise ValueError(f"{label}: scenario must have a non-empty id")
    _validate_json_tree(scenario, f"{label}.scenario")
    frames = trace["frames"]
    if not isinstance(frames, list) or not frames:
        raise ValueError(f"{label}: frames must be a non-empty array")
    for index, frame in enumerate(frames):
        _validate_frame(frame, index, label)


def _validate_frame(frame: Any, index: int, label: str) -> None:
    path = f"{label}.frames[{index}]"
    if not isinstance(frame, dict) or not REQUIRED_FRAME_KEYS <= set(frame) \
            or set(frame) - REQUIRED_FRAME_KEYS - OPTIONAL_FRAME_KEYS:
        raise ValueError(f"{path}: invalid frame shape")
    if isinstance(frame["frame"], bool) or frame["frame"] != index:
        raise ValueError(f"{path}.frame: frame sequence must be contiguous from zero")
    _finite(frame["time_seconds"], f"{path}.time_seconds")
    if not isinstance(frame["inputs"], (dict, list)) or not isinstance(frame["events"], list):
        raise ValueError(f"{path}: inputs must be an object/array and events must be an array")
    _validate_json_tree(frame["inputs"], f"{path}.inputs")
    _validate_json_tree(frame["events"], f"{path}.events")
    if "numeric" in frame:
        if not isinstance(frame["numeric"], dict):
            raise ValueError(f"{path}.numeric must be an object")
        _validate_json_tree(frame["numeric"], f"{path}.numeric")
    if "camera" in frame:
        camera = frame["camera"]
        if not isinstance(camera, dict):
            raise ValueError(f"{path}.camera must be an object")
        for matrix in ("view_matrix", "projection_matrix"):
            if matrix in camera and (not isinstance(camera[matrix], list) or len(camera[matrix]) != 16):
                raise ValueError(f"{path}.camera.{matrix} must contain 16 values")
        _validate_json_tree(camera, f"{path}.camera")
    if "render" in frame:
        if not isinstance(frame["render"], dict):
            raise ValueError(f"{path}.render must be an object")
        _validate_json_tree(frame["render"], f"{path}.render")


def _validate_json_tree(value: Any, path: str) -> None:
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError(f"{path}: object keys must be strings")
        for key, item in value.items():
            _validate_json_tree(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_tree(item, f"{path}[{index}]")
    elif isinstance(value, float):
        _finite(value, path)
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise ValueError(f"{path}: value is not JSON-compatible")


def _finite(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{path} must be a finite number")
    return float(value)


def compare_traces(
    native: dict[str, Any],
    web: dict[str, Any],
    policy: TolerancePolicy | None = None,
) -> ComparisonReport:
    validate_trace(native, "native")
    validate_trace(web, "web")
    policy = policy or TolerancePolicy()
    native_scenario = native["scenario"]
    web_scenario = web["scenario"]
    scenario_id = str(native_scenario["id"])

    if native["capture_kind"] != "native":
        return _report(scenario_id, 0, None, "capture_kind", "baseline is not native evidence", "native", native["capture_kind"])
    if web["capture_kind"] != "web":
        return _report(scenario_id, 0, None, "capture_kind", "candidate is not a web trace", "web", web["capture_kind"])
    divergence = _compare_exact(native_scenario, web_scenario, "scenario", scenario_id, None)
    if divergence:
        return ComparisonReport(scenario_id, 0, divergence)

    native_frames = native["frames"]
    web_frames = web["frames"]
    for index, (native_frame, web_frame) in enumerate(zip(native_frames, web_frames)):
        divergence = _compare_frame(native_frame, web_frame, scenario_id, index, policy)
        if divergence:
            return ComparisonReport(scenario_id, index, divergence)
    if len(native_frames) != len(web_frames):
        index = min(len(native_frames), len(web_frames))
        divergence = Divergence(
            scenario_id, index, "frames.length", "frame sequence length differs",
            len(native_frames), len(web_frames), None,
        )
        return ComparisonReport(scenario_id, index, divergence)
    return ComparisonReport(scenario_id, len(native_frames), None)


def compare_trace_domain(
    native: dict[str, Any], web: dict[str, Any], domain: str,
    policy: TolerancePolicy | None = None,
) -> ComparisonReport:
    """Compare one release-gate domain without masking absent observations."""
    if domain not in TRACE_DOMAINS:
        raise ValueError(f"unsupported trace domain: {domain!r}")
    validate_trace(native, "native")
    validate_trace(web, "web")
    policy = policy or TolerancePolicy()
    scenario_id = str(native["scenario"]["id"])
    if native["capture_kind"] != "native":
        return _report(
            scenario_id, 0, None, "capture_kind", "baseline is not native evidence",
            "native", native["capture_kind"],
        )
    if web["capture_kind"] != "web":
        return _report(
            scenario_id, 0, None, "capture_kind", "candidate is not a web trace",
            "web", web["capture_kind"],
        )
    divergence = _compare_exact(
        native["scenario"], web["scenario"], "scenario", scenario_id, None,
    )
    if divergence:
        return ComparisonReport(scenario_id, 0, divergence)

    native_frames = native["frames"]
    web_frames = web["frames"]
    if domain == "rendering":
        for capture, frames in (("native", native_frames), ("web", web_frames)):
            invalid = _invalid_pixel_checkpoint(frames)
            if invalid is not None:
                return _report(
                    scenario_id, 0, invalid, "render.pixel_checkpoint",
                    f"{capture} canonical pixel evidence is invalid", None, None,
                )
    for index, (native_frame, web_frame) in enumerate(zip(native_frames, web_frames)):
        divergence = _compare_exact(
            native_frame["frame"], web_frame["frame"], "frame", scenario_id, index,
        )
        if divergence:
            return ComparisonReport(scenario_id, index, divergence)
        divergence = _compare_numeric(
            native_frame["time_seconds"], web_frame["time_seconds"], "time_seconds",
            "timing", scenario_id, index, policy,
        )
        if divergence:
            return ComparisonReport(scenario_id, index, divergence)
        divergence = _compare_domain_frame(
            native_frame, web_frame, domain, scenario_id, index, policy,
        )
        if divergence:
            return ComparisonReport(scenario_id, index, divergence)
    if len(native_frames) != len(web_frames):
        index = min(len(native_frames), len(web_frames))
        return ComparisonReport(scenario_id, index, Divergence(
            scenario_id, index, "frames.length", "frame sequence length differs",
            len(native_frames), len(web_frames), None,
        ))
    if domain == "rendering" and not any(
        "pixel_checkpoint" in frame.get("render", {}) for frame in native_frames
    ):
        return _report(
            scenario_id, len(native_frames), None, "render.pixel_checkpoint",
            "rendering domain has no canonical native pixel evidence", None, None,
        )
    if domain == "rendering" and not any(
        "pixel_checkpoint" in frame.get("render", {}) for frame in web_frames
    ):
        return _report(
            scenario_id, len(native_frames), None, "render.pixel_checkpoint",
            "rendering domain has no canonical web pixel evidence", None, None,
        )
    return ComparisonReport(scenario_id, len(native_frames), None)


def _compare_domain_frame(
    native: dict[str, Any], web: dict[str, Any], domain: str, scenario: str,
    frame: int, policy: TolerancePolicy,
) -> Divergence | None:
    for capture, candidate in (("native", native), ("web", web)):
        incomplete = _incomplete_domain_path(candidate, domain)
        if incomplete is not None:
            return Divergence(
                scenario, frame, incomplete,
                f"{capture} domain observation is incomplete",
                _path_value(native, incomplete), _path_value(web, incomplete),
            )
    if domain == "timing":
        return _compare_numeric(
            native["numeric"]["timing"]["deltaSeconds"],
            web["numeric"]["timing"]["deltaSeconds"],
            "numeric.timing.deltaSeconds", "timing", scenario, frame, policy,
        )
    if domain == "controls":
        divergence = _compare_exact(
            native["inputs"], web["inputs"], "inputs", scenario, frame,
        )
        if divergence:
            return divergence
        return _compare_required_numeric_field(
            native, web, ("numeric", "controls"), "numeric.controls",
            scenario, frame, policy,
        )
    if domain == "physics":
        return _compare_required_numeric_field(
            native, web, ("numeric", "physics"), "numeric.physics",
            scenario, frame, policy,
        )
    if domain == "systems":
        return _compare_required_numeric_field(
            native, web, ("numeric", "systems"), "numeric.systems",
            scenario, frame, policy,
        )
    if domain == "collision":
        divergence = _compare_required_numeric_field(
            native, web, ("numeric", "collisions"), "numeric.collisions",
            scenario, frame, policy,
        )
        if divergence:
            return divergence
        return _compare_exact(native["events"], web["events"], "events", scenario, frame)
    if domain == "camera":
        if "camera" not in native or "camera" not in web:
            return Divergence(
                scenario, frame, "camera", "required domain field is absent",
                native.get("camera"), web.get("camera"),
            )
        return _compare_tolerant_tree(
            native["camera"], web["camera"], "camera", scenario, frame, policy,
        )
    if "render" not in native or "render" not in web:
        return Divergence(
            scenario, frame, "render", "required domain field is absent",
            native.get("render"), web.get("render"),
        )
    return _compare_render(native["render"], web["render"], scenario, frame)


def _incomplete_domain_path(frame: dict[str, Any], domain: str) -> str | None:
    numeric = frame.get("numeric")
    if domain == "timing":
        timing = numeric.get("timing") if isinstance(numeric, dict) else None
        if not isinstance(timing, dict) or "deltaSeconds" not in timing \
                or not _is_number(timing["deltaSeconds"]) \
                or timing["deltaSeconds"] <= 0:
            return "numeric.timing"
    elif domain == "controls":
        controls = numeric.get("controls") if isinstance(numeric, dict) else None
        required = {
            "keys", "analogHorizontal", "analogVertical", "propulsion",
            "propulsionScale", "horizontal", "vertical", "enabled", "windowFocused",
        }
        if not isinstance(controls, dict) or set(controls) != required:
            return "numeric.controls"
        keys = controls["keys"]
        if not isinstance(keys, dict) or set(keys) != set(NATIVE_CONTROL_KEYS) \
                or any(type(keys[key]) is not bool for key in NATIVE_CONTROL_KEYS):
            return "numeric.controls.keys"
        if type(controls["enabled"]) is not bool or type(controls["windowFocused"]) is not bool \
                or any(not _is_number(controls[field])
                       for field in required - {"keys", "enabled", "windowFocused"}):
            return "numeric.controls"
    elif domain == "physics":
        physics = numeric.get("physics") if isinstance(numeric, dict) else None
        vector_sizes = {
            "position": 3, "orientation": 4, "velocity": 3, "angularVelocity": 3,
        }
        if not isinstance(physics, dict) or set(physics) != set(vector_sizes):
            return "numeric.physics"
        for field, size in vector_sizes.items():
            if not isinstance(physics[field], list) or len(physics[field]) != size \
                    or any(not _is_number(value) for value in physics[field]):
                return f"numeric.physics.{field}"
    elif domain == "systems":
        systems = numeric.get("systems") if isinstance(numeric, dict) else None
        required_systems = {
            "fuel", "integrity", "maximumIntegrity", "pendingDamage",
            "damageGateTimer", "active", "inactive", "floorEnabled",
        }
        if not isinstance(systems, dict) or set(systems) != required_systems:
            return "numeric.systems"
        if any(not _is_number(systems[field]) for field in {
            "fuel", "integrity", "maximumIntegrity", "pendingDamage", "damageGateTimer",
        }) or any(type(systems[field]) is not bool for field in {
            "active", "inactive", "floorEnabled",
        }):
            return "numeric.systems"
    elif domain == "collision":
        collisions = numeric.get("collisions") if isinstance(numeric, dict) else None
        if not isinstance(collisions, dict) \
                or set(collisions) != {"observed", "contacts"}:
            return "numeric.collisions"
        if type(collisions["observed"]) is not bool or not collisions["observed"]:
            return "numeric.collisions.observed"
        contacts = collisions["contacts"]
        if not isinstance(contacts, list):
            return "numeric.collisions.contacts"
        required_collision = {
            "kind", "contactPosition", "contactNormal", "relativeVelocity",
            "damage", "landingClassification",
        }
        for index, collision in enumerate(contacts):
            if not isinstance(collision, dict) or set(collision) != required_collision:
                return f"numeric.collisions.contacts[{index}]"
            if not isinstance(collision["kind"], str) or not collision["kind"] \
                    or not isinstance(collision["landingClassification"], str) \
                    or not collision["landingClassification"] \
                    or not _is_number(collision["damage"]):
                return f"numeric.collisions.contacts[{index}]"
            for field in ("contactPosition", "contactNormal", "relativeVelocity"):
                if not isinstance(collision[field], list) or len(collision[field]) != 3 \
                        or any(not _is_number(value) for value in collision[field]):
                    return f"numeric.collisions.contacts[{index}].{field}"
    elif domain == "camera":
        camera = frame.get("camera")
        required_camera = {
            "view_matrix", "projection_matrix", "vertical_fov_radians",
            "near_clip", "far_clip", "viewport", "control",
        }
        if not isinstance(camera, dict) or not required_camera <= set(camera):
            return "camera"
        for field in ("view_matrix", "projection_matrix"):
            if not isinstance(camera[field], list) or len(camera[field]) != 16 \
                    or any(not _is_number(value) for value in camera[field]):
                return f"camera.{field}"
        if any(not _is_number(camera[field])
               for field in ("vertical_fov_radians", "near_clip", "far_clip")):
            return "camera"
        control = camera["control"]
        if not isinstance(control, dict):
            return "camera.control"
        if control.get("owner") == "common_location":
            if set(control) != {"owner", "state"} or type(control["state"]) is not int:
                return "camera.control"
        elif control.get("owner") == "mode_fly":
            fields = {"owner", "manual_camera_enabled", "move_forward", "move_backward"}
            if set(control) != fields or any(
                    type(control[field]) is not bool for field in fields - {"owner"}
            ):
                return "camera.control"
        else:
            return "camera.control"
        viewport = camera["viewport"]
        if not isinstance(viewport, dict) or set(viewport) != {"x", "y", "width", "height"} \
                or any(not _is_number(viewport[field]) for field in viewport) \
                or viewport["width"] <= 0 or viewport["height"] <= 0:
            return "camera.viewport"
    elif not isinstance(frame.get("render"), dict):
        return "render"
    return None


def _path_value(value: Any, path: str) -> Any:
    for key in path.split("."):
        value = value.get(key) if isinstance(value, dict) else None
    return value


def _invalid_pixel_checkpoint(frames: list[dict[str, Any]]) -> int | None:
    required = {
        "id", "width", "height", "pixel_format", "origin", "alpha_mode",
        "reference_sha256",
    }
    for index, frame in enumerate(frames):
        render = frame.get("render")
        checkpoint = render.get("pixel_checkpoint") if isinstance(render, dict) else None
        if checkpoint is None:
            continue
        if not isinstance(checkpoint, dict) or set(checkpoint) != required \
                or not isinstance(checkpoint["id"], str) or not checkpoint["id"] \
                or any(isinstance(checkpoint[field], bool)
                       or not isinstance(checkpoint[field], int) or checkpoint[field] <= 0
                       for field in ("width", "height")) \
                or checkpoint["pixel_format"] != "rgba8" \
                or checkpoint["origin"] != "top-left" \
                or checkpoint["alpha_mode"] != "straight" \
                or not _sha256_string(checkpoint["reference_sha256"]):
            return index
    return None


def _compare_required_numeric_field(
    native: dict[str, Any], web: dict[str, Any], keys: tuple[str, ...], path: str,
    scenario: str, frame: int, policy: TolerancePolicy,
) -> Divergence | None:
    native_value: Any = native
    web_value: Any = web
    for key in keys:
        native_value = native_value.get(key) if isinstance(native_value, dict) else None
        web_value = web_value.get(key) if isinstance(web_value, dict) else None
    if native_value is None or web_value is None:
        return Divergence(
            scenario, frame, path, "required domain field is absent",
            native_value, web_value,
        )
    return _compare_tolerant_tree(
        native_value, web_value, path, scenario, frame, policy,
    )


def _compare_frame(
    native: dict[str, Any], web: dict[str, Any], scenario: str, frame: int,
    policy: TolerancePolicy,
) -> Divergence | None:
    for key in ("frame",):
        divergence = _compare_exact(native[key], web[key], key, scenario, frame)
        if divergence:
            return divergence
    divergence = _compare_numeric(
        native["time_seconds"], web["time_seconds"], "time_seconds",
        "timing", scenario, frame, policy,
    )
    if divergence:
        return divergence
    # Inputs and events are causal protocol, so numeric values inside them are
    # intentionally exact and array order is never normalized.
    for key in ("inputs", "events"):
        divergence = _compare_exact(native[key], web[key], key, scenario, frame)
        if divergence:
            return divergence
    for key in ("numeric", "camera"):
        if (key in native) != (key in web):
            return Divergence(scenario, frame, key, "field presence differs", native.get(key), web.get(key))
        if key in native:
            divergence = _compare_tolerant_tree(native[key], web[key], key, scenario, frame, policy)
            if divergence:
                return divergence
    if ("render" in native) != ("render" in web):
        return Divergence(scenario, frame, "render", "field presence differs", native.get("render"), web.get("render"))
    if "render" in native:
        return _compare_render(native["render"], web["render"], scenario, frame)
    return None


def _compare_render(
    native: dict[str, Any], web: dict[str, Any], scenario: str, frame: int,
) -> Divergence | None:
    # Backend counters are diagnostics and cannot match Direct3D to WebGL.
    # Only a cryptographically bound framebuffer checkpoint is parity proof.
    native_pixel = native.get("pixel_checkpoint")
    web_pixel = web.get("pixel_checkpoint")
    if (native_pixel is None) != (web_pixel is None):
        return Divergence(
            scenario, frame, "render.pixel_checkpoint", "field presence differs",
            native_pixel, web_pixel,
        )
    if native_pixel is not None:
        return _compare_exact(
            native_pixel, web_pixel, "render.pixel_checkpoint", scenario, frame
        )
    return None


def _compare_tolerant_tree(
    native: Any, web: Any, path: str, scenario: str, frame: int,
    policy: TolerancePolicy,
) -> Divergence | None:
    if _is_number(native) and _is_number(web):
        return _compare_numeric(native, web, path, _domain_for(path), scenario, frame, policy)
    if isinstance(native, dict) and isinstance(web, dict):
        if set(native) != set(web):
            return Divergence(scenario, frame, path, "object keys differ", sorted(native), sorted(web))
        for key in sorted(native):
            divergence = _compare_tolerant_tree(native[key], web[key], f"{path}.{key}", scenario, frame, policy)
            if divergence:
                return divergence
        return None
    if isinstance(native, list) and isinstance(web, list):
        if len(native) != len(web):
            return Divergence(scenario, frame, f"{path}.length", "array length differs", len(native), len(web))
        for index, (native_item, web_item) in enumerate(zip(native, web)):
            divergence = _compare_tolerant_tree(native_item, web_item, f"{path}[{index}]", scenario, frame, policy)
            if divergence:
                return divergence
        return None
    return _compare_exact(native, web, path, scenario, frame)


def _compare_numeric(
    native: int | float, web: int | float, path: str, domain: str | None,
    scenario: str, frame: int, policy: TolerancePolicy,
) -> Divergence | None:
    tolerance = policy.for_path(path, domain)
    if math.isclose(float(native), float(web), rel_tol=tolerance.relative, abs_tol=tolerance.absolute):
        return None
    return Divergence(
        scenario, frame, path, f"numeric values exceed {domain or 'default'} tolerance",
        native, web, tolerance,
    )


def _compare_exact(
    native: Any, web: Any, path: str, scenario: str, frame: int | None,
) -> Divergence | None:
    if isinstance(native, dict) and isinstance(web, dict):
        if set(native) != set(web):
            return Divergence(scenario, frame, path, "object keys differ", sorted(native), sorted(web))
        for key in sorted(native):
            divergence = _compare_exact(native[key], web[key], f"{path}.{key}", scenario, frame)
            if divergence:
                return divergence
        return None
    if isinstance(native, list) and isinstance(web, list):
        if len(native) != len(web):
            return Divergence(scenario, frame, f"{path}.length", "array length differs", len(native), len(web))
        for index, (native_item, web_item) in enumerate(zip(native, web)):
            divergence = _compare_exact(native_item, web_item, f"{path}[{index}]", scenario, frame)
            if divergence:
                return divergence
        return None
    if type(native) is not type(web) or native != web:
        return Divergence(scenario, frame, path, "exact values differ", native, web)
    return None


def _domain_for(path: str) -> str | None:
    if path.startswith("camera.") or path == "camera":
        return "camera"
    if path.startswith("numeric."):
        remainder = path[len("numeric."):]
        return remainder.split(".", 1)[0].split("[", 1)[0]
    return None


def _is_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _display(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _report(
    scenario: str, frames: int, frame: int | None, path: str, reason: str,
    native: Any, web: Any,
) -> ComparisonReport:
    return ComparisonReport(scenario, frames, Divergence(scenario, frame, path, reason, native, web))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("native", type=Path, help="captured native trace JSON")
    parser.add_argument("web", type=Path, help="captured web trace JSON")
    parser.add_argument("--tolerances", type=Path, help="domain/path tolerance policy JSON")
    parser.add_argument(
        "--natural-transition", action="store_true",
        help="compare schema-3 natural-transition NDJSON traces",
    )
    parser.add_argument(
        "--receipt", type=Path,
        help="write a canonical PASS receipt (natural-transition mode only)",
    )
    args = parser.parse_args(argv)
    if args.natural_transition:
        if args.tolerances is not None:
            parser.error("--tolerances cannot be used for exact natural transitions")
        try:
            receipt = validate_natural_transition_receipt(
                compare_natural_transition_files(args.native, args.web)
            )
            encoded = json.dumps(
                receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ) + "\n"
            if args.receipt is not None:
                args.receipt.write_text(encoded, encoding="utf-8")
                print(f"MATCH edge={receipt['edge']}")
            else:
                print(encoded, end="")
        except (OSError, ValueError, TypeError) as error:
            print(f"INVALID TRANSITION TRACE: {error}", file=sys.stderr)
            return 2
        return 0
    if args.receipt is not None:
        parser.error("--receipt requires --natural-transition")
    try:
        native = load_trace(args.native)
        web = load_trace(args.web)
        report = compare_traces(native, web, load_tolerance_policy(args.tolerances))
    except (OSError, ValueError, TypeError) as error:
        print(f"INVALID TRACE: {error}", file=sys.stderr)
        return 2
    if report.divergence:
        print(report.divergence.format())
        return 1
    print(f"MATCH scenario={report.scenario} frames={report.frames_compared}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
