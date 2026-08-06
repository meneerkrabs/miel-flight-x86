#!/usr/bin/env python3
"""Deterministic scenario and semantic native-observer artifact contracts.

This is a fail-closed staging layer.  It binds replay inputs, clocks, RNG,
initial state, semantic MVT records and optional raw framebuffer bytes, but it
deliberately cannot promote any artifact to production parity evidence.  The
older replay, discovery and MVOBSV1 importers remain independent consumers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

try:
    from tools.miel_vliegt import native_observation_profile_contract
except ModuleNotFoundError:
    import native_observation_profile_contract


SCENARIO_PROTOCOL = "miel-vliegt-native-semantic-scenario"
TRACE_PROTOCOL = "miel-vliegt-native-semantic-trace"
FRAMEBUFFER_PROTOCOL = "miel-vliegt-native-frame"
FRAMEBUFFER_VERSION = 2
FRAMEBUFFER_SOURCE_PROTOCOL = "miel-vliegt-native-frame-source-layout"
FRAMEBUFFER_SOURCE_VERSION = 1
FRAMEBUFFER_CLIENT_WIDTH = 640
FRAMEBUFFER_CLIENT_HEIGHT = 480
CANDIDATE_PROTOCOL = "miel-vliegt-native-observer-candidate"
SUITE_SPEC_PROTOCOL = "miel-vliegt-native-semantic-suite-spec"
INITIAL_STATE_RESTORE_PROTOCOL = "miel-vliegt-native-initial-state-restore"
HOOK_PROTOCOL = "miel-vliegt-native-observer-hook"
VERSION = 1
REVIEWED_GT_SOFTWARE_SHA256 = (
    "c3cebce34373255993b23ca54e3f678487f44a5fb7c1b9f4a63aa3b5d82a9ee8"
)
REVIEWED_GT_SOFTWARE_CONFIG_SHA256 = (
    "e0a3a19a5b21d2caa678023ed6587935f26722f9a43de5d4763c6d685032ca65"
)

# ---------------------------------------------------------------------------
# Native frame-rate physics contract
#
# The FEX-emu/ARM64 runner observes the game's natural exitFrame interval at
# ~179 FPS (dt ≈ 0.005594 s, IEEE-754 f32 bits 0x3bb75064).  The legacy
# scenario generator hard-coded a dt of 0.02 s (50 FPS, 0x3ca3d70a), a 3.575×
# overstep.  At that larger step size gravity integration diverged: the plane
# descended 3.575× faster per tick and crashed during approach-landing at
# tick 1016 instead of landing at tick 1080.
#
# All scenario tick counts, event timings, and checkpoint ticks are scaled by
# _DT_SCALE so the same simulated wall-clock duration is covered at the
# natural dt.  This is a physics correctness fix, not a tolerance.
# ---------------------------------------------------------------------------
NATURAL_DT_F32_BITS = "0x3bb75064"
_LEGACY_DT_F32 = struct.unpack(">f", struct.pack(">I", 0x3CA3D70A))[0]
_NATURAL_DT_F32 = struct.unpack(">f", struct.pack(">I", 0x3BB75064))[0]
_DT_SCALE = _LEGACY_DT_F32 / _NATURAL_DT_F32  # ≈ 3.5751
NATURAL_DT_NS = round(_NATURAL_DT_F32 * 1e9)  # 5_594_300

SCENARIO_ID_ORDER = (
    "controls-press-hold-release",
    "taxi-straight",
    "takeoff-climb",
    "level-flight-turn",
    "approach-landing",
    "impact-crash",
    "default-airplane-fixed-camera-frame",
)
SCENARIO_IDS = frozenset(SCENARIO_ID_ORDER)
VISUAL_OBSERVATION_SCENARIO = "default-airplane-fixed-camera-frame"
OBSERVATION_RECEIPT_CHANNELS = (
    native_observation_profile_contract.RECEIPT_CHANNELS
)
SEMANTIC_OBSERVATION_RECEIPT_CHANNELS = (
    native_observation_profile_contract.SEMANTIC_RECEIPT_CHANNELS
)
VISUAL_OBSERVER_CHANNELS = (
    native_observation_profile_contract.VISUAL_OBSERVER_CHANNELS
)
CONTROL_KEYS = ("left", "right", "up", "down", "shift", "control")
SEMANTIC_CHANNELS = frozenset({
    "flight.tick",
    "controls.pre",
    "controls.post",
    "physics.state",
    "collision.state",
    "camera.commit",
    "render.final",
    "outcome.contact",
    "outcome.damage",
    "outcome.crash",
    "outcome.terrain",
})
SCENARIO_REQUIRED_CHANNELS = {
    "controls-press-hold-release": frozenset({
        "flight.tick", "clock.tick", "controls.pre", "controls.post", "physics.state",
    }),
    "taxi-straight": frozenset({
        "flight.tick", "clock.tick", "controls.pre", "controls.post",
        "physics.state", "collision.state", "camera.commit",
    }),
    "takeoff-climb": frozenset({
        "flight.tick", "clock.tick", "controls.pre", "controls.post",
        "physics.state", "collision.state", "camera.commit",
    }),
    "level-flight-turn": frozenset({
        "flight.tick", "clock.tick", "controls.pre", "controls.post",
        "physics.state", "camera.commit",
    }),
    "approach-landing": frozenset({
        "flight.tick", "clock.tick", "controls.pre", "controls.post",
        "physics.state", "collision.state", "camera.commit",
    }),
    "impact-crash": frozenset({
        "flight.tick", "clock.tick", "controls.pre", "controls.post",
        "physics.state", "collision.state", "camera.commit",
    }),
    "default-airplane-fixed-camera-frame": frozenset({
        "flight.tick", "clock.tick", "camera.commit", "render.final",
    }),
}
OUTCOME_CHANNEL_ORDER = (
    "outcome.contact", "outcome.damage", "outcome.crash", "outcome.terrain",
)
OUTCOME_PREDICATES = {
    "outcome.contact": {"correction"},
    "outcome.damage": {"any", "nonterminal", "terminal"},
    "outcome.crash": {"terminal"},
    "outcome.terrain": {"class-range"},
}
CHECKPOINT_CHANNELS = frozenset({
    *SEMANTIC_CHANNELS,
    "clock.tick", "rng.seed", "rng.draw", "rng.end",
    "input.focus", "input.transition", "input.sample",
    "system.fuel", "render.framebuffer",
})

SHA256 = re.compile(r"^[0-9a-f]{64}$")
F32_BITS = re.compile(r"^0x[0-9a-f]{8}$")
MASK8 = re.compile(r"^0x[0-9a-f]{2}$")
STATIC_IDENTITY = re.compile(r"^[a-z0-9._-]+\+0x[0-9a-f]{8}$")
U16_BITS = re.compile(r"^0x[0-9a-f]{4}$")
IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
STATE_NAME = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
FOCUS_TIMELINE_LATE_LIMIT_NS = 250_000_000

# Reviewed scalar-only flight-state adapter.  Order is part of MVO_REPLAY_V3;
# pointers, vtables, ownership links and whole-object byte dumps are excluded.
RUNTIME_STATE_FIELDS = (
    ("flight.active", "u8"),
    ("flight.position_x", "f32le-bits"),
    ("flight.position_y", "f32le-bits"),
    ("flight.position_z", "f32le-bits"),
    ("flight.orientation_w", "f32le-bits"),
    ("flight.orientation_x", "f32le-bits"),
    ("flight.orientation_y", "f32le-bits"),
    ("flight.orientation_z", "f32le-bits"),
    ("flight.linear_momentum_x", "f32le-bits"),
    ("flight.linear_momentum_y", "f32le-bits"),
    ("flight.linear_momentum_z", "f32le-bits"),
    ("flight.angular_momentum_x", "f32le-bits"),
    ("flight.angular_momentum_y", "f32le-bits"),
    ("flight.angular_momentum_z", "f32le-bits"),
    ("flight.velocity_x", "f32le-bits"),
    ("flight.velocity_y", "f32le-bits"),
    ("flight.velocity_z", "f32le-bits"),
    ("flight.angular_velocity_x", "f32le-bits"),
    ("flight.angular_velocity_y", "f32le-bits"),
    ("flight.angular_velocity_z", "f32le-bits"),
    ("flight.accumulated_force_x", "f32le-bits"),
    ("flight.accumulated_force_y", "f32le-bits"),
    ("flight.accumulated_force_z", "f32le-bits"),
    ("flight.accumulated_torque_x", "f32le-bits"),
    ("flight.accumulated_torque_y", "f32le-bits"),
    ("flight.accumulated_torque_z", "f32le-bits"),
    ("flight.pending_damage", "f32le-bits"),
    ("flight.propulsion_scale", "f32le-bits"),
    ("flight.propulsion", "f32le-bits"),
    ("flight.fuel_capacity", "f32le-bits"),
    ("flight.fuel", "f32le-bits"),
    ("flight.integrity", "f32le-bits"),
    ("flight.maximum_integrity", "f32le-bits"),
    ("flight.controls_enabled", "u8"),
    ("flight.horizontal_control", "f32le-bits"),
    ("flight.vertical_control", "f32le-bits"),
    ("flight.floor_enabled", "u8"),
    ("flight.inactive", "u8"),
    ("flight.damage_gate_timer", "f32le-bits"),
)
RUNTIME_STATE_FIELD_MAP = dict(RUNTIME_STATE_FIELDS)
RUNTIME_STATE_ACCESS = {
    name: "write-readback" if name == "flight.damage_gate_timer" else "compare-only"
    for name, _encoding in RUNTIME_STATE_FIELDS
}


class ArtifactError(ValueError):
    """A scenario, trace, framebuffer or provenance artifact is invalid."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ArtifactError(f"value is not canonical JSON: {error}") from error


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_canonical_json(path: Path, value: Any) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ArtifactError(f"non-finite JSON number is forbidden: {value}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArtifactError(f"invalid JSON in {path}: {error}") from error


def _json_text(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ArtifactError(f"{label}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ArtifactError(f"{label}: expected a JSON object")
    return value


def _strict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        raise ArtifactError(
            f"{label} fields differ: missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def scenario_observation_profile(identifier: str) -> dict[str, Any]:
    """Return the one reviewed observer-cost contract for a suite scenario."""

    try:
        return native_observation_profile_contract.profile_for_scenario(
            identifier
        )
    except native_observation_profile_contract.ObservationProfileContractError \
            as error:
        raise ArtifactError(str(error)) from error


def validate_scenario_observation_profile(
    value: Any, *, scenario_id: str,
) -> dict[str, Any]:
    """Reject profile aliases, partial shadow families and channel ambiguity."""

    profile = _strict(value, {
        "schema", "protocol", "id", "observer_profile", "omit_mask",
        "observer_omitted_channels", "applicable_receipt_channels",
        "omitted_receipt_channels", "parity_evidence_eligible",
        "evidence_blocker", "framebuffer_required", "profile_sha256",
    }, f"{scenario_id} observation profile")
    expected = scenario_observation_profile(scenario_id)
    if profile != expected:
        raise ArtifactError(f"{scenario_id} observation profile drifted")
    return profile


def observation_profile_sha256(value: Any, *, scenario_id: str) -> str:
    return str(validate_scenario_observation_profile(
        value, scenario_id=scenario_id,
    )["profile_sha256"])


def _integer(value: Any, label: str, minimum: int = 0,
             maximum: int = UINT64_MAX) -> int:
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < minimum or value > maximum:
        raise ArtifactError(f"{label} must be an integer in {minimum}..{maximum}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ArtifactError(f"{label} must be boolean")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ArtifactError(f"{label} must be a lowercase SHA-256")
    return value


def _f32(value: Any, label: str) -> str:
    if not isinstance(value, str) or F32_BITS.fullmatch(value) is None:
        raise ArtifactError(f"{label} must be lowercase f32 bits (0x00000000)")
    return value


def _control_mask(value: Any, label: str) -> int:
    if not isinstance(value, str) or MASK8.fullmatch(value) is None:
        raise ArtifactError(f"{label} must be lowercase 8-bit hex")
    mask = int(value, 16)
    if mask & ~((1 << len(CONTROL_KEYS)) - 1):
        raise ArtifactError(f"{label} sets an unknown control bit")
    return mask


def _positive_finite_f32(value: Any, label: str) -> str:
    bits = int(_f32(value, label), 16)
    if bits & 0x80000000 or bits & 0x7FFFFFFF == 0 \
            or bits & 0x7F800000 == 0x7F800000:
        raise ArtifactError(f"{label} must encode a positive finite non-zero f32")
    return value


def _relative_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ArtifactError(f"{label} must be a non-empty relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactError(f"{label} is unsafe: {value!r}")
    return path


def _resolve(root: Path, relative: Any, label: str) -> Path:
    pure = _relative_path(relative, label)
    resolved_root = root.resolve()
    path = (resolved_root / Path(*pure.parts)).resolve()
    if path != resolved_root and resolved_root not in path.parents:
        raise ArtifactError(f"{label} escapes the artifact root")
    if not path.is_file():
        raise ArtifactError(f"{label} does not exist: {relative}")
    return path


def _path_from_file(root: Path, path: Path, label: str) -> str:
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ArtifactError(f"{label} must be inside the artifact root") from error
    if not resolved.is_file():
        raise ArtifactError(f"{label} does not exist: {path}")
    return relative.as_posix()


def _verify_file(root: Path, row: Mapping[str, Any], *, path_field: str,
                 hash_field: str, length_field: str | None, label: str) -> Path:
    path = _resolve(root, row[path_field], f"{label}.{path_field}")
    expected = _hash(row[hash_field], f"{label}.{hash_field}")
    if sha256_file(path) != expected:
        raise ArtifactError(f"{label} hash drifted")
    if length_field is not None:
        expected_length = _integer(row[length_field], f"{label}.{length_field}")
        if path.stat().st_size != expected_length:
            raise ArtifactError(f"{label} byte length drifted")
    return path


def validate_scenario(value: Any, *, root: Path | None = None) -> dict[str, Any]:
    """Validate one of the seven contract scenarios and all transcripts."""

    scenario = _strict(value, {
        "schema", "protocol", "id", "description", "evidence_status",
        "input_script", "clock_transcript", "rng_transcript", "initial_state",
        "checkpoints", "outcome_expectations",
    }, "scenario")
    if scenario["schema"] != VERSION or scenario["protocol"] != SCENARIO_PROTOCOL:
        raise ArtifactError("unsupported semantic scenario schema or protocol")
    if scenario["id"] not in SCENARIO_IDS:
        raise ArtifactError("scenario id is not one of the seven runtime-contract scenarios")
    if not isinstance(scenario["description"], str) or not scenario["description"].strip():
        raise ArtifactError("scenario description must be non-empty")
    if scenario["evidence_status"] != "CAPTURE_SPEC_ONLY":
        raise ArtifactError("scenario evidence_status must remain CAPTURE_SPEC_ONLY")

    script = _strict(scenario["input_script"], {"tick_count", "events"},
                     "scenario.input_script")
    tick_count = _integer(script["tick_count"], "input_script.tick_count", 1)
    events = script["events"]
    if not isinstance(events, list):
        raise ArtifactError("input_script.events must be an array")
    pressed: set[str] = set()
    focus_active = True
    focus_transitions: list[bool] = []
    key_down: set[str] = set()
    key_up: set[str] = set()
    saw_horizontal_opposition = False
    saw_vertical_opposition = False
    previous_tick = 0
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ArtifactError(f"input event {index} must be an object")
        event_type = event.get("type")
        if event_type == "key":
            event = _strict(event, {"sequence", "tick", "type", "key", "action"},
                            f"input event {index}")
        elif event_type == "focus":
            event = _strict(event, {"sequence", "tick", "type", "active"},
                            f"input event {index}")
        else:
            raise ArtifactError(f"input event {index}.type must be key or focus")
        if _integer(event["sequence"], f"input event {index}.sequence") != index:
            raise ArtifactError("input event sequence must be contiguous from zero")
        tick = _integer(event["tick"], f"input event {index}.tick", 0, tick_count - 1)
        if tick < previous_tick:
            raise ArtifactError("input events must be ordered by non-decreasing tick")
        previous_tick = tick
        if event_type == "focus":
            active = _boolean(event["active"], f"input event {index}.active")
            if active == focus_active:
                raise ArtifactError("input focus event does not change focus state")
            focus_active = active
            focus_transitions.append(active)
        else:
            key = event["key"]
            if key not in CONTROL_KEYS:
                raise ArtifactError(f"input event {index} has an unsupported control key")
            if not focus_active:
                raise ArtifactError(
                    "key events must remain manager-tick-bound and cannot occur "
                    "while the projector focus timeline is suspended"
                )
            action = event["action"]
            if action == "down":
                if key in pressed:
                    raise ArtifactError(f"input key {key} is already pressed")
                pressed.add(key)
                key_down.add(key)
            elif action == "up":
                if key not in pressed:
                    raise ArtifactError(f"input key {key} is not pressed")
                pressed.remove(key)
                key_up.add(key)
            else:
                raise ArtifactError(f"input event {index} action must be down or up")
            saw_horizontal_opposition |= {"left", "right"} <= pressed
            saw_vertical_opposition |= {"up", "down"} <= pressed
    if pressed:
        raise ArtifactError(f"input script ends with pressed keys: {sorted(pressed)}")
    if not focus_active:
        raise ArtifactError("input script must reactivate focus before completion")
    if scenario["id"] == "controls-press-hold-release":
        if key_down != set(CONTROL_KEYS) or key_up != set(CONTROL_KEYS):
            raise ArtifactError("controls contract must press and release all six keys")
        if not saw_horizontal_opposition or not saw_vertical_opposition:
            raise ArtifactError("controls contract must exercise both opposing-key pairs")
        if focus_transitions != [False, True]:
            raise ArtifactError("controls contract must prove focus-loss and reactivation exactly once")

    clock = _strict(scenario["clock_transcript"], {"samples"},
                    "scenario.clock_transcript")
    samples = clock["samples"]
    if not isinstance(samples, list) or len(samples) != tick_count:
        raise ArtifactError("clock transcript must contain exactly one sample for every tick")
    previous_ns = -1
    for tick, sample in enumerate(samples):
        sample = _strict(sample, {"tick", "monotonic_ns", "dt_f32_bits"},
                         f"clock sample {tick}")
        if _integer(sample["tick"], f"clock sample {tick}.tick") != tick:
            raise ArtifactError("clock transcript must cover every tick contiguously")
        monotonic_ns = _integer(sample["monotonic_ns"],
                                f"clock sample {tick}.monotonic_ns")
        if tick == 0 and monotonic_ns != 0:
            raise ArtifactError("clock transcript must use a zero monotonic origin")
        if monotonic_ns <= previous_ns:
            raise ArtifactError("clock transcript monotonic_ns must strictly increase")
        previous_ns = monotonic_ns
        _positive_finite_f32(
            sample["dt_f32_bits"], f"clock sample {tick}.dt_f32_bits",
        )

    rng = scenario["rng_transcript"]
    if not isinstance(rng, dict) or frozenset(rng) not in {
        frozenset({"algorithm", "seed_u32", "reseeds", "draws"}),
        frozenset({
            "algorithm", "flight_activation_seed_u32",
            "flight_activation_dt_f32_bits", "seed_u32", "reseeds", "draws",
        }),
    }:
        raise ArtifactError("scenario.rng_transcript fields differ")
    if rng["algorithm"] != "recorded-u32":
        raise ArtifactError("rng transcript algorithm must be recorded-u32")
    if "flight_activation_seed_u32" in rng:
        _integer(
            rng["flight_activation_seed_u32"],
            "rng_transcript.flight_activation_seed_u32", 0, UINT32_MAX,
        )
        activation_dts = rng["flight_activation_dt_f32_bits"]
        if not isinstance(activation_dts, list):
            raise ArtifactError("rng_transcript.flight_activation_dt_f32_bits must be an array")
        for index, dt in enumerate(activation_dts):
            _positive_finite_f32(dt, f"flight activation dt {index}")
    _integer(rng["seed_u32"], "rng_transcript.seed_u32", 0, UINT32_MAX)
    for transcript_field, noun in (("reseeds", "reseed"), ("draws", "draw")):
        transcript = rng[transcript_field]
        if not isinstance(transcript, list):
            raise ArtifactError(f"rng_transcript.{transcript_field} must be an array")
        previous_tick = 0
        for index, row in enumerate(transcript):
            row = _strict(row, {"sequence", "tick", "value_u32"},
                          f"rng {noun} {index}")
            if _integer(row["sequence"], f"rng {noun} {index}.sequence") != index:
                raise ArtifactError(f"rng {noun} sequence must be contiguous from zero")
            tick = _integer(row["tick"], f"rng {noun} {index}.tick", 0, tick_count - 1)
            if tick < previous_tick:
                raise ArtifactError(
                    f"rng {transcript_field} must be ordered by non-decreasing tick"
                )
            previous_tick = tick
            _integer(row["value_u32"], f"rng {noun} {index}.value_u32", 0, UINT32_MAX)

    initial = _strict(scenario["initial_state"], {"files", "values"},
                      "scenario.initial_state")
    files = initial["files"]
    if not isinstance(files, list) or not files:
        raise ArtifactError("initial_state.files must contain at least one file")
    file_identities: set[tuple[str, str]] = set()
    for index, row in enumerate(files):
        row = _strict(row, {"role", "path", "byte_length", "sha256"},
                      f"initial file {index}")
        if not isinstance(row["role"], str) or IDENTIFIER.fullmatch(row["role"]) is None:
            raise ArtifactError(f"initial file {index}.role is invalid")
        _relative_path(row["path"], f"initial file {index}.path")
        _integer(row["byte_length"], f"initial file {index}.byte_length")
        _hash(row["sha256"], f"initial file {index}.sha256")
        identity = (row["role"], row["path"])
        if identity in file_identities:
            raise ArtifactError(f"duplicate initial-state file identity: {identity}")
        file_identities.add(identity)
        if root is not None:
            _verify_file(root, row, path_field="path", hash_field="sha256",
                         length_field="byte_length", label=f"initial file {index}")
    values = initial["values"]
    if not isinstance(values, list):
        raise ArtifactError("initial_state.values must be an array")
    names: set[str] = set()
    lengths = {"u8": 2, "u16le": 4, "u32le": 8, "f32le-bits": 8}
    for index, row in enumerate(values):
        row = _strict(row, {"name", "encoding", "value_hex"},
                      f"initial value {index}")
        name = row["name"]
        if not isinstance(name, str) or STATE_NAME.fullmatch(name) is None:
            raise ArtifactError(f"initial value {index}.name is invalid")
        if name not in RUNTIME_STATE_FIELD_MAP:
            raise ArtifactError(f"initial value {index}.name is not reviewed")
        if name in names:
            raise ArtifactError(f"duplicate initial-state value: {name}")
        names.add(name)
        encoding = row["encoding"]
        value_hex = row["value_hex"]
        if encoding != RUNTIME_STATE_FIELD_MAP[name]:
            raise ArtifactError(
                f"initial value {index}.encoding differs from the reviewed adapter"
            )
        if encoding not in {*lengths, "bytes"} or not isinstance(value_hex, str) \
                or re.fullmatch(r"[0-9a-f]*", value_hex) is None \
                or len(value_hex) % 2:
            raise ArtifactError(f"initial value {index} has invalid hex encoding")
        if encoding in lengths and len(value_hex) != lengths[encoding]:
            raise ArtifactError(f"initial value {index} has the wrong encoded width")

    checkpoints = scenario["checkpoints"]
    if not isinstance(checkpoints, list) or not checkpoints:
        raise ArtifactError("scenario.checkpoints must contain at least one checkpoint")
    checkpoint_ids: set[str] = set()
    previous_tick = 0
    for index, checkpoint in enumerate(checkpoints):
        checkpoint = _strict(checkpoint, {"id", "tick", "required_channels"},
                             f"checkpoint {index}")
        identifier = checkpoint["id"]
        if not isinstance(identifier, str) or IDENTIFIER.fullmatch(identifier) is None:
            raise ArtifactError(f"checkpoint {index}.id is invalid")
        if identifier in checkpoint_ids:
            raise ArtifactError(f"duplicate checkpoint id: {identifier}")
        checkpoint_ids.add(identifier)
        tick = _integer(checkpoint["tick"], f"checkpoint {index}.tick", 0, tick_count - 1)
        if tick < previous_tick:
            raise ArtifactError("checkpoints must be ordered by non-decreasing tick")
        previous_tick = tick
        channels = checkpoint["required_channels"]
        if not isinstance(channels, list) or not channels \
                or len(channels) != len(set(channels)) \
                or not all(channel in CHECKPOINT_CHANNELS for channel in channels):
            raise ArtifactError(f"checkpoint {index}.required_channels is invalid")

    outcomes = scenario["outcome_expectations"]
    if not isinstance(outcomes, list) or len(outcomes) != len(OUTCOME_CHANNEL_ORDER):
        raise ArtifactError("outcome_expectations must cover all four native outcome channels")
    for index, (expectation, expected_channel) in enumerate(
        zip(outcomes, OUTCOME_CHANNEL_ORDER, strict=True),
    ):
        expectation = _strict(expectation, {"channel", "presence", "predicate"},
                              f"outcome expectation {index}")
        if expectation["channel"] != expected_channel:
            raise ArtifactError("outcome expectations must use canonical channel order")
        if expectation["presence"] not in {"required", "optional", "forbidden"}:
            raise ArtifactError(f"outcome expectation {index}.presence is invalid")
        if expectation["predicate"] not in OUTCOME_PREDICATES[expected_channel]:
            raise ArtifactError(f"outcome expectation {index}.predicate is invalid")
    return scenario


def load_scenario(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    return validate_scenario(load_json(path), root=root)


def scenario_sha256(value: Any, *, root: Path | None = None) -> str:
    return canonical_sha256(validate_scenario(value, root=root))


def _input_schedule(scenario: Mapping[str, Any]) -> list[tuple[int, bool]]:
    events_by_tick: dict[int, list[Mapping[str, Any]]] = {}
    for event in scenario["input_script"]["events"]:
        events_by_tick.setdefault(event["tick"], []).append(event)
    pressed: set[str] = set()
    focus_active = True
    key_bits = {key: 1 << index for index, key in enumerate(CONTROL_KEYS)}
    schedule: list[tuple[int, bool]] = []
    for tick in range(scenario["input_script"]["tick_count"]):
        for event in events_by_tick.get(tick, []):
            if event["type"] == "focus":
                focus_active = event["active"]
            elif event["action"] == "down":
                pressed.add(event["key"])
            else:
                pressed.remove(event["key"])
        schedule.append((sum(key_bits[key] for key in pressed), focus_active))
    return schedule


def _focus_timeline(scenario: Mapping[str, Any]) -> list[dict[str, int | bool]]:
    """Compile focus transitions onto an episode-relative monotonic clock.

    The native projector stops advancing manager ticks while it is not the
    foreground window.  Focus regain therefore cannot be scheduled by the
    manager-tick cursor itself.  Each loss starts a host-monotonic episode;
    its matching regain is timed relative to that loss while key samples
    remain bound to the native manager ticks that actually execute.
    """

    samples = scenario["clock_transcript"]["samples"]
    focus_events = [
        event for event in scenario["input_script"]["events"]
        if event["type"] == "focus"
    ]
    timeline: list[dict[str, int | bool]] = []
    episode = -1
    origin_ns: int | None = None
    expected_active = False
    for ordinal, event in enumerate(focus_events):
        active = event["active"]
        tick = event["tick"]
        if active is not expected_active:
            raise ArtifactError("focus timeline is duplicate or out of order")
        if not active:
            if tick == 0:
                raise ArtifactError(
                    "focus loss requires an established native manager-tick origin"
                )
            episode += 1
            origin_ns = samples[tick]["monotonic_ns"]
        elif origin_ns is None:
            raise ArtifactError("focus timeline regain has no loss origin")
        offset_ns = samples[tick]["monotonic_ns"] - origin_ns
        if offset_ns < 0 or (active and offset_ns == 0):
            raise ArtifactError("focus timeline offset is invalid")
        timeline.append({
            "ordinal": ordinal,
            "episode": episode,
            "tick": tick,
            "active": active,
            "offset_ns": offset_ns,
        })
        expected_active = not expected_active
    if expected_active:
        raise ArtifactError("focus timeline has an unmatched loss event")
    return timeline


def _focus_timeline_sha256(
    timeline: list[Mapping[str, int | bool]],
) -> str:
    digest = hashlib.sha256()
    for event in timeline:
        digest.update(struct.pack(
            "<IIIBQ",
            event["ordinal"],
            event["episode"],
            event["tick"],
            int(event["active"]),
            event["offset_ns"],
        ))
    return digest.hexdigest()


def _native_manager_tick_schedule(
    scenario: Mapping[str, Any],
) -> list[int]:
    """Return native ticks that can execute without synthesizing focus."""

    return [
        tick for tick, (_, focus_active) in enumerate(_input_schedule(scenario))
        if focus_active
    ]


def build_native_replay_script(
    value: Any, *, root: Path | None = None, capture_tick: int | None = None,
    calibration: bool = False,
) -> bytes:
    """Compile an exact V3 replay or an explicitly unbound calibration V2."""

    scenario = validate_scenario(value, root=root)
    state_values = scenario["initial_state"]["values"]
    actual_state_contract = tuple(
        (row["name"], row["encoding"]) for row in state_values
    )
    if not isinstance(calibration, bool):
        raise ArtifactError("native replay calibration flag must be boolean")
    if calibration and state_values:
        raise ArtifactError("calibration replay requires empty runtime initial state")
    if not calibration and actual_state_contract != RUNTIME_STATE_FIELDS:
        raise ArtifactError(
            "native replay requires the complete reviewed runtime state in canonical order"
        )
    if not calibration and "flight_activation_dt_f32_bits" not in scenario["rng_transcript"]:
        raise ArtifactError("native replay requires a calibrated flight activation clock")
    tick_count = scenario["input_script"]["tick_count"]
    complete_tick = tick_count - 1
    if capture_tick is None:
        capture_tick = scenario["checkpoints"][-1]["tick"]
    _integer(capture_tick, "native replay capture_tick", 0, complete_tick)
    rng = scenario["rng_transcript"]
    focus_timeline = _focus_timeline(scenario)
    lines = [
        "MVO_REPLAY_V2" if calibration else "MVO_REPLAY_V3",
        f"scenario={scenario['id']}",
        f"scenario_sha256={canonical_sha256(scenario)}",
        f"focus_event_count={len(focus_timeline)}",
    ]
    lines.extend(
        "focus_event."
        f"{event['ordinal']}={event['tick']} {int(event['active'])} "
        f"{event['episode']} {event['offset_ns']}"
        for event in focus_timeline
    )
    lines.append(
        f"focus_timeline_sha256={_focus_timeline_sha256(focus_timeline)}"
    )
    if not calibration:
        lines.append(
            "flight_activation_seed="
            f"{rng.get('flight_activation_seed_u32', rng['seed_u32'])}"
        )
    lines.extend([
        f"rng_seed={rng['seed_u32']}",
        f"capture_tick={capture_tick}",
        f"complete_tick={complete_tick}",
    ])
    if not calibration:
        lines.append(f"state_count={len(RUNTIME_STATE_FIELDS)}")
        lines.extend(
            f"state.{row['name'].removeprefix('flight.')}={row['value_hex']}"
            for row in state_values
        )
        activation_dts = rng["flight_activation_dt_f32_bits"]
        activation_digest = hashlib.sha256()
        lines.append(f"activation_tick_count={len(activation_dts)}")
        for index, dt in enumerate(activation_dts):
            bits = int(dt, 16)
            activation_digest.update(struct.pack("<II", index, bits))
            lines.append(f"activation_dt.{index}={dt[2:]}")
        lines.append(f"activation_clock_sha256={activation_digest.hexdigest()}")
    schedule = _input_schedule(scenario)
    for tick, clock in enumerate(scenario["clock_transcript"]["samples"]):
        mask, focus_active = schedule[tick]
        lines.append(
            f"{tick} {clock['dt_f32_bits'][2:]} {mask:02x} {int(focus_active)}"
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def validate_scenario_set(values: Any, *, root: Path | None = None) -> list[dict[str, Any]]:
    """Require the complete seven-scenario contract, once each, in stable order."""

    if not isinstance(values, list):
        raise ArtifactError("scenario set must be an array")
    by_id: dict[str, dict[str, Any]] = {}
    for value in values:
        scenario = validate_scenario(value, root=root)
        if scenario["id"] in by_id:
            raise ArtifactError(f"duplicate scenario in scenario set: {scenario['id']}")
        by_id[scenario["id"]] = scenario
    if set(by_id) != SCENARIO_IDS:
        raise ArtifactError(
            "scenario set must contain exactly the seven contract scenarios: "
            f"missing={sorted(SCENARIO_IDS - set(by_id))}, "
            f"unknown={sorted(set(by_id) - SCENARIO_IDS)}"
        )
    return [by_id[identifier] for identifier in SCENARIO_ID_ORDER]


def build_tracked_scenario_catalog(
    initial_state: Mapping[str, Any], *, root: Path | None = None,
) -> list[dict[str, Any]]:
    """Materialize the seven reviewed native capture specifications.

    These are deterministic replay requests, not native evidence.  The
    ``CAPTURE_SPEC_ONLY`` status is intentionally validated and cannot be
    promoted by this generator.
    """

    initial = json.loads(canonical_json(initial_state))
    common_channels = [
        "input.sample", "clock.tick", "flight.tick", "controls.post",
        "physics.state", "camera.commit",
    ]
    outcome_default = {
        "outcome.contact": ("optional", "correction"),
        "outcome.damage": ("forbidden", "any"),
        "outcome.crash": ("forbidden", "terminal"),
        "outcome.terrain": ("optional", "class-range"),
    }
    blueprints: tuple[tuple[str, str, int, list[tuple[int, str, Any]],
                            list[tuple[str, int, list[str]]],
                            Mapping[str, tuple[str, str]]], ...] = (
        (
            "controls-press-hold-release",
            "Exercise every native control, both opposing pairs, and focus reacquisition.",
            64,
            [
                (2, "key", ("left", "down")), (6, "key", ("left", "up")),
                (8, "key", ("right", "down")), (12, "key", ("right", "up")),
                (14, "key", ("up", "down")), (18, "key", ("up", "up")),
                (20, "key", ("down", "down")), (24, "key", ("down", "up")),
                (26, "key", ("shift", "down")), (30, "key", ("shift", "up")),
                (32, "key", ("control", "down")), (36, "key", ("control", "up")),
                (38, "key", ("left", "down")), (39, "key", ("right", "down")),
                (42, "key", ("left", "up")), (43, "key", ("right", "up")),
                (45, "key", ("up", "down")), (46, "key", ("down", "down")),
                (49, "key", ("up", "up")), (50, "key", ("down", "up")),
                (52, "key", ("left", "down")), (54, "focus", False),
                (58, "focus", True), (60, "key", ("left", "up")),
            ],
            [
                ("all-controls", 36, common_channels),
                ("opposing-pairs", 46, common_channels),
                ("focus-lost", 54, ["input.focus", "input.transition"]),
                ("focus-reactivated", 58,
                 ["input.focus", "input.transition", "input.sample"]),
            ],
            outcome_default,
        ),
        (
            "taxi-straight",
            "Legacy taxi scenario: measure straight airborne acceleration from "
            "the native mygghanget spawn.",
            300,
            [(5, "key", ("shift", "down")), (220, "key", ("shift", "up"))],
            [("taxi-established", 160, [*common_channels, "collision.state"]),
             ("taxi-complete", 299, common_channels)],
            # The reviewed native spawn starts at y=70 with floor_enabled=0.
            # A 300-tick FEX capture (semantic SHA-256
            # c37d31e7347decdbcc2d85b506e8c7d91527d1f8b581b4c62a5be7267754c7c0)
            # proves that this legacy-named scenario never enters the native
            # contact-correction path. Requiring contact here encoded an
            # invented runway precondition rather than original behavior.
            {**outcome_default, "outcome.contact": ("forbidden", "correction")},
        ),
        (
            "takeoff-climb", "Accelerate, rotate, and establish a climb.", 600,
            [(5, "key", ("shift", "down")), (100, "key", ("down", "down")),
             (260, "key", ("down", "up")), (520, "key", ("shift", "up"))],
            [("rotation", 180, [*common_channels, "collision.state"]),
             ("climb-established", 420, common_channels)],
            outcome_default,
        ),
        (
            "level-flight-turn", "Climb, level, and hold a coordinated left turn.", 900,
            [(5, "key", ("shift", "down")), (100, "key", ("down", "down")),
             (260, "key", ("down", "up")), (400, "key", ("left", "down")),
             (560, "key", ("left", "up")), (840, "key", ("shift", "up"))],
            [("level-flight", 360, common_channels),
             ("turn-midpoint", 480, common_channels),
             ("turn-complete", 620, common_channels)],
            {**outcome_default, "outcome.contact": ("forbidden", "correction")},
        ),
        (
            "approach-landing", "Reduce power, descend, and complete a survivable landing.",
            1200,
            [(5, "key", ("shift", "down")), (100, "key", ("down", "down")),
             (260, "key", ("down", "up")), (700, "key", ("shift", "up")),
             (700, "key", ("control", "down")), (760, "key", ("up", "down")),
             (1000, "key", ("control", "up")), (1040, "key", ("up", "up"))],
            [("approach", 800, common_channels),
             ("touchdown", 1080, [*common_channels, "collision.state", "outcome.contact"]),
             ("rollout", 1199, common_channels)],
            {**outcome_default, "outcome.contact": ("required", "correction"),
             "outcome.damage": ("optional", "nonterminal")},
        ),
        (
            "impact-crash", "Drive a terminal terrain impact and observe the crash path.", 900,
            [(5, "key", ("shift", "down")), (100, "key", ("down", "down")),
             (250, "key", ("down", "up")), (500, "key", ("shift", "up")),
             (500, "key", ("up", "down")), (850, "key", ("up", "up"))],
            [("impact", 850, [*common_channels, "collision.state", "outcome.contact",
                               "outcome.damage", "outcome.crash"])],
            {**outcome_default, "outcome.contact": ("required", "correction"),
             "outcome.damage": ("required", "terminal"),
             "outcome.crash": ("required", "terminal")},
        ),
        (
            "default-airplane-fixed-camera-frame",
            "Capture the default airplane from the committed fixed camera.", 30, [],
            [("reference-frame", 29,
              ["input.sample", "clock.tick", "flight.tick", "camera.commit",
               "render.final", "render.framebuffer"])],
            outcome_default,
        ),
    )

    catalog: list[dict[str, Any]] = []
    seed = 1_592_639_710
    for identifier, description, tick_count, script, checkpoints, outcomes in blueprints:
        scaled_tick_count = round(tick_count * _DT_SCALE)
        events: list[dict[str, Any]] = []
        for sequence, (tick, event_type, payload) in enumerate(script):
            scaled_tick = round(tick * _DT_SCALE)
            if event_type == "focus":
                events.append({"sequence": sequence, "tick": scaled_tick,
                               "type": "focus", "active": payload})
            else:
                key, action = payload
                events.append({"sequence": sequence, "tick": scaled_tick,
                               "type": "key", "key": key, "action": action})
        scenario = {
            "schema": VERSION,
            "protocol": SCENARIO_PROTOCOL,
            "id": identifier,
            "description": description,
            "evidence_status": "CAPTURE_SPEC_ONLY",
            "input_script": {"tick_count": scaled_tick_count, "events": events},
            "clock_transcript": {"samples": [
                {"tick": tick, "monotonic_ns": tick * NATURAL_DT_NS,
                 "dt_f32_bits": NATURAL_DT_F32_BITS}
                for tick in range(scaled_tick_count)
            ]},
            "rng_transcript": {
                "algorithm": "recorded-u32",
                **({
                    "flight_activation_seed_u32": seed,
                    "flight_activation_dt_f32_bits": [],
                } if initial["values"] else {}),
                "seed_u32": seed, "reseeds": [], "draws": [],
            },
            "initial_state": json.loads(canonical_json(initial)),
            "checkpoints": [
                {"id": checkpoint_id, "tick": round(tick * _DT_SCALE),
                 "required_channels": list(channels)}
                for checkpoint_id, tick, channels in checkpoints
            ],
            "outcome_expectations": [
                {"channel": channel, "presence": outcomes[channel][0],
                 "predicate": outcomes[channel][1]}
                for channel in OUTCOME_CHANNEL_ORDER
            ],
        }
        catalog.append(validate_scenario(scenario, root=root))
    return validate_scenario_set(catalog, root=root)


def materialize_scenario_suite(
    root: Path, initial_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Write the exact seven reviewed scenarios and native replay wires."""
    root.mkdir(parents=True, exist_ok=True)
    scenario_directory = root / "scenarios"
    replay_directory = root / "replays"
    scenario_directory.mkdir(exist_ok=True)
    replay_directory.mkdir(exist_ok=True)
    entries = []
    for scenario in build_tracked_scenario_catalog(initial_state, root=root):
        identifier = scenario["id"]
        scenario_path = scenario_directory / f"{identifier}.json"
        replay_path = replay_directory / f"{identifier}.mvo"
        write_canonical_json(scenario_path, scenario)
        replay_path.write_bytes(build_native_replay_script(
            scenario, root=root,
            calibration=not scenario["initial_state"]["values"],
        ))
        entries.append({
            "id": identifier,
            "observation_profile": scenario_observation_profile(identifier),
            "scenario": {
                "path": scenario_path.relative_to(root).as_posix(),
                "sha256": sha256_file(scenario_path),
                "semantic_sha256": scenario_sha256(scenario, root=root),
            },
            "native_replay": {
                "path": replay_path.relative_to(root).as_posix(),
                "sha256": sha256_file(replay_path),
            },
            "capture_tick": scenario["checkpoints"][-1]["tick"],
            "complete_tick": scenario["input_script"]["tick_count"] - 1,
        })
    manifest = {
        "schema": VERSION,
        "protocol": SUITE_SPEC_PROTOCOL,
        "status": "CAPTURE_SPEC_ONLY",
        "production_claim": False,
        "scenario_order": list(SCENARIO_ID_ORDER),
        "scenarios": entries,
    }
    validate_scenario_suite_manifest(manifest, root=root)
    write_canonical_json(root / "suite-spec.json", manifest)
    return manifest


def validate_scenario_suite_manifest(
    value: Any, *, root: Path,
) -> dict[str, Any]:
    manifest = _strict(value, {
        "schema", "protocol", "status", "production_claim",
        "scenario_order", "scenarios",
    }, "scenario suite manifest")
    if manifest["schema"] != VERSION or manifest["protocol"] != SUITE_SPEC_PROTOCOL:
        raise ArtifactError("unsupported scenario suite manifest")
    if manifest["status"] != "CAPTURE_SPEC_ONLY" \
            or manifest["production_claim"] is not False:
        raise ArtifactError("scenario suite manifest cannot claim native evidence")
    if manifest["scenario_order"] != list(SCENARIO_ID_ORDER):
        raise ArtifactError("scenario suite order drifted")
    rows = manifest["scenarios"]
    if not isinstance(rows, list) or len(rows) != len(SCENARIO_ID_ORDER):
        raise ArtifactError("scenario suite must contain exactly seven entries")
    for expected_id, row in zip(SCENARIO_ID_ORDER, rows, strict=True):
        row = _strict(row, {
            "id", "observation_profile", "scenario", "native_replay",
            "capture_tick", "complete_tick",
        }, f"scenario suite {expected_id}")
        if row["id"] != expected_id:
            raise ArtifactError("scenario suite entries are out of order")
        if validate_scenario_observation_profile(
            row["observation_profile"], scenario_id=expected_id,
        ) != scenario_observation_profile(expected_id):
            raise ArtifactError("scenario suite observation profile drifted")
        scenario_ref = _strict(row["scenario"], {
            "path", "sha256", "semantic_sha256",
        }, f"scenario suite {expected_id}.scenario")
        scenario_path = _verify_file(
            root, scenario_ref, path_field="path", hash_field="sha256",
            length_field=None, label=f"scenario suite {expected_id}.scenario",
        )
        scenario = load_scenario(scenario_path, root=root)
        if scenario["id"] != expected_id \
                or scenario_ref["semantic_sha256"] != scenario_sha256(
                    scenario, root=root,
                ):
            raise ArtifactError("scenario suite semantic identity drifted")
        replay_ref = _strict(row["native_replay"], {"path", "sha256"},
                             f"scenario suite {expected_id}.native_replay")
        replay_path = _verify_file(
            root, replay_ref, path_field="path", hash_field="sha256",
            length_field=None, label=f"scenario suite {expected_id}.native_replay",
        )
        if replay_path.read_bytes() != build_native_replay_script(
            scenario, root=root,
            calibration=not scenario["initial_state"]["values"],
        ):
            raise ArtifactError("scenario suite native replay drifted")
        if row["capture_tick"] != scenario["checkpoints"][-1]["tick"] \
                or row["complete_tick"] != scenario["input_script"]["tick_count"] - 1:
            raise ArtifactError("scenario suite tick binding drifted")
    return manifest


def load_scenario_suite_manifest(path: Path) -> dict[str, Any]:
    """Load a suite spec and verify every referenced scenario and replay.

    The manifest directory is the artifact root.  Keeping that convention in
    one loader prevents callers from validating paths against an unrelated
    working directory.
    """

    path = path.resolve()
    if not path.is_file():
        raise ArtifactError(f"scenario suite manifest does not exist: {path}")
    return validate_scenario_suite_manifest(load_json(path), root=path.parent)


def scenario_suite_entry(
    manifest: Mapping[str, Any], identifier: str,
) -> Mapping[str, Any]:
    """Select one already-validated suite entry without accepting aliases."""

    if identifier not in SCENARIO_IDS:
        raise ArtifactError(f"unknown scenario suite id: {identifier!r}")
    rows = manifest.get("scenarios")
    if not isinstance(rows, list):
        raise ArtifactError("scenario suite has no validated scenario entries")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == identifier]
    if len(matches) != 1:
        raise ArtifactError(f"scenario suite must contain exactly one {identifier}")
    return matches[0]


def restore_scenario_initial_state_files(
    scenario: Mapping[str, Any], *, artifact_root: Path, state_root: Path,
    role_targets: Mapping[str, str], purge_undeclared_files: bool = False,
) -> dict[str, Any]:
    """Restore a scenario's file state into a clean, bounded native state root.

    ``role_targets`` maps every declared role to one relative destination in a
    disposable native user-state directory. Runtime-memory values remain bound
    to the receipt but are applied and read back later by the in-process
    observer, after the exact native flight owner exists.
    """

    scenario = validate_scenario(scenario, root=artifact_root)
    initial = scenario["initial_state"]
    files = initial["files"]
    roles = [row["role"] for row in files]
    if len(roles) != len(set(roles)):
        raise ArtifactError(
            "native initial-state file roles must be unique for exact target mapping"
        )
    if set(role_targets) != set(roles):
        raise ArtifactError(
            "native initial-state targets differ: "
            f"missing={sorted(set(roles) - set(role_targets))}, "
            f"unknown={sorted(set(role_targets) - set(roles))}"
        )

    if not isinstance(purge_undeclared_files, bool):
        raise ArtifactError("purge_undeclared_files must be boolean")

    resolved_state_root = state_root.resolve()
    resolved_state_root.mkdir(parents=True, exist_ok=True)
    targets: dict[str, Path] = {}
    for role in roles:
        relative = _relative_path(role_targets[role], f"initial-state target {role}")
        target = (resolved_state_root / Path(*relative.parts)).resolve()
        if resolved_state_root not in target.parents:
            raise ArtifactError(f"initial-state target {role} escapes the state root")
        targets[role] = target
    if len(set(targets.values())) != len(targets):
        raise ArtifactError("native initial-state roles cannot share a destination")

    allowed_targets = set(targets.values())
    managed_directories = set(target.parent for target in targets.values())
    ownership = []
    for directory in sorted(managed_directories):
        directory.mkdir(parents=True, exist_ok=True)
        directory_stat = directory.stat()
        effective_uid = os.geteuid() if hasattr(os, "geteuid") else None
        if effective_uid is not None and directory_stat.st_uid != effective_uid:
            raise ArtifactError(
                f"native state directory is not owned by effective uid {effective_uid}: "
                f"{directory} (owner {directory_stat.st_uid})"
            )
        probe = directory / f".miel-write-probe-{os.getpid()}"
        try:
            descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            probe.unlink()
        except OSError as error:
            probe.unlink(missing_ok=True)
            raise ArtifactError(
                f"native state directory is not writable by the runner: {directory}"
            ) from error
        ownership.append({
            "path": directory.relative_to(resolved_state_root).as_posix(),
            "owner_uid": directory_stat.st_uid,
            "owner_gid": directory_stat.st_gid,
            "mode": f"0o{stat.S_IMODE(directory_stat.st_mode):03o}",
        })

    undeclared_directories = sorted(
        path.relative_to(resolved_state_root).as_posix()
        for directory in managed_directories
        for path in directory.rglob("*")
        if path.is_dir()
    )
    if undeclared_directories:
        raise ArtifactError(
            "native initial-state root contains undeclared directories: "
            + ", ".join(undeclared_directories)
        )
    stale_paths = sorted({
        path
        for directory in managed_directories
        for path in directory.rglob("*")
        if (path.is_file() or path.is_symlink()) and path not in allowed_targets
    })
    stale = [
        path.relative_to(resolved_state_root).as_posix()
        for path in stale_paths
    ]
    if stale:
        if not purge_undeclared_files:
            raise ArtifactError(
                "native initial-state root contains undeclared files: " + ", ".join(stale)
            )
        for path in stale_paths:
            path.unlink()

    staged: list[tuple[Mapping[str, Any], Path, Path]] = []
    temporary_paths: list[Path] = []
    try:
        for index, row in enumerate(files):
            source = _verify_file(
                artifact_root, row, path_field="path", hash_field="sha256",
                length_field="byte_length", label=f"initial file {index}",
            )
            target = targets[row["role"]]
            if source.resolve() == target:
                raise ArtifactError("initial-state source and destination must differ")
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(
                f".{target.name}.miel-initial-state-{os.getpid()}-{index}.tmp"
            )
            if temporary.exists():
                raise ArtifactError(f"initial-state staging path already exists: {temporary}")
            temporary_paths.append(temporary)
            with source.open("rb") as input_stream, temporary.open("xb") as output_stream:
                for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                    output_stream.write(chunk)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            if temporary.stat().st_size != row["byte_length"] \
                    or sha256_file(temporary) != row["sha256"]:
                raise ArtifactError(f"initial-state staging verification failed for {row['role']}")
            staged.append((row, target, temporary))
        for _row, target, temporary in staged:
            os.replace(temporary, target)
        restored = []
        for row, target, _temporary in staged:
            if target.stat().st_size != row["byte_length"] \
                    or sha256_file(target) != row["sha256"]:
                raise ArtifactError(f"initial-state read-back failed for {row['role']}")
            restored.append({
                "role": row["role"],
                "source_path": row["path"],
                "target_path": target.relative_to(resolved_state_root).as_posix(),
                "byte_length": row["byte_length"],
                "sha256": row["sha256"],
            })
    finally:
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)

    return {
        "schema": VERSION,
        "protocol": INITIAL_STATE_RESTORE_PROTOCOL,
        "status": "RESTORED",
        "production_claim": False,
        "scenario": scenario["id"],
        "files": restored,
        "removed_files": stale,
        "managed_directories": ownership,
        "values": json.loads(canonical_json(initial["values"])),
    }


def _f32_vector(value: Any, size: int, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) != size:
        raise ArtifactError(f"{label} must contain {size} f32 bit strings")
    for index, item in enumerate(value):
        _f32(item, f"{label}[{index}]")
    return value


def _validate_tick_values(values: Any, label: str) -> None:
    values = _strict(values, {"dt_f32_bits"}, label)
    _f32(values["dt_f32_bits"], f"{label}.dt_f32_bits")


def _validate_controls(values: Any, label: str) -> tuple[int, bool]:
    base_keys = {
        "sample", "dt_f32_bits", "keys", "analog_horizontal_f32_bits",
        "analog_vertical_f32_bits", "flight_valid", "propulsion_f32_bits",
        "propulsion_scale_f32_bits", "horizontal_f32_bits", "vertical_f32_bits",
        "controls_enabled",
    }
    if not isinstance(values, dict) or frozenset(values) not in {
        frozenset(base_keys),
        frozenset(base_keys | {"input_source", "focus_active"}),
    }:
        raise ArtifactError(f"{label} has neither the legacy nor production controls shape")
    production = "input_source" in values
    if production:
        if values["input_source"] not in {
            "windows_sendinput_directinput", "native_directinput",
        }:
            raise ArtifactError(f"{label}.input_source is invalid")
        _boolean(values["focus_active"], f"{label}.focus_active")
    sample = _integer(values["sample"], f"{label}.sample", 0, UINT32_MAX)
    _f32(values["dt_f32_bits"], f"{label}.dt_f32_bits")
    keys = _strict(values["keys"], set(CONTROL_KEYS), f"{label}.keys")
    for key in CONTROL_KEYS:
        _integer(keys[key], f"{label}.keys.{key}", 0, 1)
    for field in (
        "analog_horizontal_f32_bits", "analog_vertical_f32_bits",
        "propulsion_f32_bits", "propulsion_scale_f32_bits",
        "horizontal_f32_bits", "vertical_f32_bits",
    ):
        _f32(values[field], f"{label}.{field}")
    valid = _boolean(values["flight_valid"], f"{label}.flight_valid")
    _integer(values["controls_enabled"], f"{label}.controls_enabled", 0, 1)
    if not valid:
        for field in (
            "propulsion_f32_bits", "propulsion_scale_f32_bits",
            "horizontal_f32_bits", "vertical_f32_bits",
        ):
            if values[field] != "0x00000000":
                raise ArtifactError(f"{label}.{field} must be zero when flight is invalid")
    return sample, production


def _validate_state(values: Any, channel: str, label: str) -> tuple[str, int, int, bool]:
    base_keys = {
        "phase", "call", "depth", "outer", "dt_f32_bits", "state_valid",
        "position_f32_bits", "orientation_wxyz_f32_bits", "velocity_f32_bits",
        "angular_velocity_f32_bits", "inactive", "floor_enabled",
    }
    extended_keys = {
        "fuel_f32_bits", "integrity_f32_bits", "maximum_integrity_f32_bits",
        "pending_damage_f32_bits", "damage_gate_timer_f32_bits", "active",
    }
    if not isinstance(values, dict) or frozenset(values) not in {
        frozenset(base_keys), frozenset(base_keys | extended_keys),
    }:
        raise ArtifactError(f"{label} has neither the legacy nor production state shape")
    production = "fuel_f32_bits" in values
    phases = {"physics.state": {"enter", "leave"},
              "collision.state": {"enter", "commit"}}
    phase = values["phase"]
    if phase not in phases[channel]:
        raise ArtifactError(f"{label}.phase is invalid for {channel}")
    call = _integer(values["call"], f"{label}.call", 0, UINT32_MAX)
    depth = _integer(values["depth"], f"{label}.depth", 0, 31)
    outer = _boolean(values["outer"], f"{label}.outer")
    if outer != (depth == 0):
        raise ArtifactError(f"{label}.outer does not match depth")
    _f32(values["dt_f32_bits"], f"{label}.dt_f32_bits")
    valid = _boolean(values["state_valid"], f"{label}.state_valid")
    vector_fields = {
        "position_f32_bits": 3,
        "orientation_wxyz_f32_bits": 4,
        "velocity_f32_bits": 3,
        "angular_velocity_f32_bits": 3,
    }
    for field, size in vector_fields.items():
        _f32_vector(values[field], size, f"{label}.{field}")
    _integer(values["inactive"], f"{label}.inactive", 0, 1)
    _integer(values["floor_enabled"], f"{label}.floor_enabled", 0, 1)
    if production:
        for field in (
            "fuel_f32_bits", "integrity_f32_bits", "maximum_integrity_f32_bits",
            "pending_damage_f32_bits", "damage_gate_timer_f32_bits",
        ):
            _f32(values[field], f"{label}.{field}")
        _integer(values["active"], f"{label}.active", 0, 1)
    if not valid:
        bits = [item for field in vector_fields for item in values[field]]
        extended_bits = [values[field] for field in extended_keys if field.endswith("_f32_bits")] \
            if production else []
        if any(item != "0x00000000" for item in [*bits, *extended_bits]) \
                or values["inactive"] != 0 or values["floor_enabled"] != 0 \
                or (production and values["active"] != 0):
            raise ArtifactError(f"{label} invalid state must be zero-filled")
    return phase, call, depth, production


def _validate_camera(values: Any, label: str) -> bool:
    legacy_keys = {
        "camera_valid", "flight_valid", "node_forward_f32_bits",
        "node_position_f32_bits", "flight_position_f32_bits",
    }
    production_keys = {
        "camera_valid", "flight_valid", "camera_control_owner", "location_state",
        "manual_camera_enabled", "move_forward", "move_backward",
        "render_world_position_f32_bits",
        "render_scaled_rotation_row_major_f32_bits", "render_scale_f32_bits",
        "render_inverse_scale_squared_f32_bits", "focal_pixels_f32_bits",
        "near_f32_bits", "far_f32_bits", "horizontal_fov_degrees_f32_bits",
        "centre_f32_bits", "window_endpoints_f32_bits", "flight_position_f32_bits",
    }
    if not isinstance(values, dict) or frozenset(values) not in {
        frozenset(legacy_keys), frozenset(production_keys),
    }:
        raise ArtifactError(f"{label} has neither the legacy nor production camera shape")
    production = "render_scaled_rotation_row_major_f32_bits" in values
    camera_valid = _boolean(values["camera_valid"], f"{label}.camera_valid")
    flight_valid = _boolean(values["flight_valid"], f"{label}.flight_valid")
    if production:
        owner = values["camera_control_owner"]
        location_state = _integer(
            values["location_state"], f"{label}.location_state", 0, UINT32_MAX,
        )
        manual_camera_enabled = _integer(
            values["manual_camera_enabled"],
            f"{label}.manual_camera_enabled", 0, 0xff,
        )
        move_forward = _integer(
            values["move_forward"], f"{label}.move_forward", 0, 0xff,
        )
        move_backward = _integer(
            values["move_backward"], f"{label}.move_backward", 0, 0xff,
        )
        if owner == "common_location":
            if location_state == UINT32_MAX or (
                manual_camera_enabled, move_forward, move_backward
            ) != (0xff, 0xff, 0xff):
                raise ArtifactError(f"{label} has invalid common-location controls")
        elif owner == "mode_fly":
            if location_state != UINT32_MAX or any(
                value not in (0, 1)
                for value in (manual_camera_enabled, move_forward, move_backward)
            ):
                raise ArtifactError(f"{label} has invalid mode_fly controls")
        else:
            raise ArtifactError(f"{label}.camera_control_owner is unsupported")
        _f32_vector(
            values["render_world_position_f32_bits"], 3,
            f"{label}.render_world_position_f32_bits",
        )
        _f32_vector(values["render_scaled_rotation_row_major_f32_bits"], 9,
                    f"{label}.render_scaled_rotation_row_major_f32_bits")
        for field in (
            "render_scale_f32_bits", "render_inverse_scale_squared_f32_bits",
            "near_f32_bits", "far_f32_bits", "horizontal_fov_degrees_f32_bits",
            "focal_pixels_f32_bits",
        ):
            _f32(values[field], f"{label}.{field}")
        _f32_vector(values["centre_f32_bits"], 2, f"{label}.centre_f32_bits")
        _f32_vector(
            values["window_endpoints_f32_bits"], 4,
            f"{label}.window_endpoints_f32_bits",
        )
        camera_fields = (
            "render_world_position_f32_bits",
            "render_scaled_rotation_row_major_f32_bits",
            "centre_f32_bits", "window_endpoints_f32_bits",
        )
    else:
        _f32_vector(values["node_forward_f32_bits"], 3,
                    f"{label}.node_forward_f32_bits")
        _f32_vector(values["node_position_f32_bits"], 3,
                    f"{label}.node_position_f32_bits")
        camera_fields = ("node_forward_f32_bits", "node_position_f32_bits")
    _f32_vector(values["flight_position_f32_bits"], 3,
                f"{label}.flight_position_f32_bits")
    if not camera_valid:
        for field in camera_fields:
            if any(item != "0x00000000" for item in values[field]):
                raise ArtifactError(f"{label}.{field} must be zero when camera is invalid")
        if production and any(values[field] != "0x00000000" for field in (
            "render_scale_f32_bits", "render_inverse_scale_squared_f32_bits",
            "near_f32_bits", "far_f32_bits", "horizontal_fov_degrees_f32_bits",
            "focal_pixels_f32_bits",
        )):
            raise ArtifactError(f"{label} projection fields must be zero when camera is invalid")
    if not flight_valid and any(
        item != "0x00000000" for item in values["flight_position_f32_bits"]
    ):
        raise ArtifactError(f"{label}.flight_position_f32_bits must be zero when flight is invalid")
    return production


def _validate_render(values: Any, label: str) -> bool:
    if not isinstance(values, dict):
        raise ArtifactError(f"{label} must be an object")
    if not values:
        return False
    _strict(values, {"crash_requested", "crash_active", "crash_timer_f32_bits"}, label)
    _integer(values["crash_requested"], f"{label}.crash_requested", 0, 1)
    _integer(values["crash_active"], f"{label}.crash_active", 0, 1)
    _f32(values["crash_timer_f32_bits"], f"{label}.crash_timer_f32_bits")
    return True


def _validate_outcome(channel: str, values: Any, label: str) -> None:
    if channel == "outcome.contact":
        _strict(values, {"kind"}, label)
        if values["kind"] != "correction":
            raise ArtifactError("outcome.contact kind must be correction")
    elif channel == "outcome.damage":
        _strict(values, {
            "effective_damage_f32_bits", "integrity_after_f32_bits", "terminal",
        }, label)
        _f32(values["effective_damage_f32_bits"], "outcome.damage effective damage")
        _f32(values["integrity_after_f32_bits"], "outcome.damage integrity after")
        _boolean(values["terminal"], "outcome.damage terminal")
    elif channel == "outcome.crash":
        _strict(values, {"terminal"}, label)
        if values["terminal"] is not True:
            raise ArtifactError("outcome.crash terminal must be true")
    elif channel == "outcome.terrain":
        _strict(values, {"class"}, label)
        # Match the C observer hook (record_terrain_result): only values > 7
        # are rejected.  Negative values from FEX x87 emulation are passed
        # through as diagnostics and must not fail artifact validation.
        _integer(values["class"], "outcome.terrain class", -2147483648, 7)
    else:
        raise ArtifactError(f"unknown outcome channel: {channel!r}")


def _focus_worker_binding(lines: list[str]) -> dict[str, Any] | None:
    """Validate the self-contained focus-worker receipt used by MVT parsing.

    Full scenario binding remains the responsibility of
    :func:`extract_focus_timeline_receipt`.  This narrower pass exists so the
    semantic parser can distinguish the one QPC focus worker from an
    accidental second game thread without trusting arbitrary off-thread MVT
    records.
    """

    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.startswith("MVD "):
            continue
        record = _json_text(line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-focus-timeline":
            rows.append(record)
    if not rows:
        return None

    common_fields = {
        "schema", "protocol", "sequence", "phase", "scenario",
        "scenario_sha256", "timeline_sha256", "clock", "origin",
        "thread_id",
    }
    identity: tuple[str, str, str, int] | None = None
    previous_sequence: int | None = None
    current_episode: int | None = None
    expected_episode = 0
    expected_ordinal = 0
    expected_active = False
    declared_event_count: int | None = None
    events: list[dict[str, Any]] = []
    completed_episodes = 0

    for index, record in enumerate(rows):
        phase = record.get("phase")
        if phase not in {"start", "event", "complete"}:
            raise ArtifactError("focus timeline worker receipt has an unknown phase")
        phase_fields = (
            {"episode", "event_count"} if phase != "event" else {
                "ordinal", "episode", "tick", "active",
                "scheduled_offset_ns", "applied_offset_ns", "lateness_ns",
            }
        )
        record = _strict(
            record, common_fields | phase_fields,
            f"focus timeline worker receipt {index}",
        )
        sequence = _integer(
            record["sequence"], f"focus timeline worker receipt {index}.sequence",
        )
        if previous_sequence is not None and sequence <= previous_sequence:
            raise ArtifactError("focus timeline worker receipt order drifted")
        previous_sequence = sequence
        thread_id = _integer(
            record["thread_id"],
            f"focus timeline worker receipt {index}.thread_id",
            1, UINT32_MAX,
        )
        if record["schema"] != 1 \
                or record["protocol"] != "miel-vliegt-native-focus-timeline" \
                or record["scenario"] not in SCENARIO_IDS \
                or record["clock"] != "query_performance_counter" \
                or record["origin"] != "episode-focus-loss":
            raise ArtifactError("focus timeline worker receipt identity drifted")
        scenario_sha256 = _hash(
            record["scenario_sha256"],
            f"focus timeline worker receipt {index}.scenario_sha256",
        )
        timeline_sha256 = _hash(
            record["timeline_sha256"],
            f"focus timeline worker receipt {index}.timeline_sha256",
        )
        actual_identity = (
            record["scenario"], scenario_sha256, timeline_sha256, thread_id,
        )
        if identity is None:
            identity = actual_identity
        elif actual_identity != identity:
            raise ArtifactError("focus timeline worker receipt changed identity")

        episode = _integer(
            record["episode"],
            f"focus timeline worker receipt {index}.episode",
        )
        if phase == "start":
            if current_episode is not None or episode != expected_episode:
                raise ArtifactError("focus timeline worker start is out of order")
            count = _integer(
                record["event_count"],
                f"focus timeline worker receipt {index}.event_count",
                1, UINT32_MAX,
            )
            if declared_event_count is None:
                declared_event_count = count
            elif count != declared_event_count:
                raise ArtifactError("focus timeline worker event count drifted")
            current_episode = episode
            expected_active = False
            continue

        if current_episode is None or episode != current_episode:
            raise ArtifactError("focus timeline worker event is outside its episode")
        if phase == "complete":
            count = _integer(
                record["event_count"],
                f"focus timeline worker receipt {index}.event_count",
                1, UINT32_MAX,
            )
            if count != declared_event_count or expected_active is not False:
                raise ArtifactError("focus timeline worker episode is incomplete")
            current_episode = None
            expected_episode += 1
            completed_episodes += 1
            continue

        ordinal = _integer(record["ordinal"], "focus timeline worker ordinal")
        tick = _integer(
            record["tick"], "focus timeline worker tick", 1, UINT32_MAX - 1,
        )
        active = _boolean(record["active"], "focus timeline worker active")
        scheduled = _integer(
            record["scheduled_offset_ns"],
            "focus timeline worker scheduled offset", 0, UINT64_MAX,
        )
        applied = _integer(
            record["applied_offset_ns"],
            "focus timeline worker applied offset", 0, UINT64_MAX,
        )
        lateness = _integer(
            record["lateness_ns"],
            "focus timeline worker lateness", 0, UINT64_MAX,
        )
        if ordinal != expected_ordinal or active is not expected_active \
                or applied < scheduled or lateness != applied - scheduled \
                or lateness > FOCUS_TIMELINE_LATE_LIMIT_NS \
                or (not active and (scheduled != 0 or applied != 0)) \
                or (active and scheduled == 0):
            raise ArtifactError("focus timeline worker chronology drifted")
        events.append({
            "ordinal": ordinal,
            "episode": episode,
            "tick": tick,
            "active": active,
            "scheduled_offset_ns": scheduled,
        })
        expected_ordinal += 1
        expected_active = not expected_active

    if current_episode is not None or completed_episodes == 0 \
            or declared_event_count != len(events):
        raise ArtifactError("focus timeline worker receipt is incomplete")
    if len({event["tick"] for event in events}) != len(events):
        raise ArtifactError("focus timeline worker ticks are not unique")
    assert identity is not None
    timeline = [
        {
            "ordinal": event["ordinal"],
            "episode": event["episode"],
            "tick": event["tick"],
            "active": event["active"],
            "offset_ns": event["scheduled_offset_ns"],
        }
        for event in events
    ]
    if _focus_timeline_sha256(timeline) != identity[2]:
        raise ArtifactError("focus timeline worker hash drifted")
    return {
        "scenario": identity[0],
        "scenario_sha256": identity[1],
        "timeline_sha256": identity[2],
        "thread_id": identity[3],
        "events": events,
    }


def parse_semantic_log(path: Path, *, require_complete: bool = False) -> dict[str, Any]:
    """Parse legacy semantic fixtures or a completed production session.

    Production canonicalization begins at ``session.dispatched`` and renumbers
    records from zero.  Login/loading traffic remains bound by ``raw_log_sha256``
    but cannot perturb the deterministic scenario hash.  Thread IDs likewise
    remain provenance rather than behavior.
    """

    raw = path.read_bytes()
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise ArtifactError("semantic log is not UTF-8") from error
    focus_worker = _focus_worker_binding(lines)
    focus_worker_expected = (
        [
            (event["tick"], channel, event["active"])
            for event in focus_worker["events"]
            for channel in ("input.transition", "input.focus")
        ]
        if focus_worker is not None else []
    )
    focus_worker_seen: list[tuple[int, str, bool]] = []
    focus_clock_resumes = (
        {
            focus_worker["events"][index]["tick"]:
                focus_worker["events"][index + 1]["tick"]
            for index in range(0, len(focus_worker["events"]), 2)
        }
        if focus_worker is not None else {}
    )
    loaded = False
    completion_marker = False
    loader_thread_id: int | None = None
    event_thread_id: int | None = None
    expected_sequence = 0
    expected_mode_diagnostic_sequence = 0
    previous_tick: int | None = None
    previous_frame = 0
    records: list[dict[str, Any]] = []
    controls: dict[int, tuple[int, int]] = {}
    physics: list[tuple[int, int, int, int]] = []
    collisions: dict[int, tuple[int, int]] = {}
    session_phase: str | None = None
    scenario_id: str | None = None
    session_ready = False
    session_complete = False
    production_shapes = True
    clock_ticks: list[int] = []
    rng_ordinals = {"seed": 0, "draw": 0}
    rng_end = False
    warmup_record_count = 0
    projector_identity: tuple[int, int] | None = None

    def append_canonical(record: dict[str, Any]) -> None:
        canonical = {key: value for key, value in record.items() if key != "diagnostics"}
        canonical["sequence"] = len(records)
        records.append(canonical)

    def reset_for_session() -> None:
        nonlocal records, controls, physics, collisions
        nonlocal previous_tick, previous_frame, warmup_record_count
        nonlocal projector_identity
        warmup_record_count = expected_sequence - 1
        records = []
        controls = {}
        physics = []
        collisions = {}
        previous_tick = None
        previous_frame = 0
        projector_identity = None

    for line_number, line in enumerate(lines, 1):
        if line.startswith("MVO "):
            marker = _json_text(line[4:], f"marker line {line_number}")
            status = marker.get("status")
            if status == "TRACE_LIMIT":
                raise ArtifactError("semantic log reached TRACE_LIMIT")
            if status in {"HOOK_FAILED", "SCENARIO_FAILED"}:
                raise ArtifactError(f"semantic observer reported {status}")
            if status not in {"LOADED", "SCENARIO_COMPLETE"}:
                raise ArtifactError(f"unknown semantic observer marker status: {status!r}")
            _strict(marker, {"schema", "protocol", "status", "thread_id"},
                    f"marker line {line_number}")
            if marker["schema"] != 1 or marker["protocol"] != HOOK_PROTOCOL:
                raise ArtifactError("unsupported semantic observer marker")
            marker_thread = _integer(marker["thread_id"], "marker thread_id", 1, UINT32_MAX)
            if status == "LOADED":
                if loaded or expected_sequence:
                    raise ArtifactError("semantic observer has a late or duplicate LOADED marker")
                loader_thread_id = marker_thread
                loaded = True
            else:
                if not loaded or completion_marker:
                    raise ArtifactError("SCENARIO_COMPLETE marker is duplicate or precedes LOADED")
                completion_marker = True
            continue
        if line.startswith("MVD "):
            diagnostic = _json_text(line[4:], f"diagnostic line {line_number}")
            if diagnostic.get("protocol") == "miel-vliegt-native-mode-transition":
                phase = diagnostic.get("phase")
                common = {
                    "schema", "protocol", "sequence", "phase", "transition_id",
                    "requested_mode", "requested_mode_valid", "thread_id",
                }
                phase_fields = {
                    "activate": {"correlation"},
                    "bootstrap_pending": {
                        "return_byte", "immediate_activation", "pending_observed",
                        "caller_site", "source_mode", "source_mode_valid",
                    },
                    "entry": {
                        "return_byte", "immediate_activation", "pending_observed",
                        "caller_site", "source_mode", "source_mode_valid",
                    },
                    "leave": {
                        "return_byte", "immediate_activation", "pending_observed",
                        "caller_site", "source_mode", "source_mode_valid",
                    },
                }
                if phase not in phase_fields:
                    raise ArtifactError(
                        f"diagnostic line {line_number}: unknown mode-transition phase"
                    )
                diagnostic = _strict(
                    diagnostic, common | phase_fields[phase],
                    f"diagnostic line {line_number}",
                )
                sequence = _integer(
                    diagnostic["sequence"],
                    f"diagnostic line {line_number}.sequence",
                )
                if sequence != expected_mode_diagnostic_sequence:
                    raise ArtifactError(
                        "mode-transition diagnostic sequence is non-contiguous"
                    )
                expected_mode_diagnostic_sequence += 1
                if diagnostic["schema"] != 1:
                    raise ArtifactError("unsupported mode-transition diagnostic schema")
                _integer(
                    diagnostic["transition_id"],
                    f"diagnostic line {line_number}.transition_id",
                )
                _integer(
                    diagnostic["thread_id"],
                    f"diagnostic line {line_number}.thread_id", 1, UINT32_MAX,
                )
                if not isinstance(diagnostic["requested_mode"], str) \
                        or not re.fullmatch(r"[A-Za-z0-9_-]+", diagnostic["requested_mode"]):
                    raise ArtifactError("mode-transition requested_mode is invalid")
                _boolean(
                    diagnostic["requested_mode_valid"],
                    f"diagnostic line {line_number}.requested_mode_valid",
                )
                if phase == "activate":
                    if diagnostic["correlation"] not in {
                        "mode_set_leave", "manager_tick_current_mode",
                    }:
                        raise ArtifactError("mode-transition correlation is invalid")
                else:
                    _integer(
                        diagnostic["return_byte"],
                        f"diagnostic line {line_number}.return_byte", 0, 0xff,
                    )
                    _boolean(
                        diagnostic["immediate_activation"],
                        f"diagnostic line {line_number}.immediate_activation",
                    )
                    _boolean(
                        diagnostic["pending_observed"],
                        f"diagnostic line {line_number}.pending_observed",
                    )
                    if not isinstance(diagnostic["caller_site"], str) or \
                            re.fullmatch(r"0x[0-9a-f]{8}", diagnostic["caller_site"]) is None:
                        raise ArtifactError("mode-transition caller_site is invalid")
                    source_valid = _boolean(
                        diagnostic["source_mode_valid"],
                        f"diagnostic line {line_number}.source_mode_valid",
                    )
                    source_mode = diagnostic["source_mode"]
                    if not isinstance(source_mode, str) or (
                        source_valid and re.fullmatch(
                            r"[A-Za-z0-9_-]+", source_mode
                        ) is None
                    ) or (not source_valid and source_mode != ""):
                        raise ArtifactError("mode-transition source_mode is invalid")
            continue
        if not line.startswith("MVT "):
            continue
        if not loaded:
            raise ArtifactError("semantic behavior appears before the LOADED marker")
        if completion_marker:
            raise ArtifactError("semantic record appears after SCENARIO_COMPLETE")
        record = _json_text(line[4:], f"semantic line {line_number}")
        record_type = record.get("record")
        envelopes = {
            "behavior": {"record", "sequence", "channel", "tick", "frame", "values", "diagnostics"},
            "input": {"record", "sequence", "channel", "tick", "frame", "values", "diagnostics"},
            "session": {"record", "sequence", "channel", "values", "diagnostics"},
            "clock": {"record", "sequence", "channel", "tick", "values", "diagnostics"},
            "rng": {"record", "sequence", "channel", "tick", "values", "diagnostics"},
            "outcome": {"record", "sequence", "channel", "tick", "frame", "values", "diagnostics"},
            "system": {"record", "sequence", "channel", "tick", "frame", "values", "diagnostics"},
            "framebuffer": {"record", "sequence", "channel", "tick", "values", "diagnostics"},
        }
        if record_type not in envelopes:
            raise ArtifactError(
                "semantic behavior parser accepts the reviewed production record types only"
            )
        _strict(record, envelopes[record_type], f"semantic line {line_number}")
        sequence = _integer(record["sequence"], f"semantic line {line_number}.sequence")
        if sequence != expected_sequence:
            raise ArtifactError("semantic record sequence is non-contiguous")
        expected_sequence += 1
        channel = record["channel"]
        legacy_focus_identity = record_type == "input" \
            and channel == "input.focus" \
            and "process_id" in record["values"]
        if record_type == "input" and channel == "input.sample":
            diagnostic_keys = {"thread_id", "window_thread_id"}
        elif record_type == "input" and channel == "input.focus" \
                and not legacy_focus_identity:
            diagnostic_keys = {"thread_id", "process_id", "window_thread_id"}
        elif record_type == "clock" and channel == "clock.tick":
            diagnostic_keys = {"thread_id"} if "observed_dt_f32_bits" in record["values"] \
                else {"thread_id", "observed_dt_f32_bits"}
        elif record_type == "rng" and "caller_rva" in record["diagnostics"]:
            diagnostic_keys = {"thread_id", "caller_rva"}
        else:
            diagnostic_keys = {"thread_id"}
        diagnostics = _strict(record["diagnostics"], diagnostic_keys,
                              f"semantic line {line_number}.diagnostics")
        thread_id = _integer(diagnostics["thread_id"],
                             f"semantic line {line_number}.thread_id", 1, UINT32_MAX)
        if "window_thread_id" in diagnostics:
            _integer(diagnostics["window_thread_id"],
                     f"semantic line {line_number}.window_thread_id", 1, UINT32_MAX)
        if "process_id" in diagnostics:
            _integer(diagnostics["process_id"],
                     f"semantic line {line_number}.process_id", 1, UINT32_MAX)
        if "caller_rva" in diagnostics:
            caller_rva = diagnostics["caller_rva"]
            if caller_rva is not None and (
                not isinstance(caller_rva, str)
                or not re.fullmatch(r"0x[0-9a-f]{8}", caller_rva)
            ):
                raise ArtifactError(
                    f"semantic line {line_number}.caller_rva is invalid"
                )
        if "observed_dt_f32_bits" in diagnostics:
            _f32(diagnostics["observed_dt_f32_bits"], "clock observed_dt_f32_bits")
        focus_worker_record = focus_worker is not None \
            and thread_id == focus_worker["thread_id"]
        if focus_worker_record:
            if record_type != "input" \
                    or channel not in {"input.transition", "input.focus"}:
                raise ArtifactError(
                    "focus worker emitted a non-focus semantic record"
                )
            tick = _integer(
                record["tick"], f"semantic line {line_number}.tick",
                0, UINT32_MAX - 1,
            )
            if len(focus_worker_seen) >= len(focus_worker_expected):
                raise ArtifactError("focus worker emitted surplus semantic records")
            expected_tick, expected_channel, expected_active = \
                focus_worker_expected[len(focus_worker_seen)]
            if tick != expected_tick or channel != expected_channel:
                raise ArtifactError(
                    "focus worker semantic record is not receipt-bound"
                )
            focus_worker_seen.append((tick, channel, expected_active))
        else:
            if event_thread_id is None:
                event_thread_id = thread_id
            elif event_thread_id != thread_id:
                raise ArtifactError("semantic behavior crossed game threads")
        values = record["values"]

        if record_type == "session":
            if channel not in {
                "session.dispatched", "session.navigating", "session.armed", "session.ready",
                "session.complete", "session.failed",
            }:
                raise ArtifactError(f"unknown session channel: {channel!r}")
            values = _strict(values, {"scenario", "reason"},
                             f"semantic line {line_number}.values")
            if values["scenario"] not in SCENARIO_IDS \
                    or not isinstance(values["reason"], str) or not values["reason"]:
                raise ArtifactError("session values have an invalid scenario or reason")
            if scenario_id is not None and values["scenario"] != scenario_id:
                raise ArtifactError("session scenario changed inside one log")
            scenario_id = values["scenario"]
            if channel == "session.failed":
                raise ArtifactError(f"production session failed: {values['reason']}")
            if channel == "session.dispatched":
                if session_phase is not None:
                    raise ArtifactError("session.dispatched is duplicate or out of order")
                reset_for_session()
                session_phase = "dispatched"
            elif channel == "session.navigating":
                if session_phase not in {"dispatched", "navigating"}:
                    raise ArtifactError(
                        "session.navigating appears without session.dispatched"
                    )
                session_phase = "navigating"
            elif channel == "session.armed":
                if session_phase != "navigating":
                    raise ArtifactError("session.armed appears without session.navigating")
                session_phase = "armed"
            elif channel == "session.ready":
                if session_phase != "armed":
                    raise ArtifactError("session.ready appears without session.armed")
                session_phase = "ready"
                session_ready = True
            else:
                if session_phase != "ready":
                    raise ArtifactError("session.complete appears without SESSION_READY")
                session_phase = "complete"
                session_complete = True
            append_canonical(record)
            continue

        if record_type == "input":
            if session_phase not in {"navigating", "armed", "ready"}:
                if session_phase == "dispatched":
                    raise ArtifactError("input proof precedes session.navigating")
                raise ArtifactError("input proof is outside the deterministic session")
            tick = _integer(record["tick"], f"semantic line {line_number}.tick",
                            0, UINT32_MAX - 1)
            _integer(record["frame"], f"semantic line {line_number}.frame",
                     0, UINT32_MAX)
            label = f"semantic line {line_number}.values"
            if channel == "input.focus":
                focus_keys = {
                    "focus_active", "valid", "projector_foreground",
                    "sink_foreground", "visible", "enabled", "iconic",
                    "candidate_count",
                }
                if legacy_focus_identity:
                    focus_keys |= {"process_id", "window_thread_id"}
                values = _strict(values, focus_keys, label)
                focus_active = _boolean(values["focus_active"], f"{label}.focus_active")
                if focus_worker_record \
                        and focus_active is not focus_worker_seen[-1][2]:
                    raise ArtifactError(
                        "focus worker semantic state contradicts its receipt"
                    )
                valid = _boolean(values["valid"], f"{label}.valid")
                projector = _boolean(values["projector_foreground"],
                                     f"{label}.projector_foreground")
                sink = _boolean(values["sink_foreground"], f"{label}.sink_foreground")
                visible = _boolean(values["visible"], f"{label}.visible")
                enabled = _boolean(values["enabled"], f"{label}.enabled")
                iconic = _boolean(values["iconic"], f"{label}.iconic")
                if legacy_focus_identity:
                    process_id = _integer(values["process_id"],
                                          f"{label}.process_id", 1, UINT32_MAX)
                    window_thread_id = _integer(
                        values["window_thread_id"],
                        f"{label}.window_thread_id", 1, UINT32_MAX,
                    )
                else:
                    process_id = diagnostics["process_id"]
                    window_thread_id = diagnostics["window_thread_id"]
                observed_identity = (process_id, window_thread_id)
                if projector_identity is None:
                    projector_identity = observed_identity
                elif projector_identity != observed_identity:
                    raise ArtifactError(
                        "production input.focus projector identity changed during replay"
                    )
                candidates = _integer(values["candidate_count"],
                                      f"{label}.candidate_count", 0, UINT32_MAX)
                if not valid or candidates != 1 or not visible or not enabled or iconic:
                    raise ArtifactError("input.focus does not prove one usable projector window")
                if focus_active != projector or sink == projector:
                    raise ArtifactError("input.focus foreground identity contradicts focus_active")
            elif channel == "input.transition":
                values = _strict(values, {
                    "from_mask", "to_mask", "event_count", "sendinput_count",
                    "complete", "input_source",
                }, label)
                _control_mask(values["from_mask"], "input.transition.from_mask")
                _control_mask(values["to_mask"], "input.transition.to_mask")
                event_count = _integer(values["event_count"], f"{label}.event_count",
                                       0, len(CONTROL_KEYS))
                sent = _integer(values["sendinput_count"], f"{label}.sendinput_count",
                                0, len(CONTROL_KEYS))
                if _boolean(values["complete"], f"{label}.complete") is not True \
                        or sent != event_count \
                        or values["input_source"] != "windows_sendinput_scancode":
                    raise ArtifactError("input.transition is not a complete SendInput transition")
            elif channel == "input.sample":
                if session_phase != "ready":
                    raise ArtifactError("input.sample precedes SESSION_READY")
                values = _strict(values, {
                    "expected_mask", "observed_mask", "read_valid",
                    "schedule_match", "sample_match", "focus_active",
                    "focus_valid", "valid", "foreground", "input_source",
                }, label)
                for field in ("expected_mask", "observed_mask"):
                    _control_mask(values[field], f"input.sample.{field}")
                focus_active = _boolean(values["focus_active"], f"{label}.focus_active")
                foreground = _boolean(values["foreground"], f"{label}.foreground")
                proof_fields = (
                    "read_valid", "schedule_match", "sample_match",
                    "focus_valid", "valid",
                )
                if any(_boolean(values[field], f"{label}.{field}") is not True
                       for field in proof_fields):
                    raise ArtifactError("input.sample native proof is incomplete")
                if values["expected_mask"] != values["observed_mask"] \
                        or foreground != focus_active \
                        or (not focus_active and values["expected_mask"] != "0x00") \
                        or values["input_source"] != "native_directinput_after_sendinput":
                    raise ArtifactError("input.sample contradicts focus or DirectInput state")
            else:
                raise ArtifactError(f"unknown input channel: {channel!r}")
            if channel == "input.focus" and legacy_focus_identity:
                normalized = dict(record)
                normalized["values"] = dict(values)
                normalized["values"].pop("process_id")
                normalized["values"].pop("window_thread_id")
                append_canonical(normalized)
            else:
                append_canonical(record)
            continue

        if record_type == "clock":
            if channel != "clock.tick" or session_phase != "ready":
                raise ArtifactError("clock.tick must occur inside a SESSION_READY replay")
            tick = _integer(record["tick"], f"semantic line {line_number}.tick", 0, UINT32_MAX - 1)
            clock_value_keys = set(values) if isinstance(values, dict) else set()
            if clock_value_keys == {
                "observed_dt_f32_bits", "scripted_dt_f32_bits", "source",
            }:
                _f32(values["observed_dt_f32_bits"], "clock observed_dt_f32_bits")
                values = {
                    "scripted_dt_f32_bits": values["scripted_dt_f32_bits"],
                    "source": values["source"],
                }
                record = {**record, "values": values}
            else:
                values = _strict(values, {
                    "scripted_dt_f32_bits", "source",
                }, f"semantic line {line_number}.values")
            _f32(values["scripted_dt_f32_bits"], "clock scripted_dt_f32_bits")
            if values["source"] != "scenario_transcript":
                raise ArtifactError("clock.tick source must be scenario_transcript")
            expected_clock_tick = 0 if not clock_ticks else clock_ticks[-1] + 1
            expected_clock_tick = focus_clock_resumes.get(
                expected_clock_tick, expected_clock_tick,
            )
            if tick != expected_clock_tick:
                raise ArtifactError(
                    "clock.tick transcript must be contiguous across active "
                    "native manager ticks"
                )
            clock_ticks.append(tick)
            append_canonical(record)
            continue

        if record_type == "rng":
            if channel not in {"rng.seed", "rng.draw", "rng.end"} \
                    or session_phase not in {"navigating", "armed", "ready"}:
                raise ArtifactError("rng record is outside the deterministic session")
            phase = channel.split(".", 1)[1]
            tick = _integer(record["tick"], f"semantic line {line_number}.tick", 0, UINT32_MAX)
            values = _strict(values, {"ordinal", "value"},
                             f"semantic line {line_number}.values")
            ordinal = _integer(values["ordinal"], f"semantic line {line_number}.ordinal", 0, UINT32_MAX)
            _integer(values["value"], f"semantic line {line_number}.value", 0, UINT32_MAX)
            if phase == "end":
                if rng_end or session_phase != "ready" \
                        or ordinal != rng_ordinals["draw"] or values["value"] != ordinal:
                    raise ArtifactError("rng.end must close the exact draw transcript once")
                rng_end = True
            else:
                if ordinal != rng_ordinals[phase]:
                    raise ArtifactError(f"rng.{phase} ordinals must be contiguous from zero")
                rng_ordinals[phase] += 1
            if session_phase in {"navigating", "armed"} \
                    and (channel != "rng.seed" or tick != UINT32_MAX):
                raise ArtifactError("only the initial rng.seed sentinel may precede SESSION_READY")
            if channel == "rng.draw" and session_phase != "ready":
                raise ArtifactError("rng.draw precedes SESSION_READY")
            if session_phase == "ready" and previous_tick != tick:
                raise ArtifactError(f"{channel} is not correlated to the active flight tick")
            append_canonical(record)
            continue

        if record_type in {"outcome", "system", "framebuffer"}:
            if session_phase != "ready":
                raise ArtifactError(f"{record_type} record is outside SESSION_READY")
            tick = _integer(record["tick"], f"semantic line {line_number}.tick", 0, UINT32_MAX - 1)
            if previous_tick != tick:
                raise ArtifactError(f"{record_type} record is not correlated to the active flight tick")
            if record_type == "outcome":
                frame = _integer(record["frame"], f"semantic line {line_number}.frame", 0, UINT32_MAX)
                _validate_outcome(channel, values, f"semantic line {line_number}.values")
                if frame < previous_frame:
                    raise ArtifactError("outcome frame precedes the current semantic frame")
                previous_frame = frame
            elif record_type == "system":
                if channel != "system.fuel":
                    raise ArtifactError(f"unknown system channel: {channel!r}")
                frame = _integer(record["frame"], f"semantic line {line_number}.frame", 0, UINT32_MAX)
                values = _strict(values, {"fuel_f32_bits", "depleted"},
                                 f"semantic line {line_number}.values")
                _f32(values["fuel_f32_bits"], "system.fuel fuel_f32_bits")
                _boolean(values["depleted"], "system.fuel depleted")
                if frame < previous_frame:
                    raise ArtifactError("system.fuel frame precedes the current semantic frame")
                previous_frame = frame
            else:
                if channel != "render.framebuffer":
                    raise ArtifactError(f"unknown framebuffer channel: {channel!r}")
                values = _strict(values, {"raw_sha256", "capture"},
                                 f"semantic line {line_number}.values")
                _hash(values["raw_sha256"], "render.framebuffer raw_sha256")
                if values["capture"] != "native_read_screen":
                    raise ArtifactError("render.framebuffer capture route is invalid")
            append_canonical(record)
            continue

        if channel not in SEMANTIC_CHANNELS:
            raise ArtifactError(f"unknown semantic channel: {channel!r}")
        tick = _integer(record["tick"], f"semantic line {line_number}.tick", 0, UINT32_MAX)
        frame = _integer(record["frame"], f"semantic line {line_number}.frame", 0, UINT32_MAX)
        scenario_scope = session_phase == "ready" or session_phase is None
        if session_phase == "complete":
            raise ArtifactError("behavior record appears after session.complete")
        if scenario_scope:
            if tick == UINT32_MAX:
                if previous_tick is not None or channel != "render.final":
                    raise ArtifactError(
                        "the pre-tick sentinel is allowed only on leading render.final records"
                    )
            else:
                if previous_tick is not None and tick < previous_tick:
                    raise ArtifactError("semantic ticks must be monotonic")
                previous_tick = tick
            if records and frame < previous_frame:
                raise ArtifactError("semantic frames must be monotonic")
            previous_frame = frame

        shape_is_production = True
        if channel == "flight.tick":
            _validate_tick_values(values, f"semantic line {line_number}.values")
        elif channel in {"controls.pre", "controls.post"}:
            sample, shape_is_production = _validate_controls(
                values, f"semantic line {line_number}.values",
            )
            if scenario_scope:
                if channel == "controls.pre":
                    if sample in controls:
                        raise ArtifactError("duplicate controls.pre sample")
                    controls[sample] = (tick, frame)
                elif controls.pop(sample, None) != (tick, frame):
                    raise ArtifactError("unmatched controls.post sample")
        elif channel == "physics.state":
            phase, call, depth, shape_is_production = _validate_state(
                values, channel, f"semantic line {line_number}.values",
            )
            if scenario_scope:
                identity = (call, depth, tick, frame)
                if phase == "enter":
                    if depth != len(physics):
                        raise ArtifactError("physics enter depth is not stack-correlated")
                    physics.append(identity)
                elif not physics or physics.pop() != identity:
                    raise ArtifactError("unmatched physics leave state")
        elif channel == "collision.state":
            phase, call, depth, shape_is_production = _validate_state(
                values, channel, f"semantic line {line_number}.values",
            )
            if depth != 0:
                raise ArtifactError("collision state depth must be zero")
            if scenario_scope:
                if phase == "enter":
                    if call in collisions:
                        raise ArtifactError("duplicate collision enter state")
                    collisions[call] = (tick, frame)
                elif collisions.pop(call, None) != (tick, frame):
                    raise ArtifactError("unmatched collision commit state")
        elif channel == "camera.commit":
            shape_is_production = _validate_camera(
                values, f"semantic line {line_number}.values",
            )
        elif channel == "render.final":
            shape_is_production = _validate_render(
                values, f"semantic line {line_number}.values",
            )
        else:
            raise ArtifactError("outcome channels must use record:'outcome'")
        if session_phase == "ready" and not shape_is_production:
            production_shapes = False
        if scenario_scope:
            append_canonical(record)

    if not loaded:
        raise ArtifactError("semantic log has no LOADED marker")
    if not records:
        raise ArtifactError("semantic log has no semantic records")
    if controls:
        raise ArtifactError("semantic log has unmatched controls.pre samples")
    if physics:
        raise ArtifactError("semantic log has unmatched physics enter state")
    if collisions:
        raise ArtifactError("semantic log has unmatched collision enter state")
    if focus_worker is not None:
        if event_thread_id is None \
                or focus_worker["thread_id"] == event_thread_id \
                or focus_worker_seen != focus_worker_expected \
                or scenario_id != focus_worker["scenario"]:
            raise ArtifactError("focus worker semantic binding is incomplete")
    production = session_phase is not None
    complete = production and session_complete and completion_marker
    if production and not production_shapes:
        raise ArtifactError("production session contains legacy behavior value shapes")
    if require_complete and not production:
        raise ArtifactError("candidate evidence requires a production session")
    if require_complete and not session_ready:
        raise ArtifactError("candidate evidence requires SESSION_READY/session.ready")
    if require_complete and not session_complete:
        raise ArtifactError("candidate evidence requires session.complete")
    if require_complete and not rng_end:
        raise ArtifactError("candidate evidence requires rng.end")
    if require_complete and not completion_marker:
        raise ArtifactError("candidate evidence requires the SCENARIO_COMPLETE marker")
    semantic = {"schema": VERSION, "protocol": TRACE_PROTOCOL, "records": records}
    return {
        **semantic,
        "semantic_sha256": canonical_sha256(semantic),
        "raw_log_sha256": hashlib.sha256(raw).hexdigest(),
        "loader_thread_id": loader_thread_id,
        "thread_id": event_thread_id,
        "focus_worker_thread_id": (
            focus_worker["thread_id"] if focus_worker is not None else None
        ),
        "record_count": len(records),
        "raw_record_count": expected_sequence,
        "warmup_record_count": warmup_record_count,
        "channel_counts": dict(sorted(Counter(row["channel"] for row in records).items())),
        "profile": "production-session" if production else "legacy-semantic",
        "scenario_id": scenario_id,
        "session_ready": session_ready,
        "complete": complete,
    }


def canonicalize_semantic_log(path: Path) -> str:
    parsed = parse_semantic_log(path)
    return canonical_json({
        "schema": parsed["schema"],
        "protocol": parsed["protocol"],
        "records": parsed["records"],
    })


def validate_framebuffer_metadata(
    value: Any, *, root: Path | None = None, raw_path: Path | None = None,
) -> dict[str, Any]:
    metadata = _strict(value, {
        "schema", "protocol", "scenario", "scenario_sha256", "tick", "width",
        "height", "pitch", "bits_per_pixel", "bytes_per_pixel", "gt_format_id",
        "gt_format_name", "image_size", "raw_size", "raw_sha256", "row_layout",
        "origin", "packed_format", "memory_byte_order", "surface_alpha",
        "device_config", "device_config_sha256", "device_module",
        "device_module_sha256", "window_role", "window_top_level",
        "window_visible", "window_enabled", "window_iconic", "client_width",
        "client_height", "render_ordinal", "paint_progress",
        "non_black_pixel_count",
    }, "framebuffer metadata")
    if metadata["schema"] != FRAMEBUFFER_VERSION \
            or metadata["protocol"] != FRAMEBUFFER_PROTOCOL:
        raise ArtifactError("unsupported raw framebuffer metadata")
    if metadata["scenario"] not in SCENARIO_IDS:
        raise ArtifactError("framebuffer scenario id is not reviewed")
    _hash(metadata["scenario_sha256"], "framebuffer.scenario_sha256")
    _integer(metadata["tick"], "framebuffer.tick", 0, UINT32_MAX - 1)
    width = _integer(metadata["width"], "framebuffer.width", 1, UINT32_MAX)
    height = _integer(metadata["height"], "framebuffer.height", 1, UINT32_MAX)
    pitch = _integer(metadata["pitch"], "framebuffer.pitch", 1, UINT32_MAX)
    bits_per_pixel = _integer(
        metadata["bits_per_pixel"], "framebuffer.bits_per_pixel", 8, 128,
    )
    bytes_per_pixel = _integer(
        metadata["bytes_per_pixel"], "framebuffer.bytes_per_pixel", 1, 16,
    )
    image_format = _integer(metadata["gt_format_id"], "framebuffer.gt_format_id", 3, 8)
    image_size = _integer(metadata["image_size"], "framebuffer.image_size", 1, UINT32_MAX)
    raw_size = _integer(metadata["raw_size"], "framebuffer.raw_size", 1, UINT32_MAX)
    client_width = _integer(
        metadata["client_width"], "framebuffer.client_width", 1, UINT32_MAX,
    )
    client_height = _integer(
        metadata["client_height"], "framebuffer.client_height", 1, UINT32_MAX,
    )
    _integer(metadata["render_ordinal"], "framebuffer.render_ordinal", 1, UINT32_MAX)
    non_black_pixel_count = _integer(
        metadata["non_black_pixel_count"],
        "framebuffer.non_black_pixel_count",
        1,
        UINT32_MAX,
    )
    window_top_level = _boolean(
        metadata["window_top_level"], "framebuffer.window_top_level",
    )
    window_visible = _boolean(
        metadata["window_visible"], "framebuffer.window_visible",
    )
    window_enabled = _boolean(
        metadata["window_enabled"], "framebuffer.window_enabled",
    )
    window_iconic = _boolean(
        metadata["window_iconic"], "framebuffer.window_iconic",
    )
    if bits_per_pixel % 8 != 0 or bytes_per_pixel != bits_per_pixel // 8:
        raise ArtifactError("framebuffer bit/byte pixel sizes disagree")
    if image_format != 8 or bits_per_pixel != 32 \
            or metadata["gt_format_name"] != "ARGB8888" \
            or metadata["origin"] != "top-left" \
            or metadata["packed_format"] != "xrgb8888-le" \
            or metadata["memory_byte_order"] != "bgrx" \
            or metadata["surface_alpha"] != "unused" \
            or metadata["device_config"] != "config.ini" \
            or metadata["device_config_sha256"] \
            != REVIEWED_GT_SOFTWARE_CONFIG_SHA256 \
            or metadata["device_module"] != "gtSoftware.dll" \
            or metadata["device_module_sha256"] != REVIEWED_GT_SOFTWARE_SHA256:
        raise ArtifactError("framebuffer source layout/backend is not reviewed XRGB")
    if metadata["window_role"] != "top-level-projector" \
            or not window_top_level or not window_visible \
            or not window_enabled or window_iconic \
            or client_width != FRAMEBUFFER_CLIENT_WIDTH \
            or client_height != FRAMEBUFFER_CLIENT_HEIGHT \
            or width != client_width or height != client_height:
        raise ArtifactError("framebuffer window readiness is not canonical 640x480")
    if metadata["paint_progress"] != "manager-render-and-non-black" \
            or non_black_pixel_count > width * height:
        raise ArtifactError("framebuffer paint progress is not proven")
    if pitch != width * bytes_per_pixel:
        raise ArtifactError("framebuffer.pitch is not the packed pixel row")
    if raw_size != pitch * height:
        raise ArtifactError("framebuffer.raw_size does not equal pitch * height")
    if image_size != raw_size:
        raise ArtifactError("framebuffer.image_size does not equal raw_size")
    if metadata["row_layout"] != "native_pitch_bytes":
        raise ArtifactError("framebuffer.row_layout must be native_pitch_bytes")
    expected_hash = _hash(metadata["raw_sha256"], "framebuffer.raw_sha256")
    if raw_path is not None:
        if root is not None:
            _path_from_file(root, raw_path, "framebuffer raw artifact")
        if not raw_path.is_file():
            raise ArtifactError("framebuffer raw artifact does not exist")
        raw = raw_path.read_bytes()
        if len(raw) != raw_size:
            raise ArtifactError("framebuffer raw artifact byte length drifted")
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ArtifactError("framebuffer raw artifact hash drifted")
        observed_non_black = sum(
            raw[offset] != 0 or raw[offset + 1] != 0 or raw[offset + 2] != 0
            for offset in range(0, raw_size, bytes_per_pixel)
        )
        if observed_non_black != non_black_pixel_count:
            raise ArtifactError("framebuffer non-black paint evidence drifted")
    return metadata


def load_framebuffer_metadata(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    return validate_framebuffer_metadata(
        load_json(path), root=root, raw_path=path.with_suffix(".raw"),
    )


def validate_framebuffer_source_metadata(
    value: Any, *, root: Path | None = None, raw_path: Path | None = None,
) -> dict[str, Any]:
    metadata = _strict(value, {
        "schema", "protocol", "scenario", "scenario_sha256", "tick", "width",
        "height", "pitch", "bits_per_pixel", "bytes_per_pixel",
        "gt_format_id", "gt_format_name", "image_size", "raw_size",
        "raw_sha256", "row_layout", "origin", "packed_format", "conversion",
    }, "framebuffer source metadata")
    if metadata["schema"] != FRAMEBUFFER_SOURCE_VERSION \
            or metadata["protocol"] != FRAMEBUFFER_SOURCE_PROTOCOL:
        raise ArtifactError("unsupported native framebuffer source metadata")
    if metadata["scenario"] not in SCENARIO_IDS:
        raise ArtifactError("framebuffer source scenario id is not reviewed")
    _hash(metadata["scenario_sha256"], "framebuffer_source.scenario_sha256")
    _integer(metadata["tick"], "framebuffer_source.tick", 0, UINT32_MAX - 1)
    width = _integer(metadata["width"], "framebuffer_source.width", 1, UINT32_MAX)
    height = _integer(metadata["height"], "framebuffer_source.height", 1, UINT32_MAX)
    pitch = _integer(metadata["pitch"], "framebuffer_source.pitch", 1, UINT32_MAX)
    bits_per_pixel = _integer(
        metadata["bits_per_pixel"], "framebuffer_source.bits_per_pixel", 8, 128,
    )
    bytes_per_pixel = _integer(
        metadata["bytes_per_pixel"], "framebuffer_source.bytes_per_pixel", 1, 16,
    )
    image_format = _integer(
        metadata["gt_format_id"], "framebuffer_source.gt_format_id", 3, 8,
    )
    image_size = _integer(
        metadata["image_size"], "framebuffer_source.image_size", 1, UINT32_MAX,
    )
    raw_size = _integer(
        metadata["raw_size"], "framebuffer_source.raw_size", 1, UINT32_MAX,
    )
    if width != FRAMEBUFFER_CLIENT_WIDTH or height != FRAMEBUFFER_CLIENT_HEIGHT:
        raise ArtifactError("framebuffer source dimensions are not canonical 640x480")
    if bits_per_pixel % 8 != 0 or bytes_per_pixel != bits_per_pixel // 8:
        raise ArtifactError("framebuffer source bit/byte pixel sizes disagree")
    reviewed_layouts = {
        5: {
            "bits": 16,
            "name": "RGB565",
            "packed": "rgb565-le",
            "conversion": "rgb565-le-to-xrgb8888-le",
        },
        8: {
            "bits": 32,
            "name": "ARGB8888",
            "packed": "xrgb8888-le",
            "conversion": "identity",
        },
    }
    layout = reviewed_layouts.get(image_format)
    if layout is None \
            or bits_per_pixel != layout["bits"] \
            or metadata["gt_format_name"] != layout["name"] \
            or metadata["packed_format"] != layout["packed"] \
            or metadata["conversion"] != layout["conversion"] \
            or metadata["origin"] != "top-left" \
            or metadata["row_layout"] != "native_pitch_bytes":
        raise ArtifactError("framebuffer source layout is not reviewed")
    if pitch < width * bytes_per_pixel \
            or raw_size != pitch * height \
            or image_size != raw_size:
        raise ArtifactError("framebuffer source buffer geometry drifted")
    expected_hash = _hash(
        metadata["raw_sha256"], "framebuffer_source.raw_sha256",
    )
    if raw_path is not None:
        if root is not None:
            _path_from_file(root, raw_path, "framebuffer source raw artifact")
        if not raw_path.is_file():
            raise ArtifactError("framebuffer source raw artifact does not exist")
        raw = raw_path.read_bytes()
        if len(raw) != raw_size:
            raise ArtifactError("framebuffer source raw byte length drifted")
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ArtifactError("framebuffer source raw hash drifted")
    return metadata


def load_framebuffer_source_metadata(
    path: Path, *, root: Path | None = None,
) -> dict[str, Any]:
    raw_path = path.with_name(path.name.removesuffix(".json") + ".raw")
    return validate_framebuffer_source_metadata(
        load_json(path), root=root, raw_path=raw_path,
    )


def _expand_gt_channel(value: int, bits: int) -> int:
    maximum = (1 << bits) - 1
    return (value * 255 + maximum // 2) // maximum


def canonicalize_framebuffer_source(
    metadata: Mapping[str, Any], raw: bytes,
) -> bytes:
    """Derive the reviewed packed XRGB surface from the exact GtImage bytes."""

    metadata = validate_framebuffer_source_metadata(dict(metadata))
    if len(raw) != metadata["raw_size"]:
        raise ArtifactError(
            "framebuffer source raw byte length drifted during canonicalization"
        )
    if hashlib.sha256(raw).hexdigest() != metadata["raw_sha256"]:
        raise ArtifactError(
            "framebuffer source raw hash drifted during canonicalization"
        )
    canonical = bytearray(metadata["width"] * metadata["height"] * 4)
    target = 0
    for row in range(metadata["height"]):
        row_start = row * metadata["pitch"]
        for column in range(metadata["width"]):
            if metadata["gt_format_id"] == 8:
                source = row_start + column * 4
                canonical[target:target + 4] = raw[source:source + 4]
            else:
                source = row_start + column * 2
                pixel = raw[source] | raw[source + 1] << 8
                red = _expand_gt_channel((pixel >> 11) & 0x1f, 5)
                green = _expand_gt_channel((pixel >> 5) & 0x3f, 6)
                blue = _expand_gt_channel(pixel & 0x1f, 5)
                canonical[target:target + 4] = bytes((blue, green, red, 0))
            target += 4
    return bytes(canonical)


def validate_framebuffer_derivation(
    source_metadata: Mapping[str, Any],
    source_raw: bytes,
    canonical_metadata: Mapping[str, Any],
    canonical_raw: bytes,
) -> dict[str, Any]:
    """Cryptographically bind the preserved native surface to its conversion."""

    source = validate_framebuffer_source_metadata(dict(source_metadata))
    canonical = validate_framebuffer_metadata(dict(canonical_metadata))
    identity_fields = ("scenario", "scenario_sha256", "tick", "width", "height")
    if any(source[field] != canonical[field] for field in identity_fields):
        raise ArtifactError("framebuffer native/canonical identity drifted")
    if len(canonical_raw) != canonical["raw_size"]:
        raise ArtifactError("framebuffer canonical raw byte length drifted")
    canonical_sha256 = hashlib.sha256(canonical_raw).hexdigest()
    if canonical_sha256 != canonical["raw_sha256"]:
        raise ArtifactError("framebuffer canonical raw hash drifted")
    observed_non_black = sum(
        canonical_raw[offset] != 0
        or canonical_raw[offset + 1] != 0
        or canonical_raw[offset + 2] != 0
        for offset in range(0, len(canonical_raw), 4)
    )
    if observed_non_black != canonical["non_black_pixel_count"]:
        raise ArtifactError("framebuffer canonical non-black evidence drifted")
    derived = canonicalize_framebuffer_source(source, source_raw)
    if derived != canonical_raw:
        raise ArtifactError(
            "framebuffer canonical pixels are not derived from native source"
        )
    from tools.miel_vliegt import native_framebuffer_origin_contract as origin_contract

    origin_path = origin_contract.DEFAULT_OUTPUT
    origin_value = load_json(origin_path)
    try:
        resolved_origin = origin_contract.resolve_origin(
            origin_value,
            measured_pitch=source["pitch"],
            lock_call_address=origin_contract.FULL_SURFACE_LOCK_SITE,
        )
    except origin_contract.FramebufferOriginContractError as error:
        raise ArtifactError(
            f"framebuffer origin contract failed closed: {error}"
        ) from error
    if resolved_origin != "TOP_LEFT" \
            or source["origin"] != "top-left" \
            or canonical["origin"] != "top-left":
        raise ArtifactError("framebuffer origin contract did not resolve TOP_LEFT")
    return {
        "source_raw_sha256": source["raw_sha256"],
        "canonical_raw_sha256": canonical_sha256,
        "conversion": source["conversion"],
        "byte_exact": True,
        "origin": {
            "protocol": origin_value["protocol"],
            "contract_file_sha256": sha256_file(origin_path),
            "contract_receipt_sha256": origin_value["receiptSha256"],
            "lock_call_address": (
                f"0x{origin_contract.FULL_SURFACE_LOCK_SITE:08x}"
            ),
            "measured_pitch": source["pitch"],
            "resolved": resolved_origin,
        },
        "pixel_parity_eligible": True,
    }


def validate_framebuffer_trace_binding(
    trace: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    require_render_final: bool,
) -> dict[str, Any]:
    """Bind one capture row to its pixels and, for exact runs, final render."""

    metadata = validate_framebuffer_metadata(dict(metadata))
    records = trace.get("records")
    if not isinstance(records, list):
        raise ArtifactError("framebuffer trace records are unavailable")
    framebuffer_rows = [
        (index, row) for index, row in enumerate(records)
        if isinstance(row, dict) and row.get("channel") == "render.framebuffer"
    ]
    if len(framebuffer_rows) != 1:
        raise ArtifactError("trace must contain exactly one render.framebuffer record")
    frame_index, frame_row = framebuffer_rows[0]
    values = frame_row.get("values")
    if not isinstance(values, dict) \
            or frame_row.get("tick") != metadata["tick"] \
            or values.get("raw_sha256") != metadata["raw_sha256"] \
            or values.get("capture") != "native_read_screen":
        raise ArtifactError("framebuffer metadata lost its exact trace binding")
    render_final_correlated = (
        frame_index > 0
        and records[frame_index - 1].get("channel") == "render.final"
        and records[frame_index - 1].get("tick") == metadata["tick"]
    )
    if require_render_final and not render_final_correlated:
        raise ArtifactError("framebuffer metadata lost its render.final correlation")
    return {
        "tick": metadata["tick"],
        "raw_sha256": metadata["raw_sha256"],
        "capture": "native_read_screen",
        "render_final_correlated": render_final_correlated,
        "profile": "exact" if require_render_final else "calibration-only",
    }


def canonicalize_native_framebuffer(metadata: Mapping[str, Any], raw: bytes) -> bytes:
    """Convert the reviewed DirectDraw XRGB capture to top-left straight RGBA."""

    metadata = validate_framebuffer_metadata(dict(metadata))
    if len(raw) != metadata["raw_size"]:
        raise ArtifactError("framebuffer raw byte length drifted during canonicalization")
    width = metadata["width"]
    height = metadata["height"]
    pitch = metadata["pitch"]
    rgba = bytearray(width * height * 4)
    target = 0
    for target_row in range(height):
        source = target_row * pitch
        for column in range(width):
            blue, green, red, _unused = raw[source + column * 4:source + column * 4 + 4]
            rgba[target:target + 4] = bytes((red, green, blue, 255))
            target += 4
    return bytes(rgba)


def build_native_framebuffer_checkpoint(
    metadata_path: Path, *, root: Path, checkpoint_id: str,
) -> dict[str, Any]:
    """Build cryptographically bound canonical pixel evidence from a raw capture."""

    if not isinstance(checkpoint_id, str) or not checkpoint_id:
        raise ArtifactError("framebuffer checkpoint id must be non-empty")
    metadata = load_framebuffer_metadata(metadata_path, root=root)
    rgba = canonicalize_native_framebuffer(
        metadata, metadata_path.with_suffix(".raw").read_bytes(),
    )
    return {
        "id": checkpoint_id,
        "width": metadata["width"],
        "height": metadata["height"],
        "pixel_format": "rgba8",
        "origin": "top-left",
        "alpha_mode": "straight",
        "reference_sha256": hashlib.sha256(rgba).hexdigest(),
    }


def build_native_framebuffer_evidence(
    metadata_path: Path, *, root: Path, checkpoint_id: str,
) -> dict[str, Any]:
    metadata = load_framebuffer_metadata(metadata_path, root=root)
    return {
        "tick": metadata["tick"],
        "raw_sha256": metadata["raw_sha256"],
        "pixel_checkpoint": build_native_framebuffer_checkpoint(
            metadata_path, root=root, checkpoint_id=checkpoint_id,
        ),
    }


def _file_reference(root: Path, path: Path, label: str) -> dict[str, str]:
    relative = _path_from_file(root, path, label)
    return {"path": relative, "sha256": sha256_file(path)}


def _validate_trace_against_scenario(
    trace: Mapping[str, Any], scenario: Mapping[str, Any],
) -> None:
    """Bind production session records to every deterministic transcript."""

    identifier = scenario["id"]
    if trace.get("profile") != "production-session" or trace.get("complete") is not True:
        raise ArtifactError("scenario binding requires a completed production trace")
    if trace.get("scenario_id") != identifier:
        raise ArtifactError("production trace targets a different scenario")
    counts = trace["channel_counts"]
    missing = SCENARIO_REQUIRED_CHANNELS[identifier] - set(counts)
    if missing:
        raise ArtifactError(f"production trace misses required scenario channels: {sorted(missing)}")
    for channel in (
        "session.dispatched", "session.armed", "session.ready", "session.complete",
    ):
        if counts.get(channel) != 1:
            raise ArtifactError(f"production trace must contain exactly one {channel}")
    if counts.get("session.navigating", 0) < 1:
        raise ArtifactError("production trace must contain at least one session.navigating")

    records = trace["records"]
    tick_count = scenario["input_script"]["tick_count"]
    clocks = [row for row in records if row["channel"] == "clock.tick"]
    flight_ticks = [row for row in records if row["channel"] == "flight.tick"]
    schedule = _input_schedule(scenario)
    expected_ticks = _native_manager_tick_schedule(scenario)
    if [row["tick"] for row in clocks] != expected_ticks:
        raise ArtifactError("production clock ticks do not exactly match the scenario")
    if [row["tick"] for row in flight_ticks] != expected_ticks:
        raise ArtifactError("production flight ticks do not exactly match the scenario")
    for tick, clock, flight in zip(
        expected_ticks, clocks, flight_ticks, strict=True,
    ):
        sample = scenario["clock_transcript"]["samples"][tick]
        scripted = sample["dt_f32_bits"]
        if clock["values"]["scripted_dt_f32_bits"] != scripted \
                or flight["values"]["dt_f32_bits"] != scripted:
            raise ArtifactError(f"production clock transcript drifted at tick {tick}")

    seeds = [row for row in records if row["channel"] == "rng.seed"]
    draws = [row for row in records if row["channel"] == "rng.draw"]
    rng = scenario["rng_transcript"]
    activation_seed = rng.get("flight_activation_seed_u32", rng["seed_u32"])
    expected_bootstrap_seeds = [
        {"ordinal": 0, "value": activation_seed},
        {"ordinal": 1, "value": rng["seed_u32"]},
    ]
    if len(seeds) < 2 or any(row["tick"] != UINT32_MAX for row in seeds[:2]) \
            or [row["values"] for row in seeds[:2]] != expected_bootstrap_seeds:
        raise ArtifactError("production construction/session rng seeds drifted")
    expected_reseeds = [
        {
            "tick": row["tick"],
            "values": {"ordinal": row["sequence"] + 2, "value": row["value_u32"]},
        }
        for row in rng["reseeds"]
    ]
    actual_reseeds = [
        {"tick": row["tick"], "values": row["values"]} for row in seeds[2:]
    ]
    if actual_reseeds != expected_reseeds:
        raise ArtifactError("production rng.seed reseed transcript drifted")
    expected_draws = [
        {
            "tick": row["tick"],
            "values": {"ordinal": row["sequence"], "value": row["value_u32"]},
        }
        for row in rng["draws"]
    ]
    actual_draws = [{"tick": row["tick"], "values": row["values"]} for row in draws]
    if actual_draws != expected_draws:
        raise ArtifactError("production rng.draw transcript drifted")
    ends = [row for row in records if row["channel"] == "rng.end"]
    if len(ends) != 1 or ends[0]["tick"] != tick_count - 1 \
            or ends[0]["values"] != {"ordinal": len(draws), "value": len(draws)}:
        raise ArtifactError("production rng.end does not close the scenario transcript")

    focus_rows = [row for row in records if row["channel"] == "input.focus"]
    transition_rows = [row for row in records if row["channel"] == "input.transition"]
    sample_rows = [row for row in records if row["channel"] == "input.sample"]
    focus_loss_ticks = {
        event["tick"] for event in scenario["input_script"]["events"]
        if event["type"] == "focus" and event["active"] is False
    }
    expected_input_ticks = sorted(set(expected_ticks) | focus_loss_ticks)
    for channel, rows, channel_ticks in (
        ("input.focus", focus_rows, expected_input_ticks),
        ("input.transition", transition_rows, expected_input_ticks),
        ("input.sample", sample_rows, expected_ticks),
    ):
        if [row["tick"] for row in rows] != channel_ticks:
            raise ArtifactError(f"production {channel} proof does not cover every tick")
    previous_physical = 0
    expected_keys: dict[int, dict[str, int]] = {}
    focus_by_tick = {row["tick"]: row for row in focus_rows}
    transition_by_tick = {row["tick"]: row for row in transition_rows}
    sample_by_tick = {row["tick"]: row for row in sample_rows}
    for tick in expected_input_ticks:
        logical_mask, focus_active = schedule[tick]
        physical_mask = logical_mask if focus_active else 0
        expected_mask = f"0x{physical_mask:02x}"
        focus = focus_by_tick[tick]["values"]
        transition = transition_by_tick[tick]["values"]
        if focus["focus_active"] is not focus_active or focus["valid"] is not True:
            raise ArtifactError(f"production input.focus drifted at tick {tick}")
        changed = (previous_physical ^ physical_mask).bit_count()
        if transition["from_mask"] != f"0x{previous_physical:02x}" \
                or transition["to_mask"] != expected_mask \
                or transition["event_count"] != changed \
                or transition["sendinput_count"] != changed \
                or transition["complete"] is not True:
            raise ArtifactError(f"production input.transition drifted at tick {tick}")
        if tick in sample_by_tick:
            sample = sample_by_tick[tick]["values"]
            if sample["expected_mask"] != expected_mask \
                    or sample["observed_mask"] != expected_mask \
                    or sample["focus_active"] is not focus_active \
                    or sample["foreground"] is not focus_active:
                raise ArtifactError(f"production input.sample drifted at tick {tick}")
        if focus_active:
            expected_keys[tick] = {
                key: int(bool(physical_mask & (1 << index)))
                for index, key in enumerate(CONTROL_KEYS)
            }
        previous_physical = physical_mask

    if {"controls.pre", "controls.post"} <= SCENARIO_REQUIRED_CHANNELS[identifier]:
        for channel in ("controls.pre", "controls.post"):
            samples = [row for row in records if row["channel"] == channel]
            if [row["tick"] for row in samples] != expected_ticks:
                raise ArtifactError(f"production {channel} samples do not cover every tick")
            for tick, row in zip(expected_ticks, samples, strict=True):
                if row["values"].get("input_source") \
                        != "windows_sendinput_directinput" \
                        or row["values"].get("focus_active") is not schedule[tick][1] \
                        or row["values"]["keys"] != expected_keys[tick] \
                        or row["values"]["dt_f32_bits"] \
                            != scenario["clock_transcript"]["samples"][tick]["dt_f32_bits"]:
                    raise ArtifactError(f"production {channel} input drifted at tick {tick}")

    records_by_channel: dict[str, list[Mapping[str, Any]]] = {}
    for record in records:
        records_by_channel.setdefault(record["channel"], []).append(record)
    for checkpoint in scenario["checkpoints"]:
        for channel in checkpoint["required_channels"]:
            if not any(row.get("tick") == checkpoint["tick"]
                       for row in records_by_channel.get(channel, [])):
                raise ArtifactError(
                    f"checkpoint {checkpoint['id']} misses {channel} at tick "
                    f"{checkpoint['tick']}"
                )

    for expectation in scenario["outcome_expectations"]:
        channel = expectation["channel"]
        rows = records_by_channel.get(channel, [])
        presence = expectation["presence"]
        if presence == "required" and not rows:
            raise ArtifactError(f"production trace misses required {channel}")
        if presence == "forbidden" and rows:
            raise ArtifactError(f"production trace contains forbidden {channel}")
        if not rows:
            continue
        predicate = expectation["predicate"]
        if channel == "outcome.damage" and predicate == "terminal" \
                and not any(row["values"]["terminal"] is True for row in rows):
            raise ArtifactError("outcome.damage never reaches the required terminal state")
        if channel == "outcome.damage" and predicate == "nonterminal" \
                and any(row["values"]["terminal"] is True for row in rows):
            raise ArtifactError("outcome.damage violates the nonterminal expectation")


def validate_completed_scenario_trace(
    observer_log: Path, scenario: Mapping[str, Any], *, root: Path,
) -> dict[str, Any]:
    """Validate a completed observer log against every scenario transcript."""

    scenario = validate_scenario(scenario, root=root)
    trace = parse_semantic_log(observer_log, require_complete=True)
    _validate_trace_against_scenario(trace, scenario)
    return trace


def calibrate_scenario_rng_transcript(
    scenario: Mapping[str, Any], trace: Mapping[str, Any], *, root: Path,
) -> dict[str, Any]:
    """Bind a capture specification to the RNG calls observed by native code.

    Calibration never promotes evidence. It copies only reseeds/draws from a
    completed production session, then re-runs the complete scenario validator
    against that calibrated copy. A second native run is still required to
    prove that the resulting transcript is reproducible.
    """

    candidate = validate_scenario(scenario, root=root)
    if not isinstance(trace, Mapping) or trace.get("profile") != "production-session" \
            or trace.get("complete") is not True:
        raise ArtifactError("RNG calibration requires a completed production trace")
    records = trace.get("records")
    if not isinstance(records, list):
        raise ArtifactError("RNG calibration trace has no records")
    seeds = [row for row in records if row.get("channel") == "rng.seed"]
    draws = [row for row in records if row.get("channel") == "rng.draw"]
    rng = candidate["rng_transcript"]
    expected_bootstrap_seeds = [
        {"ordinal": 0, "value": rng.get("flight_activation_seed_u32", rng["seed_u32"])},
        {"ordinal": 1, "value": rng["seed_u32"]},
    ]
    if len(seeds) < 2 or any(row.get("tick") != UINT32_MAX for row in seeds[:2]) \
            or [row.get("values") for row in seeds[:2]] != expected_bootstrap_seeds:
        raise ArtifactError("RNG calibration bootstrap seeds differ from the specification")
    calibrated = json.loads(canonical_json(candidate))
    calibrated["rng_transcript"]["reseeds"] = [
        {
            "sequence": index,
            "tick": row["tick"],
            "value_u32": row["values"]["value"],
        }
        for index, row in enumerate(seeds[2:])
    ]
    calibrated["rng_transcript"]["draws"] = [
        {
            "sequence": index,
            "tick": row["tick"],
            "value_u32": row["values"]["value"],
        }
        for index, row in enumerate(draws)
    ]
    calibrated = validate_scenario(calibrated, root=root)
    _validate_trace_against_scenario(trace, calibrated)
    return calibrated


def _extract_runtime_initial_state(
    observer_log: Path, *, phase: str, replay_bound: bool,
) -> list[dict[str, str]]:

    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-initial-state":
            rows.append(record)
    if len(rows) != len(RUNTIME_STATE_FIELDS) + 1:
        raise ArtifactError(f"runtime initial-state {phase} receipt is incomplete")
    values: list[dict[str, str]] = []
    for index, ((name, encoding), record) in enumerate(
        zip(RUNTIME_STATE_FIELDS, rows[:-1], strict=True),
    ):
        record = _strict(record, {
            "schema", "protocol", "sequence", "phase", "index", "name",
            "encoding", "access_mode", "value_hex", "thread_id",
        }, f"runtime state calibration {index}")
        if record["schema"] != 1 \
                or record["protocol"] != "miel-vliegt-native-initial-state" \
                or record["phase"] != phase \
                or _integer(record["index"], f"runtime state calibration {index}.index") != index \
                or record["name"] != name or record["encoding"] != encoding \
                or record["access_mode"] != RUNTIME_STATE_ACCESS[name]:
            raise ArtifactError(f"runtime initial-state {phase} order drifted")
        _integer(record["sequence"], f"runtime state calibration {index}.sequence")
        _integer(record["thread_id"], f"runtime state calibration {index}.thread_id", 1)
        width = 2 if encoding == "u8" else 8
        value_hex = record["value_hex"]
        if not isinstance(value_hex, str) \
                or re.fullmatch(rf"[0-9a-f]{{{width}}}", value_hex) is None:
            raise ArtifactError(f"runtime initial-state {phase} value is invalid")
        values.append({"name": name, "encoding": encoding, "value_hex": value_hex})
    complete = _strict(rows[-1], {
        "schema", "protocol", "sequence", "phase", "field_count",
        "replay_bound", "thread_id",
    }, "runtime state calibration completion")
    if complete["schema"] != 1 \
            or complete["protocol"] != "miel-vliegt-native-initial-state" \
            or complete["phase"] != f"{phase}_complete" \
            or complete["field_count"] != len(RUNTIME_STATE_FIELDS) \
            or complete["replay_bound"] is not replay_bound:
        raise ArtifactError(f"runtime initial-state {phase} completion drifted")
    return values


def extract_calibrated_runtime_initial_state(observer_log: Path) -> list[dict[str, str]]:
    """Extract one complete, ordered scalar-state calibration receipt."""

    return _extract_runtime_initial_state(
        observer_log, phase="calibration", replay_bound=False,
    )


def extract_bound_runtime_initial_state(observer_log: Path) -> list[dict[str, str]]:
    """Extract the exact post-apply/readback state from a bound V3 run."""

    return _extract_runtime_initial_state(
        observer_log, phase="readback", replay_bound=True,
    )


# Canonical location-phase RNG seed value emitted by the observer hook at
# ``phase=seed`` (hangover/native_observer_hook.c -> emit_location_phase_rng).
# The hook only guards the caller_rva half of the contract; this constant pins
# the VALUE half so a capture that passes caller_rva while emitting the wrong
# seed can no longer go green. Kept in sync with the seed-consistency gate and
# the observer-log test module by test_flight_seed_consistency.
LOCATION_PHASE_RNG_SEED_VALUE = 1592639710


def validate_location_phase_rng_seed(observer_log: Path) -> dict[str, Any]:
    """Validate the location-phase RNG seed emitted at the start of a capture.

    Reads the observer log produced by a flight scenario capture and asserts
    that the single ``miel-vliegt-native-location-phase-rng`` ``phase=seed``
    record carries the canonical seed value (``LOCATION_PHASE_RNG_SEED_VALUE``).
    Raises ``ArtifactError`` with an actual-vs-expected diagnostic if the seed
    record is missing, not unique, structurally drifted, or its value disagrees
    with the pinned seed -- the regression where a capture passes the
    caller_rva gate while emitting the wrong seed.
    """

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if (record.get("protocol") == "miel-vliegt-native-location-phase-rng"
                and record.get("phase") == "seed"):
            records.append(record)
    if not records:
        raise ArtifactError(
            "location-phase RNG seed record missing: observer log has no "
            "miel-vliegt-native-location-phase-rng phase=seed record"
        )
    if len(records) > 1:
        raise ArtifactError(
            "location-phase RNG seed record is not unique: found "
            f"{len(records)} phase=seed records"
        )
    seed = _strict(records[0], {
        "schema", "protocol", "sequence", "phase", "ordinal", "value",
        "caller_rva", "count", "sha256", "thread_id",
    }, "location-phase RNG seed record")
    if seed["schema"] != 1:
        raise ArtifactError(
            "location-phase RNG seed record schema drifted: expected 1, "
            f"got {seed['schema']!r}"
        )
    value = _integer(
        seed["value"], "location-phase RNG seed value", 0, UINT32_MAX,
    )
    if value != LOCATION_PHASE_RNG_SEED_VALUE:
        raise ArtifactError(
            "location-phase RNG seed value drifted: expected "
            f"{LOCATION_PHASE_RNG_SEED_VALUE}, got {value}"
        )
    return seed


def extract_flight_activation_rng(observer_log: Path) -> dict[str, Any]:
    """Validate the pre-SESSION_ARMED activation RNG transcript and digest."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-flight-activation-rng":
            records.append(record)
    if not records or records[-1].get("phase") != "complete":
        raise ArtifactError("flight activation RNG transcript is incomplete")
    draws = []
    digest = hashlib.sha256()
    for index, record in enumerate(records[:-1]):
        record = _strict(record, {
            "schema", "protocol", "sequence", "phase", "ordinal", "value",
            "caller_rva", "thread_id",
        }, f"flight activation RNG draw {index}")
        caller = record["caller_rva"]
        if record["schema"] != 1 or record["phase"] != "draw" \
                or record["ordinal"] != index \
                or not isinstance(caller, str) \
                or re.fullmatch(r"0x[0-9a-f]{8}", caller) is None:
            raise ArtifactError("flight activation RNG draw contract drifted")
        value = _integer(record["value"], f"flight activation RNG draw {index}.value", 0, UINT32_MAX)
        caller_value = int(caller, 16)
        digest.update(struct.pack("<III", index, value, caller_value))
        draws.append({"ordinal": index, "value": value, "caller_rva": caller})
    complete = _strict(records[-1], {
        "schema", "protocol", "sequence", "phase", "count", "sha256", "thread_id",
    }, "flight activation RNG completion")
    if complete["count"] != len(draws) \
            or complete["sha256"] != digest.hexdigest():
        raise ArtifactError("flight activation RNG completion digest drifted")
    return {"count": len(draws), "sha256": digest.hexdigest(), "draws": draws}


def extract_flight_activation_clock(observer_log: Path) -> dict[str, Any]:
    """Validate the activation-to-ARMED scripted manager-clock transcript."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-flight-activation-clock":
            records.append(record)
    if not records or records[-1].get("phase") != "complete":
        raise ArtifactError("flight activation clock transcript is incomplete")
    digest = hashlib.sha256()
    ticks = []
    for index, record in enumerate(records[:-1]):
        record = _strict(record, {
            "schema", "protocol", "sequence", "phase", "ordinal",
            "observed_dt_f32_bits", "scripted_dt_f32_bits", "thread_id",
        }, f"flight activation clock tick {index}")
        if record["schema"] != 1 or record["phase"] != "tick" \
                or record["ordinal"] != index:
            raise ArtifactError("flight activation clock tick contract drifted")
        _f32(record["observed_dt_f32_bits"], "flight activation observed dt")
        scripted = _f32(
            record["scripted_dt_f32_bits"], "flight activation scripted dt",
        )
        scripted_value = int(scripted, 16)
        digest.update(struct.pack("<II", index, scripted_value))
        ticks.append({"ordinal": index, "scripted_dt_f32_bits": scripted})
    complete = _strict(records[-1], {
        "schema", "protocol", "sequence", "phase", "count", "sha256", "thread_id",
    }, "flight activation clock completion")
    if complete["count"] != len(ticks) \
            or complete["sha256"] != digest.hexdigest():
        raise ArtifactError("flight activation clock completion digest drifted")
    return {"count": len(ticks), "sha256": digest.hexdigest(), "ticks": ticks}


def extract_focus_timeline_receipt(
    observer_log: Path, scenario: Mapping[str, Any], *, root: Path,
) -> dict[str, Any]:
    """Independently validate the observer's dual-clock focus chronology."""

    scenario = validate_scenario(scenario, root=root)
    expected_events = _focus_timeline(scenario)
    expected_scenario_sha256 = canonical_sha256(scenario)
    expected_timeline_sha256 = _focus_timeline_sha256(expected_events)
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(),
        1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-focus-timeline":
            rows.append(record)
    if not expected_events:
        if rows:
            raise ArtifactError("focus timeline emitted events for a focus-free scenario")
        receipt = {
            "clock": "query_performance_counter",
            "origin": "episode-focus-loss",
            "scenario_sha256": expected_scenario_sha256,
            "timeline_sha256": expected_timeline_sha256,
            "event_count": 0,
            "events": [],
        }
        return {**receipt, "sha256": canonical_sha256(receipt)}

    by_episode: dict[int, list[Mapping[str, int | bool]]] = {}
    for event in expected_events:
        by_episode.setdefault(int(event["episode"]), []).append(event)
    expected_rows: list[tuple[str, int, Mapping[str, int | bool] | None]] = []
    for episode, events in by_episode.items():
        expected_rows.append(("start", episode, None))
        expected_rows.extend(("event", episode, event) for event in events)
        expected_rows.append(("complete", episode, None))
    if len(rows) != len(expected_rows):
        raise ArtifactError("focus timeline receipt is incomplete or duplicated")

    thread_id: int | None = None
    applied_events: list[dict[str, Any]] = []
    common_fields = {
        "schema", "protocol", "sequence", "phase", "scenario",
        "scenario_sha256", "timeline_sha256", "clock", "origin",
        "thread_id",
    }
    for index, (record, expected) in enumerate(
        zip(rows, expected_rows, strict=True),
    ):
        phase, episode, expected_event = expected
        phase_fields = (
            {"episode", "event_count"} if phase != "event" else {
                "ordinal", "episode", "tick", "active",
                "scheduled_offset_ns", "applied_offset_ns", "lateness_ns",
            }
        )
        record = _strict(
            record, common_fields | phase_fields,
            f"focus timeline receipt {index}",
        )
        actual_thread = _integer(
            record["thread_id"], f"focus timeline receipt {index}.thread_id",
            1, UINT32_MAX,
        )
        if thread_id is None:
            thread_id = actual_thread
        if record["schema"] != 1 \
                or record["protocol"] != "miel-vliegt-native-focus-timeline" \
                or record["phase"] != phase \
                or record["scenario"] != scenario["id"] \
                or record["scenario_sha256"] != expected_scenario_sha256 \
                or record["timeline_sha256"] != expected_timeline_sha256 \
                or record["clock"] != "query_performance_counter" \
                or record["origin"] != "episode-focus-loss" \
                or actual_thread != thread_id \
                or _integer(record["episode"], "focus timeline episode") != episode:
            raise ArtifactError("focus timeline receipt identity or order drifted")
        _integer(record["sequence"], f"focus timeline receipt {index}.sequence")
        if phase != "event":
            if record["event_count"] != len(expected_events):
                raise ArtifactError("focus timeline receipt event count drifted")
            continue
        assert expected_event is not None
        ordinal = _integer(record["ordinal"], "focus timeline ordinal")
        tick = _integer(record["tick"], "focus timeline tick")
        active = _boolean(record["active"], "focus timeline active")
        scheduled = _integer(
            record["scheduled_offset_ns"], "focus timeline scheduled offset",
            0, UINT64_MAX,
        )
        applied = _integer(
            record["applied_offset_ns"], "focus timeline applied offset",
            0, UINT64_MAX,
        )
        lateness = _integer(
            record["lateness_ns"], "focus timeline lateness",
            0, UINT64_MAX,
        )
        if ordinal != expected_event["ordinal"] \
                or tick != expected_event["tick"] \
                or active is not expected_event["active"] \
                or scheduled != expected_event["offset_ns"] \
                or applied < scheduled \
                or lateness != applied - scheduled \
                or (not active and (scheduled != 0 or applied != 0)) \
                or lateness > FOCUS_TIMELINE_LATE_LIMIT_NS:
            raise ArtifactError("focus timeline event chronology drifted")
        applied_events.append({
            "ordinal": ordinal,
            "episode": episode,
            "tick": tick,
            "active": active,
            "scheduled_offset_ns": scheduled,
            "applied_offset_ns": applied,
            "lateness_ns": lateness,
        })
    receipt = {
        "clock": "query_performance_counter",
        "origin": "episode-focus-loss",
        "scenario_sha256": expected_scenario_sha256,
        "timeline_sha256": expected_timeline_sha256,
        "event_count": len(expected_events),
        "events": applied_events,
    }
    return {**receipt, "sha256": canonical_sha256(receipt)}


def extract_particle_lifecycle(observer_log: Path) -> dict[str, Any]:
    """Validate the read-only, pointer-free flight particle transcript."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-particle-lifecycle":
            records.append(record)
    canonical = []
    active_calls: dict[int, dict[str, set[int] | int]] = {}
    active_resets: dict[int, set[str]] = {}
    for index, record in enumerate(records):
        phase = record.get("phase")
        common = {
            "schema", "protocol", "sequence", "phase", "tick", "type",
            "ordinal", "flag_38", "flag_50", "f32", "thread_id",
        }
        if phase in {"TICK_BEFORE", "TICK_AFTER"}:
            ordinal = _integer(record.get("ordinal"), f"particle row {index}.ordinal", 0)
            expected = common | {
                "call_id", "dt_f32_bits", "render_present", "render_f32",
            }
            if ordinal == 0:
                expected |= {
                    "child_count", "child_array_present", "source_present",
                    "phase_f32_bits", "source_f32_bits", "audio_f32_bits",
                    "position_f32",
                }
            row = _strict(record, expected, f"particle tick row {index}")
            call_id = _integer(row["call_id"], f"particle row {index}.call_id", 0)
            dt = _positive_finite_f32(
                row["dt_f32_bits"], f"particle row {index}.dt_f32_bits",
            )
            state = active_calls.setdefault(call_id, {
                "child_count": -1, "TICK_BEFORE": set(), "TICK_AFTER": set(),
            })
            if ordinal == 0:
                child_count = _integer(
                    row["child_count"], f"particle row {index}.child_count", 0, 64,
                )
                if state["child_count"] not in {-1, child_count}:
                    raise ArtifactError("particle child count changed within one tick call")
                state["child_count"] = child_count
                if not isinstance(row["child_array_present"], bool) \
                        or not isinstance(row["source_present"], bool) \
                        or (child_count != 0 and row["child_array_present"] is not True):
                    raise ArtifactError("particle emitter presence contract drifted")
                for name in ("phase_f32_bits", "source_f32_bits", "audio_f32_bits"):
                    _f32(row[name], f"particle row {index}.{name}")
                position = row["position_f32"]
                if not isinstance(position, list) or len(position) != 3:
                    raise ArtifactError("particle emitter-position scalar count drifted")
                for scalar in position:
                    _f32(scalar, f"particle row {index}.position_f32")
            phase_ordinals = state[phase]
            assert isinstance(phase_ordinals, set)
            if ordinal in phase_ordinals:
                raise ArtifactError("particle ordinal repeated within one phase")
            phase_ordinals.add(ordinal)
        elif phase in {"RESET_BEFORE", "RESET_AFTER"}:
            row = _strict(
                record, common | {"reset_id", "caller_site"},
                f"particle reset row {index}",
            )
            reset_id = _integer(row["reset_id"], f"particle row {index}.reset_id", 0)
            caller = row["caller_site"]
            if not isinstance(caller, str) \
                    or re.fullmatch(r"0x[0-9a-f]{8}", caller) is None:
                raise ArtifactError("particle reset caller site drifted")
            reset_phases = active_resets.setdefault(reset_id, set())
            if phase in reset_phases:
                raise ArtifactError("particle reset phase repeated")
            reset_phases.add(phase)
            dt = None
        else:
            raise ArtifactError("particle lifecycle phase drifted")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-particle-lifecycle" \
                or row["sequence"] != index \
                or row["type"] not in {"flight-emitter", "flight-particle"}:
            raise ArtifactError("particle lifecycle identity or sequence drifted")
        _integer(row["tick"], f"particle row {index}.tick", 0)
        _integer(row["ordinal"], f"particle row {index}.ordinal", 0, 64)
        _integer(row["flag_38"], f"particle row {index}.flag_38", 0, 255)
        _integer(row["flag_50"], f"particle row {index}.flag_50", 0, 255)
        _integer(row["thread_id"], f"particle row {index}.thread_id", 1)
        scalars = row["f32"]
        if not isinstance(scalars, list) or len(scalars) != 17:
            raise ArtifactError("particle base scalar count drifted")
        for scalar in scalars:
            _f32(scalar, f"particle row {index}.f32")
        if phase in {"TICK_BEFORE", "TICK_AFTER"}:
            if not isinstance(row["render_present"], bool):
                raise ArtifactError("particle render presence drifted")
            render_scalars = row["render_f32"]
            if not isinstance(render_scalars, list) or len(render_scalars) != 15:
                raise ArtifactError("particle render scalar count drifted")
            for scalar in render_scalars:
                _f32(scalar, f"particle row {index}.render_f32")
            if not row["render_present"] \
                    and any(value != "0x00000000" for value in render_scalars):
                raise ArtifactError("absent particle render state is not canonical")
        canonical_row = {
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        }
        # Native Particle::tick guards target_position (+0x2c..+0x34) with
        # flag_38.  The constructor and reset deliberately leave those bytes
        # untouched while the flag is clear, so hashing them would promote
        # semantically dead heap residue into a false repeatability failure.
        if row["flag_38"] == 0:
            canonical_row["f32"] = list(canonical_row["f32"])
            for scalar_index in (9, 10, 11):
                canonical_row["f32"][scalar_index] = "0x00000000"
        # ParticleEmitter construction invokes the Particle base constructor,
        # which never defines +0x54; the emitter constructor also never writes
        # it.  Child particles receive a configured value, so this mask is
        # deliberately type-specific and the observable flag_50 result stays
        # in the transcript.
        if row["type"] == "flight-emitter":
            canonical_row["f32"] = list(canonical_row["f32"])
            canonical_row["f32"][16] = "0x00000000"
        canonical.append(canonical_row)
    for call_id, state in active_calls.items():
        child_count = state["child_count"]
        if not isinstance(child_count, int) or child_count < 0:
            raise ArtifactError(f"particle emitter row missing for call {call_id}")
        expected_ordinals = set(range(child_count + 1))
        if state["TICK_BEFORE"] != expected_ordinals \
                or state["TICK_AFTER"] != expected_ordinals:
            raise ArtifactError(f"particle tick pair incomplete for call {call_id}")
    if any(phases != {"RESET_BEFORE", "RESET_AFTER"}
           for phases in active_resets.values()):
        raise ArtifactError("particle reset pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_particle_activation_lifecycle(observer_log: Path) -> dict[str, Any]:
    """Validate the pre-READY particle placement/reset/update diagnostic epoch."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-particle-activation":
            records.append(record)
    canonical = []
    active_events: dict[tuple[str, int], dict[str, set[int] | int]] = {}
    active_resets: dict[int, set[str]] = {}
    for index, record in enumerate(records):
        phase = record.get("phase")
        common = {
            "schema", "protocol", "sequence", "phase", "manager_tick",
            "event_id", "caller_site", "type", "ordinal", "flag_38",
            "flag_50", "f32", "thread_id",
        }
        if phase in {
            "PLACE_BEFORE", "PLACE_AFTER", "TICK_BEFORE", "TICK_AFTER",
        }:
            ordinal = _integer(
                record.get("ordinal"), f"particle activation row {index}.ordinal",
                0, 64,
            )
            expected = common | {
                "dt_f32_bits", "input_present", "input_f32",
            }
            if ordinal == 0:
                expected |= {"child_count", "position_f32"}
            row = _strict(
                record, expected, f"particle activation event row {index}",
            )
            event_id = _integer(
                row["event_id"], f"particle activation row {index}.event_id", 0,
            )
            operation = phase.split("_", 1)[0]
            state = active_events.setdefault((operation, event_id), {
                "child_count": -1,
                f"{operation}_BEFORE": set(),
                f"{operation}_AFTER": set(),
            })
            if ordinal == 0:
                child_count = _integer(
                    row["child_count"],
                    f"particle activation row {index}.child_count", 0, 64,
                )
                if state["child_count"] not in {-1, child_count}:
                    raise ArtifactError(
                        "particle activation child count changed within event"
                    )
                state["child_count"] = child_count
                position = row["position_f32"]
                if not isinstance(position, list) or len(position) != 3:
                    raise ArtifactError(
                        "particle activation emitter position count drifted"
                    )
                for scalar in position:
                    _f32(scalar, f"particle activation row {index}.position_f32")
            ordinals = state[phase]
            assert isinstance(ordinals, set)
            if ordinal in ordinals:
                raise ArtifactError("particle activation ordinal repeated")
            ordinals.add(ordinal)
            _f32(row["dt_f32_bits"], f"particle activation row {index}.dt")
            input_values = row["input_f32"]
            if not isinstance(input_values, list) or len(input_values) != 3:
                raise ArtifactError("particle activation input vector count drifted")
            for scalar in input_values:
                _f32(scalar, f"particle activation row {index}.input_f32")
            if not isinstance(row["input_present"], bool) \
                    or (operation == "PLACE") != row["input_present"]:
                raise ArtifactError("particle activation input presence drifted")
        elif phase in {"RESET_BEFORE", "RESET_AFTER"}:
            row = _strict(
                record, common, f"particle activation reset row {index}",
            )
            reset_id = _integer(
                row["event_id"], f"particle activation row {index}.event_id", 0,
            )
            reset_phases = active_resets.setdefault(reset_id, set())
            if phase in reset_phases:
                raise ArtifactError("particle activation reset phase repeated")
            reset_phases.add(phase)
        else:
            raise ArtifactError("particle activation phase drifted")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-particle-activation" \
                or row["sequence"] != index \
                or row["type"] not in {"flight-emitter", "flight-particle"}:
            raise ArtifactError("particle activation identity or sequence drifted")
        _integer(row["manager_tick"], f"particle activation row {index}.manager_tick", 0)
        caller = row["caller_site"]
        if not isinstance(caller, str) \
                or re.fullmatch(r"0x[0-9a-f]{8}", caller) is None:
            raise ArtifactError("particle activation caller site drifted")
        _integer(row["flag_38"], f"particle activation row {index}.flag_38", 0, 255)
        _integer(row["flag_50"], f"particle activation row {index}.flag_50", 0, 255)
        _integer(row["thread_id"], f"particle activation row {index}.thread_id", 1)
        scalars = row["f32"]
        if not isinstance(scalars, list) or len(scalars) != 17:
            raise ArtifactError("particle activation base scalar count drifted")
        for scalar in scalars:
            _f32(scalar, f"particle activation row {index}.f32")
        canonical_row = {
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        }
        if row["flag_38"] == 0:
            canonical_row["f32"] = list(canonical_row["f32"])
            for scalar_index in (9, 10, 11):
                canonical_row["f32"][scalar_index] = "0x00000000"
        if row["type"] == "flight-emitter":
            canonical_row["f32"] = list(canonical_row["f32"])
            canonical_row["f32"][16] = "0x00000000"
        canonical.append(canonical_row)
    for (operation, event_id), state in active_events.items():
        child_count = state["child_count"]
        if not isinstance(child_count, int) or child_count < 0:
            raise ArtifactError(
                f"particle activation emitter row missing for {operation} {event_id}"
            )
        expected_ordinals = set(range(child_count + 1))
        if state[f"{operation}_BEFORE"] != expected_ordinals \
                or state[f"{operation}_AFTER"] != expected_ordinals:
            raise ArtifactError(
                f"particle activation pair incomplete for {operation} {event_id}"
            )
    if any(phases != {"RESET_BEFORE", "RESET_AFTER"}
           for phases in active_resets.values()):
        raise ArtifactError("particle activation reset pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_render_presentation(observer_log: Path) -> dict[str, Any]:
    """Validate pointer-free render-list and airplane presentation snapshots."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-render-presentation":
            records.append(record)
    if not records:
        raise ArtifactError("render presentation diagnostic is missing")

    def static_identity(value: Any, label: str) -> str:
        if not isinstance(value, str) or STATIC_IDENTITY.fullmatch(value) is None:
            raise ArtifactError(f"{label} must be a module-relative identity")
        return value

    def f32_vector(value: Any, length: int, label: str) -> list[str]:
        if not isinstance(value, list) or len(value) != length:
            raise ArtifactError(f"{label} scalar count drifted")
        for scalar in value:
            _f32(scalar, label)
        return value

    def track(value: Any, label: str, *, scalar_count: int,
              includes_flag: bool) -> dict[str, Any]:
        keys = {"present", "f32"}
        if includes_flag:
            keys.add("flag_6d")
        row = _strict(value, keys, label)
        if not isinstance(row["present"], bool):
            raise ArtifactError(f"{label}.present must be boolean")
        if includes_flag:
            _integer(row["flag_6d"], f"{label}.flag_6d", 0, 255)
        f32_vector(row["f32"], scalar_count, f"{label}.f32")
        if not row["present"] and (
            (includes_flag and row["flag_6d"] != 0)
            or any(scalar != "0x00000000" for scalar in row["f32"])
        ):
            raise ArtifactError(f"{label} absent state is not canonical")
        return row

    common = {
        "schema", "protocol", "sequence", "kind", "phase", "tick",
        "manager_render", "call_id", "thread_id",
    }
    list_calls: dict[int, dict[str, set[int] | int]] = {}
    airplane_calls: dict[int, set[str]] = {}
    canonical = []
    for index, record in enumerate(records):
        if record.get("kind") == "render-list":
            row = _strict(record, common | {
                "node_count", "ordinal", "dt_f32_bits", "position_f32",
                "vtable", "visible_method", "prepare_method",
                "phase_method", "draw_method",
            }, f"render-list row {index}")
            phase = row["phase"]
            if phase not in {"BEFORE", "AFTER"}:
                raise ArtifactError("render-list phase drifted")
            call_id = _integer(row["call_id"], f"render-list row {index}.call_id")
            node_count = _integer(
                row["node_count"], f"render-list row {index}.node_count", 1, 128,
            )
            ordinal = _integer(
                row["ordinal"], f"render-list row {index}.ordinal",
                0, node_count - 1,
            )
            state = list_calls.setdefault(call_id, {
                "node_count": node_count, "BEFORE": set(), "AFTER": set(),
            })
            if state["node_count"] != node_count:
                raise ArtifactError("render-list node count changed within call")
            ordinals = state[phase]
            assert isinstance(ordinals, set)
            if ordinal in ordinals:
                raise ArtifactError("render-list ordinal repeated within phase")
            ordinals.add(ordinal)
            _f32(row["dt_f32_bits"], f"render-list row {index}.dt")
            f32_vector(row["position_f32"], 3, f"render-list row {index}.position")
            for field in (
                "vtable", "visible_method", "prepare_method",
                "phase_method", "draw_method",
            ):
                static_identity(row[field], f"render-list row {index}.{field}")
        elif record.get("kind") == "airplane":
            row = _strict(record, common | {
                "owner_vtable", "source_present", "world_present",
                "anchor_f32", "track_a", "track_b",
            }, f"airplane presentation row {index}")
            phase = row["phase"]
            if phase not in {"BEFORE", "AFTER"}:
                raise ArtifactError("airplane presentation phase drifted")
            call_id = _integer(
                row["call_id"], f"airplane presentation row {index}.call_id",
            )
            phases = airplane_calls.setdefault(call_id, set())
            if phase in phases:
                raise ArtifactError("airplane presentation phase repeated")
            phases.add(phase)
            static_identity(
                row["owner_vtable"],
                f"airplane presentation row {index}.owner_vtable",
            )
            if not isinstance(row["source_present"], bool) \
                    or not isinstance(row["world_present"], bool):
                raise ArtifactError("airplane presentation presence drifted")
            f32_vector(row["anchor_f32"], 3, f"airplane row {index}.anchor")
            track(
                row["track_a"], f"airplane row {index}.track_a",
                scalar_count=6, includes_flag=False,
            )
            track(
                row["track_b"], f"airplane row {index}.track_b",
                scalar_count=7, includes_flag=True,
            )
        else:
            raise ArtifactError("render presentation kind drifted")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-render-presentation" \
                or row["sequence"] != index:
            raise ArtifactError("render presentation identity or sequence drifted")
        _integer(row["tick"], f"render presentation row {index}.tick")
        _integer(
            row["manager_render"],
            f"render presentation row {index}.manager_render",
        )
        _integer(row["thread_id"], f"render presentation row {index}.thread_id", 1)
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    for call_id, state in list_calls.items():
        node_count = state["node_count"]
        assert isinstance(node_count, int)
        expected = set(range(node_count))
        if state["BEFORE"] != expected or state["AFTER"] != expected:
            raise ArtifactError(f"render-list pair incomplete for call {call_id}")
    if any(phases != {"BEFORE", "AFTER"}
           for phases in airplane_calls.values()):
        raise ArtifactError("airplane presentation pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_render(observer_log: Path) -> dict[str, Any]:
    """Validate CcShadow::Render call order and its direct scalar inputs."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-render":
            records.append(record)
    if not records:
        raise ArtifactError("shadow render diagnostic is missing")
    canonical = []
    calls: dict[int, set[str]] = {}
    for index, record in enumerate(records):
        row = _strict(record, {
            "schema", "protocol", "sequence", "phase", "tick",
            "manager_render", "parent_call_id", "call_id", "target_vtable",
            "surface_present", "resource_present", "room_present",
            "surface_active", "render_mode_f32_bits", "transform_f32",
            "mask_u16", "thread_id",
        }, f"shadow render row {index}")
        phase = row["phase"]
        if phase not in {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow render phase drifted")
        call_id = _integer(row["call_id"], f"shadow render row {index}.call_id")
        phases = calls.setdefault(call_id, set())
        if phase in phases:
            raise ArtifactError("shadow render phase repeated")
        phases.add(phase)
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-render" \
                or row["sequence"] != index:
            raise ArtifactError("shadow render identity or sequence drifted")
        _integer(row["tick"], f"shadow render row {index}.tick")
        _integer(
            row["manager_render"], f"shadow render row {index}.manager_render",
        )
        _integer(
            row["parent_call_id"], f"shadow render row {index}.parent_call_id",
        )
        _integer(
            row["surface_active"], f"shadow render row {index}.surface_active",
            0, 255,
        )
        _integer(row["thread_id"], f"shadow render row {index}.thread_id", 1)
        if not isinstance(row["target_vtable"], str) \
                or STATIC_IDENTITY.fullmatch(row["target_vtable"]) is None:
            raise ArtifactError("shadow render target identity drifted")
        for field in ("surface_present", "resource_present", "room_present"):
            if not isinstance(row[field], bool):
                raise ArtifactError(f"shadow render {field} must be boolean")
        _f32(row["render_mode_f32_bits"], f"shadow render row {index}.mode")
        transforms = row["transform_f32"]
        if not isinstance(transforms, list) or len(transforms) != 6:
            raise ArtifactError("shadow render transform scalar count drifted")
        for scalar in transforms:
            _f32(scalar, f"shadow render row {index}.transform")
        masks = row["mask_u16"]
        if not isinstance(masks, list) or len(masks) != 17 \
                or any(not isinstance(mask, str) or U16_BITS.fullmatch(mask) is None
                       for mask in masks):
            raise ArtifactError("shadow render mask scalar count or encoding drifted")
        if not row["surface_present"] and (
            row["surface_active"] != 0
            or any(mask != "0x0000" for mask in masks)
        ):
            raise ArtifactError("absent shadow surface is not canonical")
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    if any(phases != {"BEFORE", "AFTER"} for phases in calls.values()):
        raise ArtifactError("shadow render pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_camera_render(observer_log: Path) -> dict[str, Any]:
    """Validate the nested CcCamera::Render call used by CcShadow::Render."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-camera-render":
            records.append(record)
    if not records:
        raise ArtifactError("shadow camera render diagnostic is missing")

    canonical = []
    calls: dict[int, dict[str, Any]] = {}
    for index, record in enumerate(records):
        row = _strict(record, {
            "schema", "protocol", "sequence", "phase", "tick",
            "manager_render", "parent_shadow_call_id", "call_id",
            "render_shadow", "camera_vtable", "gate_968", "gate_969",
            "room_present", "device_present", "clip_present",
            "scratch_present", "render_flags_u8", "projection_f32",
            "transform_f32", "saved_transform_f32", "thread_id",
        }, f"shadow camera render row {index}")
        phase = row["phase"]
        if phase not in {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow camera render phase drifted")
        call_id = _integer(
            row["call_id"], f"shadow camera render row {index}.call_id",
        )
        parent_call_id = _integer(
            row["parent_shadow_call_id"],
            f"shadow camera render row {index}.parent_shadow_call_id",
        )
        state = calls.setdefault(call_id, {
            "parent_shadow_call_id": parent_call_id, "phases": set(),
        })
        if state["parent_shadow_call_id"] != parent_call_id:
            raise ArtifactError("shadow camera parent changed within call")
        if phase in state["phases"]:
            raise ArtifactError("shadow camera render phase repeated")
        state["phases"].add(phase)
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-camera-render" \
                or row["sequence"] != index:
            raise ArtifactError("shadow camera render identity or sequence drifted")
        _integer(row["tick"], f"shadow camera render row {index}.tick")
        _integer(
            row["manager_render"],
            f"shadow camera render row {index}.manager_render",
        )
        _integer(row["thread_id"], f"shadow camera row {index}.thread_id", 1)
        if not isinstance(row["render_shadow"], bool):
            raise ArtifactError("shadow camera render argument must be boolean")
        if not isinstance(row["camera_vtable"], str) \
                or STATIC_IDENTITY.fullmatch(row["camera_vtable"]) is None:
            raise ArtifactError("shadow camera vtable identity drifted")
        for field in ("gate_968", "gate_969"):
            _integer(row[field], f"shadow camera row {index}.{field}", 0, 255)
        for field in (
            "room_present", "device_present", "clip_present", "scratch_present",
        ):
            if not isinstance(row[field], bool):
                raise ArtifactError(f"shadow camera {field} must be boolean")
        flags = row["render_flags_u8"]
        if not isinstance(flags, list) or len(flags) != 4:
            raise ArtifactError("shadow camera render flag count drifted")
        for flag in flags:
            _integer(flag, "shadow camera render flag", 0, 255)
        for field, length in (
            ("projection_f32", 17),
            ("transform_f32", 14),
            ("saved_transform_f32", 14),
        ):
            values = row[field]
            if not isinstance(values, list) or len(values) != length:
                raise ArtifactError(f"shadow camera {field} scalar count drifted")
            for value in values:
                _f32(value, f"shadow camera row {index}.{field}")
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    if any(state["phases"] != {"BEFORE", "AFTER"}
           for state in calls.values()):
        raise ArtifactError("shadow camera render pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_render_room(observer_log: Path) -> dict[str, Any]:
    """Validate the RenderRoom boundary nested below the shadow camera."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-render-room":
            records.append(record)
    if not records:
        raise ArtifactError("shadow RenderRoom diagnostic is missing")

    canonical = []
    calls: dict[int, dict[str, Any]] = {}
    for index, record in enumerate(records):
        row = _strict(record, {
            "schema", "protocol", "sequence", "phase", "tick",
            "manager_render", "parent_camera_call_id", "call_id",
            "camera_vtable", "room_vtable", "clip_vtable",
            "collect_objects", "recursion_depth", "room_links", "clip_links",
            "camera_transient_present", "thread_id",
        }, f"shadow RenderRoom row {index}")
        phase = row["phase"]
        if phase not in {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow RenderRoom phase drifted")
        call_id = _integer(row["call_id"], f"shadow RenderRoom row {index}.call_id")
        parent_call_id = _integer(
            row["parent_camera_call_id"],
            f"shadow RenderRoom row {index}.parent_camera_call_id",
        )
        state = calls.setdefault(call_id, {
            "parent_camera_call_id": parent_call_id, "phases": set(),
        })
        if state["parent_camera_call_id"] != parent_call_id:
            raise ArtifactError("shadow RenderRoom parent changed within call")
        if phase in state["phases"]:
            raise ArtifactError("shadow RenderRoom phase repeated")
        state["phases"].add(phase)
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-render-room" \
                or row["sequence"] != index:
            raise ArtifactError("shadow RenderRoom identity or sequence drifted")
        _integer(row["tick"], f"shadow RenderRoom row {index}.tick")
        _integer(row["manager_render"], f"shadow RenderRoom row {index}.render")
        _integer(row["thread_id"], f"shadow RenderRoom row {index}.thread", 1)
        for field in ("collect_objects", "recursion_depth"):
            _integer(row[field], f"shadow RenderRoom row {index}.{field}")
        for field in ("camera_vtable", "room_vtable", "clip_vtable"):
            if not isinstance(row[field], str) \
                    or STATIC_IDENTITY.fullmatch(row[field]) is None:
                raise ArtifactError(f"shadow RenderRoom {field} drifted")
        for field, length in (("room_links", 5), ("clip_links", 2)):
            links = row[field]
            if not isinstance(links, list) or len(links) != length \
                    or any(not isinstance(value, bool) for value in links):
                raise ArtifactError(f"shadow RenderRoom {field} drifted")
        if not isinstance(row["camera_transient_present"], bool):
            raise ArtifactError("shadow RenderRoom camera transient drifted")
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    if any(state["phases"] != {"BEFORE", "AFTER"}
           for state in calls.values()):
        raise ArtifactError("shadow RenderRoom pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_visible_objects(observer_log: Path) -> dict[str, Any]:
    """Validate ordered visible-object selection beneath shadow RenderRoom."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-visible-objects":
            records.append(record)
    if not records:
        raise ArtifactError("shadow visible-object diagnostic is missing")

    common = {
        "schema", "protocol", "sequence", "kind", "phase", "tick",
        "manager_render", "parent_room_call_id", "call_id", "thread_id",
    }
    canonical = []
    calls: dict[int, dict[str, Any]] = {}
    for index, record in enumerate(records):
        kind = record.get("kind")
        if kind == "call":
            row = _strict(record, common | {
                "room_vtable", "camera_vtable", "chain_count",
                "render_list_present",
            }, f"shadow visible-object call row {index}")
        elif kind == "object":
            row = _strict(record, common | {
                "ordinal", "chain_count", "object_vtable", "flags_u8",
                "geometry_present", "relation_matches_camera", "mode_u32",
                "child_count", "children_array_present", "render_link_present",
                "geometry_extent_f32", "derived_f32", "transform_f32",
            }, f"shadow visible-object row {index}")
        else:
            raise ArtifactError("shadow visible-object kind drifted")
        phase = row["phase"]
        if phase not in {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow visible-object phase drifted")
        call_id = _integer(
            row["call_id"], f"shadow visible-object row {index}.call_id",
        )
        parent = _integer(
            row["parent_room_call_id"],
            f"shadow visible-object row {index}.parent_room_call_id",
        )
        chain_count = _integer(
            row["chain_count"], f"shadow visible-object row {index}.chain_count",
            0, 128,
        )
        state = calls.setdefault(call_id, {
            "parent": parent,
            "chain_count": {"BEFORE": None, "AFTER": None},
            "calls": set(),
            "objects": {"BEFORE": set(), "AFTER": set()},
        })
        if state["parent"] != parent:
            raise ArtifactError("shadow visible-object parent changed within call")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-visible-objects" \
                or row["sequence"] != index:
            raise ArtifactError("shadow visible-object identity or sequence drifted")
        _integer(row["tick"], f"shadow visible-object row {index}.tick")
        _integer(row["manager_render"], f"shadow visible-object row {index}.render")
        _integer(row["thread_id"], f"shadow visible-object row {index}.thread", 1)
        if kind == "call":
            if phase in state["calls"]:
                raise ArtifactError("shadow visible-object call phase repeated")
            state["calls"].add(phase)
            state["chain_count"][phase] = chain_count
            for field in ("room_vtable", "camera_vtable"):
                if not isinstance(row[field], str) \
                        or STATIC_IDENTITY.fullmatch(row[field]) is None:
                    raise ArtifactError(f"shadow visible-object {field} drifted")
            presence = row["render_list_present"]
            if not isinstance(presence, list) or len(presence) != 11 \
                    or any(not isinstance(value, bool) for value in presence):
                raise ArtifactError("shadow visible-object render list drifted")
        else:
            ordinal = _integer(
                row["ordinal"], f"shadow visible-object row {index}.ordinal",
                0, max(chain_count - 1, 0),
            )
            if chain_count == 0 or ordinal in state["objects"][phase]:
                raise ArtifactError("shadow visible-object ordinal drifted")
            state["objects"][phase].add(ordinal)
            if not isinstance(row["object_vtable"], str) \
                    or STATIC_IDENTITY.fullmatch(row["object_vtable"]) is None:
                raise ArtifactError("shadow visible-object vtable drifted")
            flags = row["flags_u8"]
            if not isinstance(flags, list) or len(flags) != 6:
                raise ArtifactError("shadow visible-object flag count drifted")
            for flag in flags:
                _integer(flag, "shadow visible-object flag", 0, 255)
            for field in (
                "geometry_present", "relation_matches_camera",
                "children_array_present", "render_link_present",
            ):
                if not isinstance(row[field], bool):
                    raise ArtifactError(f"shadow visible-object {field} drifted")
            _integer(row["mode_u32"], "shadow visible-object mode")
            _integer(
                row["child_count"], "shadow visible-object child count", 0, 65535,
            )
            _f32(row["geometry_extent_f32"], "shadow geometry extent")
            for field, length in (("derived_f32", 7), ("transform_f32", 14)):
                values = row[field]
                if not isinstance(values, list) or len(values) != length:
                    raise ArtifactError(f"shadow visible-object {field} drifted")
                for value in values:
                    _f32(value, f"shadow visible-object {field}")
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    for state in calls.values():
        if state["calls"] != {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow visible-object call pair is incomplete")
        for phase in ("BEFORE", "AFTER"):
            count = state["chain_count"][phase]
            if count is None or state["objects"][phase] != set(range(count)):
                raise ArtifactError("shadow visible-object rows are incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_visible_polygons(observer_log: Path) -> dict[str, Any]:
    """Validate object-to-polygon dispatch records beneath shadow RenderRoom."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-visible-polygons":
            records.append(record)
    if not records:
        raise ArtifactError("shadow visible-polygon diagnostic is missing")

    expected = {
        "schema", "protocol", "sequence", "phase", "tick", "manager_render",
        "parent_room_call_id", "call_id", "object_vtable", "camera_vtable",
        "outline_enabled", "object_outline_u8", "object_outline_f32",
        "camera_mirror_u8", "geometry_present", "topology_present",
        "polygon_count", "transform_f32", "render_list_present",
        "render_list_head_changed", "thread_id",
    }
    canonical = []
    calls: dict[int, dict[str, Any]] = {}
    for index, record in enumerate(records):
        row = _strict(record, expected, f"shadow visible-polygon row {index}")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-visible-polygons" \
                or row["sequence"] != index:
            raise ArtifactError("shadow visible-polygon identity or sequence drifted")
        phase = row["phase"]
        if phase not in {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow visible-polygon phase drifted")
        call_id = _integer(row["call_id"], f"shadow polygon row {index}.call_id")
        parent = _integer(
            row["parent_room_call_id"], f"shadow polygon row {index}.parent",
        )
        state = calls.setdefault(call_id, {"parent": parent, "phases": set()})
        if state["parent"] != parent or phase in state["phases"]:
            raise ArtifactError("shadow visible-polygon pairing drifted")
        state["phases"].add(phase)
        _integer(row["tick"], f"shadow polygon row {index}.tick")
        _integer(row["manager_render"], f"shadow polygon row {index}.render")
        _integer(row["thread_id"], f"shadow polygon row {index}.thread", 1)
        _integer(row["object_outline_u8"], "shadow polygon object outline", 0, 255)
        _integer(row["camera_mirror_u8"], "shadow polygon camera mirror", 0, 255)
        _integer(row["polygon_count"], "shadow polygon count", 0, 65535)
        for field in ("object_vtable", "camera_vtable"):
            if not isinstance(row[field], str) \
                    or STATIC_IDENTITY.fullmatch(row[field]) is None:
                raise ArtifactError(f"shadow visible-polygon {field} drifted")
        for field in (
            "outline_enabled", "geometry_present", "topology_present",
        ):
            if not isinstance(row[field], bool):
                raise ArtifactError(f"shadow visible-polygon {field} drifted")
        _f32(row["object_outline_f32"], "shadow polygon outline")
        transform = row["transform_f32"]
        if not isinstance(transform, list) or len(transform) != 14:
            raise ArtifactError("shadow visible-polygon transform drifted")
        for value in transform:
            _f32(value, "shadow visible-polygon transform")
        for field in ("render_list_present", "render_list_head_changed"):
            values = row[field]
            if not isinstance(values, list) or len(values) != 11 \
                    or any(not isinstance(value, bool) for value in values):
                raise ArtifactError(f"shadow visible-polygon {field} drifted")
        if phase == "BEFORE" and any(row["render_list_head_changed"]):
            raise ArtifactError("shadow visible-polygon BEFORE changed a render head")
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    if any(state["phases"] != {"BEFORE", "AFTER"} for state in calls.values()):
        raise ArtifactError("shadow visible-polygon pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_polygon_render(observer_log: Path) -> dict[str, Any]:
    """Validate actual CcObjPolygon draw-dispatch inputs beneath RenderRoom."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-polygon-render":
            records.append(record)
    if not records:
        raise ArtifactError("shadow polygon-render diagnostic is missing")

    expected = {
        "schema", "protocol", "sequence", "tick", "manager_render",
        "parent_room_call_id", "call_id", "polygon_vtable", "object_vtable",
        "camera_vtable", "material_type", "material_flags_u8", "material_f32",
        "mode_u32", "material_present", "camera_mirror_u8",
        "camera_projection_f32", "vertex_indices", "owner_transform_f32",
        "vertex_f32", "vertex_cache_u8", "thread_id",
    }
    canonical = []
    for index, record in enumerate(records):
        row = _strict(record, expected, f"shadow polygon-render row {index}")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-polygon-render" \
                or row["sequence"] != index \
                or row["call_id"] != index:
            raise ArtifactError("shadow polygon-render identity or sequence drifted")
        _integer(row["tick"], f"shadow polygon-render row {index}.tick")
        _integer(row["manager_render"], f"shadow polygon-render row {index}.render")
        _integer(row["parent_room_call_id"], f"shadow polygon-render row {index}.parent")
        _integer(row["mode_u32"], f"shadow polygon-render row {index}.mode")
        _integer(row["camera_mirror_u8"], "shadow polygon-render mirror", 0, 255)
        _integer(row["thread_id"], f"shadow polygon-render row {index}.thread", 1)
        for field in ("polygon_vtable", "object_vtable", "camera_vtable"):
            if not isinstance(row[field], str) \
                    or STATIC_IDENTITY.fullmatch(row[field]) is None:
                raise ArtifactError(f"shadow polygon-render {field} drifted")
        if not isinstance(row["material_present"], bool):
            raise ArtifactError("shadow polygon-render material presence drifted")
        if row["material_type"] not in {"none", "CcMaterial"} \
                or (row["material_type"] == "CcMaterial") \
                != row["material_present"]:
            raise ArtifactError("shadow polygon-render material type drifted")
        _integer(row["material_flags_u8"], "shadow polygon material flags", 0, 255)
        material = row["material_f32"]
        if not isinstance(material, list) or len(material) != 7:
            raise ArtifactError("shadow polygon-render material values drifted")
        for value in material:
            _f32(value, "shadow polygon-render material value")
        _f32(row["camera_projection_f32"], "shadow polygon-render projection")
        indices = row["vertex_indices"]
        if not isinstance(indices, list) or len(indices) != 3:
            raise ArtifactError("shadow polygon-render vertex indices drifted")
        for value in indices:
            _integer(value, "shadow polygon-render vertex index", 0, 65535)
        transform = row["owner_transform_f32"]
        if not isinstance(transform, list) or len(transform) != 14:
            raise ArtifactError("shadow polygon-render transform drifted")
        for value in transform:
            _f32(value, "shadow polygon-render transform")
        vertices = row["vertex_f32"]
        if not isinstance(vertices, list) or len(vertices) != 3 \
                or any(not isinstance(vertex, list) or len(vertex) != 4
                       for vertex in vertices):
            raise ArtifactError("shadow polygon-render vertex values drifted")
        for vertex in vertices:
            for value in vertex:
                _f32(value, "shadow polygon-render vertex")
        cache = row["vertex_cache_u8"]
        if not isinstance(cache, list) or len(cache) != 3:
            raise ArtifactError("shadow polygon-render vertex cache drifted")
        for value in cache:
            _integer(value, "shadow polygon-render vertex cache", 0, 255)
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_world_relation(observer_log: Path) -> dict[str, Any]:
    """Validate recursive CcSrtNode world-matrix writer observations."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-world-relation":
            records.append(record)
    if not records:
        raise ArtifactError("shadow world-relation diagnostic is missing")

    expected = {
        "schema", "protocol", "sequence", "phase", "tick", "manager_render",
        "parent_room_call_id", "parent_world_call_id", "call_id", "depth",
        "node_vtable", "parent_vtable", "geometry_vtable",
        "geometry_polygon_count", "geometry_extent_f32", "rotation_mode_u32",
        "cache_u32", "return_u8", "local_rotation_f32", "rotation_aux_f32",
        "world_transform_f32", "thread_id",
    }
    canonical = []
    calls: dict[int, dict[str, Any]] = {}
    for index, record in enumerate(records):
        row = _strict(record, expected, f"shadow world-relation row {index}")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-world-relation" \
                or row["sequence"] != index:
            raise ArtifactError("shadow world-relation identity or sequence drifted")
        phase = row["phase"]
        if phase not in {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow world-relation phase drifted")
        call_id = _integer(row["call_id"], f"shadow world row {index}.call")
        parent_call = _integer(
            row["parent_world_call_id"], f"shadow world row {index}.parent call",
        )
        depth = _integer(row["depth"], f"shadow world row {index}.depth", 0, 63)
        state = calls.setdefault(call_id, {
            "parent_call": parent_call, "depth": depth, "phases": set(),
        })
        if state["parent_call"] != parent_call or state["depth"] != depth \
                or phase in state["phases"]:
            raise ArtifactError("shadow world-relation pairing drifted")
        state["phases"].add(phase)
        _integer(row["tick"], f"shadow world row {index}.tick")
        _integer(row["manager_render"], f"shadow world row {index}.render")
        _integer(row["parent_room_call_id"], f"shadow world row {index}.room")
        _integer(row["thread_id"], f"shadow world row {index}.thread", 1)
        _integer(row["geometry_polygon_count"], "shadow world polygon count", 0, 65535)
        _integer(row["rotation_mode_u32"], "shadow world rotation mode", 0, 2)
        return_u8 = _integer(row["return_u8"], "shadow world return", 0, 255)
        if (phase == "BEFORE" and return_u8 != 255) \
                or (phase == "AFTER" and return_u8 not in {0, 1}):
            raise ArtifactError("shadow world-relation return sentinel drifted")
        for field in ("node_vtable", "parent_vtable", "geometry_vtable"):
            value = row[field]
            if value != "none" and (
                not isinstance(value, str) or STATIC_IDENTITY.fullmatch(value) is None
            ):
                raise ArtifactError(f"shadow world-relation {field} drifted")
        _f32(row["geometry_extent_f32"], "shadow world geometry extent")
        cache = row["cache_u32"]
        if not isinstance(cache, list) or len(cache) != 2:
            raise ArtifactError("shadow world-relation cache drifted")
        for value in cache:
            _integer(value, "shadow world cache")
        for field, length in (
            ("local_rotation_f32", 11),
            ("rotation_aux_f32", 9),
            ("world_transform_f32", 14),
        ):
            values = row[field]
            if not isinstance(values, list) or len(values) != length:
                raise ArtifactError(f"shadow world-relation {field} drifted")
            for value in values:
                _f32(value, f"shadow world-relation {field}")
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    if any(state["phases"] != {"BEFORE", "AFTER"} for state in calls.values()):
        raise ArtifactError("shadow world-relation pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def extract_shadow_rotation_setter(observer_log: Path) -> dict[str, Any]:
    """Validate paired in-place CcMatrixRot Z-axis writer observations."""

    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = _json_text(raw_line[4:], f"diagnostic line {line_number}")
        if record.get("protocol") == "miel-vliegt-native-shadow-rotation-setter":
            records.append(record)
    if not records:
        raise ArtifactError("shadow rotation-setter diagnostic is missing")

    expected = {
        "schema", "protocol", "sequence", "phase", "tick", "manager_render",
        "call_id", "caller", "angle_f32", "owner_vtable", "parent_vtable",
        "object_ordinal", "object_vtable", "geometry_vtable",
        "geometry_polygon_count", "geometry_extent_f32",
        "local_rotation_f32", "thread_id",
    }
    canonical = []
    calls: dict[int, dict[str, Any]] = {}
    stable_fields = (
        "tick", "manager_render", "caller", "angle_f32", "owner_vtable",
        "parent_vtable", "object_ordinal", "object_vtable", "geometry_vtable",
        "geometry_polygon_count", "geometry_extent_f32",
    )
    for index, record in enumerate(records):
        row = _strict(record, expected, f"shadow rotation-setter row {index}")
        if row["schema"] != 1 \
                or row["protocol"] != "miel-vliegt-native-shadow-rotation-setter" \
                or row["sequence"] != index:
            raise ArtifactError("shadow rotation-setter identity or sequence drifted")
        phase = row["phase"]
        if phase not in {"BEFORE", "AFTER"}:
            raise ArtifactError("shadow rotation-setter phase drifted")
        call_id = _integer(row["call_id"], f"shadow rotation row {index}.call")
        state = calls.setdefault(call_id, {"phases": set(), "stable": None})
        stable = tuple(row[field] for field in stable_fields)
        if phase in state["phases"] \
                or (state["stable"] is not None and state["stable"] != stable):
            raise ArtifactError("shadow rotation-setter pairing drifted")
        state["phases"].add(phase)
        state["stable"] = stable
        _integer(row["tick"], f"shadow rotation row {index}.tick")
        _integer(row["manager_render"], f"shadow rotation row {index}.render")
        _integer(row["thread_id"], f"shadow rotation row {index}.thread", 1)
        for field in (
            "caller", "owner_vtable", "parent_vtable", "object_vtable",
            "geometry_vtable",
        ):
            value = row[field]
            if value != "none" and (
                not isinstance(value, str) or STATIC_IDENTITY.fullmatch(value) is None
            ):
                raise ArtifactError(f"shadow rotation-setter {field} drifted")
        _f32(row["angle_f32"], "shadow rotation angle")
        ordinal = _integer(row["object_ordinal"], "shadow rotation object ordinal")
        if ordinal != 0xffffffff and ordinal > 63:
            raise ArtifactError("shadow rotation-setter object ordinal drifted")
        polygon_count = _integer(
            row["geometry_polygon_count"], "shadow rotation polygon count", 0, 65535,
        )
        _f32(row["geometry_extent_f32"], "shadow rotation geometry extent")
        object_present = row["object_vtable"] != "none"
        if object_present != (ordinal != 0xffffffff) \
                or object_present != (row["geometry_vtable"] != "none") \
                or (not object_present and polygon_count != 0):
            raise ArtifactError("shadow rotation-setter child identity drifted")
        rotation = row["local_rotation_f32"]
        if not isinstance(rotation, list) or len(rotation) != 11:
            raise ArtifactError("shadow rotation-setter matrix drifted")
        for value in rotation:
            _f32(value, "shadow rotation-setter matrix")
        canonical.append({
            key: value for key, value in row.items()
            if key not in {"sequence", "thread_id"}
        })
    if any(state["phases"] != {"BEFORE", "AFTER"} for state in calls.values()):
        raise ArtifactError("shadow rotation-setter pair is incomplete")
    digest = hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()
    return {"count": len(canonical), "sha256": digest, "records": canonical}


def build_candidate_receipt(
    *, root: Path, scenario: Path, native_replay: Path, observer_log: Path,
    framebuffer_metadata: Path | None, executable: Path, observer_hook: Path,
    capture_controller: Path, launch_receipt: Path,
    capture_host: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a verified, explicitly non-promotable provenance handoff."""

    scenario_value = load_scenario(scenario, root=root)
    trace = parse_semantic_log(observer_log, require_complete=True)
    _validate_trace_against_scenario(trace, scenario_value)
    if framebuffer_metadata is None:
        raise ArtifactError("production scenario requires raw framebuffer metadata")
    metadata = load_framebuffer_metadata(framebuffer_metadata, root=root)
    native_metadata_path = framebuffer_metadata.with_name(
        f"{framebuffer_metadata.stem}.native.json"
    )
    native_raw_path = native_metadata_path.with_name(
        native_metadata_path.name.removesuffix(".json") + ".raw"
    )
    native_metadata = load_framebuffer_source_metadata(
        native_metadata_path, root=root,
    )
    raw_path = framebuffer_metadata.with_suffix(".raw")
    derivation = validate_framebuffer_derivation(
        native_metadata,
        native_raw_path.read_bytes(),
        metadata,
        raw_path.read_bytes(),
    )
    expected_replay = build_native_replay_script(
        scenario_value, root=root, capture_tick=metadata["tick"],
    )
    if native_replay.read_bytes() != expected_replay:
        raise ArtifactError("native replay script drifted from the scenario transcripts")
    replay_sha256 = sha256_file(native_replay)
    if metadata["scenario"] != scenario_value["id"] \
            or metadata["scenario_sha256"] != replay_sha256:
        raise ArtifactError("framebuffer metadata is bound to a different native replay")
    trace_binding = validate_framebuffer_trace_binding(
        trace, metadata, require_render_final=True,
    )
    framebuffer_checkpoints = [
        checkpoint for checkpoint in scenario_value["checkpoints"]
        if checkpoint["tick"] == metadata["tick"]
        and "render.framebuffer" in checkpoint["required_channels"]
    ]
    if len(framebuffer_checkpoints) != 1:
        raise ArtifactError(
            "framebuffer metadata has no unique scenario pixel checkpoint"
        )
    framebuffer_ref = {
        **_file_reference(root, framebuffer_metadata, "framebuffer metadata"),
        "raw_path": _path_from_file(root, raw_path, "framebuffer raw artifact"),
        "raw_sha256": metadata["raw_sha256"],
        "native_metadata_path": _path_from_file(
            root, native_metadata_path, "native framebuffer metadata",
        ),
        "native_metadata_sha256": sha256_file(native_metadata_path),
        "native_raw_path": _path_from_file(
            root, native_raw_path, "native framebuffer raw artifact",
        ),
        "native_raw_sha256": native_metadata["raw_sha256"],
        "conversion": native_metadata["conversion"],
        "derivation": derivation,
        "trace_binding": trace_binding,
        "canonical_checkpoint": build_native_framebuffer_checkpoint(
            framebuffer_metadata,
            root=root,
            checkpoint_id=framebuffer_checkpoints[0]["id"],
        ),
    }
    host = _strict(dict(capture_host), {"os", "architecture", "backend"}, "capture_host")
    if not all(isinstance(host[field], str) and host[field] for field in host):
        raise ArtifactError("capture_host values must be non-empty strings")
    return {
        "schema": VERSION,
        "protocol": CANDIDATE_PROTOCOL,
        "status": "CANDIDATE_ONLY",
        "production_claim": False,
        "scenario": {
            **_file_reference(root, scenario, "scenario"),
            "id": scenario_value["id"],
            "semantic_sha256": scenario_sha256(scenario_value, root=root),
        },
        "native_replay": _file_reference(root, native_replay, "native replay"),
        "observer_log": {
            **_file_reference(root, observer_log, "observer log"),
            "semantic_sha256": trace["semantic_sha256"],
            "record_count": trace["record_count"],
        },
        "framebuffer": framebuffer_ref,
        "provenance": {
            "executable": _file_reference(root, executable, "executable"),
            "observer_hook": _file_reference(root, observer_hook, "observer hook"),
            "capture_controller": _file_reference(root, capture_controller, "capture controller"),
            "launch_receipt": _file_reference(root, launch_receipt, "launch receipt"),
            "capture_host": host,
        },
        "promotion_route": "reviewed-native-observer-receipt",
        "promotion_blockers": [
            "candidate receipt is not a reviewed native-observer receipt",
            "runtime trace contract status remains BLOCKED_NATIVE_REFERENCE",
        ],
    }


def _verify_reference(root: Path, value: Any, keys: set[str], label: str) -> Path:
    row = _strict(value, keys, label)
    return _verify_file(root, row, path_field="path", hash_field="sha256",
                        length_field=None, label=label)


def verify_candidate_receipt(path: Path, *, root: Path) -> dict[str, Any]:
    receipt = _strict(load_json(path), {
        "schema", "protocol", "status", "production_claim", "scenario",
        "native_replay", "observer_log", "framebuffer", "provenance", "promotion_route",
        "promotion_blockers",
    }, "candidate receipt")
    if receipt["schema"] != VERSION or receipt["protocol"] != CANDIDATE_PROTOCOL:
        raise ArtifactError("unsupported native observer candidate receipt")
    if receipt["status"] != "CANDIDATE_ONLY":
        raise ArtifactError("candidate receipt status must remain CANDIDATE_ONLY")
    if receipt["production_claim"] is not False:
        raise ArtifactError("candidate receipt production_claim must remain false")
    if receipt["promotion_route"] != "reviewed-native-observer-receipt":
        raise ArtifactError("candidate receipt has an unknown promotion route")
    blockers = receipt["promotion_blockers"]
    if not isinstance(blockers, list) or not blockers \
            or not all(isinstance(item, str) and item for item in blockers):
        raise ArtifactError("candidate receipt must retain explicit promotion blockers")

    scenario_ref = _strict(receipt["scenario"],
                           {"path", "sha256", "id", "semantic_sha256"},
                           "candidate scenario")
    scenario_path = _verify_reference(
        root, scenario_ref, {"path", "sha256", "id", "semantic_sha256"},
        "candidate scenario",
    )
    scenario_value = load_scenario(scenario_path, root=root)
    if scenario_ref["id"] != scenario_value["id"]:
        raise ArtifactError("candidate scenario id drifted")
    _hash(scenario_ref["semantic_sha256"], "candidate scenario.semantic_sha256")
    if scenario_ref["semantic_sha256"] != scenario_sha256(scenario_value, root=root):
        raise ArtifactError("candidate scenario semantic hash drifted")

    replay_ref = _strict(receipt["native_replay"], {"path", "sha256"},
                         "candidate native_replay")
    replay_path = _verify_reference(
        root, replay_ref, {"path", "sha256"}, "candidate native_replay",
    )

    log_ref = _strict(receipt["observer_log"],
                      {"path", "sha256", "semantic_sha256", "record_count"},
                      "candidate observer_log")
    log_path = _verify_reference(
        root, log_ref, {"path", "sha256", "semantic_sha256", "record_count"},
        "candidate observer_log",
    )
    trace = parse_semantic_log(log_path, require_complete=True)
    _validate_trace_against_scenario(trace, scenario_value)
    _hash(log_ref["semantic_sha256"], "candidate observer_log.semantic_sha256")
    if log_ref["semantic_sha256"] != trace["semantic_sha256"]:
        raise ArtifactError("candidate observer semantic hash drifted")
    if _integer(log_ref["record_count"], "candidate observer_log.record_count") \
            != trace["record_count"]:
        raise ArtifactError("candidate observer record count drifted")

    framebuffer = receipt["framebuffer"]
    if framebuffer is None:
        raise ArtifactError("candidate receipt has no framebuffer provenance")
    framebuffer = _strict(framebuffer,
                          {"path", "sha256", "raw_path", "raw_sha256",
                           "native_metadata_path", "native_metadata_sha256",
                           "native_raw_path", "native_raw_sha256", "conversion",
                           "derivation", "trace_binding", "canonical_checkpoint"},
                          "candidate framebuffer")
    metadata_path = _verify_reference(
        root, framebuffer,
        {"path", "sha256", "raw_path", "raw_sha256",
         "native_metadata_path", "native_metadata_sha256",
         "native_raw_path", "native_raw_sha256", "conversion",
         "derivation", "trace_binding", "canonical_checkpoint"},
        "candidate framebuffer",
    )
    metadata = load_framebuffer_metadata(metadata_path, root=root)
    raw_path = _resolve(root, framebuffer["raw_path"], "candidate framebuffer.raw_path")
    if raw_path != metadata_path.with_suffix(".raw") \
            or framebuffer["raw_sha256"] != metadata["raw_sha256"] \
            or sha256_file(raw_path) != metadata["raw_sha256"]:
        raise ArtifactError("candidate framebuffer raw artifact identity drifted")
    native_metadata_path = _resolve(
        root,
        framebuffer["native_metadata_path"],
        "candidate framebuffer.native_metadata_path",
    )
    native_raw_path = _resolve(
        root,
        framebuffer["native_raw_path"],
        "candidate framebuffer.native_raw_path",
    )
    if native_metadata_path != metadata_path.with_name(
        f"{metadata_path.stem}.native.json"
    ) or native_raw_path != native_metadata_path.with_name(
        native_metadata_path.name.removesuffix(".json") + ".raw"
    ) or sha256_file(native_metadata_path) != framebuffer["native_metadata_sha256"]:
        raise ArtifactError("candidate native framebuffer reference drifted")
    native_metadata = load_framebuffer_source_metadata(
        native_metadata_path, root=root,
    )
    if framebuffer["native_raw_sha256"] != native_metadata["raw_sha256"] \
            or sha256_file(native_raw_path) != native_metadata["raw_sha256"] \
            or framebuffer["conversion"] != native_metadata["conversion"]:
        raise ArtifactError("candidate native framebuffer identity drifted")
    derivation = validate_framebuffer_derivation(
        native_metadata,
        native_raw_path.read_bytes(),
        metadata,
        raw_path.read_bytes(),
    )
    if framebuffer["derivation"] != derivation:
        raise ArtifactError("candidate framebuffer derivation receipt drifted")
    if metadata["scenario"] != scenario_value["id"] \
            or metadata["scenario_sha256"] != replay_ref["sha256"] \
            or replay_path.read_bytes() != build_native_replay_script(
                scenario_value, root=root, capture_tick=metadata["tick"],
            ):
        raise ArtifactError("candidate native replay/framebuffer binding drifted")
    checkpoint_rows = [
        checkpoint for checkpoint in scenario_value["checkpoints"]
        if checkpoint["tick"] == metadata["tick"]
        and "render.framebuffer" in checkpoint["required_channels"]
    ]
    if len(checkpoint_rows) != 1 or framebuffer["canonical_checkpoint"] \
            != build_native_framebuffer_checkpoint(
                metadata_path, root=root, checkpoint_id=checkpoint_rows[0]["id"],
            ):
        raise ArtifactError("candidate canonical framebuffer checkpoint drifted")
    trace_binding = validate_framebuffer_trace_binding(
        trace, metadata, require_render_final=True,
    )
    if framebuffer["trace_binding"] != trace_binding:
        raise ArtifactError("candidate framebuffer trace receipt drifted")

    provenance = _strict(receipt["provenance"], {
        "executable", "observer_hook", "capture_controller", "launch_receipt",
        "capture_host",
    }, "candidate provenance")
    for field in ("executable", "observer_hook", "capture_controller", "launch_receipt"):
        _verify_reference(root, provenance[field], {"path", "sha256"},
                          f"candidate provenance.{field}")
    host = _strict(provenance["capture_host"], {"os", "architecture", "backend"},
                   "candidate provenance.capture_host")
    if not all(isinstance(host[field], str) and host[field] for field in host):
        raise ArtifactError("candidate provenance capture_host values must be non-empty")
    return receipt
