#!/usr/bin/env python3
import copy
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.miel_vliegt import native_discovery
from tools.miel_vliegt import native_scenario_artifacts as artifacts


SCHEMA = Path(__file__).resolve().parent / "scenarios/native_semantic_scenario.schema.json"


# Observer-log line-4 contract: location-phase RNG seed (authoritative statement
# in docs/flight-capture-fix-bundle.md). The caller RVA 0x00030a8a is pinned at
# the C-source level by test_native_observer_build; these constants pin the SEED
# VALUE the hook emits at phase=seed, so a capture that passes caller_rva while
# emitting the wrong seed can no longer go green.
LOCATION_PHASE_RNG_SEED_VALUE = 1592639710
LOCATION_PHASE_RAND_CALLER_RVA = "0x00030a8a"


def location_phase_rng_seed_record(observer_log: Path) -> dict:
    """Return the sole MVD ``miel-vliegt-native-location-phase-rng`` seed record.

    Mirrors the C hook emit path (``hangover/native_observer_hook.c`` ->
    ``emit_location_phase_rng`` with ``phase="seed"``). The production library
    now enforces this contract through
    ``native_scenario_artifacts.validate_location_phase_rng_seed``; this parser
    is the independent test-owned pin the seed-consistency gate keeps in sync,
    and it stays minimal so a drift between the library validator and this
    helper can never go unnoticed.
    """
    records = []
    for raw_line in (
        observer_log.read_text(encoding="utf-8", errors="strict").splitlines()
    ):
        if not raw_line.startswith("MVD "):
            continue
        record = json.loads(raw_line[4:])
        if (record.get("protocol") == "miel-vliegt-native-location-phase-rng"
                and record.get("phase") == "seed"):
            records.append(record)
    if not records:
        raise artifacts.ArtifactError(
            "observer log has no miel-vliegt-native-location-phase-rng seed record"
        )
    if len(records) > 1:
        raise artifacts.ArtifactError(
            "observer log has multiple location-phase-rng seed records"
        )
    return records[0]


def assert_location_phase_rng_seed_contract(record: dict) -> None:
    """Assert an MVD location-phase-rng seed record honors the pinned contract."""
    if record.get("protocol") != "miel-vliegt-native-location-phase-rng":
        raise AssertionError("record is not the location-phase-rng protocol")
    if record.get("phase") != "seed":
        raise AssertionError(
            f"expected phase=seed, got {record.get('phase')!r}"
        )
    if record.get("value") != LOCATION_PHASE_RNG_SEED_VALUE:
        raise AssertionError(
            "location-phase-rng seed VALUE drifted: expected "
            f"{LOCATION_PHASE_RNG_SEED_VALUE}, got {record.get('value')}"
        )
    if record.get("caller_rva") != LOCATION_PHASE_RAND_CALLER_RVA:
        raise AssertionError(
            "location-phase-rng seed caller_rva drifted: expected "
            f"{LOCATION_PHASE_RAND_CALLER_RVA}, got {record.get('caller_rva')}"
        )


def f32(value: int = 0) -> str:
    return f"0x{value:08x}"


def painted_framebuffer_bytes() -> bytes:
    raw = bytearray(
        artifacts.FRAMEBUFFER_CLIENT_WIDTH
        * artifacts.FRAMEBUFFER_CLIENT_HEIGHT
        * 4
    )
    raw[:16] = bytes(range(16))
    return bytes(raw)


def framebuffer_metadata(
    frame: Path, *, scenario_id: str, scenario_sha256: str,
) -> dict:
    raw = frame.read_bytes()
    non_black_pixel_count = sum(
        raw[offset] != 0 or raw[offset + 1] != 0 or raw[offset + 2] != 0
        for offset in range(0, len(raw), 4)
    )
    width = artifacts.FRAMEBUFFER_CLIENT_WIDTH
    height = artifacts.FRAMEBUFFER_CLIENT_HEIGHT
    raw_size = width * height * 4
    return {
        "schema": artifacts.FRAMEBUFFER_VERSION,
        "protocol": artifacts.FRAMEBUFFER_PROTOCOL,
        "scenario": scenario_id,
        "scenario_sha256": scenario_sha256,
        "tick": 0,
        "width": width,
        "height": height,
        "pitch": width * 4,
        "window_role": "top-level-projector",
        "window_top_level": True,
        "window_visible": True,
        "window_enabled": True,
        "window_iconic": False,
        "client_width": width,
        "client_height": height,
        "render_ordinal": 1,
        "paint_progress": "manager-render-and-non-black",
        "non_black_pixel_count": non_black_pixel_count,
        "bits_per_pixel": 32,
        "bytes_per_pixel": 4,
        "gt_format_id": 8,
        "gt_format_name": "ARGB8888",
        "image_size": raw_size,
        "raw_size": raw_size,
        "raw_sha256": artifacts.sha256_file(frame),
        "row_layout": "native_pitch_bytes",
        "origin": "top-left",
        "packed_format": "xrgb8888-le",
        "memory_byte_order": "bgrx",
        "surface_alpha": "unused",
        "device_config": "config.ini",
        "device_config_sha256": artifacts.REVIEWED_GT_SOFTWARE_CONFIG_SHA256,
        "device_module": "gtSoftware.dll",
        "device_module_sha256": artifacts.REVIEWED_GT_SOFTWARE_SHA256,
    }


def runtime_initial_values() -> list[dict]:
    return [
        {
            "name": name,
            "encoding": encoding,
            "value_hex": "00" if encoding == "u8" else "00000000",
        }
        for name, encoding in artifacts.RUNTIME_STATE_FIELDS
    ]


def state_values(*, phase: str, call: int = 0, production: bool = False) -> dict:
    values = {
        "phase": phase,
        "call": call,
        "depth": 0,
        "outer": True,
        "dt_f32_bits": f32(0x3CA3D70A if production else 0x3D23D70A),
        "state_valid": True,
        "position_f32_bits": [f32(), f32(), f32()],
        "orientation_wxyz_f32_bits": [f32(0x3F800000), f32(), f32(), f32()],
        "velocity_f32_bits": [f32(), f32(), f32()],
        "angular_velocity_f32_bits": [f32(), f32(), f32()],
        "inactive": 0,
        "floor_enabled": 1,
    }
    if production:
        values.update({
            "fuel_f32_bits": f32(0x3F800000),
            "integrity_f32_bits": f32(0x3F800000),
            "maximum_integrity_f32_bits": f32(0x3F800000),
            "pending_damage_f32_bits": f32(),
            "damage_gate_timer_f32_bits": f32(),
            "active": 1,
        })
    return values


def controls_values(sample: int = 0, *, production: bool = False) -> dict:
    values = {
        "sample": sample,
        "dt_f32_bits": f32(0x3CA3D70A if production else 0x3D23D70A),
        "keys": {key: 0 for key in artifacts.CONTROL_KEYS},
        "analog_horizontal_f32_bits": f32(),
        "analog_vertical_f32_bits": f32(),
        "flight_valid": True,
        "propulsion_f32_bits": f32(),
        "propulsion_scale_f32_bits": f32(0x3F800000),
        "horizontal_f32_bits": f32(),
        "vertical_f32_bits": f32(),
        "controls_enabled": 1,
    }
    if production:
        values["input_source"] = "windows_sendinput_directinput"
        values["focus_active"] = True
    return values


def semantic_lines() -> list[str]:
    records = [
        ("flight.tick", {"dt_f32_bits": f32(0x3D23D70A)}),
        ("controls.pre", controls_values()),
        ("controls.post", controls_values()),
        ("physics.state", state_values(phase="enter")),
        ("physics.state", state_values(phase="leave")),
        ("collision.state", state_values(phase="enter")),
        ("collision.state", state_values(phase="commit")),
        ("camera.commit", {
            "camera_valid": True,
            "flight_valid": True,
            "node_forward_f32_bits": [f32(), f32(), f32(0x3F800000)],
            "node_position_f32_bits": [f32(), f32(), f32()],
            "flight_position_f32_bits": [f32(), f32(), f32()],
        }),
        ("render.final", {}),
    ]
    lines = [
        'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
        '"status":"LOADED","thread_id":7}'
    ]
    for sequence, (channel, values) in enumerate(records):
        lines.append("MVT " + json.dumps({
            "record": "behavior",
            "sequence": sequence,
            "channel": channel,
            "tick": 0,
            "frame": 0,
            "values": values,
            "diagnostics": {"thread_id": 7},
        }, separators=(",", ":")))
    return lines


def production_lines(identifier: str = "controls-press-hold-release",
                     raw_sha256: str = "a" * 64) -> list[str]:
    camera = {
        "camera_valid": True,
        "flight_valid": True,
        "camera_control_owner": "common_location",
        "location_state": 5,
        "manual_camera_enabled": 0xff,
        "move_forward": 0xff,
        "move_backward": 0xff,
        "render_world_position_f32_bits": [f32(), f32(), f32()],
        "render_scaled_rotation_row_major_f32_bits": [
            f32(0x3F800000), f32(), f32(),
            f32(), f32(0x3F800000), f32(),
            f32(), f32(), f32(0x3F800000),
        ],
        "render_scale_f32_bits": f32(0x3F800000),
        "render_inverse_scale_squared_f32_bits": f32(0x3F800000),
        "near_f32_bits": f32(0x3DCCCCCD),
        "far_f32_bits": f32(0x447A0000),
        "horizontal_fov_degrees_f32_bits": f32(0x42200000),
        "centre_f32_bits": [f32(), f32()],
        "window_endpoints_f32_bits": [
            f32(), f32(), f32(0x441FC000), f32(0x43EF8000),
        ],
        "focal_pixels_f32_bits": f32(0x445B746B),
        "flight_position_f32_bits": [f32(), f32(), f32()],
    }
    records = [
        {"record": "session", "channel": "session.dispatched",
         "values": {"scenario": identifier, "reason": "native_login_fsm"}},
        {"record": "session", "channel": "session.navigating",
         "values": {"scenario": identifier, "reason": "native_barn_flyaway_handler"}},
        {"record": "session", "channel": "session.navigating",
         "values": {"scenario": identifier, "reason": "native_mygghanget_state_five"}},
        {"record": "rng", "channel": "rng.seed", "tick": artifacts.UINT32_MAX,
         "values": {"ordinal": 0, "value": 7}},
        {"record": "input", "channel": "input.focus", "tick": 0, "frame": 0,
         "values": {"focus_active": True, "valid": True,
                    "projector_foreground": True, "sink_foreground": False,
                    "visible": True, "enabled": True, "iconic": False,
                    "process_id": 10, "window_thread_id": 11, "candidate_count": 1}},
        {"record": "input", "channel": "input.transition", "tick": 0, "frame": 0,
         "values": {"from_mask": "0x00", "to_mask": "0x00", "event_count": 0,
                    "sendinput_count": 0, "complete": True,
                    "input_source": "windows_sendinput_scancode"}},
        {"record": "session", "channel": "session.armed",
         "values": {"scenario": identifier, "reason": "native_flight_preroll_pending"}},
        {"record": "rng", "channel": "rng.seed", "tick": artifacts.UINT32_MAX,
         "values": {"ordinal": 1, "value": 7}},
        {"record": "session", "channel": "session.ready",
         "values": {"scenario": identifier, "reason": "exact_native_predicate"}},
        {"record": "input", "channel": "input.sample", "tick": 0, "frame": 0,
         "values": {"expected_mask": "0x00", "observed_mask": "0x00",
                    "read_valid": True, "schedule_match": True, "sample_match": True,
                    "focus_valid": True, "valid": True, "foreground": True,
                    "input_source": "native_directinput_after_sendinput",
                    "focus_active": True}},
        {"record": "clock", "channel": "clock.tick", "tick": 0,
         "values": {"scripted_dt_f32_bits": f32(0x3CA3D70A),
                    "source": "scenario_transcript"}},
        {"record": "behavior", "channel": "flight.tick", "tick": 0, "frame": 0,
         "values": {"dt_f32_bits": f32(0x3CA3D70A)}},
        {"record": "behavior", "channel": "controls.pre", "tick": 0, "frame": 0,
         "values": controls_values(production=True)},
        {"record": "behavior", "channel": "controls.post", "tick": 0, "frame": 0,
         "values": controls_values(production=True)},
        {"record": "behavior", "channel": "physics.state", "tick": 0, "frame": 0,
         "values": state_values(phase="enter", production=True)},
        {"record": "behavior", "channel": "physics.state", "tick": 0, "frame": 0,
         "values": state_values(phase="leave", production=True)},
        {"record": "behavior", "channel": "collision.state", "tick": 0, "frame": 0,
         "values": state_values(phase="enter", production=True)},
        {"record": "behavior", "channel": "collision.state", "tick": 0, "frame": 0,
         "values": state_values(phase="commit", production=True)},
        {"record": "system", "channel": "system.fuel", "tick": 0, "frame": 0,
         "values": {"fuel_f32_bits": f32(0x3F800000), "depleted": False}},
        {"record": "behavior", "channel": "camera.commit", "tick": 0, "frame": 0,
         "values": camera},
        {"record": "behavior", "channel": "render.final", "tick": 0, "frame": 0,
         "values": {"crash_requested": 0, "crash_active": 0,
                    "crash_timer_f32_bits": f32()}},
        {"record": "framebuffer", "channel": "render.framebuffer", "tick": 0,
         "values": {"raw_sha256": raw_sha256, "capture": "native_read_screen"}},
        {"record": "rng", "channel": "rng.end", "tick": 0,
         "values": {"ordinal": 0, "value": 0}},
        {"record": "session", "channel": "session.complete",
         "values": {"scenario": identifier, "reason": "replay_complete_tick"}},
    ]
    lines = [
        'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
        '"status":"LOADED","thread_id":70}'
    ]
    for sequence, record in enumerate(records):
        record["sequence"] = sequence
        record["diagnostics"] = {"thread_id": 7}
        if record["channel"] == "clock.tick":
            record["diagnostics"]["observed_dt_f32_bits"] = f32(0x3CA3D70A)
        if record["channel"] == "input.sample":
            record["diagnostics"]["window_thread_id"] = 11
        lines.append("MVT " + json.dumps(record, separators=(",", ":")))
    lines.append(
        'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
        '"status":"SCENARIO_COMPLETE","thread_id":7}'
    )
    return lines


def production_lines_with_focus_worker(worker_thread_id: int = 99) -> list[str]:
    lines = production_lines()
    identifier = "controls-press-hold-release"
    events = [
        {
            "ordinal": 0, "episode": 0, "tick": 1, "active": False,
            "offset_ns": 0,
        },
        {
            "ordinal": 1, "episode": 0, "tick": 2, "active": True,
            "offset_ns": 80_000_000,
        },
    ]
    timeline_sha256 = artifacts._focus_timeline_sha256(events)
    common = {
        "schema": 1,
        "protocol": "miel-vliegt-native-focus-timeline",
        "scenario": identifier,
        "scenario_sha256": "0" * 64,
        "timeline_sha256": timeline_sha256,
        "clock": "query_performance_counter",
        "origin": "episode-focus-loss",
        "thread_id": worker_thread_id,
    }
    diagnostics = [
        {**common, "sequence": 1000, "phase": "start",
         "episode": 0, "event_count": 2},
        {**common, "sequence": 1001, "phase": "event",
         "ordinal": 0, "episode": 0, "tick": 1, "active": False,
         "scheduled_offset_ns": 0, "applied_offset_ns": 0,
         "lateness_ns": 0},
        {**common, "sequence": 1002, "phase": "event",
         "ordinal": 1, "episode": 0, "tick": 2, "active": True,
         "scheduled_offset_ns": 80_000_000,
         "applied_offset_ns": 84_000_000, "lateness_ns": 4_000_000},
        {**common, "sequence": 1003, "phase": "complete",
         "episode": 0, "event_count": 2},
    ]
    worker_records = [
        {
            "record": "input", "channel": "input.transition",
            "tick": 1, "frame": 0,
            "values": {
                "from_mask": "0x00", "to_mask": "0x00",
                "event_count": 0, "sendinput_count": 0, "complete": True,
                "input_source": "windows_sendinput_scancode",
            },
            "diagnostics": {"thread_id": worker_thread_id},
        },
        {
            "record": "input", "channel": "input.focus",
            "tick": 1, "frame": 0,
            "values": {
                "focus_active": False, "valid": True,
                "projector_foreground": False, "sink_foreground": True,
                "visible": True, "enabled": True, "iconic": False,
                "process_id": 10, "window_thread_id": 11,
                "candidate_count": 1,
            },
            "diagnostics": {"thread_id": worker_thread_id},
        },
        {
            "record": "input", "channel": "input.transition",
            "tick": 2, "frame": 0,
            "values": {
                "from_mask": "0x00", "to_mask": "0x00",
                "event_count": 0, "sendinput_count": 0, "complete": True,
                "input_source": "windows_sendinput_scancode",
            },
            "diagnostics": {"thread_id": worker_thread_id},
        },
        {
            "record": "input", "channel": "input.focus",
            "tick": 2, "frame": 0,
            "values": {
                "focus_active": True, "valid": True,
                "projector_foreground": True, "sink_foreground": False,
                "visible": True, "enabled": True, "iconic": False,
                "process_id": 10, "window_thread_id": 11,
                "candidate_count": 1,
            },
            "diagnostics": {"thread_id": worker_thread_id},
        },
    ]
    insertion = next(
        index for index, line in enumerate(lines) if '"rng.end"' in line
    )
    lines[insertion:insertion] = [
        "MVD " + json.dumps(diagnostics[0], separators=(",", ":")),
        "MVT " + json.dumps(worker_records[0], separators=(",", ":")),
        "MVT " + json.dumps(worker_records[1], separators=(",", ":")),
        "MVD " + json.dumps(diagnostics[1], separators=(",", ":")),
        "MVT " + json.dumps(worker_records[2], separators=(",", ":")),
        "MVT " + json.dumps(worker_records[3], separators=(",", ":")),
        "MVD " + json.dumps(diagnostics[2], separators=(",", ":")),
        "MVD " + json.dumps(diagnostics[3], separators=(",", ":")),
        "MVT " + json.dumps({
            "record": "clock", "channel": "clock.tick", "tick": 2,
            "values": {
                "scripted_dt_f32_bits": f32(0x3CA3D70A),
                "source": "scenario_transcript",
            },
            "diagnostics": {
                "thread_id": 7,
                "observed_dt_f32_bits": f32(0x3CA3D70A),
            },
        }, separators=(",", ":")),
    ]
    sequence = 0
    for index, line in enumerate(lines):
        if not line.startswith("MVT "):
            continue
        record = json.loads(line[4:])
        record["sequence"] = sequence
        sequence += 1
        lines[index] = "MVT " + json.dumps(record, separators=(",", ":"))
    return lines


def scenario(root: Path, identifier: str = "level-flight-turn") -> dict:
    source = root / "initial.bin"
    source.write_bytes(b"initial state")
    return {
        "schema": 1,
        "protocol": artifacts.SCENARIO_PROTOCOL,
        "id": identifier,
        "description": "Deterministic semantic observer scenario.",
        "evidence_status": "CAPTURE_SPEC_ONLY",
        "input_script": {
            "tick_count": 3,
            "events": [
                {"sequence": 0, "tick": 0, "type": "key", "key": "left", "action": "down"},
                {"sequence": 1, "tick": 2, "type": "key", "key": "left", "action": "up"},
            ],
        },
        "clock_transcript": {
            "samples": [
                {"tick": tick, "monotonic_ns": tick * 20_000_000,
                 "dt_f32_bits": f32(0x3CA3D70A)}
                for tick in range(3)
            ],
        },
        "rng_transcript": {
            "algorithm": "recorded-u32",
            "flight_activation_seed_u32": 7,
            "flight_activation_dt_f32_bits": [],
            "seed_u32": 7,
            "reseeds": [],
            "draws": [{"sequence": 0, "tick": 1, "value_u32": 42}],
        },
        "initial_state": {
            "files": [{
                "role": "fixture",
                "path": "initial.bin",
                "byte_length": source.stat().st_size,
                "sha256": artifacts.sha256_file(source),
            }],
            "values": runtime_initial_values(),
        },
        "checkpoints": [{"id": "settled", "tick": 2,
                         "required_channels": ["flight.tick"]}],
        "outcome_expectations": [
            {"channel": "outcome.contact", "presence": "optional", "predicate": "correction"},
            {"channel": "outcome.damage", "presence": "optional", "predicate": "any"},
            {"channel": "outcome.crash", "presence": "optional", "predicate": "terminal"},
            {"channel": "outcome.terrain", "presence": "optional", "predicate": "class-range"},
        ],
    }


class NativeScenarioArtifactTests(unittest.TestCase):
    def test_schema_and_validator_allow_exactly_the_seven_contract_scenarios(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]["id"]["enum"]), artifacts.SCENARIO_IDS)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial_state = scenario(root)["initial_state"]
            catalog = artifacts.build_tracked_scenario_catalog(initial_state, root=root)
            for value in catalog:
                identifier = value["id"]
                self.assertEqual(artifacts.validate_scenario(value, root=root)["id"], identifier)
            value = scenario(root, "unreviewed-scenario")
            with self.assertRaisesRegex(artifacts.ArtifactError, "scenario id"):
                artifacts.validate_scenario(value, root=root)

    def test_scenario_set_requires_each_contract_scenario_exactly_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = artifacts.build_tracked_scenario_catalog(
                scenario(root)["initial_state"], root=root,
            )
            self.assertEqual(
                [row["id"] for row in artifacts.validate_scenario_set(values, root=root)],
                list(artifacts.SCENARIO_ID_ORDER),
            )
            with self.assertRaisesRegex(artifacts.ArtifactError, "scenario set"):
                artifacts.validate_scenario_set(values[:-1], root=root)
            with self.assertRaisesRegex(artifacts.ArtifactError, "duplicate"):
                artifacts.validate_scenario_set([*values, values[0]], root=root)

    def test_materialized_suite_binds_all_scenarios_and_replay_wires(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial_state = scenario(root)["initial_state"]
            manifest = artifacts.materialize_scenario_suite(root, initial_state)
            self.assertEqual(
                [row["id"] for row in manifest["scenarios"]],
                list(artifacts.SCENARIO_ID_ORDER),
            )
            self.assertFalse(manifest["production_claim"])
            for row in manifest["scenarios"][:-1]:
                self.assertEqual(
                    row["observation_profile"],
                    artifacts.scenario_observation_profile(row["id"]),
                )
                self.assertEqual(row["observation_profile"]["omit_mask"], "0x1fff")
                self.assertTrue(
                    row["observation_profile"]["parity_evidence_eligible"]
                )
                self.assertEqual(
                    row["observation_profile"]["observer_profile"],
                    "scenario-bounded",
                )
            visual = manifest["scenarios"][-1]["observation_profile"]
            self.assertEqual(visual["id"], "full-visual-pixel-v1")
            self.assertEqual(visual["omit_mask"], "0x0000")
            self.assertTrue(visual["parity_evidence_eligible"])
            artifacts.validate_scenario_suite_manifest(manifest, root=root)
            replay = root / manifest["scenarios"][0]["native_replay"]["path"]
            replay.write_bytes(replay.read_bytes() + b"tampered\n")
            with self.assertRaisesRegex(artifacts.ArtifactError, "hash drifted"):
                artifacts.validate_scenario_suite_manifest(manifest, root=root)

    def test_suite_rejects_partial_shadow_or_profile_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = artifacts.materialize_scenario_suite(
                root, scenario(root)["initial_state"],
            )
            manifest["scenarios"][0]["observation_profile"]["omit_mask"] = "0x0fff"
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "observation profile drifted",
            ):
                artifacts.validate_scenario_suite_manifest(manifest, root=root)

            legacy = artifacts.scenario_observation_profile("taxi-straight")
            legacy["observer_profile"] = "semantic-only"
            legacy["parity_evidence_eligible"] = False
            legacy["evidence_blocker"] = "startup_scheduler_divergence"
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "observation profile drifted",
            ):
                artifacts.validate_scenario_observation_profile(
                    legacy, scenario_id="taxi-straight",
                )

            manifest = artifacts.load_scenario_suite_manifest(root / "suite-spec.json")
            manifest["scenarios"][-1]["observation_profile"]["id"] = \
                "production-semantic-v1"
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "observation profile drifted",
            ):
                artifacts.validate_scenario_suite_manifest(manifest, root=root)

    def test_suite_loader_binds_manifest_directory_and_all_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial_state = scenario(root)["initial_state"]
            artifacts.materialize_scenario_suite(root, initial_state)
            loaded = artifacts.load_scenario_suite_manifest(root / "suite-spec.json")
            self.assertEqual(loaded["scenario_order"], list(artifacts.SCENARIO_ID_ORDER))
            selected = artifacts.scenario_suite_entry(loaded, "impact-crash")
            self.assertEqual(selected["id"], "impact-crash")
            (root / selected["native_replay"]["path"]).write_bytes(b"drift")
            with self.assertRaisesRegex(artifacts.ArtifactError, "hash drifted"):
                artifacts.load_scenario_suite_manifest(root / "suite-spec.json")

    def test_initial_state_restore_is_exact_clean_and_read_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "suite"
            root.mkdir()
            value = scenario(root)
            value["initial_state"]["values"] = []
            state_root = Path(temporary) / "native-user"
            receipt = artifacts.restore_scenario_initial_state_files(
                value,
                artifact_root=root,
                state_root=state_root,
                role_targets={"fixture": "user0.dat"},
            )
            self.assertEqual(receipt["status"], "RESTORED")
            self.assertFalse(receipt["production_claim"])
            self.assertEqual((state_root / "user0.dat").read_bytes(), b"initial state")
            self.assertEqual(receipt["files"][0]["sha256"], artifacts.sha256_file(
                state_root / "user0.dat",
            ))

            (state_root / "stale.dat").write_bytes(b"stale")
            with self.assertRaisesRegex(artifacts.ArtifactError, "undeclared files"):
                artifacts.restore_scenario_initial_state_files(
                    value,
                    artifact_root=root,
                    state_root=state_root,
                    role_targets={"fixture": "user0.dat"},
                )

    def test_initial_state_restore_binds_observer_applied_runtime_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "suite"
            root.mkdir()
            value = scenario(root)
            receipt = artifacts.restore_scenario_initial_state_files(
                value,
                artifact_root=root,
                state_root=Path(temporary) / "native-user",
                role_targets={"fixture": "user0.dat"},
            )
            self.assertEqual(receipt["values"], value["initial_state"]["values"])

    def test_runtime_state_and_activation_transcript_receipts_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = runtime_initial_values()
            rows = []
            for index, row in enumerate(values):
                rows.append("MVD " + json.dumps({
                    "schema": 1,
                    "protocol": "miel-vliegt-native-initial-state",
                    "sequence": index,
                    "phase": "readback",
                    "index": index,
                    **row,
                    "access_mode": artifacts.RUNTIME_STATE_ACCESS[row["name"]],
                    "thread_id": 1,
                }, separators=(",", ":")))
            rows.append("MVD " + json.dumps({
                "schema": 1,
                "protocol": "miel-vliegt-native-initial-state",
                "sequence": 39,
                "phase": "readback_complete",
                "field_count": 39,
                "replay_bound": True,
                "thread_id": 1,
            }, separators=(",", ":")))
            state_log = root / "state.log"
            state_log.write_text("\n".join(rows) + "\n", encoding="utf-8")
            self.assertEqual(
                artifacts.extract_bound_runtime_initial_state(state_log), values,
            )

            rng_digest = hashlib.sha256(
                (0).to_bytes(4, "little")
                + (42).to_bytes(4, "little")
                + (0x32F3D).to_bytes(4, "little")
            ).hexdigest()
            clock_digest = hashlib.sha256(
                (0).to_bytes(4, "little") + (0x3CA3D70A).to_bytes(4, "little")
            ).hexdigest()
            activation = root / "activation.log"
            activation.write_text("\n".join([
                'MVD {"schema":1,"protocol":"miel-vliegt-native-flight-activation-rng","sequence":0,"phase":"draw","ordinal":0,"value":42,"caller_rva":"0x00032f3d","thread_id":1}',
                f'MVD {{"schema":1,"protocol":"miel-vliegt-native-flight-activation-rng","sequence":1,"phase":"complete","count":1,"sha256":"{rng_digest}","thread_id":1}}',
                'MVD {"schema":1,"protocol":"miel-vliegt-native-flight-activation-clock","sequence":2,"phase":"tick","ordinal":0,"observed_dt_f32_bits":"0x3d23d70a","scripted_dt_f32_bits":"0x3ca3d70a","thread_id":1}',
                f'MVD {{"schema":1,"protocol":"miel-vliegt-native-flight-activation-clock","sequence":3,"phase":"complete","count":1,"sha256":"{clock_digest}","thread_id":1}}',
            ]) + "\n", encoding="utf-8")
            self.assertEqual(
                artifacts.extract_flight_activation_rng(activation)["sha256"],
                rng_digest,
            )
            self.assertEqual(
                artifacts.extract_flight_activation_clock(activation)["sha256"],
                clock_digest,
            )

    def test_location_phase_rng_seed_contract_is_value_pinned_and_deterministic(self):
        """The line-4 seed contract pins the VALUE, not just the caller RVA.

        ``test_native_observer_build`` pins the caller RVA 0x00030a8a at the
        C-source level. This gate pins the SEED VALUE 1592639710 that the hook
        emits at ``phase=seed`` so a capture that passes caller_rva while
        emitting the wrong seed can no longer go green, and asserts the seed is
        identical across every scenario fixture that sources it.
        """
        caller_rva = LOCATION_PHASE_RAND_CALLER_RVA
        seed_value = LOCATION_PHASE_RNG_SEED_VALUE

        def seed_line(*, value, caller=caller_rva, sequence=3):
            return "MVD " + json.dumps({
                "schema": 1,
                "protocol": "miel-vliegt-native-location-phase-rng",
                "sequence": sequence,
                "phase": "seed",
                "ordinal": artifacts.UINT32_MAX,
                "value": value,
                "caller_rva": caller,
                "count": 0,
                "sha256": None,
                "thread_id": 1,
            }, separators=(",", ":"))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            # Positive: the canonical seed record honors the pinned contract.
            canonical = root / "canonical.log"
            canonical.write_text(
                seed_line(value=seed_value) + "\n", encoding="utf-8")
            assert_location_phase_rng_seed_contract(
                location_phase_rng_seed_record(canonical)
            )

            # False-green guard: correct caller_rva but a WRONG seed value MUST
            # fail the contract (the exact regression this gate exists to catch).
            wrong_seed = root / "wrong_seed.log"
            wrong_seed.write_text(
                seed_line(value=seed_value + 1) + "\n", encoding="utf-8")
            drifted = location_phase_rng_seed_record(wrong_seed)
            self.assertEqual(drifted["caller_rva"], caller_rva)
            with self.assertRaises(AssertionError):
                assert_location_phase_rng_seed_contract(drifted)

            # A drifted caller_rva is rejected independently of the seed value.
            wrong_caller = root / "wrong_caller.log"
            wrong_caller.write_text(
                seed_line(value=seed_value, caller="0x00000bad") + "\n",
                encoding="utf-8")
            with self.assertRaises(AssertionError):
                assert_location_phase_rng_seed_contract(
                    location_phase_rng_seed_record(wrong_caller)
                )

            # A log with no location-phase-rng seed record fails closed.
            empty = root / "empty.log"
            empty.write_text(
                'MVD {"schema":1,"protocol":"miel-vliegt-native-flight-activation-rng",'
                '"sequence":0,"phase":"draw","ordinal":0,"value":1,'
                '"caller_rva":"0x00032f3d","thread_id":1}\n',
                encoding="utf-8")
            with self.assertRaises(artifacts.ArtifactError):
                location_phase_rng_seed_record(empty)

        # Cross-scenario determinism: every scenario fixture that sources the
        # replay seed pins the same value the hook must emit at phase=seed.
        module_root = Path(__file__).resolve().parent
        fixture_seeds = []
        for fixture_name in (
            "scenarios/native_replay_controls_fixture.json",
            "scenarios/native_replay_receipt_fixture.json",
        ):
            fixture = json.loads(
                (module_root / fixture_name).read_text(encoding="utf-8"))
            fixture_seeds.append(fixture["seed"])
        replay_mvo = module_root / "fixtures/native_dispatch_driver/replay.mvo"
        for raw in replay_mvo.read_text(encoding="utf-8").splitlines():
            if raw.startswith("rng_seed="):
                fixture_seeds.append(int(raw.split("=", 1)[1]))
                break
        self.assertTrue(fixture_seeds, "no scenario seed fixture was found")
        for seed in fixture_seeds:
            self.assertEqual(seed, seed_value)
        self.assertEqual(len(set(fixture_seeds)), 1)

    def test_location_phase_rng_seed_validator_pins_value_in_production_library(self):
        """The production-library seed-equality gate pins the VALUE post-capture.

        ``validate_location_phase_rng_seed`` is the library-side counterpart to
        this module's test-only seed-contract helpers: it reads a captured
        observer log and asserts the sole ``miel-vliegt-native-location-phase-rng``
        ``phase=seed`` record carries the canonical value, failing closed with an
        actual-vs-expected diagnostic on any drift.
        """
        seed_value = artifacts.LOCATION_PHASE_RNG_SEED_VALUE

        def seed_line(*, value, sequence=3):
            return "MVD " + json.dumps({
                "schema": 1,
                "protocol": "miel-vliegt-native-location-phase-rng",
                "sequence": sequence,
                "phase": "seed",
                "ordinal": artifacts.UINT32_MAX,
                "value": value,
                "caller_rva": "0x00030a8a",
                "count": 0,
                "sha256": None,
                "thread_id": 1,
            }, separators=(",", ":"))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            # Positive: a canonical seed record validates and round-trips.
            canonical = root / "canonical.log"
            canonical.write_text(
                seed_line(value=seed_value) + "\n", encoding="utf-8")
            validated = artifacts.validate_location_phase_rng_seed(canonical)
            self.assertEqual(validated["value"], seed_value)
            self.assertEqual(validated["phase"], "seed")

            # False-green guard: a wrong seed value MUST fail with an
            # actual-vs-expected diagnostic (the regression this gate catches).
            wrong = root / "wrong.log"
            wrong.write_text(
                seed_line(value=seed_value + 1) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError,
                r"seed value drifted.*expected %d.*got %d"
                % (seed_value, seed_value + 1),
            ):
                artifacts.validate_location_phase_rng_seed(wrong)

            # A log with no seed record fails closed.
            empty = root / "empty.log"
            empty.write_text(
                'MVD {"schema":1,"protocol":"miel-vliegt-native-flight-'
                'activation-rng","sequence":0,"phase":"draw","ordinal":0,'
                '"value":1,"caller_rva":"0x00032f3d","thread_id":1}\n',
                encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, r"seed record missing"):
                artifacts.validate_location_phase_rng_seed(empty)

            # Multiple seed records fail closed (the seed must be unique).
            duplicate = root / "duplicate.log"
            duplicate.write_text(
                seed_line(value=seed_value, sequence=3) + "\n"
                + seed_line(value=seed_value, sequence=4) + "\n",
                encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, r"seed record is not unique"):
                artifacts.validate_location_phase_rng_seed(duplicate)

            # A structurally drifted seed record fails closed.
            drifted = root / "drifted.log"
            drifted.write_text(
                "MVD " + json.dumps({
                    "schema": 1,
                    "protocol": "miel-vliegt-native-location-phase-rng",
                    "sequence": 3,
                    "phase": "seed",
                    "value": seed_value,
                    "caller_rva": "0x00030a8a",
                }, separators=(",", ":")) + "\n",
                encoding="utf-8")
            with self.assertRaises(artifacts.ArtifactError):
                artifacts.validate_location_phase_rng_seed(drifted)

    def test_initial_state_restore_purges_native_login_placeholders_when_requested(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "suite"
            root.mkdir()
            value = scenario(root)
            value["initial_state"]["values"] = []
            state_root = Path(temporary) / "game"
            user_root = state_root / "Data/User"
            user_root.mkdir(parents=True)
            for user_id in range(1, 11):
                (user_root / f"user{user_id}.dat").write_bytes(b"placeholder")

            receipt = artifacts.restore_scenario_initial_state_files(
                value,
                artifact_root=root,
                state_root=state_root,
                role_targets={"fixture": "Data/User/user0.dat"},
                purge_undeclared_files=True,
            )

            self.assertEqual(
                receipt["removed_files"],
                sorted(f"Data/User/user{user_id}.dat" for user_id in range(1, 11)),
            )
            self.assertEqual(
                sorted(path.name for path in user_root.iterdir()), ["user0.dat"],
            )
            self.assertEqual(
                receipt["managed_directories"][0]["owner_uid"],
                __import__("os").geteuid(),
            )

    def test_initial_state_restore_rejects_a_state_directory_owned_by_another_uid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "suite"
            root.mkdir()
            value = scenario(root)
            value["initial_state"]["values"] = []
            state_root = Path(temporary) / "game"
            (state_root / "Data/User").mkdir(parents=True)
            with patch(
                "tools.miel_vliegt.native_scenario_artifacts.os.geteuid",
                return_value=__import__("os").geteuid() + 1,
            ):
                with self.assertRaisesRegex(artifacts.ArtifactError, "not owned"):
                    artifacts.restore_scenario_initial_state_files(
                        value,
                        artifact_root=root,
                        state_root=state_root,
                        role_targets={"fixture": "Data/User/user0.dat"},
                    )
    def test_tracked_catalog_materializes_seven_capture_specs_without_evidence_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            initial_state = scenario(root)["initial_state"]
            catalog = artifacts.build_tracked_scenario_catalog(initial_state, root=root)
            self.assertEqual([row["id"] for row in catalog], list(artifacts.SCENARIO_ID_ORDER))
            self.assertTrue(all(row["evidence_status"] == "CAPTURE_SPEC_ONLY" for row in catalog))
            self.assertTrue(all(
                all(sample["dt_f32_bits"] == artifacts.NATURAL_DT_F32_BITS
                    and sample["monotonic_ns"] == sample["tick"] * artifacts.NATURAL_DT_NS
                    for sample in row["clock_transcript"]["samples"])
                for row in catalog
            ))
            controls = catalog[0]
            key_events = [event for event in controls["input_script"]["events"]
                          if event["type"] == "key"]
            self.assertEqual({event["key"] for event in key_events}, set(artifacts.CONTROL_KEYS))
            focus = [event["active"] for event in controls["input_script"]["events"]
                     if event["type"] == "focus"]
            self.assertEqual(focus, [False, True])
            replay_rows = artifacts.build_native_replay_script(
                controls, root=root,
            ).decode().splitlines()[-controls["input_script"]["tick_count"]:]
            masks = [int(row.split()[2], 16) for row in replay_rows]
            self.assertTrue(any(mask & 0x03 == 0x03 for mask in masks))
            self.assertTrue(any(mask & 0x0c == 0x0c for mask in masks))
            expectations = {row["id"]: {item["channel"]: item["presence"]
                                         for item in row["outcome_expectations"]}
                            for row in catalog}
            taxi = next(row for row in catalog if row["id"] == "taxi-straight")
            self.assertIn("airborne acceleration", taxi["description"])
            self.assertEqual(expectations["taxi-straight"]["outcome.contact"], "forbidden")
            self.assertEqual(expectations["impact-crash"]["outcome.crash"], "required")
            self.assertEqual(expectations["approach-landing"]["outcome.crash"], "forbidden")

    def test_scenario_transcripts_are_strict_balanced_and_hash_stable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = scenario(root)
            reordered = {key: value[key] for key in reversed(value)}
            self.assertEqual(
                artifacts.scenario_sha256(value, root=root),
                artifacts.scenario_sha256(reordered, root=root),
            )
            broken = copy.deepcopy(value)
            broken["input_script"]["events"][0]["action"] = "up"
            with self.assertRaisesRegex(artifacts.ArtifactError, "not pressed"):
                artifacts.validate_scenario(broken, root=root)
            broken = copy.deepcopy(value)
            broken["clock_transcript"]["samples"].pop()
            with self.assertRaisesRegex(artifacts.ArtifactError, "every tick"):
                artifacts.validate_scenario(broken, root=root)
            broken = copy.deepcopy(value)
            broken["rng_transcript"]["draws"][0]["sequence"] = True
            with self.assertRaisesRegex(artifacts.ArtifactError, "sequence"):
                artifacts.validate_scenario(broken, root=root)
            broken = copy.deepcopy(value)
            broken["initial_state"]["files"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(artifacts.ArtifactError, "hash drifted"):
                artifacts.validate_scenario(broken, root=root)

    def test_rng_calibration_copies_only_native_transcript_then_revalidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = scenario(root)
            value["rng_transcript"]["reseeds"] = []
            value["rng_transcript"]["draws"] = []
            trace = {
                "profile": "production-session", "complete": True,
                "records": [
                    {"channel": "rng.seed", "tick": artifacts.UINT32_MAX,
                     "values": {"ordinal": 0, "value": 7}},
                    {"channel": "rng.seed", "tick": artifacts.UINT32_MAX,
                     "values": {"ordinal": 1, "value": 7}},
                    {"channel": "rng.seed", "tick": 1,
                     "values": {"ordinal": 2, "value": 99}},
                    {"channel": "rng.draw", "tick": 2,
                     "values": {"ordinal": 0, "value": 42}},
                ],
            }
            with patch.object(artifacts, "_validate_trace_against_scenario") as validate:
                calibrated = artifacts.calibrate_scenario_rng_transcript(
                    value, trace, root=root,
                )
            self.assertEqual(calibrated["rng_transcript"]["reseeds"], [
                {"sequence": 0, "tick": 1, "value_u32": 99},
            ])
            self.assertEqual(calibrated["rng_transcript"]["draws"], [
                {"sequence": 0, "tick": 2, "value_u32": 42},
            ])
            validate.assert_called_once_with(trace, calibrated)
            self.assertEqual(value["rng_transcript"]["draws"], [])

    def test_focus_events_suspend_native_keys_and_must_reactivate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = scenario(root)
            value["input_script"] = {
                "tick_count": 5,
                "events": [
                    {"sequence": 0, "tick": 0, "type": "key", "key": "left", "action": "down"},
                    {"sequence": 1, "tick": 1, "type": "focus", "active": False},
                    {"sequence": 2, "tick": 3, "type": "focus", "active": True},
                    {"sequence": 3, "tick": 4, "type": "key", "key": "left", "action": "up"},
                ],
            }
            value["clock_transcript"]["samples"] = [
                {"tick": tick, "monotonic_ns": tick * 20_000_000,
                 "dt_f32_bits": f32(0x3CA3D70A)} for tick in range(5)
            ]
            value["checkpoints"] = [
                {"id": "reactivated", "tick": 4, "required_channels": ["input.sample"]}
            ]
            replay = artifacts.build_native_replay_script(value, root=root).decode("ascii")
            self.assertIn("MVO_REPLAY_V3", replay)
            self.assertIn("1 3ca3d70a 01 0", replay)
            self.assertIn("3 3ca3d70a 01 1", replay)
            self.assertIn("focus_event_count=2", replay)
            self.assertIn("focus_event.0=1 0 0 0", replay)
            self.assertIn("focus_event.1=3 1 0 40000000", replay)
            self.assertEqual(
                artifacts._native_manager_tick_schedule(value), [0, 3, 4],
            )
            broken = copy.deepcopy(value)
            broken["input_script"]["events"].pop(2)
            broken["input_script"]["events"][2]["sequence"] = 2
            with self.assertRaisesRegex(artifacts.ArtifactError, "reactivate|focus"):
                artifacts.validate_scenario(broken, root=root)
            key_while_unfocused = copy.deepcopy(value)
            key_while_unfocused["input_script"]["events"].insert(2, {
                "sequence": 2, "tick": 2, "type": "key",
                "key": "right", "action": "down",
            })
            for sequence, event in enumerate(
                key_while_unfocused["input_script"]["events"],
            ):
                event["sequence"] = sequence
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "manager-tick-bound",
            ):
                artifacts.validate_scenario(key_while_unfocused, root=root)

    def test_focus_timeline_receipt_binds_dual_clock_order_and_lateness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = scenario(root)
            value["input_script"] = {
                "tick_count": 5,
                "events": [
                    {"sequence": 0, "tick": 0, "type": "key",
                     "key": "left", "action": "down"},
                    {"sequence": 1, "tick": 1, "type": "focus",
                     "active": False},
                    {"sequence": 2, "tick": 3, "type": "focus",
                     "active": True},
                    {"sequence": 3, "tick": 4, "type": "key",
                     "key": "left", "action": "up"},
                ],
            }
            value["clock_transcript"]["samples"] = [
                {"tick": tick, "monotonic_ns": tick * 20_000_000,
                 "dt_f32_bits": f32(0x3CA3D70A)} for tick in range(5)
            ]
            value["checkpoints"] = [
                {"id": "reactivated", "tick": 4,
                 "required_channels": ["input.sample"]}
            ]
            value = artifacts.validate_scenario(value, root=root)
            timeline = artifacts._focus_timeline(value)
            scenario_hash = artifacts.canonical_sha256(value)
            timeline_hash = artifacts._focus_timeline_sha256(timeline)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-focus-timeline",
                "scenario": value["id"],
                "scenario_sha256": scenario_hash,
                "timeline_sha256": timeline_hash,
                "clock": "query_performance_counter",
                "origin": "episode-focus-loss",
                "thread_id": 77,
            }
            rows = [
                {**common, "sequence": 10, "phase": "start",
                 "episode": 0, "event_count": 2},
                {**common, "sequence": 11, "phase": "event",
                 "ordinal": 0, "episode": 0, "tick": 1,
                 "active": False, "scheduled_offset_ns": 0,
                 "applied_offset_ns": 0,
                 "lateness_ns": 0},
                {**common, "sequence": 12, "phase": "event",
                 "ordinal": 1, "episode": 0, "tick": 3,
                 "active": True, "scheduled_offset_ns": 40_000_000,
                 "applied_offset_ns": 42_000_000,
                 "lateness_ns": 2_000_000},
                {**common, "sequence": 13, "phase": "complete",
                 "episode": 0, "event_count": 2},
            ]
            log = root / "focus.log"
            log.write_text(
                "".join(
                    "MVD " + json.dumps(row, separators=(",", ":")) + "\n"
                    for row in rows
                ),
                encoding="utf-8",
            )
            receipt = artifacts.extract_focus_timeline_receipt(
                log, value, root=root,
            )
            self.assertEqual(receipt["event_count"], 2)
            self.assertEqual(receipt["events"][0]["applied_offset_ns"], 0)
            self.assertEqual(receipt["events"][1]["applied_offset_ns"],
                             42_000_000)
            rows[1]["applied_offset_ns"] = 1
            rows[1]["lateness_ns"] = 1
            log.write_text(
                "".join(
                    "MVD " + json.dumps(row, separators=(",", ":")) + "\n"
                    for row in rows
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "chronology",
            ):
                artifacts.extract_focus_timeline_receipt(
                    log, value, root=root,
                )
            rows[1]["applied_offset_ns"] = 0
            rows[1]["lateness_ns"] = 0
            rows[2]["applied_offset_ns"] = (
                rows[2]["scheduled_offset_ns"]
                + artifacts.FOCUS_TIMELINE_LATE_LIMIT_NS + 1
            )
            rows[2]["lateness_ns"] = (
                artifacts.FOCUS_TIMELINE_LATE_LIMIT_NS + 1
            )
            log.write_text(
                "".join(
                    "MVD " + json.dumps(row, separators=(",", ":")) + "\n"
                    for row in rows
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "chronology",
            ):
                artifacts.extract_focus_timeline_receipt(
                    log, value, root=root,
                )

    def test_scenario_compiles_to_byte_stable_native_tick_key_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay = artifacts.build_native_replay_script(scenario(root), root=root)
            lines = replay.decode("ascii").splitlines()
            self.assertEqual(lines[:10], [
                "MVO_REPLAY_V3", "scenario=level-flight-turn",
                f"scenario_sha256={artifacts.canonical_sha256(artifacts.validate_scenario(scenario(root), root=root))}",
                "focus_event_count=0",
                "focus_timeline_sha256="
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855",
                "flight_activation_seed=7", "rng_seed=7", "capture_tick=2",
                "complete_tick=2", "state_count=39",
            ])
            self.assertEqual(lines[-3:], [
                "0 3ca3d70a 01 1", "1 3ca3d70a 01 1", "2 3ca3d70a 00 1",
            ])

    def test_particle_lifecycle_is_pointer_free_paired_and_canonical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-particle-lifecycle",
                "tick": 0,
                "type": "flight-emitter",
                "ordinal": 0,
                "flag_38": 0,
                "flag_50": 0,
                "f32": ["0x00000000"] * 17,
                "thread_id": 7,
            }
            rows = []
            for sequence, phase in enumerate(("TICK_BEFORE", "TICK_AFTER")):
                rows.append({
                    **common, "sequence": sequence, "phase": phase,
                    "call_id": 0, "dt_f32_bits": "0x3ca3d70a",
                    "child_count": 0, "child_array_present": False,
                    "source_present": False,
                    "phase_f32_bits": "0x00000000",
                    "source_f32_bits": "0x00000000",
                    "audio_f32_bits": "0x00000000",
                    "position_f32": ["0x00000000"] * 3,
                    "render_present": False,
                    "render_f32": ["0x00000000"] * 15,
                })
            for sequence, phase in enumerate(("RESET_BEFORE", "RESET_AFTER"), 2):
                rows.append({
                    **common, "sequence": sequence, "phase": phase,
                    "reset_id": 0, "caller_site": "0x00433e93",
                })
            trace = root / "particle.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_particle_lifecycle(trace)
            self.assertEqual(extracted["count"], 4)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", extracted["records"][0])

            dead_state_rows = json.loads(json.dumps(rows))
            for row in dead_state_rows:
                row["f32"][9:12] = ["0x11111111", "0x22222222", "0x33333333"]
                row["f32"][16] = "0x44444444"
            dead_state_trace = root / "particle-dead-state.log"
            dead_state_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":"))
                for row in dead_state_rows
            ) + "\n", encoding="utf-8")
            self.assertEqual(
                artifacts.extract_particle_lifecycle(dead_state_trace)["sha256"],
                extracted["sha256"],
            )

            active_state_rows = json.loads(json.dumps(rows))
            for row in active_state_rows[:2]:
                row["flag_38"] = 1
                row["f32"][9] = "0x3f800000"
            active_state_trace = root / "particle-active-state.log"
            active_state_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":"))
                for row in active_state_rows
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_particle_lifecycle(active_state_trace)["sha256"],
                extracted["sha256"],
            )

    def test_particle_activation_is_pointer_free_paired_and_canonical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-particle-activation",
                "manager_tick": 12,
                "event_id": 0,
                "caller_site": "0x00433e00",
                "type": "flight-emitter",
                "ordinal": 0,
                "flag_38": 0,
                "flag_50": 0,
                "f32": ["0x00000000"] * 17,
                "thread_id": 7,
            }
            rows = []
            for sequence, phase in enumerate(("PLACE_BEFORE", "PLACE_AFTER")):
                rows.append({
                    **common, "sequence": sequence, "phase": phase,
                    "dt_f32_bits": "0x00000000", "input_present": True,
                    "input_f32": ["0x00000000"] * 3,
                    "child_count": 0,
                    "position_f32": ["0x00000000"] * 3,
                })
            for sequence, phase in enumerate(("RESET_BEFORE", "RESET_AFTER"), 2):
                rows.append({
                    **common, "sequence": sequence, "phase": phase,
                })
            trace = root / "particle-activation.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_particle_activation_lifecycle(trace)
            self.assertEqual(extracted["count"], 4)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", extracted["records"][0])

    def test_render_presentation_is_pointer_free_paired_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-render-presentation",
                "tick": 3,
                "manager_render": 14,
                "call_id": 0,
                "thread_id": 7,
            }
            rows = []
            for sequence, phase in enumerate(("BEFORE", "AFTER")):
                rows.append({
                    **common, "sequence": sequence, "kind": "render-list",
                    "phase": phase, "node_count": 1, "ordinal": 0,
                    "dt_f32_bits": "0x3ca3d70a",
                    "position_f32": ["0x00000000"] * 3,
                    "vtable": "mullemeck.exe+0x0004d34c",
                    "visible_method": "mullemeck.exe+0x00033010",
                    "prepare_method": "mullemeck.exe+0x00033020",
                    "phase_method": "mullemeck.exe+0x00033030",
                    "draw_method": "cc.dll+0x00001000",
                })
            track_a = {
                "present": True,
                "f32": ["0x00000000"] * 6,
            }
            track_b = {
                "present": True,
                "flag_6d": 1,
                "f32": ["0x00000000"] * 7,
            }
            for sequence, phase in enumerate(("BEFORE", "AFTER"), 2):
                rows.append({
                    **common, "sequence": sequence, "kind": "airplane",
                    "phase": phase,
                    "owner_vtable": "mullemeck.exe+0x0000c9fc",
                    "source_present": True, "world_present": True,
                    "anchor_f32": ["0x00000000"] * 3,
                    "track_a": copy.deepcopy(track_a),
                    "track_b": copy.deepcopy(track_b),
                })
            trace = root / "render-presentation.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_render_presentation(trace)
            self.assertEqual(extracted["count"], 4)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["track_b"]["f32"][3] = "0x3f800000"
            changed_trace = root / "render-presentation-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_render_presentation(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_render_is_pointer_free_paired_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-render",
                "tick": 3,
                "manager_render": 14,
                "parent_call_id": 0,
                "call_id": 0,
                "target_vtable": "mullemeck.exe+0x0004c9fc",
                "surface_present": True,
                "resource_present": True,
                "room_present": True,
                "surface_active": 1,
                "render_mode_f32_bits": "0x3f800000",
                "transform_f32": ["0x00000000"] * 6,
                "mask_u16": ["0x0000"] * 17,
                "thread_id": 7,
            }
            rows = [
                {**common, "sequence": sequence, "phase": phase}
                for sequence, phase in enumerate(("BEFORE", "AFTER"))
            ]
            trace = root / "shadow-render.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_shadow_render(trace)
            self.assertEqual(extracted["count"], 2)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["mask_u16"][4] = "0x0001"
            changed_trace = root / "shadow-render-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_shadow_render(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_camera_render_is_pointer_free_paired_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-camera-render",
                "tick": 3,
                "manager_render": 14,
                "parent_shadow_call_id": 0,
                "call_id": 0,
                "render_shadow": True,
                "camera_vtable": "cc.dll+0x00052138",
                "gate_968": 1,
                "gate_969": 1,
                "room_present": True,
                "device_present": True,
                "clip_present": True,
                "scratch_present": True,
                "render_flags_u8": [0, 0, 0, 1],
                "projection_f32": ["0x00000000"] * 17,
                "transform_f32": ["0x00000000"] * 14,
                "saved_transform_f32": ["0x00000000"] * 14,
                "thread_id": 7,
            }
            rows = [
                {**common, "sequence": sequence, "phase": phase}
                for sequence, phase in enumerate(("BEFORE", "AFTER"))
            ]
            trace = root / "shadow-camera-render.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_shadow_camera_render(trace)
            self.assertEqual(extracted["count"], 2)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["projection_f32"][8] = "0x3f800000"
            changed_trace = root / "shadow-camera-render-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_shadow_camera_render(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_render_room_is_pointer_free_paired_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-render-room",
                "tick": 3,
                "manager_render": 14,
                "parent_camera_call_id": 0,
                "call_id": 0,
                "camera_vtable": "mullemeck.exe+0x0004c998",
                "room_vtable": "cc.dll+0x00053218",
                "clip_vtable": "cc.dll+0x00053110",
                "collect_objects": 1,
                "recursion_depth": 0,
                "room_links": [True, False, True, False, False],
                "clip_links": [True, True],
                "camera_transient_present": False,
                "thread_id": 7,
            }
            rows = [
                {**common, "sequence": sequence, "phase": phase}
                for sequence, phase in enumerate(("BEFORE", "AFTER"))
            ]
            trace = root / "shadow-render-room.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_shadow_render_room(trace)
            self.assertEqual(extracted["count"], 2)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["room_links"][2] = False
            changed_trace = root / "shadow-render-room-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_shadow_render_room(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_visible_objects_is_paired_ordered_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-visible-objects",
                "tick": 3,
                "manager_render": 14,
                "parent_room_call_id": 0,
                "call_id": 0,
                "thread_id": 7,
            }
            rows = []
            sequence = 0
            for phase in ("BEFORE", "AFTER"):
                rows.append({
                    **common, "sequence": sequence, "kind": "call",
                    "phase": phase,
                    "room_vtable": "cc.dll+0x000534f4",
                    "camera_vtable": "mullemeck.exe+0x0004c998",
                    "chain_count": 1,
                    "render_list_present": [False] * 11,
                })
                sequence += 1
                rows.append({
                    **common, "sequence": sequence, "kind": "object",
                    "phase": phase, "ordinal": 0, "chain_count": 1,
                    "object_vtable": "cc.dll+0x0005357c",
                    "flags_u8": [1, 0, 1, 0, 0, 1],
                    "geometry_present": True,
                    "relation_matches_camera": False,
                    "mode_u32": 0,
                    "child_count": 0,
                    "children_array_present": False,
                    "render_link_present": phase == "AFTER",
                    "geometry_extent_f32": "0x3f800000",
                    "derived_f32": ["0x00000000"] * 7,
                    "transform_f32": ["0x00000000"] * 14,
                })
                sequence += 1
            trace = root / "shadow-visible-objects.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_shadow_visible_objects(trace)
            self.assertEqual(extracted["count"], 4)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["derived_f32"][3] = "0x3f800000"
            changed_trace = root / "shadow-visible-objects-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_shadow_visible_objects(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_visible_polygons_is_paired_pointer_free_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-visible-polygons",
                "tick": 3,
                "manager_render": 14,
                "parent_room_call_id": 0,
                "call_id": 0,
                "object_vtable": "cc.dll+0x000535e4",
                "camera_vtable": "mullemeck.exe+0x0004c998",
                "outline_enabled": False,
                "object_outline_u8": 0,
                "object_outline_f32": "0x00000000",
                "camera_mirror_u8": 0,
                "geometry_present": True,
                "topology_present": True,
                "polygon_count": 12,
                "transform_f32": ["0x00000000"] * 14,
                "render_list_present": [False] * 11,
                "thread_id": 7,
            }
            rows = [
                {
                    **common, "sequence": 0, "phase": "BEFORE",
                    "render_list_head_changed": [False] * 11,
                },
                {
                    **common, "sequence": 1, "phase": "AFTER",
                    "render_list_head_changed": [False] * 4 + [True] + [False] * 6,
                },
            ]
            trace = root / "shadow-visible-polygons.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_shadow_visible_polygons(trace)
            self.assertEqual(extracted["count"], 2)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("object_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["transform_f32"][3] = "0x3f800000"
            changed_trace = root / "shadow-visible-polygons-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_shadow_visible_polygons(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_polygon_render_is_ordered_pointer_free_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = [{
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-polygon-render",
                "sequence": 0,
                "tick": 3,
                "manager_render": 14,
                "parent_room_call_id": 0,
                "call_id": 0,
                "polygon_vtable": "cc.dll+0x00053648",
                "object_vtable": "cc.dll+0x000535e4",
                "camera_vtable": "mullemeck.exe+0x0004c998",
                "material_type": "CcMaterial",
                "material_flags_u8": 1,
                "material_f32": ["0x3f800000"] * 7,
                "mode_u32": 0,
                "material_present": True,
                "camera_mirror_u8": 0,
                "camera_projection_f32": "0x3f800000",
                "vertex_indices": [1, 2, 3],
                "owner_transform_f32": ["0x00000000"] * 14,
                "vertex_f32": [["0x00000000"] * 4 for _ in range(3)],
                "vertex_cache_u8": [0, 1, 0],
                "thread_id": 7,
            }]
            trace = root / "shadow-polygon-render.log"
            trace.write_text(
                "MVD " + json.dumps(rows[0], separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            extracted = artifacts.extract_shadow_polygon_render(trace)
            self.assertEqual(extracted["count"], 1)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("polygon_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[0]["vertex_f32"][2][1] = "0x3f800000"
            changed_trace = root / "shadow-polygon-render-changed.log"
            changed_trace.write_text(
                "MVD " + json.dumps(changed[0], separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            self.assertNotEqual(
                artifacts.extract_shadow_polygon_render(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_world_relation_is_recursive_paired_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-world-relation",
                "tick": 3,
                "manager_render": 14,
                "parent_room_call_id": 0,
                "parent_world_call_id": 4294967295,
                "call_id": 0,
                "depth": 0,
                "node_vtable": "cc.dll+0x000535e4",
                "parent_vtable": "cc.dll+0x00053580",
                "geometry_vtable": "cc.dll+0x000534fc",
                "geometry_polygon_count": 80,
                "geometry_extent_f32": "0x3f800000",
                "rotation_mode_u32": 0,
                "cache_u32": [1, 2],
                "local_rotation_f32": ["0x00000000"] * 11,
                "rotation_aux_f32": ["0x00000000"] * 9,
                "world_transform_f32": ["0x00000000"] * 14,
                "thread_id": 7,
            }
            rows = [
                {**common, "sequence": 0, "phase": "BEFORE", "return_u8": 255},
                {**common, "sequence": 1, "phase": "AFTER", "return_u8": 1},
            ]
            trace = root / "shadow-world-relation.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_shadow_world_relation(trace)
            self.assertEqual(extracted["count"], 2)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("node_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["local_rotation_f32"][0] = "0x3f800000"
            changed_trace = root / "shadow-world-relation-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_shadow_world_relation(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_shadow_rotation_setter_is_paired_structural_and_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "schema": 1,
                "protocol": "miel-vliegt-native-shadow-rotation-setter",
                "tick": 3,
                "manager_render": 14,
                "call_id": 0,
                "caller": "mullemeck.exe+0x00010b4a",
                "angle_f32": "0x3c23d70a",
                "owner_vtable": "cc.dll+0x00053580",
                "parent_vtable": "cc.dll+0x00053580",
                "object_ordinal": 2,
                "object_vtable": "cc.dll+0x000535e4",
                "geometry_vtable": "cc.dll+0x000534fc",
                "geometry_polygon_count": 80,
                "geometry_extent_f32": "0x3fa74310",
                "local_rotation_f32": ["0x00000000"] * 11,
                "thread_id": 7,
            }
            rows = [
                {**common, "sequence": 0, "phase": "BEFORE"},
                {**common, "sequence": 1, "phase": "AFTER"},
            ]
            trace = root / "shadow-rotation-setter.log"
            trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in rows
            ) + "\n", encoding="utf-8")
            extracted = artifacts.extract_shadow_rotation_setter(trace)
            self.assertEqual(extracted["count"], 2)
            self.assertNotIn("thread_id", extracted["records"][0])
            self.assertNotIn("matrix_address", json.dumps(extracted))

            changed = copy.deepcopy(rows)
            changed[-1]["local_rotation_f32"][0] = "0x3f800000"
            changed_trace = root / "shadow-rotation-setter-changed.log"
            changed_trace.write_text("\n".join(
                "MVD " + json.dumps(row, separators=(",", ":")) for row in changed
            ) + "\n", encoding="utf-8")
            self.assertNotEqual(
                artifacts.extract_shadow_rotation_setter(changed_trace)["sha256"],
                extracted["sha256"],
            )

    def test_v3_binds_ordered_activation_clock_bits_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = scenario(root)
            bits = ["0x3ca3d70a", "0x3c888889"]
            value["rng_transcript"]["flight_activation_dt_f32_bits"] = bits
            replay = artifacts.build_native_replay_script(value, root=root).decode("ascii")
            digest = hashlib.sha256(b"".join(
                struct.pack("<II", index, int(item, 16))
                for index, item in enumerate(bits)
            )).hexdigest()
            self.assertIn("activation_tick_count=2\n", replay)
            self.assertIn("activation_dt.0=3ca3d70a\n", replay)
            self.assertIn("activation_dt.1=3c888889\n", replay)
            self.assertIn(f"activation_clock_sha256={digest}\n", replay)

    def test_semantic_log_is_correlated_and_canonical_without_thread_noise(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first.log"
            first.write_text("\n".join(semantic_lines()) + "\n", encoding="utf-8")
            second_lines = [line.replace('"thread_id":7', '"thread_id":99') for line in semantic_lines()]
            second = root / "second.log"
            second.write_text("\n".join(second_lines) + "\n", encoding="utf-8")
            parsed = artifacts.parse_semantic_log(first)
            other = artifacts.parse_semantic_log(second)
            self.assertEqual(parsed["semantic_sha256"], other["semantic_sha256"])
            self.assertNotEqual(parsed["raw_log_sha256"], other["raw_log_sha256"])
            self.assertEqual(parsed["thread_id"], 7)
            self.assertEqual(parsed["channel_counts"]["render.final"], 1)
            self.assertNotIn("diagnostics", parsed["records"][0])
            self.assertEqual(parsed["profile"], "legacy-semantic")
            self.assertFalse(parsed["complete"])

    def test_production_log_accepts_session_clock_rng_and_extended_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "production.log"
            path.write_text("\n".join(production_lines()) + "\n", encoding="utf-8")
            parsed = artifacts.parse_semantic_log(path, require_complete=True)
            self.assertEqual(parsed["profile"], "production-session")
            self.assertTrue(parsed["session_ready"])
            self.assertTrue(parsed["complete"])
            self.assertEqual(parsed["channel_counts"]["clock.tick"], 1)
            self.assertEqual(parsed["channel_counts"]["rng.seed"], 2)
            self.assertEqual(parsed["channel_counts"]["system.fuel"], 1)
            self.assertEqual(parsed["scenario_id"], "controls-press-hold-release")

            scheduler_variant = production_lines()
            clock_index = next(index for index, line in enumerate(scheduler_variant)
                               if '"clock.tick"' in line)
            clock = json.loads(scheduler_variant[clock_index][4:])
            clock["diagnostics"]["observed_dt_f32_bits"] = f32(0x3E99999A)
            scheduler_variant[clock_index] = "MVT " + json.dumps(
                clock, separators=(",", ":"),
            )
            path.write_text("\n".join(scheduler_variant) + "\n", encoding="utf-8")
            other = artifacts.parse_semantic_log(path, require_complete=True)
            self.assertEqual(parsed["semantic_sha256"], other["semantic_sha256"])
            self.assertNotEqual(parsed["raw_log_sha256"], other["raw_log_sha256"])

            new_wire = production_lines()
            focus_index = next(index for index, line in enumerate(new_wire)
                               if '"input.focus"' in line)
            focus = json.loads(new_wire[focus_index][4:])
            focus["diagnostics"]["process_id"] = focus["values"].pop("process_id")
            focus["diagnostics"]["window_thread_id"] = focus["values"].pop(
                "window_thread_id"
            )
            new_wire[focus_index] = "MVT " + json.dumps(
                focus, separators=(",", ":"),
            )
            rng_index = next(index for index, line in enumerate(new_wire)
                             if '"rng.seed"' in line)
            rng = json.loads(new_wire[rng_index][4:])
            rng["diagnostics"]["caller_rva"] = "0x0000ee49"
            new_wire[rng_index] = "MVT " + json.dumps(
                rng, separators=(",", ":"),
            )
            path.write_text("\n".join(new_wire) + "\n", encoding="utf-8")
            normalized = artifacts.parse_semantic_log(path, require_complete=True)
            self.assertEqual(parsed["semantic_sha256"], normalized["semantic_sha256"])
            focus_record = next(record for record in normalized["records"]
                                if record["channel"] == "input.focus")
            self.assertNotIn("process_id", focus_record["values"])
            self.assertNotIn("window_thread_id", focus_record["values"])

            invalid_caller = new_wire.copy()
            rng["diagnostics"]["caller_rva"] = "0x0040ee49-too-wide"
            invalid_caller[rng_index] = "MVT " + json.dumps(
                rng, separators=(",", ":"),
            )
            path.write_text("\n".join(invalid_caller) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(artifacts.ArtifactError, "caller_rva"):
                artifacts.parse_semantic_log(path, require_complete=True)

            missing_ready = [line for line in production_lines() if '"session.ready"' not in line]
            for sequence, index in enumerate(range(1, len(missing_ready) - 1)):
                record = json.loads(missing_ready[index][4:])
                record["sequence"] = sequence
                missing_ready[index] = "MVT " + json.dumps(record, separators=(",", ":"))
            path.write_text("\n".join(missing_ready) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(artifacts.ArtifactError, "SESSION_READY|session.ready"):
                artifacts.parse_semantic_log(path, require_complete=True)

            missing_navigation = [
                line for line in production_lines()
                if '"session.navigating"' not in line
            ]
            for sequence, index in enumerate(range(1, len(missing_navigation) - 1)):
                record = json.loads(missing_navigation[index][4:])
                record["sequence"] = sequence
                missing_navigation[index] = "MVT " + json.dumps(
                    record, separators=(",", ":"),
                )
            path.write_text("\n".join(missing_navigation) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "session.navigating|deterministic session",
            ):
                artifacts.parse_semantic_log(path, require_complete=True)

            missing_armed = [
                line for line in production_lines() if '"session.armed"' not in line
            ]
            for sequence, index in enumerate(range(1, len(missing_armed) - 1)):
                record = json.loads(missing_armed[index][4:])
                record["sequence"] = sequence
                missing_armed[index] = "MVT " + json.dumps(
                    record, separators=(",", ":"),
                )
            path.write_text("\n".join(missing_armed) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(artifacts.ArtifactError, "session.armed"):
                artifacts.parse_semantic_log(path, require_complete=True)

            for source_channel, insert_after, message in (
                ("session.armed", "session.armed", "session.armed"),
                ("session.ready", "session.ready", "session.ready"),
                ("session.navigating", "session.armed", "session.navigating"),
            ):
                invalid = production_lines()
                source = next(
                    line for line in invalid if f'"{source_channel}"' in line
                )
                insertion = next(
                    index for index, line in enumerate(invalid)
                    if f'"{insert_after}"' in line
                ) + 1
                invalid.insert(insertion, source)
                for sequence, index in enumerate(range(1, len(invalid) - 1)):
                    record = json.loads(invalid[index][4:])
                    record["sequence"] = sequence
                    invalid[index] = "MVT " + json.dumps(
                        record, separators=(",", ":"),
                    )
                path.write_text("\n".join(invalid) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(artifacts.ArtifactError, message):
                    artifacts.parse_semantic_log(path, require_complete=True)

    def test_production_input_proof_fails_closed_on_identity_transition_or_sample_drift(self):
        mutations = (
            ("input.focus", "valid", False, "projector window"),
            ("input.transition", "to_mask", "0x80", "control bit"),
            ("input.sample", "observed_mask", "0x01", "DirectInput state"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input-proof.log"
            for channel, field, value, message in mutations:
                lines = production_lines()
                index = next(index for index, line in enumerate(lines)
                             if f'"{channel}"' in line)
                record = json.loads(lines[index][4:])
                record["values"][field] = value
                lines[index] = "MVT " + json.dumps(record, separators=(",", ":"))
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(artifacts.ArtifactError, message):
                    artifacts.parse_semantic_log(path, require_complete=True)

    def test_focus_worker_records_are_exactly_bound_to_the_qpc_receipt(self):
        def renumber(lines: list[str]) -> None:
            sequence = 0
            for index, line in enumerate(lines):
                if not line.startswith("MVT "):
                    continue
                record = json.loads(line[4:])
                record["sequence"] = sequence
                sequence += 1
                lines[index] = "MVT " + json.dumps(
                    record, separators=(",", ":"),
                )

        def worker_indices(lines: list[str]) -> list[int]:
            return [
                index for index, line in enumerate(lines)
                if line.startswith("MVT ")
                and json.loads(line[4:])["diagnostics"]["thread_id"] == 99
            ]

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "focus-worker.log"
            lines = production_lines_with_focus_worker()
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            parsed = artifacts.parse_semantic_log(path, require_complete=True)
            self.assertEqual(parsed["thread_id"], 7)
            self.assertEqual(parsed["focus_worker_thread_id"], 99)

            third_thread = production_lines_with_focus_worker()
            index = worker_indices(third_thread)[-1]
            record = json.loads(third_thread[index][4:])
            record["diagnostics"]["thread_id"] = 100
            third_thread[index] = "MVT " + json.dumps(
                record, separators=(",", ":"),
            )
            path.write_text("\n".join(third_thread) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "crossed game threads",
            ):
                artifacts.parse_semantic_log(path, require_complete=True)

            non_event_tick = production_lines_with_focus_worker()
            index = worker_indices(non_event_tick)[-1]
            record = json.loads(non_event_tick[index][4:])
            record["tick"] = 3
            non_event_tick[index] = "MVT " + json.dumps(
                record, separators=(",", ":"),
            )
            path.write_text("\n".join(non_event_tick) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "not receipt-bound",
            ):
                artifacts.parse_semantic_log(path, require_complete=True)

            wrong_order = production_lines_with_focus_worker()
            first, second = worker_indices(wrong_order)[:2]
            wrong_order[first], wrong_order[second] = (
                wrong_order[second], wrong_order[first],
            )
            renumber(wrong_order)
            path.write_text("\n".join(wrong_order) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "not receipt-bound",
            ):
                artifacts.parse_semantic_log(path, require_complete=True)

            missing = production_lines_with_focus_worker()
            del missing[worker_indices(missing)[-1]]
            renumber(missing)
            path.write_text("\n".join(missing) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "binding is incomplete",
            ):
                artifacts.parse_semantic_log(path, require_complete=True)

            sample_on_worker = production_lines_with_focus_worker()
            sample_index = next(
                index for index, line in enumerate(sample_on_worker)
                if line.startswith("MVT ") and '"input.sample"' in line
            )
            record = json.loads(sample_on_worker[sample_index][4:])
            record["diagnostics"]["thread_id"] = 99
            sample_on_worker[sample_index] = "MVT " + json.dumps(
                record, separators=(",", ":"),
            )
            path.write_text(
                "\n".join(sample_on_worker) + "\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "non-focus semantic record",
            ):
                artifacts.parse_semantic_log(path, require_complete=True)

    def test_production_outcome_channels_have_exact_wire_shapes(self):
        lines = production_lines()
        outcome_values = [
            ("outcome.contact", {"kind": "correction"}),
            ("outcome.damage", {
                "effective_damage_f32_bits": f32(0x3F000000),
                "integrity_after_f32_bits": f32(0x3F000000),
                "terminal": False,
            }),
            ("outcome.crash", {"terminal": True}),
            ("outcome.terrain", {"class": 3}),
        ]
        insertion = len(lines) - 2
        for channel, values in outcome_values:
            lines.insert(insertion, "MVT " + json.dumps({
                "record": "outcome", "sequence": 0, "channel": channel,
                "tick": 0, "frame": 0, "values": values,
                "diagnostics": {"thread_id": 7},
            }, separators=(",", ":")))
            insertion += 1
        for sequence, index in enumerate(range(1, len(lines) - 1)):
            record = json.loads(lines[index][4:])
            record["sequence"] = sequence
            lines[index] = "MVT " + json.dumps(record, separators=(",", ":"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "outcomes.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            parsed = artifacts.parse_semantic_log(path, require_complete=True)
            for channel, _ in outcome_values:
                self.assertEqual(parsed["channel_counts"][channel], 1)
            broken = lines.copy()
            terrain_index = next(index for index, line in enumerate(broken)
                                 if '"outcome.terrain"' in line)
            broken[terrain_index] = broken[terrain_index].replace('"class":3', '"class":8')
            path.write_text("\n".join(broken) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(artifacts.ArtifactError, "terrain class"):
                artifacts.parse_semantic_log(path, require_complete=True)

    def test_semantic_log_accepts_explicit_pre_tick_render_sentinel(self):
        lines = semantic_lines()
        pre_tick = json.loads(lines[-1][4:])
        pre_tick["sequence"] = 0
        pre_tick["tick"] = artifacts.UINT32_MAX
        for index in range(1, len(lines)):
            record = json.loads(lines[index][4:])
            record["sequence"] += 1
            record["frame"] += 1
            lines[index] = "MVT " + json.dumps(record, separators=(",", ":"))
        lines.insert(1, "MVT " + json.dumps(pre_tick, separators=(",", ":")))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trace.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            parsed = artifacts.parse_semantic_log(path)
            self.assertEqual(parsed["records"][0]["tick"], artifacts.UINT32_MAX)
            self.assertEqual(parsed["records"][1]["tick"], 0)

    def test_semantic_log_rejects_gaps_unpaired_state_and_saturation(self):
        variants = []
        gap = semantic_lines()
        gap[2] = gap[2].replace('"sequence":1', '"sequence":2')
        variants.append((gap, "sequence"))
        unpaired = [line for line in semantic_lines() if '"phase":"leave"' not in line]
        for sequence, index in enumerate(range(1, len(unpaired))):
            record = json.loads(unpaired[index][4:])
            record["sequence"] = sequence
            unpaired[index] = "MVT " + json.dumps(record, separators=(",", ":"))
        variants.append((unpaired, "unmatched physics"))
        saturated = semantic_lines() + [
            'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
            '"status":"TRACE_LIMIT"}'
        ]
        variants.append((saturated, "TRACE_LIMIT"))
        uppercase = semantic_lines()
        uppercase[1] = uppercase[1].replace("0x3d23d70a", "0x3D23D70A")
        variants.append((uppercase, "f32"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trace.log"
            for lines, message in variants:
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(artifacts.ArtifactError, message):
                    artifacts.parse_semantic_log(path)

    def test_mode_transition_diagnostic_does_not_consume_semantic_sequence(self):
        diagnostic = (
            'MVD {"schema":1,"protocol":"miel-vliegt-native-mode-transition",'
            '"sequence":0,"phase":"entry","transition_id":0,'
            '"requested_mode":"mode_barn","requested_mode_valid":true,'
            '"return_byte":0,"immediate_activation":false,'
            '"pending_observed":false,"caller_site":"0x00428bb3",'
            '"source_mode":"mode_login","source_mode_valid":true,'
            '"thread_id":7}'
        )
        pending_failure = [
            'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
            '"status":"LOADED","thread_id":7}',
            'MVT {"record":"session","sequence":0,'
            '"channel":"session.dispatched","values":{'
            '"scenario":"default-airplane-fixed-camera-frame",'
            '"reason":"native_login_fsm"},"diagnostics":{"thread_id":7}}',
            'MVD {"schema":1,"protocol":"miel-vliegt-native-mode-transition",'
            '"sequence":0,"phase":"bootstrap_pending","transition_id":0,'
            '"requested_mode":"mode_login","requested_mode_valid":true,'
            '"return_byte":0,"immediate_activation":false,'
            '"pending_observed":true,"caller_site":"0x0041d763",'
            '"source_mode":"","source_mode_valid":false,"thread_id":7}',
            'MVT {"record":"session","sequence":1,'
            '"channel":"session.failed","values":{'
            '"scenario":"default-airplane-fixed-camera-frame",'
            '"reason":"first_mode_transition_not_startup_login"},'
            '"diagnostics":{"thread_id":7}}',
            'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
            '"status":"SCENARIO_FAILED","thread_id":7}',
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pending-bootstrap.log"
            baseline_lines = production_lines()
            path.write_text("\n".join(baseline_lines) + "\n", encoding="utf-8")
            baseline = artifacts.parse_semantic_log(path, require_complete=True)
            with_diagnostic = baseline_lines.copy()
            with_diagnostic.insert(2, diagnostic)
            path.write_text("\n".join(with_diagnostic) + "\n", encoding="utf-8")
            parsed = artifacts.parse_semantic_log(path, require_complete=True)
            self.assertEqual(parsed["semantic_sha256"], baseline["semantic_sha256"])
            self.assertEqual(parsed["record_count"], baseline["record_count"])

            malformed = with_diagnostic.copy()
            malformed[2] = malformed[2].replace('"sequence":0', '"sequence":1')
            path.write_text("\n".join(malformed) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "diagnostic sequence is non-contiguous",
            ):
                artifacts.parse_semantic_log(path, require_complete=True)

            for mutation, message in (
                ("old-missing-fields", "missing"),
                ("unknown-field", "unknown"),
                ("invalid-source-binding", "source_mode"),
            ):
                invalid = with_diagnostic.copy()
                row = json.loads(invalid[2][4:])
                if mutation == "old-missing-fields":
                    for field in ("caller_site", "source_mode", "source_mode_valid"):
                        del row[field]
                elif mutation == "unknown-field":
                    row["unreviewed"] = True
                else:
                    row["source_mode"] = ""
                invalid[2] = "MVD " + json.dumps(row, separators=(",", ":"))
                path.write_text("\n".join(invalid) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(artifacts.ArtifactError, message):
                    artifacts.parse_semantic_log(path, require_complete=True)

            path.write_text("\n".join(pending_failure) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                artifacts.ArtifactError,
                "production session failed: first_mode_transition_not_startup_login",
            ):
                artifacts.parse_semantic_log(path)

    def test_raw_framebuffer_metadata_binds_layout_length_and_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frame = root / "frame.raw"
            frame.write_bytes(painted_framebuffer_bytes())
            metadata = framebuffer_metadata(
                frame,
                scenario_id="default-airplane-fixed-camera-frame",
                scenario_sha256="1" * 64,
            )
            metadata_path = root / "frame.json"
            artifacts.write_canonical_json(metadata_path, metadata)
            self.assertEqual(
                artifacts.load_framebuffer_metadata(metadata_path, root=root)["raw_sha256"],
                metadata["raw_sha256"],
            )
            rgba = artifacts.canonicalize_native_framebuffer(
                metadata, frame.read_bytes(),
            )
            self.assertEqual(
                rgba[:16],
                bytes((
                    2, 1, 0, 255, 6, 5, 4, 255,
                    10, 9, 8, 255, 14, 13, 12, 255,
                )),
            )
            self.assertEqual(
                len(rgba),
                artifacts.FRAMEBUFFER_CLIENT_WIDTH
                * artifacts.FRAMEBUFFER_CLIENT_HEIGHT
                * 4,
            )
            checkpoint = artifacts.build_native_framebuffer_checkpoint(
                metadata_path, root=root, checkpoint_id="reference-frame",
            )
            self.assertEqual(checkpoint["id"], "reference-frame")
            self.assertEqual(
                (checkpoint["width"], checkpoint["height"]),
                (
                    artifacts.FRAMEBUFFER_CLIENT_WIDTH,
                    artifacts.FRAMEBUFFER_CLIENT_HEIGHT,
                ),
            )
            self.assertEqual(checkpoint["reference_sha256"], hashlib.sha256(rgba).hexdigest())
            broken = dict(metadata, pitch=7)
            with self.assertRaisesRegex(artifacts.ArtifactError, "pitch"):
                artifacts.validate_framebuffer_metadata(broken)
            missing_gate = dict(metadata)
            del missing_gate["window_top_level"]
            with self.assertRaisesRegex(artifacts.ArtifactError, "fields differ"):
                artifacts.validate_framebuffer_metadata(missing_gate)
            wrong_client = dict(metadata, client_width=639)
            with self.assertRaisesRegex(artifacts.ArtifactError, "window readiness"):
                artifacts.validate_framebuffer_metadata(wrong_client)
            no_paint = dict(metadata, non_black_pixel_count=0)
            with self.assertRaisesRegex(artifacts.ArtifactError, "non_black_pixel_count"):
                artifacts.validate_framebuffer_metadata(no_paint)
            frame.write_bytes(bytes(len(frame.read_bytes())))
            metadata["raw_sha256"] = artifacts.sha256_file(frame)
            artifacts.write_canonical_json(metadata_path, metadata)
            with self.assertRaisesRegex(artifacts.ArtifactError, "non-black"):
                artifacts.load_framebuffer_metadata(metadata_path, root=root)
            tampered = bytearray(frame.read_bytes())
            tampered[0] = 1
            frame.write_bytes(tampered)
            with self.assertRaisesRegex(artifacts.ArtifactError, "hash drifted"):
                artifacts.load_framebuffer_metadata(metadata_path, root=root)

    def test_native_framebuffer_source_receipt_binds_rgb565_before_conversion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw_path = root / "frame.native.raw"
            width = artifacts.FRAMEBUFFER_CLIENT_WIDTH
            height = artifacts.FRAMEBUFFER_CLIENT_HEIGHT
            source_raw = bytearray(width * height * 2)
            source_raw[:2] = b"\x00\xf8"
            raw_path.write_bytes(source_raw)
            metadata = {
                "schema": artifacts.FRAMEBUFFER_SOURCE_VERSION,
                "protocol": artifacts.FRAMEBUFFER_SOURCE_PROTOCOL,
                "scenario": "default-airplane-fixed-camera-frame",
                "scenario_sha256": "1" * 64,
                "tick": 29,
                "width": width,
                "height": height,
                "pitch": width * 2,
                "bits_per_pixel": 16,
                "bytes_per_pixel": 2,
                "gt_format_id": 5,
                "gt_format_name": "RGB565",
                "image_size": width * height * 2,
                "raw_size": width * height * 2,
                "raw_sha256": artifacts.sha256_file(raw_path),
                "row_layout": "native_pitch_bytes",
                "origin": "top-left",
                "packed_format": "rgb565-le",
                "conversion": "rgb565-le-to-xrgb8888-le",
            }
            metadata_path = root / "frame.native.json"
            artifacts.write_canonical_json(metadata_path, metadata)
            self.assertEqual(
                artifacts.load_framebuffer_source_metadata(
                    metadata_path, root=root,
                )["gt_format_name"],
                "RGB565",
            )
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "source layout",
            ):
                artifacts.validate_framebuffer_source_metadata(
                    dict(metadata, conversion="identity"),
                )
            raw_path.write_bytes(b"\1" + raw_path.read_bytes()[1:])
            with self.assertRaisesRegex(artifacts.ArtifactError, "hash drifted"):
                artifacts.load_framebuffer_source_metadata(
                    metadata_path, root=root,
                )

    def test_framebuffer_derivation_rejects_individually_valid_forgery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            width = artifacts.FRAMEBUFFER_CLIENT_WIDTH
            height = artifacts.FRAMEBUFFER_CLIENT_HEIGHT
            source_path = root / "frame.native.raw"
            source_raw = bytearray(width * height * 2)
            source_raw[:2] = b"\x00\xf8"
            source_path.write_bytes(source_raw)
            source_metadata = {
                "schema": artifacts.FRAMEBUFFER_SOURCE_VERSION,
                "protocol": artifacts.FRAMEBUFFER_SOURCE_PROTOCOL,
                "scenario": "default-airplane-fixed-camera-frame",
                "scenario_sha256": "1" * 64,
                "tick": 29,
                "width": width,
                "height": height,
                "pitch": width * 2,
                "bits_per_pixel": 16,
                "bytes_per_pixel": 2,
                "gt_format_id": 5,
                "gt_format_name": "RGB565",
                "image_size": width * height * 2,
                "raw_size": width * height * 2,
                "raw_sha256": artifacts.sha256_file(source_path),
                "row_layout": "native_pitch_bytes",
                "origin": "top-left",
                "packed_format": "rgb565-le",
                "conversion": "rgb565-le-to-xrgb8888-le",
            }
            canonical_path = root / "frame.raw"
            canonical_raw = artifacts.canonicalize_framebuffer_source(
                source_metadata, bytes(source_raw),
            )
            self.assertEqual(canonical_raw[:4], b"\x00\x00\xff\x00")
            canonical_path.write_bytes(canonical_raw)
            canonical_metadata = framebuffer_metadata(
                canonical_path,
                scenario_id="default-airplane-fixed-camera-frame",
                scenario_sha256="1" * 64,
            )
            canonical_metadata["tick"] = 29
            derivation = artifacts.validate_framebuffer_derivation(
                source_metadata,
                bytes(source_raw),
                canonical_metadata,
                canonical_raw,
            )
            self.assertTrue(derivation["byte_exact"])
            self.assertTrue(derivation["pixel_parity_eligible"])
            self.assertEqual(derivation["origin"]["resolved"], "TOP_LEFT")
            self.assertEqual(derivation["origin"]["measured_pitch"], width * 2)

            forged = bytearray(canonical_raw)
            forged[:4] = b"\xff\x00\x00\x00"
            forged_path = root / "forged.raw"
            forged_path.write_bytes(forged)
            forged_metadata = dict(
                canonical_metadata,
                raw_sha256=artifacts.sha256_file(forged_path),
            )
            artifacts.validate_framebuffer_source_metadata(source_metadata)
            artifacts.validate_framebuffer_metadata(forged_metadata)
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "not derived from native source",
            ):
                artifacts.validate_framebuffer_derivation(
                    source_metadata,
                    bytes(source_raw),
                    forged_metadata,
                    bytes(forged),
                )

    def test_framebuffer_trace_binding_is_unique_and_profile_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frame = root / "frame.raw"
            frame.write_bytes(painted_framebuffer_bytes())
            metadata = framebuffer_metadata(
                frame,
                scenario_id="default-airplane-fixed-camera-frame",
                scenario_sha256="1" * 64,
            )
            exact_trace = {"records": [
                {"channel": "render.final", "tick": 0, "values": {}},
                {
                    "channel": "render.framebuffer",
                    "tick": 0,
                    "values": {
                        "raw_sha256": metadata["raw_sha256"],
                        "capture": "native_read_screen",
                    },
                },
            ]}
            self.assertTrue(
                artifacts.validate_framebuffer_trace_binding(
                    exact_trace, metadata, require_render_final=True,
                )["render_final_correlated"]
            )
            calibration_trace = {"records": [exact_trace["records"][1]]}
            calibration = artifacts.validate_framebuffer_trace_binding(
                calibration_trace, metadata, require_render_final=False,
            )
            self.assertEqual(calibration["profile"], "calibration-only")
            self.assertFalse(calibration["render_final_correlated"])
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "render.final correlation",
            ):
                artifacts.validate_framebuffer_trace_binding(
                    calibration_trace, metadata, require_render_final=True,
                )
            duplicate = {
                "records": exact_trace["records"] + [exact_trace["records"][1]],
            }
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "exactly one",
            ):
                artifacts.validate_framebuffer_trace_binding(
                    duplicate, metadata, require_render_final=True,
                )
            wrong_route = copy.deepcopy(exact_trace)
            wrong_route["records"][1]["values"]["capture"] = "desktop_copy"
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "exact trace binding",
            ):
                artifacts.validate_framebuffer_trace_binding(
                    wrong_route, metadata, require_render_final=True,
                )

    def test_candidate_receipt_binds_all_inputs_but_cannot_claim_promotion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario_value = scenario(root)
            scenario_value["input_script"] = {
                "tick_count": 1,
                "events": [
                    {"sequence": 0, "tick": 0, "type": "key", "key": "left", "action": "down"},
                    {"sequence": 1, "tick": 0, "type": "key", "key": "left", "action": "up"},
                ],
            }
            scenario_value["clock_transcript"]["samples"] = [
                {"tick": 0, "monotonic_ns": 0, "dt_f32_bits": f32(0x3CA3D70A)}
            ]
            scenario_value["rng_transcript"]["draws"] = []
            scenario_value["checkpoints"] = [{
                "id": "settled", "tick": 0,
                "required_channels": ["flight.tick", "render.framebuffer"],
            }]
            scenario_path = root / "scenario.json"
            artifacts.write_canonical_json(scenario_path, scenario_value)
            replay = root / "native-replay.txt"
            replay.write_bytes(artifacts.build_native_replay_script(scenario_value, root=root))
            log = root / "observer.log"
            frame = root / "frame.raw"
            frame.write_bytes(painted_framebuffer_bytes())
            log.write_text(
                "\n".join(production_lines(
                    identifier=scenario_value["id"],
                    raw_sha256=artifacts.sha256_file(frame),
                )) + "\n",
                encoding="utf-8",
            )
            metadata_path = root / "frame.json"
            artifacts.write_canonical_json(
                metadata_path,
                framebuffer_metadata(
                    frame,
                    scenario_id=scenario_value["id"],
                    scenario_sha256=artifacts.sha256_file(replay),
                ),
            )
            native_frame = root / "frame.native.raw"
            native_frame.write_bytes(frame.read_bytes())
            native_metadata_path = root / "frame.native.json"
            artifacts.write_canonical_json(native_metadata_path, {
                "schema": artifacts.FRAMEBUFFER_SOURCE_VERSION,
                "protocol": artifacts.FRAMEBUFFER_SOURCE_PROTOCOL,
                "scenario": scenario_value["id"],
                "scenario_sha256": artifacts.sha256_file(replay),
                "tick": 0,
                "width": artifacts.FRAMEBUFFER_CLIENT_WIDTH,
                "height": artifacts.FRAMEBUFFER_CLIENT_HEIGHT,
                "pitch": artifacts.FRAMEBUFFER_CLIENT_WIDTH * 4,
                "bits_per_pixel": 32,
                "bytes_per_pixel": 4,
                "gt_format_id": 8,
                "gt_format_name": "ARGB8888",
                "image_size": len(frame.read_bytes()),
                "raw_size": len(frame.read_bytes()),
                "raw_sha256": artifacts.sha256_file(native_frame),
                "row_layout": "native_pitch_bytes",
                "origin": "top-left",
                "packed_format": "xrgb8888-le",
                "conversion": "identity",
            })
            files = {}
            for name in ("game.exe", "observer.dll", "controller.exe", "launch.json"):
                path = root / name
                path.write_bytes(name.encode())
                files[name] = path
            receipt = artifacts.build_candidate_receipt(
                root=root,
                scenario=scenario_path,
                native_replay=replay,
                observer_log=log,
                framebuffer_metadata=metadata_path,
                executable=files["game.exe"],
                observer_hook=files["observer.dll"],
                capture_controller=files["controller.exe"],
                launch_receipt=files["launch.json"],
                capture_host={"os": "Linux", "architecture": "aarch64", "backend": "hangover-box64"},
            )
            receipt_path = root / "candidate.json"
            artifacts.write_canonical_json(receipt_path, receipt)
            verified = artifacts.verify_candidate_receipt(receipt_path, root=root)
            self.assertEqual(verified["status"], "CANDIDATE_ONLY")
            self.assertFalse(verified["production_claim"])
            self.assertTrue(verified["promotion_blockers"])
            self.assertTrue(verified["framebuffer"]["derivation"]["byte_exact"])
            self.assertTrue(
                verified["framebuffer"]["derivation"]["pixel_parity_eligible"]
            )
            self.assertEqual(
                verified["framebuffer"]["derivation"]["origin"]["resolved"],
                "TOP_LEFT",
            )
            promoted = copy.deepcopy(receipt)
            promoted["production_claim"] = True
            artifacts.write_canonical_json(receipt_path, promoted)
            with self.assertRaisesRegex(artifacts.ArtifactError, "production_claim"):
                artifacts.verify_candidate_receipt(receipt_path, root=root)

            forged = copy.deepcopy(receipt)
            forged["framebuffer"]["native_raw_sha256"] = "0" * 64
            artifacts.write_canonical_json(receipt_path, forged)
            with self.assertRaisesRegex(
                artifacts.ArtifactError, "native framebuffer identity",
            ):
                artifacts.verify_candidate_receipt(receipt_path, root=root)

    def test_legacy_discovery_importer_remains_compatible(self):
        lines = [
            'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook","status":"LOADED","thread_id":7}',
            'MVT {"record":"discovery","sequence":0,"channel":"controls.sample.raw",'
            '"frame":0,"values":{"this_address":"0x00000000","camera_address":"0x00000000",'
            '"flight_address":"0x00000000","snapshot_size":0,"snapshot_hex":""},'
            '"diagnostics":{"thread_id":7}}',
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.log"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertEqual(len(native_discovery.parse_log(path)), 1)
            with self.assertRaisesRegex(artifacts.ArtifactError, "semantic behavior"):
                artifacts.parse_semantic_log(path)


if __name__ == "__main__":
    unittest.main()
