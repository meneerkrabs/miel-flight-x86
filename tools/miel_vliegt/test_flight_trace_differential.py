#!/usr/bin/env python3
import copy
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import flight_trace_differential as differential


def f32(bits=0):
    return f"0x{bits:08x}"


def transition_event(edge, driver, **overrides):
    values = {
        "capture_id": f"{driver}-{edge}",
        "sequence": 1,
        "tick": 0,
    }
    values.update(overrides)
    return differential.natural_transition_event(edge, driver, **values)


def write_transition_capture(directory, edge, driver, capture_id=None):
    root = Path(directory)
    capture_id = capture_id or f"{driver}-{edge}"
    event = transition_event(edge, driver, capture_id=capture_id)
    raw = root / f"{driver}-{edge}.raw.ndjson"
    if driver == "native-gameplay":
        native_identity = {
            "schema": 3,
            "protocol": "miel-vliegt-native-natural-transition",
            "scenario": edge,
            "executable_sha256":
                differential.natural_transition_trace.NATIVE_EXECUTABLE_SHA256,
            "hook_build":
                differential.natural_transition_trace.NATIVE_HOOK_BUILD,
            "observer_dll_sha256": "1" * 64,
            "thread_id": 7,
        }
        raw_lines = [
            {"prefix": "MVO ", "value": {"schema": 1,
             "protocol": "miel-vliegt-native-observer-hook", "status": "LOADED",
             "thread_id": 7}},
            {"prefix": "MVD ", "value": {**native_identity,
             "record": "natural_session_start", "result": "ACTIVE"}},
            {"prefix": "MVD ", "value": {**native_identity,
             "record": "scene_transition_source", "edge": edge,
             "transition_site": event["transition_site"], "sequence": 1,
             "tick": 0}},
            {"prefix": "MVD ", "value": {**native_identity,
             "record": "natural_session_complete", "result": "PASS"}},
            {"prefix": "MVT ", "value": {"record": "session",
             "channel": "session.complete", "values": {
                 "scenario": edge, "reason": "captured",
             }}},
            {"prefix": "MVO ", "value": {"schema": 1,
             "protocol": "miel-vliegt-native-observer-hook",
             "status": "SCENARIO_COMPLETE", "thread_id": 7}},
        ]
        raw.write_text("".join(
            row["prefix"] + json.dumps(row["value"], separators=(",", ":")) + "\n"
            for row in raw_lines
        ), encoding="utf-8")
        producer = "native-observer-hook"
        subject = differential.natural_transition_trace.NATIVE_EXECUTABLE_SHA256
    else:
        subject = differential.natural_transition_trace.WEB_BUILD_SHA256
        common = {
            "schema": 1, "protocol": "miel-web-scene-transition-runtime",
            "capture_id": capture_id, "scenario": edge, "build_sha256": subject,
            "debug_entry": False, "evidence_scope": "NATURAL_TRANSITION",
        }
        raw.write_text("\n".join(json.dumps(row, separators=(",", ":")) for row in (
            {**common, "record": "session.start", "sequence": 0, "tick": 0},
            {**common, "record": "scene_transition", "sequence": 1, "tick": 0,
             "edge": edge, "source_scene": event["source_scene"],
             "scene": event["scene"], "transition_site": event["transition_site"],
             "transition_trigger": event["transition_trigger"],
             "transition_predicate": event["transition_predicate"],
             "native_edge": edge,
             "native_transition_site": event["transition_site"],
             "classification": "EXACT_NATIVE_CONTRACT_EDGE",
             "parity_eligible": differential.natural_transition_trace.EDGES[
                 edge
             ]["parity_eligible"] is True},
            {**common, "record": "session.complete", "sequence": 2, "tick": 0,
             "result": "PASS"},
        )) + "\n", encoding="utf-8")
        producer = "web-scene-manager"
    start = {
        "schema": 3, "protocol": differential.NATURAL_TRANSITION_PROTOCOL,
        "record": "capture_start", "edition": differential.FLIGHT_EDITION,
        "entry_driver": driver, "capture_id": capture_id, "scenario": edge,
        "producer": producer, "subject_sha256": subject,
        "raw_trace": {"path": raw.name, "sha256": differential.sha256_file(raw)},
        "debug_entry": False, "evidence_scope": differential.NATURAL_TRANSITION_SCOPE,
    }
    complete = {
        "schema": 3, "protocol": differential.NATURAL_TRANSITION_PROTOCOL,
        "record": "capture_complete", "edition": differential.FLIGHT_EDITION,
        "entry_driver": driver, "capture_id": capture_id, "final_sequence": 2,
        "result": "PASS", "debug_entry": False,
        "evidence_scope": differential.NATURAL_TRANSITION_SCOPE,
    }
    path = root / f"{driver}-{edge}.ndjson"
    path.write_text("\n".join(json.dumps(row) for row in (start, event, complete)) + "\n",
                    encoding="utf-8")
    return path


def native_semantic_fixture():
    state = {
        "phase": "leave", "call": 0, "depth": 0, "outer": True,
        "dt_f32_bits": f32(0x3CA3D70A), "state_valid": True,
        "position_f32_bits": [f32(0x3F800000), f32(0x40000000), f32(0x40400000)],
        "orientation_wxyz_f32_bits": [f32(0x3F800000), f32(), f32(), f32()],
        "velocity_f32_bits": [f32(0x40800000), f32(), f32()],
        "angular_velocity_f32_bits": [f32(), f32(), f32(0x3DCCCCCD)],
        "inactive": 0, "floor_enabled": 1,
        "fuel_f32_bits": f32(0x3F000000),
        "integrity_f32_bits": f32(0x3F800000),
        "maximum_integrity_f32_bits": f32(0x3F800000),
        "pending_damage_f32_bits": f32(),
        "damage_gate_timer_f32_bits": f32(), "active": 1,
    }
    controls = {
        "sample": 0, "dt_f32_bits": f32(0x3CA3D70A),
        "keys": {key: int(key == "left") for key in differential.NATIVE_CONTROL_KEYS},
        "analog_horizontal_f32_bits": f32(), "analog_vertical_f32_bits": f32(),
        "flight_valid": True, "propulsion_f32_bits": f32(0x3F000000),
        "propulsion_scale_f32_bits": f32(0x3F800000),
        "horizontal_f32_bits": f32(0xBF800000), "vertical_f32_bits": f32(),
        "controls_enabled": 1, "input_source": "windows_sendinput_directinput",
        "focus_active": True,
    }
    camera = {
        "camera_valid": True, "flight_valid": True,
        "camera_control_owner": "common_location", "location_state": 5,
        "manual_camera_enabled": 0xff, "move_forward": 0xff,
        "move_backward": 0xff,
        "render_world_position_f32_bits": [f32(0x3F800000), f32(0x40000000), f32(0x40400000)],
        "render_scaled_rotation_row_major_f32_bits": [
            f32(0x3F800000), f32(), f32(), f32(), f32(0x3F800000), f32(),
            f32(), f32(), f32(0x3F800000),
        ],
        "render_scale_f32_bits": f32(0x3F800000),
        "render_inverse_scale_squared_f32_bits": f32(0x3F800000),
        "near_f32_bits": f32(0x3DCCCCCD), "far_f32_bits": f32(0x447A0000),
        "horizontal_fov_degrees_f32_bits": f32(0x42200000),
        "centre_f32_bits": [f32(0x43A00000), f32(0x43700000)],
        "window_endpoints_f32_bits": [
            f32(), f32(), f32(0x441FC000), f32(0x43EF8000),
        ],
        "focal_pixels_f32_bits": f32(0x445B746B),
        "flight_position_f32_bits": [f32(), f32(), f32()],
    }
    records = [
        {"channel": "input.sample", "tick": 0, "frame": 0, "values": {
            "expected_mask": "0x01", "observed_mask": "0x01", "read_valid": True,
            "schedule_match": True, "sample_match": True, "focus_active": True,
            "focus_valid": True, "valid": True, "foreground": True,
            "input_source": "native_directinput_after_sendinput",
        }},
        {"channel": "clock.tick", "tick": 0, "values": {
            "scripted_dt_f32_bits": f32(0x3CA3D70A),
            "source": "scenario_transcript",
        }},
        {"channel": "flight.tick", "tick": 0, "frame": 0,
         "values": {"dt_f32_bits": f32(0x3CA3D70A)}},
        {"channel": "controls.post", "tick": 0, "frame": 0, "values": controls},
        {"channel": "physics.state", "tick": 0, "frame": 0, "values": state},
        {"channel": "collision.state", "tick": 0, "frame": 0,
         "values": {**state, "phase": "commit"}},
        {"channel": "camera.commit", "tick": 0, "frame": 0, "values": camera},
        {"channel": "render.final", "tick": 0, "frame": 0, "values": {
            "crash_requested": 0, "crash_active": 0, "crash_timer_f32_bits": f32(),
        }},
        {"channel": "render.framebuffer", "tick": 0,
         "values": {"raw_sha256": "4" * 64, "capture": "native_read_screen"}},
    ]
    for sequence, record in enumerate(records):
        record["sequence"] = sequence
    canonical = {
        "schema": 1, "protocol": differential.NATIVE_SEMANTIC_PROTOCOL,
        "records": records,
    }
    semantic = {
        **canonical,
        "semantic_sha256": hashlib.sha256(json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest(),
        "raw_log_sha256": "5" * 64, "record_count": len(records),
        "profile": "production-session", "scenario_id": "takeoff-climb",
        "session_ready": True, "complete": True,
    }
    scenario = {"id": "takeoff-climb", "input_script": {"tick_count": 1}}
    return semantic, scenario


def trace(capture_kind="native"):
    # Protocol-only unit data. This is never emitted as native parity evidence.
    return {
        "protocol": differential.PROTOCOL,
        "version": differential.VERSION,
        "capture_kind": capture_kind,
        "source": {"unit_test_fixture": True},
        "scenario": {"id": "takeoff", "input_sha256": "0" * 64},
        "frames": [{
            "frame": 0,
            "time_seconds": 0.04,
            "inputs": [{"sequence": 0, "control": "throttle", "value": 1}],
            "events": ["engine.start", "wheel.roll"],
            "numeric": {
                "physics": {"position": [1.0, 2.0, 3.0], "speed": 4.0},
                "controls": {"elevator": 0.25},
            },
            "camera": {
                "view_matrix": [1.0] * 16,
                "projection_matrix": [2.0] * 16,
            },
            "render": {
                "stats": {"drawCalls": 12, "triangles": 300, "bufferUploads": 0, "textureBinds": 4},
                "pixel_checkpoint": {"id": "takeoff-0000", "reference_sha256": "1" * 64},
            },
        }],
    }


class FlightTraceDifferentialTests(unittest.TestCase):
    def setUp(self):
        self.native = trace("native")
        self.web = trace("web")

    def test_accepts_domain_and_path_tolerances(self):
        self.web["frames"][0]["time_seconds"] += 0.0005
        self.web["frames"][0]["numeric"]["physics"]["speed"] += 0.05
        self.web["frames"][0]["numeric"]["physics"]["position"][1] += 0.2
        self.web["frames"][0]["camera"]["view_matrix"][3] += 0.005
        policy = differential.TolerancePolicy.from_mapping({
            "domains": {
                "timing": 0.001,
                "physics": 0.1,
                "camera": {"absolute": 0.01},
            },
            "paths": {"numeric.physics.position[*]": 0.25},
        })
        report = differential.compare_traces(self.native, self.web, policy)
        self.assertTrue(report.matches)
        self.assertEqual(report.frames_compared, 1)

    def test_reports_first_input_order_divergence_exactly(self):
        self.web["frames"][0]["inputs"] = [
            {"sequence": 1, "control": "rudder", "value": 0},
            self.web["frames"][0]["inputs"][0],
        ]
        report = differential.compare_traces(self.native, self.web)
        self.assertFalse(report.matches)
        self.assertEqual(report.divergence.path, "inputs.length")

        self.native["frames"][0]["inputs"].append({"sequence": 1, "control": "rudder", "value": 0})
        report = differential.compare_traces(self.native, self.web)
        self.assertEqual(report.divergence.path, "inputs[0].control")

    def test_reports_event_order_before_later_numeric_drift(self):
        self.web["frames"][0]["events"].reverse()
        self.web["frames"][0]["numeric"]["physics"]["speed"] = 99
        report = differential.compare_traces(self.native, self.web)
        self.assertEqual(report.divergence.path, "events[0]")
        self.assertEqual(report.divergence.frame, 0)

    def test_camera_matrix_reports_element_and_tolerance(self):
        self.web["frames"][0]["camera"]["projection_matrix"][7] += 0.1
        policy = differential.TolerancePolicy.from_mapping({"domains": {"camera": 0.01}})
        divergence = differential.compare_traces(self.native, self.web, policy).divergence
        self.assertEqual(divergence.path, "camera.projection_matrix[7]")
        self.assertEqual(divergence.tolerance.absolute, 0.01)

    def test_backend_stats_are_diagnostic_but_pixel_references_are_exact(self):
        self.web["frames"][0]["render"]["stats"]["textureBinds"] = 5
        self.assertTrue(differential.compare_traces(self.native, self.web).matches)

        self.web = trace("web")
        self.web["frames"][0]["render"]["pixel_checkpoint"]["reference_sha256"] = "2" * 64
        divergence = differential.compare_traces(self.native, self.web).divergence
        self.assertEqual(divergence.path, "render.pixel_checkpoint.reference_sha256")

    def test_scenario_identity_and_frame_count_are_contracts(self):
        self.web["scenario"]["id"] = "landing"
        divergence = differential.compare_traces(self.native, self.web).divergence
        self.assertEqual(divergence.path, "scenario.id")

        self.web = trace("web")
        extra = copy.deepcopy(self.web["frames"][0])
        extra["frame"] = 1
        self.web["frames"].append(extra)
        divergence = differential.compare_traces(self.native, self.web).divergence
        self.assertEqual(divergence.path, "frames.length")
        self.assertEqual(divergence.frame, 1)

    def test_validation_rejects_noncontiguous_frames_and_bad_camera_matrix(self):
        self.native["frames"][0]["frame"] = 2
        with self.assertRaisesRegex(ValueError, "contiguous"):
            differential.validate_trace(self.native)

        self.native = trace("native")
        self.native["frames"][0]["camera"]["view_matrix"] = [1] * 15
        with self.assertRaisesRegex(ValueError, "16 values"):
            differential.validate_trace(self.native)

        legacy = trace("native")
        legacy["version"] = 1
        with self.assertRaisesRegex(ValueError, "unsupported trace protocol"):
            differential.validate_trace(legacy)

    def test_natural_transition_producer_derives_exact_canonical_edge_identity(self):
        startup = transition_event("startup.login", "native-gameplay")
        self.assertEqual(startup, {
            "schema": 3,
            "protocol": differential.NATURAL_TRANSITION_PROTOCOL,
            "record": "scene_transition",
            "edition": differential.FLIGHT_EDITION,
            "edge": "startup.login",
            "source_scene": None,
            "scene": "mode_login",
            "entry_path": "startup",
            "transition_site": "0x0041d763",
            "transition_trigger": "startup dispatch",
            "transition_predicate": "always after registry construction",
            "entry_driver": "native-gameplay",
            "capture_id": "native-gameplay-startup.login",
            "sequence": 1,
            "tick": 0,
            "debug_entry": False,
            "evidence_scope": "NATURAL_TRANSITION",
        })
        gameplay = transition_event("location.landing.mode_roymccoy", "web-gameplay")
        self.assertEqual(gameplay["source_scene"], "mode_fly")
        self.assertEqual(gameplay["scene"], "mode_roymccoy")
        self.assertEqual(gameplay["entry_path"], "gameplay-transition")
        self.assertEqual(len(differential.NATURAL_TRANSITION_EDGES), 48)
        for edge in differential.NATURAL_TRANSITION_EDGES:
            for driver in ("native-gameplay", "web-gameplay"):
                event = transition_event(edge, driver)
                self.assertEqual(
                    differential.validate_natural_transition_event(event, driver),
                    event,
                )

    def test_natural_transition_differential_emits_schema_3_hash_bound_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            native_path = write_transition_capture(
                temporary, "startup.login", "native-gameplay",
            )
            web_path = write_transition_capture(
                temporary, "startup.login", "web-gameplay",
            )
            receipt = differential.compare_natural_transition_files(
                native_path, web_path,
            )
            native_sha256 = differential.sha256_file(native_path)
            web_sha256 = differential.sha256_file(web_path)
        self.assertEqual(receipt["schema"], 3)
        self.assertEqual(receipt["protocol"], "miel-scene-transition-differential")
        self.assertEqual(receipt["edge"], "startup.login")
        self.assertEqual(receipt["evidence_scope"], "NATURAL_TRANSITION")
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(receipt["native_trace_sha256"], native_sha256)
        self.assertEqual(receipt["web_trace_sha256"], web_sha256)

    def test_committed_contract_model_fixture_cannot_promote(self):
        fixture_root = Path(__file__).parent / "fixtures"
        web_path = fixture_root / "web_natural_transition_fixture.ndjson"
        raw_path = fixture_root / "web_natural_transition_raw_fixture.ndjson"

        with self.assertRaisesRegex(ValueError, "wrong driver"):
            differential.load_natural_transition_file(
                web_path, "web-gameplay",
            )
        event = json.loads(raw_path.read_text(
            encoding="utf-8",
        ).splitlines()[1])
        self.assertEqual(
            event["classification"], "SYNTHETIC_CONTRACT_MODEL_EDGE",
        )
        self.assertFalse(event["parity_eligible"])

    def test_natural_transition_evidence_fails_closed_for_edge_debug_and_body_drift(self):
        with self.assertRaisesRegex(ValueError, "unknown natural transition edge"):
            transition_event("invented.edge", "native-gameplay")

        canonical = transition_event("startup.login", "native-gameplay")
        for field, value, message in (
            ("edge", None, "invalid natural transition trace"),
            ("edge", "login.barn.keyboard", "differs from canonical edge"),
            ("debug_entry", True, "debug entry"),
            ("evidence_scope", "BODY_ONLY", "BODY_ONLY"),
        ):
            broken = copy.deepcopy(canonical)
            broken[field] = value
            with self.assertRaisesRegex(ValueError, message):
                differential.validate_natural_transition_event(broken, "native-gameplay")

        with tempfile.TemporaryDirectory() as temporary:
            native_path = write_transition_capture(
                temporary, "startup.login", "native-gameplay",
            )
            web_path = write_transition_capture(
                temporary, "login.barn.keyboard", "web-gameplay",
            )
            with self.assertRaisesRegex(ValueError, "edge differs"):
                differential.compare_natural_transition_files(native_path, web_path)

        debug_fixture = Path(__file__).parent / "fixtures/debug_transition_fixture.ndjson"
        with self.assertRaisesRegex(ValueError, "debug/BODY"):
            differential.load_natural_transition_file(
                debug_fixture, "native-gameplay",
            )

    def test_natural_transition_cli_writes_only_a_valid_pass_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            native_path = write_transition_capture(
                temporary, "startup.login", "native-gameplay",
            )
            web_path = write_transition_capture(
                temporary, "startup.login", "web-gameplay",
            )
            receipt_path = Path(temporary) / "receipt.json"
            with contextlib.redirect_stdout(io.StringIO()):
                status = differential.main([
                    str(native_path), str(web_path), "--natural-transition",
                    "--receipt", str(receipt_path),
                ])
            self.assertEqual(status, 0)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema"], 3)
            self.assertEqual(receipt["edge"], "startup.login")

    def test_natural_transition_requires_complete_capture_and_exact_trigger_site(self):
        event = transition_event("login.barn.keyboard", "native-gameplay")
        event["transition_site"] = "0x00429092"
        with self.assertRaisesRegex(ValueError, "site differs"):
            differential.validate_natural_transition_event(event, "native-gameplay")

        with tempfile.TemporaryDirectory() as temporary:
            lone = Path(temporary) / "lone.ndjson"
            lone.write_text(json.dumps(transition_event(
                "startup.login", "native-gameplay",
            )) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "start/event/complete"):
                differential.load_natural_transition_file(lone, "native-gameplay")

    def test_web_transition_requires_pinned_build_and_exact_runtime_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = write_transition_capture(
                temporary, "startup.login", "web-gameplay",
            )
            records = [json.loads(line) for line in capture.read_text(
                encoding="utf-8",
            ).splitlines()]
            records[0]["subject_sha256"] = "c" * 64
            capture.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "pinned build"):
                differential.load_natural_transition_file(capture, "web-gameplay")

            capture = write_transition_capture(
                temporary, "startup.login", "web-gameplay",
            )
            records = [json.loads(line) for line in capture.read_text(
                encoding="utf-8",
            ).splitlines()]
            raw = Path(temporary) / records[0]["raw_trace"]["path"]
            raw_records = [json.loads(line) for line in raw.read_text(
                encoding="utf-8",
            ).splitlines()]
            del raw_records[1]["transition_predicate"]
            raw.write_text("\n".join(json.dumps(row) for row in raw_records) + "\n",
                           encoding="utf-8")
            records[0]["raw_trace"]["sha256"] = differential.sha256_file(raw)
            capture.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "record shape"):
                differential.load_natural_transition_file(capture, "web-gameplay")

            capture = write_transition_capture(
                temporary, "startup.login", "web-gameplay",
            )
            records = [json.loads(line) for line in capture.read_text(
                encoding="utf-8",
            ).splitlines()]
            raw = Path(temporary) / records[0]["raw_trace"]["path"]
            raw_records = [json.loads(line) for line in raw.read_text(
                encoding="utf-8",
            ).splitlines()]
            raw_records[0]["sequence"] = False
            raw_records[1]["sequence"] = True
            raw.write_text("\n".join(json.dumps(row) for row in raw_records) + "\n",
                           encoding="utf-8")
            records[0]["raw_trace"]["sha256"] = differential.sha256_file(raw)
            capture.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "session identity"):
                differential.load_natural_transition_file(capture, "web-gameplay")

            capture = write_transition_capture(
                temporary, "startup.login", "web-gameplay",
            )
            records = [json.loads(line) for line in capture.read_text(
                encoding="utf-8",
            ).splitlines()]
            raw = Path(temporary) / records[0]["raw_trace"]["path"]
            raw_records = [json.loads(line) for line in raw.read_text(
                encoding="utf-8",
            ).splitlines()]
            unsafe_tick = 2 ** 80
            raw_records[1]["tick"] = unsafe_tick
            raw_records[2]["tick"] = unsafe_tick
            raw.write_text("\n".join(json.dumps(row) for row in raw_records) + "\n",
                           encoding="utf-8")
            records[0]["raw_trace"]["sha256"] = differential.sha256_file(raw)
            records[1]["tick"] = unsafe_tick
            capture.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sequence/tick"):
                differential.load_natural_transition_file(capture, "web-gameplay")

            capture = write_transition_capture(
                temporary, "startup.login", "web-gameplay",
            )
            records = [json.loads(line) for line in capture.read_text(
                encoding="utf-8",
            ).splitlines()]
            raw = Path(temporary) / records[0]["raw_trace"]["path"]
            raw_records = [json.loads(line) for line in raw.read_text(
                encoding="utf-8",
            ).splitlines()]
            for row in raw_records:
                row["schema"] = True
                row["debug_entry"] = 0
            raw_records[1]["parity_eligible"] = 1
            raw.write_text("\n".join(json.dumps(row) for row in raw_records) + "\n",
                           encoding="utf-8")
            records[0]["raw_trace"]["sha256"] = differential.sha256_file(raw)
            capture.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "session identity"):
                differential.load_natural_transition_file(capture, "web-gameplay")

    def test_body_marker_anywhere_in_raw_capture_disqualifies_transition(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = write_transition_capture(
                temporary, "startup.login", "native-gameplay",
            )
            records = [json.loads(line) for line in capture.read_text(
                encoding="utf-8",
            ).splitlines()]
            raw = Path(temporary) / records[0]["raw_trace"]["path"]
            with raw.open("a", encoding="utf-8") as stream:
                stream.write(
                    'MVD {"schema":2,"protocol":"miel-vliegt-native-body-lifecycle",'
                    '"record":"body_lifecycle"}\n'
                )
            records[0]["raw_trace"]["sha256"] = differential.sha256_file(raw)
            capture.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "debug/BODY"):
                differential.load_natural_transition_file(capture, "native-gameplay")

    def test_transition_parser_accepts_utf8_bom_consistently(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = write_transition_capture(
                temporary, "startup.login", "native-gameplay",
            )
            capture.write_bytes(b"\xef\xbb\xbf" + capture.read_bytes())
            loaded = differential.load_natural_transition_file(
                capture, "native-gameplay",
            )
            self.assertEqual(loaded["edge"], "startup.login")

    def test_cli_returns_nonzero_and_actionable_first_divergence(self):
        self.web["frames"][0]["events"].reverse()
        with tempfile.TemporaryDirectory() as temporary:
            native_path = Path(temporary) / "native.json"
            web_path = Path(temporary) / "web.json"
            native_path.write_text(json.dumps(self.native), encoding="utf-8")
            web_path.write_text(json.dumps(self.web), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = differential.main([str(native_path), str(web_path)])
        self.assertEqual(status, 1)
        self.assertIn("DIVERGENCE scenario=takeoff frame=0 path=events[0]", output.getvalue())
        self.assertIn("native: \"engine.start\"", output.getvalue())

    def test_browser_observation_bridges_to_the_neutral_trace_protocol(self):
        observation = {
            "schema": differential.WEB_OBSERVATION_SCHEMA,
            "version": 1,
            "frameIndex": 0,
            "input": {"left": False, "right": True},
            "timing": {"deltaSeconds": 0.04, "fixedStepSeconds": 0.04, "stepIndex": 1},
            "physics": {
                "position": [1, 2, 3], "orientation": [0, 0, 0, 1],
                "velocity": [4, 5, 6], "angularVelocity": None,
            },
            "camera": {
                "projectionMatrix": [1] * 16, "viewMatrix": [2] * 16,
                "verticalFovRadians": 1.0, "nearClip": 0.1, "farClip": 6000,
                "control": {"owner": "common_location", "state": 5},
                "viewport": {"x": 0, "y": 0, "width": 640, "height": 480},
            },
            "collisions": {"observed": False, "contacts": []},
            "events": [],
            "render": {"drawCalls": 4, "triangles": 20, "bufferUploads": 0, "textureBinds": 1},
        }
        frame = differential.web_observation_to_trace_frame(observation, 0.04)
        self.assertEqual(frame["inputs"], observation["input"])
        self.assertEqual(frame["numeric"]["physics"]["position"], [1, 2, 3])
        self.assertEqual(frame["camera"]["view_matrix"], [2] * 16)
        self.assertEqual(frame["camera"]["control"], {
            "owner": "common_location", "state": 5,
        })
        self.assertEqual(frame["render"]["diagnostics"]["webgl"]["drawCalls"], 4)

        second = copy.deepcopy(observation)
        second["frameIndex"] = 1
        trace_value = differential.web_observations_to_trace(
            [observation, second], {"runtime_sha256": "2" * 64},
            {"id": "takeoff", "input_sha256": "3" * 64},
        )
        self.assertEqual(trace_value["version"], 2)
        self.assertEqual([row["frame"] for row in trace_value["frames"]], [0, 1])
        self.assertAlmostEqual(trace_value["frames"][1]["time_seconds"], 0.08)

        legacy = copy.deepcopy(observation)
        legacy["collisions"] = []
        with self.assertRaisesRegex(ValueError, "collisions has an invalid shape"):
            differential.web_observation_to_trace_frame(legacy, 0.04)

        forged = copy.deepcopy(observation)
        forged["collisions"]["contacts"].append({
            "kind": "terrain",
            "contactPosition": [0, 0, 0],
            "contactNormal": [0, 1, 0],
            "relativeVelocity": [0, -1, 0],
            "damage": 0,
            "landingClassification": "safe",
        })
        with self.assertRaisesRegex(ValueError, "unobserved channel"):
            differential.web_observation_to_trace_frame(forged, 0.04)

    def test_native_semantic_session_derives_camera_without_inventing_unbound_pixels(self):
        semantic, scenario = native_semantic_fixture()
        trace_value = differential.native_semantic_to_trace(
            semantic, {"executable_sha256": "6" * 64}, scenario,
        )
        frame = trace_value["frames"][0]
        self.assertEqual(trace_value["version"], 2)
        self.assertEqual(trace_value["capture_kind"], "native")
        self.assertEqual(trace_value["source"]["semantic_sha256"], semantic["semantic_sha256"])
        self.assertEqual(frame["inputs"], {
            "left": True, "right": False, "up": False, "down": False,
            "shift": False, "control": False,
        })
        self.assertEqual(frame["numeric"]["physics"]["position"], [1.0, 2.0, 3.0])
        self.assertAlmostEqual(frame["time_seconds"], 0.02)
        self.assertEqual(frame["numeric"]["physics"]["orientation"], [0.0, 0.0, 0.0, 1.0])
        self.assertEqual(
            frame["numeric"]["collisions"],
            {"observed": False, "contacts": []},
        )
        web_candidate = copy.deepcopy(trace_value)
        web_candidate["capture_kind"] = "web"
        collision = differential.compare_trace_domain(
            trace_value, web_candidate, "collision",
        ).divergence
        self.assertEqual(collision.path, "numeric.collisions.observed")
        self.assertEqual(
            collision.reason, "native domain observation is incomplete",
        )
        self.assertEqual(
            frame["numeric"]["collisionResponse"]["position"], [1.0, 2.0, 3.0],
        )
        self.assertEqual(len(frame["camera"]["view_matrix"]), 16)
        self.assertEqual(len(frame["camera"]["projection_matrix"]), 16)
        self.assertEqual(frame["camera"]["control"], {
            "owner": "common_location", "state": 5,
        })
        self.assertEqual(frame["camera"]["viewport"], {
            "x": 0.0, "y": 0.0, "width": 640.0, "height": 480.0,
        })
        self.assertNotIn("pixel_checkpoint", frame["render"])
        self.assertEqual(
            frame["render"]["diagnostics"]["native_framebuffer"]["raw_sha256"],
            "4" * 64,
        )

    def test_native_semantic_session_preserves_mode_fly_camera_controls(self):
        semantic, scenario = native_semantic_fixture()
        camera = next(
            record for record in semantic["records"]
            if record["channel"] == "camera.commit"
        )["values"]
        camera.update({
            "camera_control_owner": "mode_fly",
            "location_state": 0xffffffff,
            "manual_camera_enabled": 1,
            "move_forward": 0,
            "move_backward": 1,
        })
        canonical = {
            "schema": semantic["schema"],
            "protocol": semantic["protocol"],
            "records": semantic["records"],
        }
        semantic["semantic_sha256"] = hashlib.sha256(json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
        trace_value = differential.native_semantic_to_trace(
            semantic, {"executable_sha256": "6" * 64}, scenario,
        )
        self.assertEqual(trace_value["frames"][0]["camera"]["control"], {
            "owner": "mode_fly",
            "manual_camera_enabled": True,
            "move_forward": False,
            "move_backward": True,
        })

    def test_native_semantic_session_accepts_only_raw_bound_canonical_pixels(self):
        semantic, scenario = native_semantic_fixture()
        checkpoint = {
            "id": "reference-frame", "width": 640, "height": 480,
            "pixel_format": "rgba8", "origin": "top-left",
            "alpha_mode": "straight", "reference_sha256": "7" * 64,
        }
        evidence = {
            "tick": 0, "raw_sha256": "4" * 64,
            "pixel_checkpoint": checkpoint,
        }
        trace_value = differential.native_semantic_to_trace(
            semantic, {"executable_sha256": "6" * 64}, scenario, evidence,
        )
        self.assertEqual(
            trace_value["frames"][0]["render"]["pixel_checkpoint"], checkpoint,
        )
        evidence["raw_sha256"] = "8" * 64
        with self.assertRaisesRegex(ValueError, "raw hash differs"):
            differential.native_semantic_to_trace(
                semantic, {"executable_sha256": "6" * 64}, scenario, evidence,
            )

    def test_native_semantic_bridge_rejects_unbound_or_incomplete_evidence(self):
        semantic, scenario = native_semantic_fixture()
        semantic["semantic_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "provenance hash"):
            differential.native_semantic_to_trace(semantic, {"source": "unit"}, scenario)

        semantic, scenario = native_semantic_fixture()
        semantic["complete"] = False
        with self.assertRaisesRegex(ValueError, "completed production session"):
            differential.native_semantic_to_trace(semantic, {"source": "unit"}, scenario)

    def test_domain_comparison_isolates_fields_and_requires_complete_observations(self):
        self.web["frames"][0]["camera"]["projection_matrix"][0] = 99.0
        controls = {
            "keys": {key: False for key in differential.NATIVE_CONTROL_KEYS},
            "analogHorizontal": 0.0, "analogVertical": 0.0,
            "propulsion": 0.0, "propulsionScale": 1.0,
            "horizontal": 0.0, "vertical": 0.0, "enabled": True,
            "windowFocused": True,
        }
        self.native["frames"][0]["numeric"]["controls"] = copy.deepcopy(controls)
        self.web["frames"][0]["numeric"]["controls"] = copy.deepcopy(controls)
        self.assertTrue(
            differential.compare_trace_domain(self.native, self.web, "controls").matches
        )

        physics = {
            "position": [1.0, 2.0, 3.0], "orientation": [0.0, 0.0, 0.0, 1.0],
            "velocity": [4.0, 0.0, 0.0], "angularVelocity": [0.0, 0.0, 0.0],
        }
        systems = {
            "fuel": 1.0, "integrity": 1.0, "maximumIntegrity": 1.0,
            "pendingDamage": 0.0, "damageGateTimer": 0.0,
            "active": True, "inactive": False, "floorEnabled": True,
        }
        self.native["frames"][0]["numeric"]["physics"] = copy.deepcopy(physics)
        self.web["frames"][0]["numeric"]["physics"] = copy.deepcopy(physics)
        self.native["frames"][0]["numeric"]["systems"] = copy.deepcopy(systems)
        self.web["frames"][0]["numeric"]["systems"] = copy.deepcopy(systems)
        self.assertTrue(
            differential.compare_trace_domain(self.native, self.web, "physics").matches
        )
        self.web["frames"][0]["numeric"]["physics"]["velocity"][0] = 5.0
        divergence = differential.compare_trace_domain(
            self.native, self.web, "physics",
        ).divergence
        self.assertEqual(divergence.path, "numeric.physics.velocity[0]")

        collision = differential.compare_trace_domain(
            self.native, self.web, "collision",
        ).divergence
        self.assertEqual(collision.path, "numeric.collisions")
        self.assertEqual(collision.reason, "native domain observation is incomplete")

    def test_collision_domain_accepts_explicit_observed_no_contact_frames(self):
        no_contact = {"observed": True, "contacts": []}
        self.native["frames"][0]["numeric"]["collisions"] = copy.deepcopy(no_contact)
        self.web["frames"][0]["numeric"]["collisions"] = copy.deepcopy(no_contact)

        self.assertTrue(
            differential.compare_trace_domain(
                self.native, self.web, "collision",
            ).matches
        )

    def test_collision_domain_rejects_unobserved_empty_contact_frames(self):
        unobserved = {"observed": False, "contacts": []}
        self.native["frames"][0]["numeric"]["collisions"] = copy.deepcopy(unobserved)
        self.web["frames"][0]["numeric"]["collisions"] = copy.deepcopy(unobserved)

        divergence = differential.compare_trace_domain(
            self.native, self.web, "collision",
        ).divergence
        self.assertEqual(divergence.path, "numeric.collisions.observed")
        self.assertEqual(
            divergence.reason, "native domain observation is incomplete",
        )

    def test_timing_and_system_domains_project_only_their_reviewed_observations(self):
        timing = {"deltaSeconds": 0.04}
        self.native["frames"][0]["numeric"]["timing"] = copy.deepcopy(timing)
        self.web["frames"][0]["numeric"]["timing"] = {
            **timing, "fixedStepSeconds": 0.02, "stepIndex": 2,
        }
        self.assertTrue(
            differential.compare_trace_domain(self.native, self.web, "timing").matches
        )

        systems = {
            "fuel": 1.0, "integrity": 1.0, "maximumIntegrity": 1.0,
            "pendingDamage": 0.0, "damageGateTimer": 0.0,
            "active": True, "inactive": False, "floorEnabled": True,
        }
        self.native["frames"][0]["numeric"]["systems"] = copy.deepcopy(systems)
        self.web["frames"][0]["numeric"]["systems"] = copy.deepcopy(systems)
        self.web["frames"][0]["numeric"]["physics"]["position"][0] = 99.0
        self.assertTrue(
            differential.compare_trace_domain(self.native, self.web, "systems").matches
        )
        self.web["frames"][0]["numeric"]["systems"]["fuel"] = 0.5
        divergence = differential.compare_trace_domain(
            self.native, self.web, "systems",
        ).divergence
        self.assertEqual(divergence.path, "numeric.systems.fuel")

    def test_native_consensus_bridge_preserves_partial_evidence_boundaries(self):
        semantic, scenario = native_semantic_fixture()
        by_channel = {
            row["channel"]: row["values"]
            for row in semantic["records"]
            if row["channel"] in {
                "clock.tick", "input.sample", "controls.post",
                "physics.state", "collision.state",
            }
        }
        state = copy.deepcopy(by_channel["physics.state"])
        state.pop("damage_gate_timer_f32_bits")
        enter = {**state, "phase": "enter"}
        leave = {**state, "phase": "leave"}
        collision_enter = {**state, "phase": "enter"}
        collision_commit = {**state, "phase": "commit"}
        sample = {
            "tick": 0,
            "clock.tick": by_channel["clock.tick"],
            "input.sample": by_channel["input.sample"],
            "controls.post": by_channel["controls.post"],
            "system.fuel": {
                "fuel_f32_bits": state["fuel_f32_bits"], "depleted": False,
            },
            "physics.state": {"enter": enter, "leave": leave},
            "collision.state": {
                "enter": collision_enter, "commit": collision_commit,
            },
        }
        projection = differential._canonical_sha256([sample])
        consensus = {
            "schema": 1,
            "protocol": differential.NATIVE_CONSENSUS_PROTOCOL,
            "status": "CANDIDATE_PARTIAL_NATIVE_EVIDENCE",
            "promotion_allowed": False,
            "scenario": scenario["id"],
            "provenance": {
                "executable_sha256": "1" * 64,
                "observer_dll_sha256": "2" * 64,
                "runs": [{
                    "observer_log_path": f"observer-{index}.log",
                    "observer_log_sha256": "4" * 64,
                    "observer_semantic_sha256": "5" * 64,
                    "launcher": {
                        "path": f"launcher-{index}.json",
                        "sha256": "6" * 64,
                        "executable_sha256": "1" * 64,
                        "observer_dll_sha256": "2" * 64,
                    },
                } for index in range(2)],
            },
            "determinism": {
                "run_count": 2, "sample_count": 1,
                "projection_sha256": projection,
            },
            "coverage": {"proved": [], "not_proved": []},
            "samples": [sample],
        }
        native = differential.native_consensus_to_trace(
            consensus, {"artifact_sha256": "3" * 64}, scenario,
        )
        self.assertEqual(native["frames"][0]["numeric"]["timing"], {
            "deltaSeconds": differential._f32_from_bits(
                by_channel["clock.tick"]["scripted_dt_f32_bits"], "unit",
            ),
        })
        self.assertNotIn(
            "damageGateTimer", native["frames"][0]["numeric"]["systems"],
        )
        self.assertEqual(
            native["frames"][0]["numeric"]["collisions"],
            {"observed": False, "contacts": []},
        )
        self.assertNotIn("camera", native["frames"][0])
        with self.assertRaisesRegex(ValueError, "projection hash differs"):
            consensus["determinism"]["projection_sha256"] = "0" * 64
            differential.native_consensus_to_trace(
                consensus, {"artifact_sha256": "3" * 64}, scenario,
            )

    def test_rendering_domain_requires_canonical_pixel_evidence(self):
        malformed = differential.compare_trace_domain(
            self.native, self.web, "rendering",
        ).divergence
        self.assertEqual(malformed.reason, "native canonical pixel evidence is invalid")

        self.native["frames"][0]["render"].pop("pixel_checkpoint")
        self.web["frames"][0]["render"].pop("pixel_checkpoint")
        divergence = differential.compare_trace_domain(
            self.native, self.web, "rendering",
        ).divergence
        self.assertEqual(divergence.path, "render.pixel_checkpoint")
        self.assertIn("no canonical native pixel evidence", divergence.reason)

    def test_domain_comparison_rejects_unknown_domains(self):
        with self.assertRaisesRegex(ValueError, "unsupported trace domain"):
            differential.compare_trace_domain(self.native, self.web, "everything")


if __name__ == "__main__":
    unittest.main()
