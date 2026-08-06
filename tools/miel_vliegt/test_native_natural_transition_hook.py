#!/usr/bin/env python3
import ast
import json
import re
import unittest
from pathlib import Path

from tools.miel_vliegt import web_transition_build


_validate_manifest = web_transition_build.validate_manifest
web_transition_build.validate_manifest = lambda: {"build_sha256": "0" * 64}
try:
    from tools.miel_vliegt import natural_transition_trace as trace
finally:
    web_transition_build.validate_manifest = _validate_manifest


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"


def expanded_contract_edges():
    contract = json.loads(trace.CONTRACT_PATH.read_text(encoding="utf-8"))
    rows = list(contract["edges"])
    for location in contract["location_edges"]:
        rows.extend((location["landing"], location["departure"]))
    return rows


class NativeNaturalTransitionHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HOOK.read_text(encoding="utf-8")

    def test_hook_table_is_an_exact_48_edge_projection_of_canonical_contract(self):
        rows = re.findall(
            r'NATURAL_EDGE\("([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*'
            r'(0x[0-9a-f]{8})u,\s*(NATURAL_[A-Z_]+)\)',
            self.source,
        )
        self.assertEqual(len(rows), 48)
        actual = {edge: (source, target, site, kind)
                  for edge, source, target, site, kind in rows}
        expected = {}
        for edge in expanded_contract_edges():
            if edge["id"].startswith("location.landing."):
                kind = "NATURAL_FLIGHT_TARGET"
            elif edge["id"].startswith("location.departure."):
                kind = "NATURAL_LOCATION_DEPARTURE"
            elif edge["id"] == "flight.barn.crash":
                kind = "NATURAL_FLIGHT_TARGET"
            elif edge["id"] == "credits.terminal":
                kind = "NATURAL_QUEUE_MODE"
            else:
                kind = "NATURAL_MODE_SET"
            source = "" if edge["source_type"] in {"bootstrap", "mission"} else edge["source"]
            target = "" if edge["target_type"] == "terminal" else edge["target"]
            expected[edge["id"]] = (
                source, target, edge["address"].lower(), kind,
            )
        self.assertEqual(actual, expected)

    def test_all_auxiliary_hooks_are_signature_checked_installed_and_rolled_back(self):
        expected = {
            "FLIGHT_TARGET": ("FLIGHT_TARGET_SIGNATURE", "flight_target_hook"),
            "QUEUE_MODE": ("QUEUE_MODE_SIGNATURE", "queue_mode_hook"),
            "EXHIBITION_CALLBACK": (
                "EXHIBITION_CALLBACK_SIGNATURE", "exhibition_callback_hook",
            ),
        }
        for address, (signature, hook) in expected.items():
            self.assertIn(f"memcmp({address}, {signature}", self.source)
            self.assertEqual(
                self.source.count(f"install_detour({address}, {signature}"), 1,
            )
            self.assertEqual(
                self.source.count(f"rollback_detour({address}, {signature}"), 1,
            )
            self.assertIn(f"{hook}(void)", self.source)

    def test_capture_is_armed_by_exact_replay_edge_and_excludes_body_and_debug(self):
        configure = self.source[
            self.source.index("static BOOL configure_natural_transition_capture"):
            self.source.index("static BOOL all_hook_signatures_match")
        ]
        self.assertIn("strcmp(replay_scenario, edge->id) == 0", configure)
        self.assertIn("body_dispatch_state != BODY_DISPATCH_DISABLED", configure)
        self.assertIn("bootstrap_diagnostics_enabled", configure)
        self.assertIn("diagnostic_session_only", configure)
        self.assertIn("diagnostic_skip_target", configure)

    def test_natural_event_is_schema_3_exact_once_and_not_emitted_by_body_or_udsp(self):
        self.assertIn('\\"protocol\\":\\"miel-vliegt-native-natural-transition\\"', self.source)
        self.assertIn('\\"record\\":\\"scene_transition_source\\"', self.source)
        emitter = self.source[
            self.source.index("static void emit_natural_transition"):
            self.source.index("static void emit_mode_transition")
        ]
        self.assertIn("InterlockedCompareExchange(&natural_transition_emitted, 1, 0)", emitter)
        self.assertIn('\\"schema\\":3', emitter)
        self.assertIn(trace.NATIVE_EXECUTABLE_SHA256, self.source)
        self.assertIn(trace.NATIVE_HOOK_BUILD, self.source)
        loaded = self.source.index('write_marker("LOADED")')
        started = self.source.index('emit_natural_session("start", "ACTIVE")')
        startup_source = self.source.index(
            "emit_natural_transition(natural_capture_edge,",
            started,
        )
        self.assertLess(loaded, started)
        self.assertLess(started, startup_source)
        body_start = self.source.index("body_lifecycle_enter(")
        body_end = self.source.index("body_lifecycle_leave(void)")
        self.assertNotIn("emit_natural_transition", self.source[body_start:body_end])
        udsp_start = self.source.index("udsp_dispatch_enter(")
        udsp_end = self.source.index("udsp_dispatch_leave(void)")
        self.assertNotIn("emit_natural_transition", self.source[udsp_start:udsp_end])

    def test_flight_target_observation_is_general_pointer_free_and_capture_independent(self):
        observe_start = self.source.index(
            "static void __attribute__((used)) observe_flight_target("
        )
        observe_end = self.source.index(
            "static void __attribute__((used)) observe_queue_mode(",
            observe_start,
        )
        observer = self.source[observe_start:observe_end]
        emission = observer[:observer.index(
            "if (!edge || edge->kind != NATURAL_FLIGHT_TARGET"
        )]
        self.assertIn(
            '\\"protocol\\":\\"miel-vliegt-native-flight-target\\"',
            emission,
        )
        self.assertIn('\\"target_mode\\":\\"%s\\"', emission)
        self.assertIn('\\"source_mode\\":\\"%s\\"', emission)
        self.assertIn('\\"caller_site\\":\\"0x%08lx\\"', emission)
        self.assertLess(
            observer.index("append_record(line, (DWORD)size)"),
            observer.index("const NaturalTransitionEdge *edge = natural_capture_edge"),
        )
        self.assertNotRegex(emission, r'\\"[^\"]*(?:pointer|address)[^\"]*\\"')

    def test_post_natural_edge_input_contract_is_one_way_and_pointer_free(self):
        emitter = self.source[
            self.source.index("static void emit_natural_transition"):
            self.source.index("static void emit_mode_transition")
        ]
        self.assertIn(
            "InterlockedExchange(&post_natural_edge_input_suspended, 1)",
            emitter,
        )
        boundary = self.source[
            self.source.index(
                "static BOOL suspend_post_natural_edge_input_contract"
            ):
            self.source.index("static BOOL send_login_submit_input")
        ]
        self.assertIn(
            "&post_natural_edge_input_boundary_state, 1, 0", boundary,
        )
        self.assertIn("if (boundary_state == 2) return TRUE", boundary)
        self.assertIn("if (!release_replay_keys())", boundary)
        self.assertLess(
            boundary.index("if (!release_replay_keys())"),
            boundary.index('"MVD {\\"schema\\":1,"'),
        )
        self.assertIn(
            "InterlockedExchange(&post_natural_edge_input_boundary_state, 2)",
            boundary,
        )
        self.assertIn("append_record_checked(line, (DWORD)size)", boundary)
        self.assertNotIn("append_record(line, (DWORD)size)", boundary)
        self.assertLess(
            boundary.index("append_record_checked(line, (DWORD)size)"),
            boundary.index(
                "InterlockedExchange(&post_natural_edge_input_boundary_state, 2)"
            ),
        )
        self.assertGreaterEqual(
            boundary.count(
                "InterlockedExchange(&post_natural_edge_input_boundary_state, 0)"
            ),
            2,
        )
        format_block = boundary[
            boundary.index("size = snprintf("):
            boundary.index("if (size > 0")
        ]
        fragments = []
        for line in format_block.splitlines():
            literal = line.strip()
            if literal.endswith(","):
                literal = literal[:-1]
            if re.fullmatch(r'"(?:\\.|[^"\\])*"', literal):
                fragments.append(ast.literal_eval(literal))
        rendered = "".join(fragments) % (7, 11, 13)
        self.assertTrue(rendered.startswith("MVD "))
        record = json.loads(rendered[4:])
        self.assertEqual(record, {
            "schema": 1,
            "protocol": "miel-vliegt-native-input-contract",
            "record": "input_contract_suspended",
            "sequence": 7,
            "tick": 11,
            "reason": "natural_transition_observed",
            "evidence_scope": "POST_NATURAL_EDGE_DIAGNOSTIC_ONLY",
            "input_sample_verification": False,
            "parity_eligible": False,
            "natural_transition_evidence": False,
            "state_writes": False,
            "observer_keys_released": True,
            "thread_id": 13,
        })
        self.assertFalse(any(
            "pointer" in key or "address" in key for key in record
        ))

    def test_checked_append_rejects_every_boundary_persistence_failure(self):
        checked = self.source[
            self.source.index("static BOOL append_record_checked("):
            self.source.index("static void flush_trace(void)")
        ]
        ordered = [
            "!trace_lock_ready || size == 0u || size > TRACE_BUFFER_SIZE",
            "EnterCriticalSection(&trace_lock)",
            "before_count = trace_record_count",
            "!trace_saturated && !trace_write_failed",
            "before_count < trace_record_limit",
            "append_record_locked(text, size)",
            "accepted = !trace_saturated && !trace_write_failed",
            "trace_record_count == before_count + 1u",
            "LeaveCriticalSection(&trace_lock)",
            "return accepted",
        ]
        positions = [checked.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))

        def accepted(*, ready=True, size=1, capacity=4096,
                     saturated_before=False, write_failed_before=False,
                     count_before=0, limit=10, saturated_after=False,
                     write_failed_after=False, count_after=1):
            return (
                ready and 0 < size <= capacity and
                not saturated_before and not write_failed_before and
                count_before < limit and
                not saturated_after and not write_failed_after and
                count_after == count_before + 1
            )

        self.assertTrue(accepted())
        mutations = (
            {"ready": False},
            {"size": 0},
            {"size": 4097},
            {"saturated_before": True},
            {"write_failed_before": True},
            {"count_before": 10, "count_after": 11},
            {"saturated_after": True},
            {"write_failed_after": True},
            {"count_after": 0},
            {"count_after": 2},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertFalse(accepted(**mutation))

    def test_replay_key_release_retains_every_unsent_owned_bit(self):
        release = self.source[
            self.source.index("static BOOL release_replay_keys(void)"):
            self.source.index(
                "static BOOL post_natural_edge_input_is_suspended(void)"
            )
        ]
        ordered = [
            "release_bits[count] = bit",
            "sent = count == 0u ? 0u : SendInput",
            "index < sent && index < count",
            "remaining_keys = (BYTE)(remaining_keys & ~release_bits[index])",
            "replay_active_tick, from_keys, remaining_keys, count, sent",
            "os_input_maybe_down = remaining_keys",
            "if (sent != count) return FALSE",
            "os_input_keys = 0u",
            "return TRUE",
        ]
        positions = [release.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("os_input_maybe_down = 0u", release)

        def remaining(from_mask, ordered_bits, sent):
            value = from_mask
            for bit in ordered_bits[:sent]:
                value &= ~bit
            return value

        self.assertEqual(remaining(0x21, [0x01, 0x20], 0), 0x21)
        self.assertEqual(remaining(0x21, [0x01, 0x20], 1), 0x20)
        self.assertEqual(remaining(0x21, [0x01, 0x20], 2), 0x00)
        session_fail_start = self.source.index("static void session_fail(")
        session_fail = self.source[
            session_fail_start:
            self.source.index(
                "static void fail_activation_rng(", session_fail_start,
            )
        ]
        self.assertIn("(void)release_replay_keys();", session_fail)

    def test_post_natural_edge_skips_samples_but_keeps_clock_and_hooks_live(self):
        record_tick = self.source[
            self.source.index(
                "static DWORD __attribute__((used)) record_tick("
            ):
            self.source.index(
                "static void __attribute__((used)) record_controls_pre("
            )
        ]
        suspended = record_tick[
            record_tick.index("if (post_natural_edge_input_is_suspended())"):
            record_tick.index(
                'force_release_lag_keys(manager_node);'
            )
        ]
        self.assertIn(
            "if (!suspend_post_natural_edge_input_contract(tick->tick))",
            suspended,
        )
        self.assertIn(
            '"post_natural_edge_input_suspension_contract"', suspended,
        )
        self.assertIn("effective_dt = replay_active_dt", suspended)
        self.assertIn(
            "emit_clock(context->tick, dt_f32_bits, effective_dt)", suspended,
        )
        self.assertIn("++replay_next_tick", suspended)
        self.assertNotIn("verify_replay_key_sample", suspended)
        controls = self.source[
            self.source.index(
                "static void __attribute__((used)) record_controls_pre("
            ):
            self.source.index(
                "static void __attribute__((used)) record_physics_entry("
            )
        ]
        self.assertGreaterEqual(
            controls.count("!post_natural_edge_input_is_suspended()"), 2,
        )

    def test_post_natural_edge_session_can_only_complete_as_diagnostic(self):
        complete = self.source[
            self.source.index("static void complete_session_after_render"):
            self.source.index("static const BodyModeLifecycle *body_mode_for_vtable")
        ]
        diagnostic = complete[
            complete.index("if (post_natural_edge_input_is_suspended())"):
            complete.index(
                "} else if (framebuffer_capture_required() && !frame_captured)"
            )
        ]
        self.assertIn(
            "if (!suspend_post_natural_edge_input_contract(\n"
            "                    replay_active_tick))",
            diagnostic,
        )
        self.assertLess(
            diagnostic.index("suspend_post_natural_edge_input_contract"),
            diagnostic.index('emit_natural_session("complete", "DIAGNOSTIC_ONLY")'),
        )
        self.assertIn(
            'session_fail(\n                    '
            '"post_natural_edge_input_suspension_contract")',
            diagnostic,
        )
        self.assertIn(
            'emit_natural_session("complete", "DIAGNOSTIC_ONLY")', diagnostic,
        )
        self.assertIn(
            '"post_natural_edge_input_contract_suspended"', diagnostic,
        )
        self.assertIn(
            'write_marker("SCENARIO_DIAGNOSTIC_COMPLETE")', diagnostic,
        )
        self.assertIn('session_fail("trace_saturated")', diagnostic)
        self.assertIn('session_fail("trace_write")', diagnostic)
        self.assertLess(
            diagnostic.index("if (trace_saturated)"),
            diagnostic.index("session_state = SESSION_COMPLETE"),
        )
        self.assertLess(
            diagnostic.index("else if (trace_write_failed)"),
            diagnostic.index("session_state = SESSION_COMPLETE"),
        )
        self.assertNotIn('"PASS"', diagnostic)
        self.assertNotIn('write_marker("SCENARIO_COMPLETE")', diagnostic)

    def test_exhibition_callback_context_is_bounded_and_synthetic_return_paired(self):
        self.assertIn("NATURAL_CALLBACK_DEPTH", self.source)
        self.assertIn("natural_exhibition_enter", self.source)
        self.assertIn("natural_exhibition_leave", self.source)
        self.assertIn("exhibition_callback_leave_hook", self.source)
        self.assertIn("index == 2u", self.source)
        self.assertIn("index == 3u", self.source)

    def test_raw_source_validator_requires_the_exact_schema_3_shape(self):
        transition = {
            "edge": "login.barn.keyboard",
            "transition_site": "0x00428bb3",
            "sequence": 7,
            "tick": 11,
        }
        source = {
            "schema": 3,
            "protocol": trace.NATIVE_RAW_PROTOCOL,
            "record": "scene_transition_source",
            **transition,
            "thread_id": 42,
            "scenario": "login.barn.keyboard",
            "executable_sha256": trace.NATIVE_EXECUTABLE_SHA256,
            "hook_build": trace.NATIVE_HOOK_BUILD,
            "observer_dll_sha256": "1" * 64,
        }
        session = {
            "schema": 3,
            "protocol": trace.NATIVE_RAW_PROTOCOL,
            "scenario": "login.barn.keyboard",
            "executable_sha256": trace.NATIVE_EXECUTABLE_SHA256,
            "hook_build": trace.NATIVE_HOOK_BUILD,
            "observer_dll_sha256": "1" * 64,
            "thread_id": 42,
        }
        envelope = [
            ("MVO", {"protocol": "miel-vliegt-native-observer-hook", "status": "LOADED"}),
            ("MVD", {**session, "record": "natural_session_start", "result": "ACTIVE"}),
            ("MVD", source),
            ("MVD", {**session, "record": "natural_session_complete", "result": "PASS"}),
            ("MVT", {"record": "session", "channel": "session.complete",
                     "values": {"scenario": "login.barn.keyboard"}}),
            ("MVO", {"protocol": "miel-vliegt-native-observer-hook",
                     "status": "SCENARIO_COMPLETE"}),
        ]
        trace._validate_raw_native(
            envelope, {"scenario": "login.barn.keyboard"}, transition, "raw",
        )
        for key, value in (("schema", 2), ("thread_id", True)):
            broken = [(prefix, dict(record)) for prefix, record in envelope]
            broken[2][1][key] = value
            with self.assertRaisesRegex(ValueError, "one complete observer session"):
                trace._validate_raw_native(
                    broken, {"scenario": "login.barn.keyboard"}, transition, "raw",
                )
        extra = [(prefix, dict(record)) for prefix, record in envelope]
        extra[2][1]["debug_entry"] = False
        with self.assertRaisesRegex(ValueError, "one complete observer session"):
            trace._validate_raw_native(
                extra, {"scenario": "login.barn.keyboard"}, transition, "raw",
            )
        duplicate_start = envelope[:2] + [envelope[1]] + envelope[2:]
        with self.assertRaisesRegex(ValueError, "one complete observer session"):
            trace._validate_raw_native(
                duplicate_start, {"scenario": "login.barn.keyboard"},
                transition, "raw",
            )
        wrong_observer = [(prefix, dict(record)) for prefix, record in envelope]
        wrong_observer[2][1]["observer_dll_sha256"] = "2" * 64
        with self.assertRaisesRegex(ValueError, "one complete observer session"):
            trace._validate_raw_native(
                wrong_observer, {"scenario": "login.barn.keyboard"},
                transition, "raw",
            )


if __name__ == "__main__":
    unittest.main()
