#!/usr/bin/env python3
import copy
import json
import re
import unittest
from pathlib import Path

from tools.miel_vliegt import native_body_trace


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"


def event(sequence, edge, **changes):
    value = {
        "schema": 1,
        "protocol": native_body_trace.PROTOCOL,
        "sequence": sequence,
        "evidence_scope": "BODY_ONLY",
        "natural_transition_evidence": False,
        "mode_id": "barn",
        "object": "0x12345678",
        "vtable": "0x0044caec",
        "phase": "OPEN",
        "entry": "0x00416180",
        "edge": edge,
        "thread": 77,
        "tick": 3,
        "depth": 0,
    }
    value.update(changes)
    return value


def dispatch_receipt(*, mode="mode_barn", flight=False):
    return_mode = "mode_login" if mode == "mode_barn" else "mode_barn"
    return {
        "schema": 2,
        "protocol": native_body_trace.DISPATCH_PROTOCOL,
        "status": "INCOMPLETE" if flight else "PASS",
        "evidence_scope": "BODY_ONLY",
        "natural_transition_evidence": False,
        "debug_skip_used": False,
        "executable_sha256": "a" * 64,
        "requested_mode": mode,
        "return_mode": return_mode,
        "command": {
            "name": "engine_mode", "id": 15,
            "dispatch": "registered-command-callback",
        },
        "callback_count": 2,
        "manager_thread": True,
        "dispatch_thread": 77,
        "ticks": {
            "entry_dispatch": 1, "target_activation": 3,
            "core_ready": 3, "return_dispatch": 3,
            "return_activation": 4,
        },
        "entry": {
            "pre": {
                "manager_canonical": True, "current_mode": "mode_barn",
                "pending_null": True, "target_resolved_before_mutation": True,
                "registry_record_resolved": True,
            },
            "post": {
                "current_mode": "mode_barn",
                "pending_mode": None if mode == "mode_barn" else mode,
                "dispatch_effect": (
                    "SAME_MODE_NOOP" if mode == "mode_barn"
                    else "PENDING_TARGET"
                ),
            },
            "activation": {
                "current_mode": mode, "pending_null": True,
                "loaded": True, "opened": True,
            },
        },
        "core": {
            "paired_counts": {phase: 1 for phase in native_body_trace.CORE_PHASES},
            "last_leave_ticks": {
                phase: 3 for phase in native_body_trace.CORE_PHASES
            },
            "fresh_after_activation": {"TICK": True, "RENDER": True},
            "complete": True,
        },
        "return": {
            "pre": {
                "current_mode": mode, "pending_null": True,
                "loaded": True, "opened": True,
            },
            "post": {
                "current_mode": mode, "pending_mode": return_mode,
                "dispatch_effect": "PENDING_RETURN",
            },
            "activation": {
                "current_mode": return_mode, "pending_null": True,
                "loaded": True, "opened": True,
            },
        },
        "teardown": {
            "close_pairs_delta": 1,
            "unload_pairs_delta": 0 if flight else 1,
            "close_observed": True,
            "unload_observed": not flight,
            "unload_policy": "SKIPPED_MODE_FLY" if flight else "MANAGER_COMMIT",
            "missing_phases": ["UNLOAD"] if flight else [],
            "complete": not flight,
        },
        "lifecycle_complete": not flight,
    }


class NativeBodyTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = native_body_trace.load_contract()

    def test_paired_trace_is_body_only_and_constructor_remains_unresolved(self):
        records = [event(0, "ENTER"), event(1, "LEAVE")]
        result = native_body_trace.validate_records(records, self.contract)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["observed"], {"barn": {"OPEN": 1}})
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(
            result["phase_coverage"]["barn"]["missing_phases"],
            ["LOAD", "TICK", "RENDER", "CLOSE", "UNLOAD"],
        )
        self.assertEqual(result["constructor_capture"], "UNRESOLVED")
        self.assertFalse(result["natural_transition_evidence"])
        self.assertFalse(result["parity_eligible"])

    def test_all_six_declared_phases_are_required_for_coverage_pass(self):
        entries = {
            "LOAD": "0x004156d0",
            "OPEN": "0x00416180",
            "TICK": "0x004169a0",
            "RENDER": "0x00416370",
            "CLOSE": "0x00416320",
            "UNLOAD": "0x00416000",
        }
        records = []
        for phase, entry in entries.items():
            sequence = len(records)
            records.extend([
                event(sequence, "ENTER", phase=phase, entry=entry),
                event(sequence + 1, "LEAVE", phase=phase, entry=entry),
            ])
        result = native_body_trace.validate_records(
            records, self.contract, required_mode_ids=("barn",),
        )
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["coverage_complete"])
        self.assertEqual(
            result["phase_coverage"]["barn"],
            {
                "mode": "mode_barn",
                "counts": {phase: 1 for phase in native_body_trace.PHASES},
                "last_leave_ticks": {
                    phase: 3 for phase in native_body_trace.PHASES
                },
                "missing_phases": [],
                "complete": True,
            },
        )

    def test_schema2_dispatch_is_bound_to_fresh_core_and_exact_teardown(self):
        entries = {
            "LOAD": "0x004156d0", "OPEN": "0x00416180",
            "TICK": "0x004169a0", "RENDER": "0x00416370",
            "CLOSE": "0x00416320", "UNLOAD": "0x00416000",
        }
        records = []
        for phase, entry in entries.items():
            sequence = len(records)
            records.extend([
                event(sequence, "ENTER", phase=phase, entry=entry),
                event(sequence + 1, "LEAVE", phase=phase, entry=entry),
            ])
        lifecycle = native_body_trace.validate_records(
            records, self.contract, required_mode_ids=("barn",),
        )
        receipt = dispatch_receipt()
        self.assertEqual(
            native_body_trace.validate_dispatch_receipt(
                receipt, executable_sha256="a" * 64,
                requested_mode="mode_barn", mode_id="barn",
                lifecycle_validation=lifecycle,
            ),
            receipt,
        )

        stale = copy.deepcopy(receipt)
        stale["ticks"]["target_activation"] = 4
        stale["ticks"]["core_ready"] = 4
        stale["ticks"]["return_dispatch"] = 4
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "freshness"):
            native_body_trace.validate_dispatch_receipt(
                stale, executable_sha256="a" * 64,
                requested_mode="mode_barn", mode_id="barn",
                lifecycle_validation=lifecycle,
            )

        one_callback = copy.deepcopy(receipt)
        one_callback["callback_count"] = 1
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "envelope"):
            native_body_trace.validate_dispatch_receipt(
                one_callback, executable_sha256="a" * 64,
                requested_mode="mode_barn", mode_id="barn",
                lifecycle_validation=lifecycle,
            )

        wrong_return = copy.deepcopy(receipt)
        wrong_return["return"]["post"]["pending_mode"] = "mode_barn"
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "return transition"):
            native_body_trace.validate_dispatch_receipt(
                wrong_return, executable_sha256="a" * 64,
                requested_mode="mode_barn", mode_id="barn",
                lifecycle_validation=lifecycle,
            )

    def test_schema1_activation_cannot_claim_lifecycle_completion(self):
        with self.assertRaisesRegex(
            native_body_trace.BodyTraceError,
            "schema 1 cannot prove lifecycle completion",
        ):
            native_body_trace.validate_dispatch_receipt(
                {"schema": 1}, executable_sha256="a" * 64,
                requested_mode="mode_barn", mode_id="barn",
                lifecycle_validation={},
            )

    def test_flight_unload_skip_remains_explicitly_incomplete(self):
        flight = next(
            row for row in self.contract["modes"] if row["mode"] == "mode_fly"
        )
        records = []
        for phase in native_body_trace.PHASES:
            if phase == "UNLOAD":
                continue
            sequence = len(records)
            changes = {
                "mode_id": flight["id"], "vtable": flight["vtable"],
                "phase": phase, "entry": flight["lifecycle"][phase.lower()],
            }
            records.extend([
                event(sequence, "ENTER", **changes),
                event(sequence + 1, "LEAVE", **changes),
            ])
        lifecycle = native_body_trace.validate_records(
            records, self.contract, required_mode_ids=(flight["id"],),
        )
        receipt = dispatch_receipt(mode="mode_fly", flight=True)
        native_body_trace.validate_dispatch_receipt(
            receipt, executable_sha256="a" * 64,
            requested_mode="mode_fly", mode_id=flight["id"],
            lifecycle_validation=lifecycle,
        )
        self.assertEqual(lifecycle["status"], "INCOMPLETE")
        self.assertEqual(
            lifecycle["phase_coverage"][flight["id"]]["missing_phases"],
            ["UNLOAD"],
        )

        promoted = copy.deepcopy(receipt)
        promoted["status"] = "PASS"
        promoted["teardown"]["unload_policy"] = "MANAGER_COMMIT"
        promoted["teardown"]["missing_phases"] = []
        promoted["teardown"]["complete"] = True
        promoted["lifecycle_complete"] = True
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "envelope"):
            native_body_trace.validate_dispatch_receipt(
                promoted, executable_sha256="a" * 64,
                requested_mode="mode_fly", mode_id=flight["id"],
                lifecycle_validation=lifecycle,
            )

    def test_required_unobserved_mode_is_explicitly_incomplete(self):
        records = [event(0, "ENTER"), event(1, "LEAVE")]
        result = native_body_trace.validate_records(
            records, self.contract, required_mode_ids=("login",),
        )
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(
            result["phase_coverage"]["login"]["missing_phases"],
            list(native_body_trace.PHASES),
        )

    def test_nested_pairs_require_exact_identity_and_lifo_order(self):
        records = [
            event(0, "ENTER", phase="TICK", entry="0x004169a0"),
            event(1, "ENTER", depth=1),
            event(2, "LEAVE", depth=1),
            event(3, "LEAVE", phase="TICK", entry="0x004169a0"),
        ]
        result = native_body_trace.validate_records(records, self.contract)
        self.assertEqual(result["pair_count"], 2)
        broken = copy.deepcopy(records)
        broken[2]["object"] = "0x12345679"
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "does not pair"):
            native_body_trace.validate_records(broken, self.contract)

    def test_static_address_or_unpaired_edge_never_promotes(self):
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "unpaired"):
            native_body_trace.validate_records([event(0, "ENTER")], self.contract)
        broken = [event(0, "ENTER"), event(1, "LEAVE")]
        broken[1]["entry"] = "0x00416181"
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "canonical phase"):
            native_body_trace.validate_records(broken, self.contract)

    def test_natural_transition_claim_and_non_engine_thread_fail_closed(self):
        broken = [event(0, "ENTER"), event(1, "LEAVE")]
        broken[0]["natural_transition_evidence"] = True
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "BODY-only"):
            native_body_trace.validate_records(broken, self.contract)
        broken = [event(0, "ENTER"), event(1, "LEAVE", thread=78)]
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "non-engine thread"):
            native_body_trace.validate_records(broken, self.contract)

    def test_parser_ignores_other_channels_but_rejects_malformed_mvb(self):
        lines = [
            "MVT {}\n",
            "MVB " + json.dumps(event(0, "ENTER")) + "\n",
            "MVB " + json.dumps(event(1, "LEAVE")) + "\n",
        ]
        self.assertEqual(len(native_body_trace.parse_records(lines)), 2)
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "invalid JSON"):
            native_body_trace.parse_records(["MVB {\n"])

    def test_sequence_and_phase_are_strict(self):
        broken = [event(1, "ENTER"), event(2, "LEAVE")]
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "not contiguous"):
            native_body_trace.validate_records(broken, self.contract)
        broken = [event(0, "ENTER", phase="CONSTRUCT"), event(1, "LEAVE", phase="CONSTRUCT")]
        with self.assertRaisesRegex(native_body_trace.BodyTraceError, "unknown phase"):
            native_body_trace.validate_records(broken, self.contract)

    def test_c_observer_table_matches_all_22_canonical_rows(self):
        source = HOOK.read_text(encoding="utf-8")
        row_pattern = re.compile(
            r'^\s*\{"([a-z_]+)", "([a-z_]+)", (0x[0-9a-f]{8})u, '
            r'(0x[0-9a-f]{8})u, \{([^}]+)\}\},$',
            re.MULTILINE,
        )
        rows = {}
        for match in row_pattern.finditer(source):
            entries = [item.strip().removesuffix("u") for item in match.group(5).split(",")]
            rows[match.group(1)] = {
                "mode": match.group(2),
                "vtable": match.group(3),
                "constructor": match.group(4),
                "entries": entries,
            }
        self.assertEqual(len(rows), 22)
        for mode in self.contract["modes"]:
            observed = rows[mode["id"]]
            self.assertEqual(observed["mode"], mode["mode"])
            self.assertEqual(observed["vtable"], mode["vtable"])
            self.assertEqual(observed["constructor"], mode["constructor"])
            self.assertEqual(
                observed["entries"],
                [
                    mode["lifecycle"][phase]
                    for phase in ("load", "open", "tick", "render", "close", "unload")
                ],
            )

    def test_c_observer_is_body_gated_and_interposes_exact_slots(self):
        source = HOOK.read_text(encoding="utf-8")
        self.assertIn("body_dispatch_state == BODY_DISPATCH_DISABLED", source)
        self.assertIn("install_body_lifecycle_interposition", source)
        self.assertIn("rollback_body_lifecycle_interposition", source)
        self.assertIn("natural_transition_evidence\\\":false", source)
        offsets = re.search(
            r'BODY_PHASE_VTABLE_OFFSETS\[BODY_PHASE_COUNT\] = \{([^}]+)\}',
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(offsets)
        self.assertEqual(
            [item.strip() for item in offsets.group(1).split(",") if item.strip()],
            ["0x20u", "0x08u", "0x14u", "0x10u", "0x0cu", "0x24u"],
        )
        self.assertNotIn("BODY_LIFECYCLE_HOOK(body_construct_hook", source)

    def test_c_observer_emits_schema2_after_two_lifecycle_bound_callbacks(self):
        source = HOOK.read_text(encoding="utf-8")
        self.assertIn("BODY_DISPATCH_WAIT_CORE", source)
        self.assertIn("BODY_DISPATCH_WAIT_RETURN_ACTIVATION", source)
        self.assertIn("BODY_DISPATCH_WAIT_TEARDOWN", source)
        self.assertIn('\\"callback_count\\":2', source)
        self.assertIn('\\"lifecycle_complete\\":%s', source)
        self.assertIn(
            '\\"fresh_after_activation\\":{\\"TICK\\":true,'
            '\\"RENDER\\":true}',
            source,
        )
        self.assertIn("body_dispatch.callback_count = 2u", source)
        self.assertIn(
            'strcmp(mode->mode_name, body_mode_name) != 0', source,
        )
        self.assertIn(
            'return strcmp(body_mode_name, "mode_barn") == 0', source,
        )
        self.assertIn("body_dispatch.phase_counts[BODY_PHASE_CLOSE] == 1u", source)
        self.assertIn(
            "body_dispatch.phase_counts[BODY_PHASE_UNLOAD] == expected_unloads",
            source,
        )


if __name__ == "__main__":
    unittest.main()
