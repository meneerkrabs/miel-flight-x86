#!/usr/bin/env python3
import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_udsp_trace


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"


def event(sequence, call_id, phase, opcode_id=15, depth=0, **changes):
    command = native_udsp_trace.OBSERVED_COMMANDS[opcode_id]
    value = {
        "schema": 1,
        "protocol": native_udsp_trace.PROTOCOL,
        "sequence": sequence,
        "evidence_scope": "UDSP_ONLY",
        "natural_transition_evidence": False,
        "call_id": call_id,
        "phase": phase,
        "thread": 77,
        "tick": 3,
        "depth": depth,
        "dispatcher": "0x0043c580",
        "parser_case": command["parser_case"],
        "handler_case": command["handler_case"],
        "composite": "0x12340000",
        "node": f"0x{0x12341000 + call_id * 0x100:08x}",
        "opcode_id": opcode_id,
        "opcode_name": command["name"],
        "dt_f32_bits": "0x3c888889",
        "complete": phase == "AFTER",
        "started": phase == "AFTER",
        "modifier": 0,
        "timer_f32_bits": "0x3f800000",
        "context": "0x12342000",
        "next": "0x00000000",
        "callback": "0x0044d4b0",
        "payload": [f"0x{index:08x}" for index in range(5)],
        "parent_complete": phase == "AFTER",
        "parent_current": "0x00000000" if phase == "AFTER" else
            f"0x{0x12341000 + call_id * 0x100:08x}",
        "advanced": phase == "AFTER",
        "outcome": "COMPLETE" if phase == "AFTER" else "PENDING",
    }
    value.update(changes)
    return value


class NativeUdspTraceTests(unittest.TestCase):
    def test_all_ten_observed_opcodes_pair_with_exact_static_classifier(self):
        records = []
        for call_id, opcode_id in enumerate(native_udsp_trace.OBSERVED_COMMANDS):
            records.extend([
                event(len(records), call_id, "BEFORE", opcode_id),
                event(len(records) + 1, call_id, "AFTER", opcode_id),
            ])
        result = native_udsp_trace.validate_records(records)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["pair_count"], 10)
        self.assertEqual(
            result["observed_opcode_ids"],
            list(native_udsp_trace.OBSERVED_COMMANDS),
        )
        self.assertFalse(result["natural_transition_evidence"])
        self.assertFalse(result["parity_eligible"])

    def test_observed_opcode_inventory_is_derived_from_the_selected_contract(self):
        contract = json.loads(native_udsp_trace._CONTRACT.read_text(encoding="utf-8"))
        command = next(row for row in contract["commands"] if row["id"] == 4)
        command["def_observation"] = {
            "evidence": "OBSERVED_DEF",
            "occurrences": 1,
            "arities": [1],
            "argument_schemas": {"1": ["character_id"]},
        }
        contract["policy"]["observed_def_command_count"] += 1
        contract["policy"]["unobserved_registered_ids"].remove(4)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native-commands.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            observed = native_udsp_trace._load_observed_commands(path)
        self.assertEqual(list(observed), [1, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15])
        self.assertEqual(observed[4]["name"], "STOP_CHARACTER_ANIMATION")

    def test_observed_opcode_inventory_rejects_contract_policy_drift(self):
        contract = json.loads(native_udsp_trace._CONTRACT.read_text(encoding="utf-8"))
        contract["policy"]["observed_def_command_count"] += 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native-commands.json"
            path.write_text(json.dumps(contract), encoding="utf-8")
            with self.assertRaisesRegex(
                native_udsp_trace.UdspTraceError,
                "observed opcode inventory differs from edition contract",
            ):
                native_udsp_trace._load_observed_commands(path)

    def test_nested_calls_are_lifo_and_pair_by_call_node_and_opcode(self):
        records = [
            event(0, 7, "BEFORE", 1),
            event(1, 8, "BEFORE", 3, depth=1),
            event(2, 8, "AFTER", 3, depth=1),
            event(3, 7, "AFTER", 1),
        ]
        self.assertEqual(native_udsp_trace.validate_records(records)["pair_count"], 2)
        broken = copy.deepcopy(records)
        broken[2]["node"] = "0x1234ffff"
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "does not pair"):
            native_udsp_trace.validate_records(broken)
        broken = copy.deepcopy(records)
        broken[3]["dt_f32_bits"] = "0x00000000"
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "does not pair"):
            native_udsp_trace.validate_records(broken)

    def test_interleaved_threads_have_independent_bounded_lifo_pairing(self):
        records = [
            event(0, 7, "BEFORE", 1, thread=77),
            event(1, 8, "BEFORE", 3, thread=88),
            event(2, 7, "AFTER", 1, thread=77),
            event(3, 8, "AFTER", 3, thread=88),
        ]
        self.assertEqual(native_udsp_trace.validate_records(records)["pair_count"], 2)

    def test_scope_transition_claim_unknown_opcode_and_unpaired_trace_fail_closed(self):
        records = [event(0, 0, "BEFORE"), event(1, 0, "AFTER")]
        broken = copy.deepcopy(records)
        broken[0]["natural_transition_evidence"] = True
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "UDSP-only"):
            native_udsp_trace.validate_records(broken)
        broken = copy.deepcopy(records)
        broken[1]["evidence_scope"] = "BODY_ONLY"
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "UDSP-only"):
            native_udsp_trace.validate_records(broken)
        broken = copy.deepcopy(records)
        broken[0]["opcode_id"] = 2
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "unobserved opcode"):
            native_udsp_trace.validate_records(broken)
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "unpaired"):
            native_udsp_trace.validate_records(records[:1])

    def test_static_cases_pointer_shapes_and_outcomes_are_strict(self):
        records = [event(0, 0, "BEFORE"), event(1, 0, "AFTER")]
        broken = copy.deepcopy(records)
        broken[0]["handler_case"] = "0x0043c680"
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "handler case"):
            native_udsp_trace.validate_records(broken)
        broken = copy.deepcopy(records)
        broken[1]["payload"] = broken[1]["payload"][:4]
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "payload"):
            native_udsp_trace.validate_records(broken)
        broken = copy.deepcopy(records)
        broken[1]["outcome"] = "SEMANTICALLY_EQUIVALENT"
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "outcome"):
            native_udsp_trace.validate_records(broken)
        broken = copy.deepcopy(records)
        broken[0]["invented_semantics"] = True
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "schema"):
            native_udsp_trace.validate_records(broken)
        broken = copy.deepcopy(records)
        broken[0]["depth"] = 64
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "depth"):
            native_udsp_trace.validate_records(broken)

    def test_parser_uses_a_dedicated_channel_and_rejects_malformed_records(self):
        lines = [
            "MVT {}\n",
            "MVU " + json.dumps(event(0, 0, "BEFORE")) + "\n",
            "MVU " + json.dumps(event(1, 0, "AFTER")) + "\n",
        ]
        self.assertEqual(len(native_udsp_trace.parse_records(lines)), 2)
        with self.assertRaisesRegex(native_udsp_trace.UdspTraceError, "invalid JSON"):
            native_udsp_trace.parse_records(["MVU {\n"])

    def test_c_hook_has_one_hash_gated_synthetic_return_detour(self):
        source = HOOK.read_text(encoding="utf-8")
        self.assertIn(
            "0xa8, 0x45, 0x50, 0xb4, 0x66, 0x12, 0xdc, 0x32",
            source,
        )
        self.assertIn("UDSP_DISPATCH ((BYTE *)(ULONG_PTR)0x0043c580u)", source)
        self.assertIn(
            "0x83, 0xec, 0x08, 0x53, 0x55, 0x56",
            source,
        )
        self.assertIn("UDSP_CALL_DEPTH 64u", source)
        self.assertIn("UDSP_THREAD_CONTEXT_COUNT 8u", source)
        self.assertIn("read_udsp_u32", source)
        self.assertIn("offset > MAXDWORD - address", source)
        self.assertIn("udsp_dispatch_hook", source)
        self.assertIn("udsp_dispatch_leave_hook", source)
        self.assertIn("miel-vliegt-native-udsp-command", source)
        self.assertIn('evidence_scope\\\":\\\"UDSP_ONLY', source)
        self.assertIn('natural_transition_evidence\\\":false', source)
        self.assertIn(
            "install_detour(UDSP_DISPATCH, UDSP_DISPATCH_SIGNATURE,",
            source,
        )
        self.assertEqual(
            source.count("install_detour(UDSP_DISPATCH, UDSP_DISPATCH_SIGNATURE,"),
            1,
        )
        self.assertIn(
            "rollback_detour(UDSP_DISPATCH, UDSP_DISPATCH_SIGNATURE,",
            source,
        )
        table = source[
            source.index("UDSP_COMMANDS[UDSP_COMMAND_COUNT]"):
            source.index("typedef struct ObserverThread")
        ]
        rows = re.findall(
            r'\{(\d+)u, "([A-Z_]+)", (0x[0-9a-f]{8})u, (0x[0-9a-f]{8})u\}',
            table,
        )
        expected = [
            (str(opcode_id), command["name"], command["parser_case"],
             command["handler_case"])
            for opcode_id, command in native_udsp_trace.OBSERVED_COMMANDS.items()
        ]
        self.assertEqual(rows, expected)


if __name__ == "__main__":
    unittest.main()
