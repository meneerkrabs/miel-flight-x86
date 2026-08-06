from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.native_scene_dispatch_trace import (
    PROTOCOL,
    SceneDispatchTraceError,
    load_records,
    validate_record,
)


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"


def snapshot(*, queue: list[str] | None = None, running: int = 0) -> dict:
    return {
        "valid": True,
        "queue": queue or ["0x00000000"] * 4,
        "root_complete": 0,
        "root_running": running,
        "root_current": "0x00000000",
        "root_next": "0x00000000",
    }


def record(route: str | None = "FLIGHT", kind: str = "DISPATCH") -> dict:
    root = "0x12345678"
    before_queue = ["0x00000000"] * 4
    after_queue = [root, "0x00000000", "0x00000000", "0x00000000"]
    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "sequence": 0,
        "evidence_scope": "SCENE_DISPATCH_ONLY",
        "natural_transition_evidence": False,
        "body_evidence": False,
        "observation_status": "OBSERVED",
        "call_id": 0,
        "record_kind": kind,
        "route": route,
        "object": "0x23456789",
        "object_vtable": "0x0044cf58",
        "root": root,
        "root_name": "challenge_first",
        "root_name_status": "RESOLVED",
        "caller": "0x0041e1b0",
        "thread": 7,
        "manager_thread": True,
        "manager_tick": 42,
        "depth": 0,
        "dt_f32_bits": "0x3dcccccd",
        "before": snapshot(queue=before_queue),
        "after": snapshot(queue=after_queue, running=int(kind == "ROOT_START")),
        "special_policy": {
            "policy": "GENERIC",
            "semantic_status": "NOT_SPECIAL",
            "before": ["0x00000000", "0x00000000"],
            "after": ["0x00000000", "0x00000000"],
        },
    }


class NativeSceneDispatchTraceTests(unittest.TestCase):
    def test_flight_dispatch_is_exact_and_isolated(self) -> None:
        self.assertEqual(validate_record(record())["route"], "FLIGHT")

    def test_root_start_requires_null_route_and_running_after(self) -> None:
        value = record(None, "ROOT_START")
        value["before"]["queue"] = ["0x00000000"] * 4
        value["after"]["queue"] = ["0x00000000"] * 4
        self.assertEqual(validate_record(value)["record_kind"], "ROOT_START")
        value["after"]["root_running"] = 0
        with self.assertRaisesRegex(SceneDispatchTraceError, "did not arm"):
            validate_record(value)

    def test_unresolved_name_must_be_null(self) -> None:
        value = record()
        value["root_name_status"] = "UNRESOLVED"
        with self.assertRaisesRegex(SceneDispatchTraceError, "must be null"):
            validate_record(value)

    def test_bool_cannot_bypass_integer_schema_or_sequence(self) -> None:
        for key in ("schema", "sequence", "call_id", "thread"):
            value = record()
            value[key] = True
            with self.subTest(key=key), self.assertRaises(SceneDispatchTraceError):
                validate_record(value)

    def test_body_or_natural_claim_is_rejected(self) -> None:
        for key in ("body_evidence", "natural_transition_evidence"):
            value = record()
            value[key] = True
            with self.subTest(key=key), self.assertRaises(SceneDispatchTraceError):
                validate_record(value)

    def test_special_policy_cannot_overclaim_projected_x(self) -> None:
        value = record()
        value["special_policy"] = {
            "policy": "EXHIBITION_SELECTOR",
            "semantic_status": "FULL_SELECTOR_SNAPSHOT",
            "before": ["0x00000000", "0x00000000"],
            "after": ["0x00000001", "0x00000000"],
        }
        with self.assertRaisesRegex(SceneDispatchTraceError, "fail-closed"):
            validate_record(value)

    def test_unresolved_observation_requires_an_invalid_snapshot(self) -> None:
        value = record()
        value["observation_status"] = "UNRESOLVED"
        with self.assertRaisesRegex(SceneDispatchTraceError, "disagrees"):
            validate_record(value)
        value["before"]["valid"] = False
        self.assertEqual(validate_record(value)["observation_status"], "UNRESOLVED")

    def test_barn_queue_contract_is_enforced(self) -> None:
        value = record("BARN")
        value["before"]["queue"] = ["0x11111111", "0x11111111", "0x00000000", "0x00000000"]
        value["after"]["queue"] = ["0x11111111", value["root"], "0x00000000", "0x00000000"]
        validate_record(value)
        value["after"]["queue"][1] = "0x22222222"
        with self.assertRaisesRegex(SceneDispatchTraceError, "queue tail"):
            validate_record(value)

    def test_loader_filters_other_mvd_protocols_and_requires_contiguous_ids(self) -> None:
        first = record()
        second = copy.deepcopy(first)
        second["sequence"] = second["call_id"] = 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.log"
            path.write_text(
                "MVD {\"protocol\":\"other\"}\n" +
                "MVD " + json.dumps(first, separators=(",", ":")) + "\n" +
                "MVD " + json.dumps(second, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(len(load_records(path)), 2)
            second["call_id"] = 2
            path.write_text(
                "MVD " + json.dumps(first) + "\n" +
                "MVD " + json.dumps(second) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SceneDispatchTraceError, "contiguous"):
                load_records(path)

    def test_hook_contains_all_signature_checked_rollback_safe_sites(self) -> None:
        source = HOOK.read_text(encoding="utf-8")
        for token in (
            "SCENE_DISPATCH_GROUND", "SCENE_DISPATCH_BARN",
            "SCENE_DISPATCH_FLIGHT", "UDSP_ROOT_START", "UDSP_ROOT_UPDATE",
        ):
            with self.subTest(token=token):
                self.assertIn(f"memcmp({token}, {token}_SIGNATURE", source)
                self.assertIn(f"install_detour({token}", source)
                self.assertIn(f"rollback_detour({token}", source)
        self.assertIn('"natural_transition_evidence\\\":false', source)
        self.assertIn('"body_evidence\\\":false', source)
        self.assertIn("OUTRO_FLAG_ONLY_PROJECTED_X_UNRESOLVED", source)

    def test_hook_sites_and_signatures_match_the_pinned_executable_map(self) -> None:
        compact = "".join(HOOK.read_text(encoding="utf-8").split())
        expected = {
            "SCENE_DISPATCH_BARN": (
                "0x00416940u", "0x56,0x8b,0xf1,0x57,0x33,0xff,"
                "0x8b,0x86,0xec,0x1a,0x00,0x00"
            ),
            "SCENE_DISPATCH_GROUND": (
                "0x00427210u", "0x56,0x8b,0xf1,0x6a,0x0c,"
                "0xe8,0x6a,0x14,0x02,0x00"
            ),
            "SCENE_DISPATCH_FLIGHT": (
                "0x0042e540u", "0x8b,0x44,0x24,0x04,0x85,0xc0,"
                "0x89,0x81,0xc0,0x3f,0x00,0x00"
            ),
            "UDSP_ROOT_START": (
                "0x0043cd60u", "0x56,0x8b,0xf1,0x8b,0x06,0xff,0x50,0x04"
            ),
            "UDSP_ROOT_UPDATE": (
                "0x0043cd20u", "0x56,0x8b,0xf1,0x8a,0x46,0x28"
            ),
        }
        for name, (address, signature) in expected.items():
            with self.subTest(name=name):
                self.assertIn(
                    f"#define{name}((BYTE*)(ULONG_PTR){address})", compact
                )
                self.assertIn(
                    f"staticconstBYTE{name}_SIGNATURE[]={{{signature}}};", compact
                )


if __name__ == "__main__":
    unittest.main()
