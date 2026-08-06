#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_common_location_state_machine as common


ROOT = Path(__file__).resolve().parents[2]
EXECUTABLE = ROOT / "tmp/miel-vliegt-native-local/MulleMeck.exe"
CONTRACT = ROOT / "content/miel_vliegt/native_common_location_state_machine.json"


@unittest.skipUnless(EXECUTABLE.is_file(), "pinned native executable unavailable")
class NativeCommonLocationStateMachineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = common.extract_contract(EXECUTABLE)
        cls.checked = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_checked_contract_is_exact_generator_output(self):
        self.assertEqual(self.generated, self.checked)

    def test_three_dispatch_tables_and_receipts_are_exact(self):
        routines = self.generated["routines"]
        self.assertEqual(routines["update"]["jump_table"]["targets"], [
            "0x00425c06", "0x00426534", "0x00425c89", "0x00425fc0",
            "0x00425e6b", "0x0042611f", "0x004263be", "0x004264b1",
        ])
        self.assertEqual(routines["setter"]["jump_table"]["targets"], [
            "0x00426e34", "0x00426f4d", "0x00426a43", "0x0042682c",
            "0x00426704", "0x00426c17", "0x00426596", "0x00426f1a",
        ])
        self.assertEqual(routines["render"]["jump_table"]["targets"], [
            "0x00427375", "0x004275d8", "0x004273e8", "0x004273e8",
            "0x004273e8", "0x004274c5", "0x0042745b", "0x0042757a",
        ])
        self.assertEqual(
            routines["update"]["prologue_receipt"]["sha256"],
            "298acb87f904525bae75ba37ad568fa91ea33262f8c270594f27a74af4054475",
        )
        self.assertEqual(
            routines["setter"]["prologue_receipt"]["sha256"],
            "e8f72e90f510e2e15403f51c74d5d33f2bc972aa983afaa790ffed2770e9bf6b",
        )
        self.assertEqual([
            routines[name]["jump_table"]["receipt"]["sha256"]
            for name in ("update", "setter", "render")
        ], [
            "2c326d25bacb65859ddf0f5bbc5632ae258052a0567197268ad609e7490987e3",
            "b5f40d1873bf58f3cb32fbb05c70cad27ffcd2842fc036759ea1197f62a6d99e",
            "4e9fa6b507d940052d660e9e2f8a1c9c349498ded1e81bced82b12c52a1046ff",
        ])

    def test_direct_state_references_and_stored_state_11_are_not_conflated(self):
        state = self.generated["state"]
        self.assertEqual(state["common_dispatch_domain"], {"minimum": 0, "maximum": 7})
        self.assertEqual(state["stored_domain_extension"]["value"], 11)
        self.assertEqual(state["stored_domain_extension"]["owner"], "mode_raymondrajser")
        self.assertEqual([row["address"] for row in state["direct_references"]], [
            "0x00425be9", "0x00426583", "0x0042735f", "0x00441b2c",
            "0x00441b74", "0x004440ce", "0x00444725",
        ])

    def test_common_controller_can_never_be_labelled_as_mode_fly_tick(self):
        boundary = self.generated["semantic_boundaries"]
        self.assertEqual(boundary, {
            "common_location_controller_update": "0x00425ab0",
            "mode_fly": {
                "vtable": "0x0044cf58",
                "tick": "0x0042ca10",
                "render": "0x0042d6d0",
            },
            "invariant": "COMMON_LOCATION_CONTROLLER_IS_NOT_MODE_FLY_LIFECYCLE",
            "all_entries_distinct": True,
            "runtime_parity": "NATIVE_TRACE_REQUIRED",
        })
        self.assertEqual(
            self.generated["routines"]["update"]["semantic_role"],
            "common_location_controller_update",
        )
        self.assertNotIn(
            boundary["common_location_controller_update"],
            boundary["mode_fly"].values(),
        )

    def test_complete_static_transition_graph_is_instruction_receipted(self):
        graph = self.generated["transition_graph"]
        self.assertEqual(
            [(row["source"], row["target"], row["callsite"]) for row in graph["update_edges"]],
            [
                (0, 2, "0x00425c7b"), (2, 6, "0x00425daa"),
                (2, 0, "0x00425de4"), (2, 4, "0x00425e55"),
                (4, 0, "0x00425f72"), (3, 0, "0x0042606d"),
                (5, 4, "0x00426364"), (5, 0, "0x004263b1"),
                (6, 5, "0x004264a3"), (7, 5, "0x00426527"),
            ],
        )
        self.assertEqual(
            [(row["source"], row["target"], row["callsite"])
             for row in graph["setter_reentry_edges"]],
            [(2, 4, "0x00426b23"), (2, 3, "0x00426b45")],
        )
        for row in graph["update_edges"] + graph["setter_reentry_edges"]:
            self.assertTrue(row["predicate"])
            self.assertRegex(row["receipt"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(row["runtime_parity"], "NATIVE_TRACE_REQUIRED")
        self.assertEqual(graph["runtime_parity"], "NATIVE_TRACE_REQUIRED")

    def test_all_18_locations_reach_common_tick_and_setter(self):
        rows = self.generated["reachability"]["locations"]
        self.assertEqual(len(rows), 18)
        self.assertEqual(len({row["mode"] for row in rows}), 18)
        self.assertTrue(all(row["update_callsites"] for row in rows))
        self.assertTrue(all(row["common_setter_callsites"] for row in rows))
        self.assertEqual(
            next(row for row in rows if row["mode"] == "mode_fionafalk")["update_callsites"],
            ["0x00441073", "0x0044111a"],
        )

    def test_departure_barn_and_pending_target_roles_are_exact(self):
        transitions = self.generated["transitions"]
        self.assertEqual(transitions["flight_departure"]["commit_callsites"], [
            "0x00425c2e", "0x00425cb1", "0x00425e90", "0x00425fe5", "0x004262ee",
        ])
        self.assertEqual(transitions["barn_returns"]["generic_common_callsite"], "0x00425b7e")
        pending = transitions["pending_target"]
        self.assertEqual(pending["landing_marker_producer"], "0x00430fa4")
        self.assertEqual(pending["manager_queue_commit"], "0x0042c790")
        self.assertEqual(
            pending["landing_marker"]["routine"]["sha256"],
            "e8b0fc7ff0ba11eaf3ae094da617939d53ff2f923a797b417a2b87cd85eb7348",
        )
        self.assertNotEqual(pending["landing_marker_producer"], pending["manager_queue_commit"])
        self.assertEqual(self.generated["policy"]["runtime_parity"], "NATIVE_TRACE_REQUIRED")

    def test_mutated_executable_fails_closed(self):
        data = bytearray(EXECUTABLE.read_bytes())
        image = common.PeImage(EXECUTABLE)
        data[image.address_to_offset(0x00425AB0)] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.exe"
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "identities differ|occurs 0 times"):
                common.extract_contract(path)

    def test_mode_body_attempt_to_conflate_controller_and_mode_fly_fails(self):
        mode_bodies = json.loads(common.DEFAULT_MODE_BODIES.read_text(encoding="utf-8"))
        flight = next(row for row in mode_bodies["modes"] if row["id"] == "flight")
        flight["lifecycle"]["tick"] = "0x00425ab0"
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as directory:
            path = Path(directory) / "native_mode_bodies.json"
            path.write_text(json.dumps(mode_bodies), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "mode_fly tick/render differ"):
                common.extract_contract(EXECUTABLE, path)


if __name__ == "__main__":
    unittest.main()
