#!/usr/bin/env python3
import copy
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from tools.miel_vliegt import native_reachability_closures as closures


ROOT = Path(__file__).resolve().parents[2]
PINNED_EXECUTABLE = ROOT / "tmp/miel-vliegt-native-local/MulleMeck.exe"


class NativeReachabilityClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reviews = {
            name: json.loads(
                (ROOT / relative).read_text(encoding="utf-8")
            )
            for name, relative in closures.OUTPUTS.items()
        }

    def test_tracked_reviews_are_hash_bound_and_fail_closed(self):
        self.assertEqual(
            closures.validate_all(self.reviews, root=ROOT),
            self.reviews,
        )
        self.assertEqual(
            {
                name: (
                    review["reviewStatus"],
                    len(review["inventory"]["sites"]),
                    len(review["inventory"]["targetFunctionIds"]),
                    len(review["unresolvedPaths"]),
                )
                for name, review in self.reviews.items()
            },
            {
                "roots": ("CLOSED", 1, 292, 0),
                "callbacks": ("CLOSED", 1235, 314, 0),
                "vtables": ("CLOSED", 1819, 679, 0),
                "indirectTargets": ("OPEN", 2124, 752, 948),
            },
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "resolvedExternalImportCallCount"
            ],
            853,
        )
        self.assertEqual(
            len({
                row["site"] for row in self.reviews["indirectTargets"]["evidence"][
                    "resolvedExternalImportCalls"
                ]
            }),
            853,
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "resolvedInternalBranchCount"
            ],
            36,
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "resolvedStackParameterCallCount"
            ],
            3,
        )
        self.assertEqual(
            {
                row["callAddress"]: row["targetAddresses"]
                for row in self.reviews["indirectTargets"]["evidence"][
                    "resolvedStackParameterCalls"
                ]
            },
            {
                "0x00448711": [
                    "0x00401800", "0x004083c0",
                    "0x00432d80", "0x0043df20",
                ],
                "0x00448786": [
                    "0x00401800", "0x004083c0",
                    "0x00432d80", "0x0043df20",
                ],
                "0x004487fe": [
                    "0x00408370", "0x00415510",
                    "0x00432d10", "0x0043f000",
                ],
            },
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "resolvedMergedExternalImportCallCount"
            ],
            47,
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "resolvedAssignedVtableCallCount"
            ],
            133,
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "indirectSiteClassificationKinds"
            ],
            {
                "ABSOLUTE_MEMORY_BRANCH": 93,
                "ADJUSTED_VPTR": 52,
                "CANONICAL_VPTR": 1014,
                "CFG_CARRIED_MEMORY_TARGET": 14,
                "INDEXED_MEMORY_BRANCH": 46,
                "LOCAL_DEFINED_MEMORY_BRANCH": 1,
                "REGISTER_TARGET": 901,
                "TAIL_VPTR": 3,
            },
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "indirectSiteClassificationCount"
            ],
            2124,
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "resolvedAssignedVtableBranchCount"
            ],
            1,
        )
        self.assertEqual(
            {
                row["branchAddress"]: (
                    row["slotIndex"],
                    row["targetAddresses"],
                    row["targetFunctionIds"],
                )
                for row in self.reviews["indirectTargets"]["evidence"][
                    "resolvedAssignedVtableBranches"
                ]
            },
            {
                "0x00421e6d": (
                    9,
                    ["0x00421740", "0x00421d80"],
                    ["fn_00421740", "fn_00421d80"],
                ),
            },
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "resolvedRemappedInternalBranchCount"
            ],
            10,
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "unresolvedBranchCount"
            ],
            3,
        )
        self.assertEqual(
            len({
                row["site"] for row in self.reviews["indirectTargets"]["evidence"][
                    "resolvedInternalBranches"
                ]
            }),
            36,
        )
        self.assertEqual(
            self.reviews["indirectTargets"]["evidence"][
                "remainingCandidateFunctionsIfAllPossibleLiteralTargetsReachable"
            ],
            [],
        )
        self.assertEqual(
            self.reviews["callbacks"]["evidence"]["branchXrefs"][
                "crossFunctionDirectBranchSiteCount"
            ],
            459,
        )

    def test_indirect_calls_cannot_be_closed_by_editing_the_review(self):
        forged = copy.deepcopy(self.reviews["indirectTargets"])
        forged["reviewStatus"] = "CLOSED"
        forged["unresolvedPaths"] = []
        forged["evidence"]["unresolvedPathCount"] = 0
        unhashed = dict(forged)
        unhashed.pop("reviewSha256")
        forged["reviewSha256"] = closures.sha256_json(unhashed)
        with self.assertRaisesRegex(
            closures.NativeReachabilityClosureError,
            "unresolved indexed calls were declared closed",
        ):
            closures.validate_review(
                forged, closure="indirectTargets", root=ROOT,
            )

    def test_register_import_resolution_requires_the_nearest_exact_definition(self):
        from capstone.x86 import X86_OP_MEM, X86_OP_REG

        class Instruction:
            def __init__(self, address, mnemonic, operands, writes=()):
                self.address = address
                self.mnemonic = mnemonic
                self.operands = operands
                self._writes = writes

            def regs_access(self):
                return (), self._writes

            def reg_name(self, register):
                return "ebx" if register == 19 else ""

        register = 19
        import_address = 0x0044C164
        register_operand = SimpleNamespace(type=X86_OP_REG, reg=register)
        import_operand = SimpleNamespace(
            type=X86_OP_MEM,
            mem=SimpleNamespace(base=0, index=0, disp=import_address),
        )
        definition = Instruction(
            0x00401010, "mov", [register_operand, import_operand], (register,),
        )
        call = Instruction(0x00401020, "call", [register_operand])
        imports = {import_address: "Cc.dll!GetTexture"}
        state, resolved = closures._transfer_register_import_state(
            {}, [definition, call], imports, collect=True,
        )
        self.assertEqual(state, {
            "ebx": (("0x00401010",), "Cc.dll!GetTexture")
        })
        self.assertEqual(
            resolved,
            {
                0x00401020: (
                    ("0x00401010",), "Cc.dll!GetTexture",
                )
            },
        )

        clobber = Instruction(
            0x00401018, "xor", [register_operand, register_operand], (register,),
        )
        _state, resolved = closures._transfer_register_import_state(
            {}, [definition, clobber, call], imports, collect=True,
        )
        self.assertEqual(resolved, {})
        _state, resolved = closures._transfer_register_import_state(
            {}, [definition, call], {}, collect=True,
        )
        self.assertEqual(resolved, {})

    def test_import_lattice_joins_same_symbol_with_all_definitions(self):
        self.assertEqual(
            closures._join_register_states([
                {"esi": (("0x00401010",), "USER32.dll!SendMessageA")},
                {"esi": (("0x00401020",), "USER32.dll!SendMessageA")},
            ]),
            {
                "esi": (
                    ("0x00401010", "0x00401020"),
                    "USER32.dll!SendMessageA",
                )
            },
        )
        self.assertEqual(
            closures._join_register_states([
                {"esi": (("0x00401010",), "USER32.dll!SendMessageA")},
                {"esi": (("0x00401020",), "USER32.dll!PostMessageA")},
            ]),
            {},
        )

    def test_disconnected_cfg_components_start_without_inherited_registers(self):
        predecessors = {
            0x00401000: set(),
            0x00401010: {0x00401000},
            0x00401020: set(),
            0x00401030: {0x00401020},
        }
        self.assertEqual(
            closures._register_dataflow_roots(
                predecessors,
                0x00401000,
                {0x00401030},
            ),
            {0x00401000, 0x00401020, 0x00401030},
        )

    @unittest.skipUnless(
        PINNED_EXECUTABLE.is_file(),
        "pinned native executable is not available in this checkout",
    )
    def test_stack_parameter_callbacks_require_all_exact_xrefs(self):
        from tools.miel_vliegt.analyze_native import PeImage

        code_map = json.loads(
            (ROOT / closures.CODE_MAP).read_text(encoding="utf-8")
        )
        function_index = json.loads(
            (ROOT / closures.FUNCTION_INDEX).read_text(encoding="utf-8")
        )
        _code, indexed, spans = closures._function_rows(
            code_map, function_index,
        )
        image = PeImage(PINNED_EXECUTABLE)
        recoveries = closures._exact_stack_parameter_call_recoveries(
            image, indexed, closures._instruction_map(image), spans,
        )
        self.assertEqual(set(recoveries), {
            0x00448711, 0x00448786, 0x004487FE,
        })
        self.assertEqual(
            recoveries[0x004487FE]["targetAddresses"],
            ["0x00408370", "0x00415510", "0x00432d10", "0x0043f000"],
        )
        self.assertTrue(all(
            proof["steps"]
            for recovery in recoveries.values()
            for proof in recovery["xrefProofs"]
        ))
        self.assertTrue(all(
            recovery["entryInboundProof"] == {
                "directCallXrefCount": {
                    0x00448711: 23,
                    0x00448786: 2,
                    0x004487FE: 9,
                }[address],
                "absolutePointerSiteCount": 0,
                "directBranchXrefCount": 0,
                "isLoaderRoot": False,
            }
            for address, recovery in recoveries.items()
        ))

    def test_forged_stack_parameter_target_fails_closed(self):
        forged = copy.deepcopy(self.reviews["indirectTargets"])
        recovery = forged["evidence"]["resolvedStackParameterCalls"][0]
        recovery["targetAddresses"][0] = "0x00401000"
        unhashed = dict(forged)
        unhashed.pop("reviewSha256")
        forged["reviewSha256"] = closures.sha256_json(unhashed)
        with self.assertRaisesRegex(
            closures.NativeReachabilityClosureError,
            "stack-parameter proof differs|stack-parameter targets differ",
        ):
            closures.validate_review(
                forged, closure="indirectTargets", root=ROOT,
            )

    @unittest.skipUnless(
        PINNED_EXECUTABLE.is_file(),
        "pinned native executable is not available in this checkout",
    )
    def test_byte_remap_switches_are_exact_and_locally_bounded(self):
        from tools.miel_vliegt.analyze_native import PeImage

        image = PeImage(PINNED_EXECUTABLE)
        instructions = closures._instruction_map(image)
        function_index = json.loads(
            (ROOT / closures.FUNCTION_INDEX).read_text(encoding="utf-8")
        )
        recoveries = {}
        for row in function_index["functions"]:
            recoveries.update(
                closures._exact_remapped_switch_recoveries(
                    image, row, instructions,
                )
            )
        self.assertEqual(set(recoveries), {
            0x00405C8B, 0x004175D0, 0x00419600, 0x0041DCF8,
            0x0041DD8C, 0x0041DE28, 0x0041E1CE, 0x004343E7,
            0x00435805, 0x0043C3D4,
        })
        self.assertEqual(
            recoveries[0x00405C8B]["tableEntries"],
            [
                "0x00405cf3", "0x00405ca7", "0x00405cc3",
                "0x00405c92", "0x00405d43",
            ],
        )
        self.assertEqual(
            set(recoveries[0x00405C8B]["remapValues"]),
            set(range(5)),
        )

    def test_forged_assigned_vtable_target_fails_closed(self):
        forged = copy.deepcopy(self.reviews["indirectTargets"])
        recovery = forged["evidence"]["resolvedAssignedVtableCalls"][0]
        recovery["targetAddresses"][0] = "0x00401000"
        unhashed = dict(forged)
        unhashed.pop("reviewSha256")
        forged["reviewSha256"] = closures.sha256_json(unhashed)
        with self.assertRaisesRegex(
            closures.NativeReachabilityClosureError,
            "assigned-vtable row differs|assigned-vtable targets differ",
        ):
            closures.validate_review(
                forged, closure="indirectTargets", root=ROOT,
            )

    def test_forged_indirect_site_classification_fails_closed(self):
        forged = copy.deepcopy(self.reviews["indirectTargets"])
        evidence = forged["evidence"]
        classification = next(
            row for row in evidence["indirectSiteClassifications"]
            if row["instructionAddress"] == "0x00421e6d"
        )
        self.assertEqual(classification["classification"], "TAIL_VPTR")
        classification["classification"] = "ADJUSTED_VPTR"
        kinds = evidence["indirectSiteClassificationKinds"]
        kinds["TAIL_VPTR"] -= 1
        kinds["ADJUSTED_VPTR"] += 1
        evidence["indirectSiteClassifierSha256"] = closures.sha256_json(
            evidence["indirectSiteClassifications"]
        )
        unhashed = dict(forged)
        unhashed.pop("reviewSha256")
        forged["reviewSha256"] = closures.sha256_json(unhashed)
        with self.assertRaisesRegex(
            closures.NativeReachabilityClosureError,
            "classification contradicts evidence",
        ):
            closures.validate_review(
                forged, closure="indirectTargets", root=ROOT,
            )

    def test_forged_assigned_vtable_branch_proof_fails_closed(self):
        forged = copy.deepcopy(self.reviews["indirectTargets"])
        recovery = forged["evidence"]["resolvedAssignedVtableBranches"][0]
        recovery["vptrOffset"] = 4
        recovery["proofSha256"] = closures.sha256_json({
            key: value for key, value in recovery.items()
            if key not in {"site", "proofSha256"}
        })
        unhashed = dict(forged)
        unhashed.pop("reviewSha256")
        forged["reviewSha256"] = closures.sha256_json(unhashed)
        with self.assertRaisesRegex(
            closures.NativeReachabilityClosureError,
            "assigned-vtable branch row differs",
        ):
            closures.validate_review(
                forged, closure="indirectTargets", root=ROOT,
            )

    @unittest.skipUnless(
        PINNED_EXECUTABLE.is_file(),
        "pinned native executable is not available in this checkout",
    )
    def test_exact_switch_recovery_rejects_a_non_block_table_target(self):
        from tools.miel_vliegt.analyze_native import PeImage

        image = PeImage(PINNED_EXECUTABLE)
        instructions = closures._instruction_map(image)
        function_index = json.loads(
            (ROOT / closures.FUNCTION_INDEX).read_text(encoding="utf-8")
        )
        row = next(
            row for row in function_index["functions"]
            if row["address"] == "0x00401990"
        )
        recovery = closures._exact_switch_recoveries(
            image, row, instructions,
        )
        self.assertEqual(set(recovery), {0x004019B8})
        self.assertEqual(recovery[0x004019B8]["tableEntryCount"], 6)

        class AlteredTableImage:
            def bytes_at(self, address, size):
                data = bytearray(image.bytes_at(address, size))
                if address == 0x00401B50:
                    data[:4] = (0x004019F6).to_bytes(4, "little")
                return bytes(data)

        self.assertEqual(
            closures._exact_switch_recoveries(
                AlteredTableImage(), row, instructions,
            ),
            {},
        )

    def test_forged_cross_function_switch_target_fails_closed(self):
        forged = copy.deepcopy(self.reviews["indirectTargets"])
        switch = forged["evidence"]["resolvedInternalBranches"][0]
        switch["tableEntries"][0] = "0x0043f842"
        unhashed = dict(forged)
        unhashed.pop("reviewSha256")
        forged["reviewSha256"] = closures.sha256_json(unhashed)
        with self.assertRaisesRegex(
            closures.NativeReachabilityClosureError,
            "switch target escaped its function",
        ):
            closures.validate_review(
                forged, closure="indirectTargets", root=ROOT,
            )

    def test_inventory_or_source_drift_fails_closed(self):
        for mutation in ("inventory", "generator", "candidate"):
            with self.subTest(mutation=mutation):
                broken = copy.deepcopy(self.reviews["callbacks"])
                if mutation == "inventory":
                    broken["inventory"]["sites"].pop()
                elif mutation == "generator":
                    broken["generatorSha256"] = "0" * 64
                else:
                    broken["candidateMembershipSha256"] = "0" * 64
                with self.assertRaises(closures.NativeReachabilityClosureError):
                    closures.validate_review(
                        broken, closure="callbacks", root=ROOT,
                    )

    @unittest.skipUnless(
        PINNED_EXECUTABLE.is_file(),
        "pinned native executable is not available in this checkout",
    )
    def test_pinned_executable_rebuilds_the_exact_reviews(self):
        self.assertEqual(
            closures.build_reviews(PINNED_EXECUTABLE, root=ROOT),
            self.reviews,
        )


if __name__ == "__main__":
    unittest.main()
