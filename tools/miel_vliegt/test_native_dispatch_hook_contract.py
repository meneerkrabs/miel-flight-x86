#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.miel_vliegt.native_dispatch_hook_contract import (
    ACTION_ROUTES,
    EDITION,
    EXECUTABLE_SHA256,
    PROTOCOL,
    RUNTIME_STATUS,
    SELECTORS,
    SITE_SIGNATURES,
    NativeDispatchHookContractError,
    contract,
    json_contract,
    validate_capability_receipt,
    validate_contract,
    verify_pinned_executable,
)


ROOT = Path(__file__).resolve().parents[2]
EXECUTABLE = ROOT / "tmp/miel-vliegt-native-local/MulleMeck.exe"

EXPECTED_SELECTORS = {
    "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3",
    "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3",
    "ROOT_COMPLETE_REFUEL_ARMED_AND_UNCONSUMED",
    "LOCATION_ENTER_FIRST_CHALLENGE",
    "LOCATION_ENTER_SUBSEQUENT_CHALLENGE",
    "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2",
    "CHALLENGE_ROOT_COMPLETE_RESULT_NE_2",
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_LT_900",
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_NE_3",
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_NE_3",
    "LOCATION_ENTER_OUTRO_FALSE_AND_900_LTE_PROJECTED_X_LT_2200_AND_FINAL_MISSION_STATE_EQ_3",
    "LOCATION_ENTER_OUTRO_FALSE_AND_PROJECTED_X_GTE_2200_AND_FINAL_MISSION_STATE_EQ_3",
    "LOCATION_ENTER_OUTRO_REQUESTED",
    "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE",
}


def capability() -> dict:
    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "executableSha256": EXECUTABLE_SHA256,
        "runtimeParity": RUNTIME_STATUS,
        "installedProbes": list(SITE_SIGNATURES),
        "missionSourceBinding": True,
        "rootPathBinding": True,
        "inlineProjectedXCapture": True,
        "selectorCoverage": {selector: True for selector in SELECTORS},
    }


class NativeDispatchHookContractTests(unittest.TestCase):
    def test_producer_documentation_has_no_stale_literal_hook_count(self) -> None:
        documentation = (
            ROOT / "tools/miel_vliegt/NATIVE_DISPATCH_SEMANTIC_PRODUCER.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn("29", documentation)
        self.assertIn("MVDS_HOOK_COUNT", documentation)
        # Three route hooks are forwarded by the existing observer and two
        # inventory-only sites are deliberately not semantic detours.
        self.assertEqual(len(SITE_SIGNATURES) - 5, 30)

    def test_all_four_action_routes_have_exact_native_opcodes(self) -> None:
        self.assertEqual(
            {key: (value["opcode"], value["route"]) for key, value in ACTION_ROUTES.items()},
            {
                1: ("PLAY_SCRIPT", "GROUND"),
                2: ("PLAY_BARNSCRIPT", "BARN"),
                3: ("PLAY_SCRIPTMODEFLY", "FLIGHT"),
                21: ("PLAY_OUTRO", "LOCATION_POLICY"),
            },
        )

    def test_every_selector_has_only_declared_signature_checked_probes(self) -> None:
        self.assertEqual(set(SELECTORS), EXPECTED_SELECTORS)
        for selector, spec in SELECTORS.items():
            with self.subTest(selector=selector):
                self.assertTrue(spec["probes"])
                self.assertLessEqual(set(spec["probes"]), set(SITE_SIGNATURES))
                self.assertTrue(spec["fields"])
                self.assertTrue(spec["predicate"])

    def test_checked_semantic_coverage_uses_exactly_the_supported_selectors(self) -> None:
        value = json.loads(
            (ROOT / "content/miel_vliegt/scene_semantic_coverage.json").read_text(
                encoding="utf-8"
            )
        )
        policies = []

        def visit(candidate):
            if isinstance(candidate, dict):
                if candidate.get("evidenceClass") == "LOCATION_POLICY":
                    policies.append(candidate)
                    return
                for child in candidate.values():
                    visit(child)
            elif isinstance(candidate, list):
                for child in candidate:
                    visit(child)

        visit(value)
        self.assertEqual(len(policies), 42)
        self.assertEqual(
            {policy["expectation"]["selector"] for policy in policies},
            EXPECTED_SELECTORS,
        )

    def test_checked_mission_actions_match_the_four_native_routes(self) -> None:
        value = json.loads(
            (ROOT / "content/miel_vliegt/scene_dispatch_contract.json").read_text(
                encoding="utf-8"
            )
        )
        actions = value["missionActions"]
        self.assertEqual(len(actions), 113)
        self.assertEqual(
            {(action["opcode"], action["route"]) for action in actions},
            {(route["opcode"], route["route"]) for route in ACTION_ROUTES.values()},
        )
        duplicate_ids = {}
        for action in actions:
            duplicate_ids.setdefault(action["missionId"], set()).add(
                action["missionKey"].split(":", 1)[1]
            )
        self.assertTrue(any(len(paths) > 1 for paths in duplicate_ids.values()))

    def test_contract_never_promotes_static_map_to_runtime_parity(self) -> None:
        value = contract()
        self.assertEqual(value["claim"], "PINNED_STATIC_HOOK_DESIGN")
        self.assertEqual(value["edition"], EDITION)
        self.assertEqual(value["editionPolicy"], "EDITION_LOCAL_ADDRESSES_NEVER_REUSED")
        self.assertEqual(value["runtimeParity"], "NATIVE_TRACE_REQUIRED")
        self.assertEqual(len(value["producerSources"]), 3)
        self.assertEqual(len(value["producerBuildSha256"]), 64)

    def test_producer_source_mutation_invalidates_static_contract(self) -> None:
        value = json_contract()
        source = next(iter(value["producerSources"]))
        value["producerSources"][source] = "0" * 64
        with self.assertRaisesRegex(NativeDispatchHookContractError, "pinned design"):
            validate_contract(value)

    def test_json_contract_is_exact_and_mutations_fail_closed(self) -> None:
        value = json_contract()
        self.assertEqual(validate_contract(value), value)
        value["selectors"].pop(next(iter(value["selectors"])))
        with self.assertRaisesRegex(NativeDispatchHookContractError, "pinned design"):
            validate_contract(value)

    def test_complete_capability_receipt_is_accepted(self) -> None:
        self.assertEqual(validate_capability_receipt(capability())["schema"], 1)

    def test_any_missing_probe_fails_closed(self) -> None:
        value = capability()
        value["installedProbes"].pop()
        with self.assertRaisesRegex(NativeDispatchHookContractError, "every"):
            validate_capability_receipt(value)

    def test_any_missing_structural_binding_fails_closed(self) -> None:
        for key in ("missionSourceBinding", "rootPathBinding", "inlineProjectedXCapture"):
            value = capability()
            value[key] = False
            with self.subTest(key=key), self.assertRaisesRegex(
                NativeDispatchHookContractError, key
            ):
                validate_capability_receipt(value)

    def test_any_missing_selector_fails_closed(self) -> None:
        value = capability()
        value["selectorCoverage"].pop(next(iter(value["selectorCoverage"])))
        with self.assertRaisesRegex(NativeDispatchHookContractError, "incomplete"):
            validate_capability_receipt(value)

    def test_bool_cannot_bypass_integer_schema(self) -> None:
        value = capability()
        value["schema"] = True
        with self.assertRaisesRegex(NativeDispatchHookContractError, "schema"):
            validate_capability_receipt(value)

    def test_overclaiming_runtime_parity_is_rejected(self) -> None:
        value = capability()
        value["runtimeParity"] = "PROVEN"
        with self.assertRaisesRegex(NativeDispatchHookContractError, "overclaims"):
            validate_capability_receipt(value)

    def test_extra_fields_are_rejected(self) -> None:
        value = copy.deepcopy(capability())
        value["parityEligible"] = True
        with self.assertRaisesRegex(NativeDispatchHookContractError, "shape"):
            validate_capability_receipt(value)


@unittest.skipUnless(EXECUTABLE.is_file(), "pinned native executable unavailable")
class NativeDispatchHookExecutableTests(unittest.TestCase):
    def test_all_addresses_signatures_calls_and_thresholds_match_pinned_exe(self) -> None:
        verify_pinned_executable(EXECUTABLE)

    def test_executor_and_raymond_abi_are_pinned_to_stack_arg_ret4_and_al(self) -> None:
        image = verify_pinned_executable(EXECUTABLE)

        def at(address: int, expected_hex: str) -> None:
            expected = bytes.fromhex(expected_hex)
            offset = image.address_to_offset(address)
            self.assertEqual(image.data[offset:offset + len(expected)], expected)

        # All three native callers push the phase as the sole stack argument.
        at(0x004373D8, "6a018bcee88feeffff")
        at(0x0043740B, "6a028bcee85ceeffff")
        at(0x0043744F, "6a038bcee818eeffff")
        at(0x00436CD9, "c20400")
        # Raymond copies entry [ESP+4] after its SEH/EBP prologue and returns
        # a BYTE in AL on both ret-4 exits.
        at(0x00441D16, "8b6c2414")
        at(0x00441D39, "c20400")
        at(0x00441F53, "b001")
        at(0x00441F60, "c20400")


if __name__ == "__main__":
    unittest.main()
