#!/usr/bin/env python3
"""Fail-closed tests for the native media-semantics trace contract."""

import json
import unittest
from pathlib import Path

try:
    from tools.miel_vliegt import native_media_semantics_contract as contract
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import native_media_semantics_contract as contract

ROOT = Path(__file__).resolve().parents[2]


def _receipt(**overrides):
    base = {
        "schema": 1,
        "protocol": contract.TRACE_PROTOCOL,
        "edition": contract.EDITION,
        "behaviourId": "audio_completion",
        "policy": "START_THEN_COMPLETE_SAME_UPDATE",
        "observationCount": 7,
        "observationsSha256": "a" * 64,
        "nativeProcessId": 4321,
        "captureSessionId": "mvds-" + "0" * 32,
        "observerBinarySha256": "b" * 64,
        "resolvedBlockerCode": "WEB_HEADLESS_ROUTE_COMPLETION_UNOBSERVED",
    }
    base.update(overrides)
    return base


class MediaSemanticsContractTest(unittest.TestCase):
    def test_checked_in_json_matches_generator(self):
        expected = json.dumps(
            contract.json_contract(), indent=2, ensure_ascii=True,
        ) + "\n"
        self.assertEqual(
            contract.DEFAULT_OUTPUT.read_text(encoding="utf-8"), expected,
        )

    def test_contract_declares_all_three_blocked_behaviours(self):
        codes = {
            behaviour["resolvedBlockerCode"]
            for behaviour in contract.contract()["behaviours"]
        }
        self.assertEqual(codes, {
            "WEB_HEADLESS_ROUTE_COMPLETION_UNOBSERVED",
            "FLIGHT_ACTOR_RANDOMFRAME_CADENCE_UNPROVEN",
            "FLIGHT_ACTOR_CALLBACK_INTERRUPTION_UNPROVEN",
        })

    def test_valid_receipt_passes_for_each_behaviour(self):
        for behaviour in contract.BEHAVIOURS:
            policy = contract.POLICIES_BY_BEHAVIOUR[behaviour["id"]][0]
            receipt = _receipt(
                behaviourId=behaviour["id"], policy=policy,
                resolvedBlockerCode=behaviour["resolvedBlockerCode"],
            )
            validated = contract.validate_trace_receipt(receipt)
            self.assertEqual(validated["behaviourId"], behaviour["id"])

    def test_unknown_behaviour_is_rejected(self):
        with self.assertRaises(contract.MediaSemanticsContractError):
            contract.validate_trace_receipt(_receipt(behaviourId="teleport"))

    def test_policy_must_belong_to_behaviour(self):
        with self.assertRaises(contract.MediaSemanticsContractError):
            contract.validate_trace_receipt(_receipt(
                behaviourId="audio_completion",
                policy="SAMPLE_ONCE_AT_START",
            ))

    def test_invented_policy_is_rejected(self):
        with self.assertRaises(contract.MediaSemanticsContractError):
            contract.validate_trace_receipt(_receipt(policy="ALWAYS_COMPLETE"))

    def test_blocker_code_must_match_behaviour(self):
        with self.assertRaises(contract.MediaSemanticsContractError):
            contract.validate_trace_receipt(_receipt(
                resolvedBlockerCode="FLIGHT_ACTOR_RANDOMFRAME_CADENCE_UNPROVEN",
            ))

    def test_zero_or_negative_observation_count_is_rejected(self):
        for count in (0, -1):
            with self.assertRaises(contract.MediaSemanticsContractError):
                contract.validate_trace_receipt(
                    _receipt(observationCount=count),
                )

    def test_non_hash_digests_are_rejected(self):
        for field in ("observationsSha256", "observerBinarySha256"):
            with self.assertRaises(contract.MediaSemanticsContractError):
                contract.validate_trace_receipt(_receipt(**{field: "short"}))

    def test_foreign_session_id_is_rejected(self):
        with self.assertRaises(contract.MediaSemanticsContractError):
            contract.validate_trace_receipt(
                _receipt(captureSessionId="native-1234"),
            )

    def test_extra_or_missing_keys_are_rejected(self):
        receipt = _receipt()
        receipt["fabricated"] = True
        with self.assertRaises(contract.MediaSemanticsContractError):
            contract.validate_trace_receipt(receipt)
        del receipt["fabricated"]
        del receipt["policy"]
        with self.assertRaises(contract.MediaSemanticsContractError):
            contract.validate_trace_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
