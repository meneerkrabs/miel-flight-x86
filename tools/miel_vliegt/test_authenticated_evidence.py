import copy
import unittest

from tools.miel_vliegt import authenticated_evidence, udsp_semantic_oracle


class AuthenticatedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.occurrences = ["6" * 64, "7" * 64]
        base = {
            "schema": 1,
            "sequence": 1,
            "semanticStatus": "UNPROVEN",
            "script": "LOCATION_SCRIPT:demo/audio",
            "ancestry": [],
            "depth": 0,
            "commandIndex": 2,
            "executableCommandIndex": 2,
            "sourceCommandIndex": 2,
            "opcode": "PLAY_SOUND",
            "scheduler": {
                "node": None, "repeat": False, "complete": False,
                "resetCount": 0, "parents": [],
            },
            "before": "WAITING",
            "after": "WAITING",
            "clock": 1,
            "delta": 1,
            "randomSamples": [],
            "outcome": {
                "port": "PLAY_SOUND",
                "mediaBinding": {
                    "assetKey": "flight-voice-demo", "nativeOpcode": 12,
                },
                "receipt": {},
            },
        }
        completed = copy.deepcopy(base)
        completed["sequence"] = 2
        completed["scheduler"]["complete"] = True
        self.receipts = [base, completed]
        self.payload = {
            "schema": 1,
            "protocol": authenticated_evidence.AUDIO_CALLBACK_PROTOCOL,
            "semanticStatus": "UNPROVEN",
            "parityEligible": False,
            "script": "LOCATION_SCRIPT:demo/audio",
            "executableCommandIndex": 2,
            "sourceCommandIndex": 2,
            "opcode": "PLAY_SOUND",
            "nativeOpcode": 12,
            "assetKey": "flight-voice-demo",
            "assetSourceSha256": "5" * 64,
            "take": 1,
            "completionRoute": "NATIVE_AUDIO_SERVICE_POLL",
            "armedByEventOccurrenceId": self.occurrences[0],
            "eventOccurrenceId": self.occurrences[1],
            "acceptedSignal": "PHASER_ON_COMPLETE",
            "lifecycleTranscript": [
                {"sequence": 0, "event": "START_ATTEMPT", "details": None},
                {"sequence": 1, "event": "STARTED", "details": None},
                {
                    "sequence": 2,
                    "event": "CALLBACK_ACCEPTED",
                    "details": {"signal": "PHASER_ON_COMPLETE"},
                },
                {"sequence": 3, "event": "POLL_ABSENT", "details": None},
            ],
        }
        self.expected = {
            "producer": "WEB",
            "edition": "miel-vliegt-nl",
            "claimId": "UDSP_EXECUTABLE_BODY:LOCATION_SCRIPT:demo/audio",
            "evidenceClass": "UDSP_EXECUTABLE_BODY",
            "subjectSha256": "1" * 64,
            "expectationSha256": "2" * 64,
            "runtimeSessionSha256": "3" * 64,
        }
        envelope = {
            "schema": 1,
            "protocol": authenticated_evidence.PROTOCOL,
            **self.expected,
            "evidenceKind": "AUDIO_CALLBACK",
            "occurrenceId": self.occurrences[1],
            "producerBuildSha256": "4" * 64,
            "payloadSha256": authenticated_evidence.canonical_sha256(self.payload),
        }
        envelope["envelopeSha256"] = authenticated_evidence.canonical_sha256(envelope)
        self.record = {"envelope": envelope, "payload": self.payload}

    def validate(self, record=None, **kwargs):
        return authenticated_evidence.validate_record(
            self.record if record is None else record,
            expected=self.expected,
            event_occurrence_ids=self.occurrences,
            receipts=self.receipts,
            asset_source_sha256_by_key={"flight-voice-demo": "5" * 64},
            **kwargs,
        )

    def test_accepts_exact_callback_receipt(self):
        self.assertEqual(self.validate(), self.record)

    def test_rejects_forged_and_wrong_asset(self):
        forged = copy.deepcopy(self.record)
        forged["payload"]["assetKey"] = "flight-voice-forged"
        with self.assertRaisesRegex(
            authenticated_evidence.AuthenticatedEvidenceError,
            "payload hash differs",
        ):
            self.validate(forged)

        wrong_asset = copy.deepcopy(self.record)
        wrong_asset["payload"]["assetKey"] = "flight-voice-forged"
        wrong_asset["envelope"]["payloadSha256"] = (
            authenticated_evidence.canonical_sha256(wrong_asset["payload"])
        )
        unhashed = dict(wrong_asset["envelope"])
        del unhashed["envelopeSha256"]
        wrong_asset["envelope"]["envelopeSha256"] = (
            authenticated_evidence.canonical_sha256(unhashed)
        )
        with self.assertRaisesRegex(
            authenticated_evidence.AuthenticatedEvidenceError,
            "asset source hash differs|command/asset binding differs",
        ):
            self.validate(wrong_asset)

        wrong_take = copy.deepcopy(self.record)
        wrong_take["payload"]["take"] = 2
        wrong_take["envelope"]["payloadSha256"] = (
            authenticated_evidence.canonical_sha256(wrong_take["payload"])
        )
        unhashed = dict(wrong_take["envelope"])
        del unhashed["envelopeSha256"]
        wrong_take["envelope"]["envelopeSha256"] = (
            authenticated_evidence.canonical_sha256(unhashed)
        )
        with self.assertRaisesRegex(
            authenticated_evidence.AuthenticatedEvidenceError,
            "take binding differs",
        ):
            self.validate(wrong_take)

        wrong_source = copy.deepcopy(self.record)
        wrong_source["payload"]["assetSourceSha256"] = "a" * 64
        wrong_source["envelope"]["payloadSha256"] = (
            authenticated_evidence.canonical_sha256(wrong_source["payload"])
        )
        unhashed = dict(wrong_source["envelope"])
        del unhashed["envelopeSha256"]
        wrong_source["envelope"]["envelopeSha256"] = (
            authenticated_evidence.canonical_sha256(unhashed)
        )
        with self.assertRaisesRegex(
            authenticated_evidence.AuthenticatedEvidenceError,
            "asset source hash differs",
        ):
            self.validate(wrong_source)

    def test_rejects_wrong_session_and_occurrence_reuse(self):
        with self.assertRaisesRegex(
            authenticated_evidence.AuthenticatedEvidenceError,
            "runtimeSessionSha256 differs",
        ):
            authenticated_evidence.validate_record(
                self.record,
                expected={**self.expected, "runtimeSessionSha256": "8" * 64},
                event_occurrence_ids=self.occurrences,
                receipts=self.receipts,
                asset_source_sha256_by_key={"flight-voice-demo": "5" * 64},
            )
        used_envelopes, used_payloads, used_occurrences = set(), set(), set()
        self.validate(
            used_envelopes=used_envelopes,
            used_payloads=used_payloads,
            used_occurrences=used_occurrences,
        )
        with self.assertRaisesRegex(
            authenticated_evidence.AuthenticatedEvidenceError,
            "reuses envelope",
        ):
            self.validate(
                used_envelopes=used_envelopes,
                used_payloads=used_payloads,
                used_occurrences=used_occurrences,
            )

    def test_rejects_radio_alert_or_release_as_primary_completion(self):
        alert = copy.deepcopy(self.record)
        alert["payload"]["assetKey"] = "flight-radio-alert"
        alert["payload"]["lifecycleTranscript"][-1] = {
            "sequence": 2, "event": "RELEASED", "details": {"cause": "SERVICE_RELEASE"},
        }
        alert["envelope"]["payloadSha256"] = (
            authenticated_evidence.canonical_sha256(alert["payload"])
        )
        unhashed = dict(alert["envelope"])
        del unhashed["envelopeSha256"]
        alert["envelope"]["envelopeSha256"] = (
            authenticated_evidence.canonical_sha256(unhashed)
        )
        with self.assertRaises(authenticated_evidence.AuthenticatedEvidenceError):
            self.validate(alert)

    def test_generic_differential_ignores_producer_session_but_not_semantic_payload(self):
        native = copy.deepcopy(self.record)
        native["envelope"]["producer"] = "NATIVE"
        native["envelope"]["producerBuildSha256"] = "9" * 64
        native["envelope"]["runtimeSessionSha256"] = "a" * 64
        native["envelope"]["occurrenceId"] = "b" * 64
        native["payload"]["armedByEventOccurrenceId"] = "c" * 64
        native["payload"]["eventOccurrenceId"] = "b" * 64
        self.assertEqual(
            authenticated_evidence.compare_records(self.record, native)["result"],
            "MATCH",
        )
        native["payload"]["take"] = 2
        difference = authenticated_evidence.compare_records(self.record, native)
        self.assertEqual(difference["result"], "DIFFER")
        self.assertIn("payload", difference["differences"])

    def test_semantic_oracle_requires_pinned_producer_build_and_asset_source(self):
        document = {
            **self.expected,
            "eventOccurrenceIds": self.occurrences,
            "authenticatedEvidence": [self.record],
        }
        udsp_semantic_oracle._validate_authenticated_evidence(
            document,
            self.receipts,
            expected_producer_build_sha256="4" * 64,
            expected_audio_asset_sha256={"flight-voice-demo": "5" * 64},
        )
        with self.assertRaisesRegex(
            udsp_semantic_oracle.SemanticOracleError,
            "producer build expectation is missing",
        ):
            udsp_semantic_oracle._validate_authenticated_evidence(
                document,
                self.receipts,
                expected_producer_build_sha256=None,
                expected_audio_asset_sha256={"flight-voice-demo": "5" * 64},
            )

    def test_nested_parallel_branches_receive_independent_occurrence_ids(self):
        branch_started = copy.deepcopy(self.receipts[0])
        branch_started.pop("scheduler")
        branch_started["complete"] = False
        branch_completed = copy.deepcopy(branch_started)
        branch_completed["sequence"] = 2
        branch_completed["complete"] = True
        nested_receipts = [
            {
                "opcode": "NODE_PARALLEL",
                "outcome": {"branches": [branch_started]},
            },
            {
                "opcode": "NODE_PARALLEL",
                "outcome": {"branches": [branch_completed]},
            },
        ]
        rows = authenticated_evidence.runtime_occurrence_events(
            self.occurrences, nested_receipts,
        )
        nested = copy.deepcopy(self.record)
        nested["payload"]["armedByEventOccurrenceId"] = rows[1]["occurrenceId"]
        nested["payload"]["eventOccurrenceId"] = rows[3]["occurrenceId"]
        nested["envelope"]["occurrenceId"] = rows[3]["occurrenceId"]
        nested["envelope"]["payloadSha256"] = (
            authenticated_evidence.canonical_sha256(nested["payload"])
        )
        unhashed = dict(nested["envelope"])
        del unhashed["envelopeSha256"]
        nested["envelope"]["envelopeSha256"] = (
            authenticated_evidence.canonical_sha256(unhashed)
        )
        authenticated_evidence.validate_record(
            nested,
            expected=self.expected,
            event_occurrence_ids=self.occurrences,
            receipts=nested_receipts,
            asset_source_sha256_by_key={"flight-voice-demo": "5" * 64},
        )


if __name__ == "__main__":
    unittest.main()
