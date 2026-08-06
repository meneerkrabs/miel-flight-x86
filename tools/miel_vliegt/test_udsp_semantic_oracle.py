#!/usr/bin/env python3
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import udsp_semantic_oracle as oracle


ROOT = Path(__file__).resolve().parents[2]
CASES_PATH = ROOT / "tools/miel_vliegt/fixtures/udsp_semantic_oracle_cases.json"
EMITTER_TEST = "src/flight/engine/scene/__tests__/UdspSemanticOracleFixtures.test.js"


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def script_key(script):
    return f"{script['type']}:{script['domainId']}/{script['dispatchId']}"


def current_dispatch_plan(ledger):
    from tools.miel_vliegt import scene_semantic_coverage as coverage
    from tools.miel_vliegt import scene_semantic_evidence_batches as batches
    return batches.build_plan(
        ledger,
        ledger_source=batches._source(coverage.DEFAULT_LEDGER, coverage.SCHEMA),
    )


class UdspSemanticOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        generated_path = Path(cls.temporary.name) / "actual-runtime-cases.json"
        environment = {
            "MIEL_UDSP_FIXTURE_OUTPUT": str(generated_path),
        }
        subprocess.run(
            ["npx", "jest", EMITTER_TEST, "--runInBand", "--silent"],
            cwd=ROOT, env={**__import__("os").environ, **environment},
            check=True, capture_output=True, text=True,
        )
        cls.generated_bytes = generated_path.read_bytes()
        cls.committed_bytes = CASES_PATH.read_bytes()
        cls.fixture = json.loads(cls.generated_bytes)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def raw_web_document(self, case, *, evidence_mode="TEST_ONLY"):
        executable = case["executableArtifact"]
        entry = case["entry"]
        artifact_key = f"{entry['type']}:{entry['domainId']}/{entry['dispatchId']}"
        scripts = {script_key(row): row for row in executable["scripts"]}
        semantic_case_id = case["semanticCaseId"] if evidence_mode == "TEST_ONLY" else None
        claim_id = (
            case["claimId"] if evidence_mode == "TEST_ONLY"
            else f"UDSP_EXECUTABLE_BODY:{artifact_key}"
        )
        evidence_class = (
            "UDSP_SEMANTIC_CASE" if evidence_mode == "TEST_ONLY"
            else "UDSP_EXECUTABLE_BODY"
        )
        return {
            "schema": 1,
            "protocol": oracle.WEB_RAW_PROTOCOL,
            "evidenceMode": evidence_mode,
            "producer": "WEB",
            "edition": case["edition"],
            "claimId": claim_id,
            "evidenceClass": evidence_class,
            "semanticCaseId": semantic_case_id,
            "sourceHashes": self.fixture["sourceHashes"],
            "subjectSha256": case["artifactSha256"],
            "expectationSha256": case["receiptsSha256"],
            "artifactKey": artifact_key,
            "executableScriptSha256": oracle.canonical_sha256(scripts[artifact_key]),
            "receipts": copy.deepcopy(case["receipts"]),
        }

    def identity_for(self, document):
        return {field: copy.deepcopy(document[field]) for field in oracle.IDENTITY_FIELDS}

    def normalized_cases(self):
        return [
            oracle.normalize_web_trace(
                self.raw_web_document(case), case["executableArtifact"],
                self.identity_for(self.raw_web_document(case)),
            )
            for case in self.fixture["cases"]
        ]

    def test_committed_fixture_is_byte_exact_output_of_actual_runtime(self):
        self.assertEqual(self.generated_bytes, self.committed_bytes)
        self.assertEqual(self.fixture["schema"], 1)
        self.assertEqual(
            self.fixture["protocol"], "miel-vliegt-udsp-semantic-runtime-fixtures"
        )
        self.assertEqual(self.fixture["producer"], "UdspSceneRuntime")
        self.assertEqual(self.fixture["evidenceMode"], "TEST_ONLY")
        self.assertEqual(len(self.fixture["cases"]), 11)
        self.assertEqual(
            self.fixture["canonicalHash"]["protocol"], oracle.CANONICAL_HASH_PROTOCOL
        )
        self.assertEqual(self.fixture["canonicalHash"]["vectors"], {
            "zero": oracle.canonical_sha256(0.0),
            "negativeZero": oracle.canonical_sha256(-0.0),
            "integerValuedDouble": oracle.canonical_sha256(1.0),
            "fractional": oracle.canonical_sha256(0.699999988079071),
            "smallExponent": oracle.canonical_sha256(1e-7),
            "largeExponent": oracle.canonical_sha256(1e21),
        })
        self.assertNotEqual(
            self.fixture["canonicalHash"]["vectors"]["zero"],
            self.fixture["canonicalHash"]["vectors"]["negativeZero"],
        )
        self.assertEqual(self.fixture["sourceHashes"], {
            "sceneDispatchContract": sha256_file(
                ROOT / "content/miel_vliegt/scene_dispatch_contract.json"
            ),
            "udsSceneScripts": sha256_file(
                ROOT / "content/miel_vliegt/uds_scene_scripts.json"
            ),
            "executableUdspSceneScripts": sha256_file(
                ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json"
            ),
        })
        self.assertEqual(
            self.fixture["runtimeProducer"]["sha256"],
            sha256_file(ROOT / self.fixture["runtimeProducer"]["path"]),
        )
        identifiers = []
        for case in self.fixture["cases"]:
            identifiers.append(case["semanticCaseId"])
            self.assertTrue(case["semanticCaseId"].startswith(f"{case['edition']}:"))
            self.assertEqual(
                case["claimId"], f"UDSP_SEMANTIC_CASE:{case['semanticCaseId']}"
            )
            self.assertEqual(
                oracle.canonical_sha256(case["executableArtifact"]),
                case["artifactSha256"],
            )
            self.assertEqual(
                oracle.canonical_sha256(case["receipts"]), case["receiptsSha256"]
            )
            self.assertEqual(
                oracle.canonical_sha256({
                    "edition": case["edition"],
                    "semanticCaseId": case["semanticCaseId"],
                    "artifactSha256": case["artifactSha256"],
                    "receiptsSha256": case["receiptsSha256"],
                }),
                case["caseSha256"],
            )
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_actual_receipts_cover_every_opcode_and_runtime_variant(self):
        traces = self.normalized_cases()
        states = [observation["state"] for trace in traces for observation in trace["observations"]]
        self.assertEqual({state["variant"] for state in states}, {
            "COMMAND", "NODE_PARALLEL", "SCHEDULER_ONLY", "FAILURE",
        })
        opcodes = {
            state["command"]["opcode"]
            for state in states if state["command"] is not None
        }
        opcodes.update(
            branch["command"]["opcode"]
            for state in states for branch in (state["branches"] or [])
        )
        self.assertEqual(opcodes, {
            "AWARD_DIPLOMA", "JUDGE_AIRPLANE", "PLAY_CHARACTER_ANIMATION",
            "PLAY_CHARACTER_SCRIPT", "PLAY_CHARACTER_SOUND",
            "PLAY_MULLEBARNSOUND", "PLAY_RADIO", "PLAY_SOUND",
            "POSITION_CHARACTER", "WAIT",
        })
        self.assertEqual(sum(len(trace["observations"]) for trace in traces), 36)

    def test_wait_precision_keeps_clock_and_delta_as_numbers_and_only_frounds_wait_state(self):
        case = next(row for row in self.fixture["cases"] if "wait-random" in row["semanticCaseId"])
        raw = self.raw_web_document(case)
        trace = oracle.normalize_web_trace(raw, case["executableArtifact"], self.identity_for(raw))
        first = trace["observations"][0]["state"]
        delta = 0.10000000149011612
        self.assertEqual(first["timing"], {"clock": 2000.125, "delta": delta})
        self.assertEqual([row["path"] for row in first["f32Bits"]], [
            "$.outcome.wait.delta",
            "$.outcome.wait.duration",
            "$.outcome.wait.initialTimer",
            "$.outcome.wait.timer",
        ])
        effect = first["sideEffects"][0]["value"]["wait"]
        self.assertEqual(set(effect), {"delta", "modifier", "randResult"})
        self.assertEqual(effect["delta"], first["timing"]["delta"])
        self.assertEqual(first["rng"], {"samples": [
            {"sequence": 0, "kind": "NATIVE_RAND_U15", "value": 12345}
        ]})
        self.assertEqual(first["f32Bits"], sorted(first["f32Bits"], key=lambda row: row["path"]))

    def test_nested_parallel_repeat_and_empty_scheduler_shapes_are_not_flattened(self):
        by_id = {
            case["semanticCaseId"]: oracle.normalize_web_trace(
                self.raw_web_document(case), case["executableArtifact"],
                self.identity_for(self.raw_web_document(case)),
            )
            for case in self.fixture["cases"]
        }
        nested = next(trace for key, trace in by_id.items() if "nested-character" in key)
        nested_state = nested["observations"][1]["state"]
        self.assertEqual(nested_state["depth"], 1)
        self.assertEqual(nested_state["callAncestry"], [
            "LOCATION_SCRIPT:semantic_nested_character/main",
            "CHARACTER_SCRIPT:mulle/wave",
        ])
        parallel = next(trace for key, trace in by_id.items() if "node-parallel" in key)
        self.assertEqual(parallel["observations"][0]["state"]["variant"], "NODE_PARALLEL")
        self.assertEqual(len(parallel["observations"][0]["state"]["branches"]), 2)
        self.assertEqual(
            parallel["observations"][1]["state"]["branches"][0]["afterState"][
                "schedulerResetCount"
            ],
            1,
        )
        empty = next(trace for key, trace in by_id.items() if "empty-repeat" in key)
        self.assertTrue(all(
            item["state"]["variant"] == "SCHEDULER_ONLY"
            and item["state"]["command"] is None
            for item in empty["observations"]
        ))

    def test_animation_callbacks_rate_zero_rng_and_take_persistence_remain_typed(self):
        animation_case = next(
            row for row in self.fixture["cases"] if "animation-callback" in row["semanticCaseId"]
        )
        raw = self.raw_web_document(animation_case)
        animation = oracle.normalize_web_trace(
            raw, animation_case["executableArtifact"], self.identity_for(raw)
        )
        states = [item["state"] for item in animation["observations"]]
        callback_values = [
            callback["value"] for state in states for callback in state["callbacks"]
            if callback["path"].endswith(".callback")
        ]
        self.assertEqual(callback_values, [None, 1, None, 1, None, 1])
        self.assertEqual(states[0]["rng"]["samples"], [
            {"sequence": 0, "kind": "UNIT_INTERVAL_NUMBER", "value": 0.375}
        ])
        self.assertEqual(states[4]["rng"]["samples"], [
            {"sequence": 0, "kind": "NATIVE_RAND_U15", "value": 4321}
        ])
        self.assertEqual(states[0]["sideEffects"][0]["value"]["receipt"]["rate"], 0)
        self.assertEqual(states[4]["sideEffects"][0]["value"]["receipt"]["repeats"], 4)

        take_case = next(
            row for row in self.fixture["cases"] if "opcode-6-14" in row["semanticCaseId"]
        )
        raw = self.raw_web_document(take_case)
        take_trace = oracle.normalize_web_trace(
            raw, take_case["executableArtifact"], self.identity_for(raw)
        )
        take_states = [item["state"] for item in take_trace["observations"]]
        self.assertEqual([len(state["rng"]["samples"]) for state in take_states], [1, 0, 1, 0])
        self.assertEqual(
            take_states[0]["sideEffects"][0]["value"]["mediaBinding"],
            take_states[1]["sideEffects"][0]["value"]["mediaBinding"],
        )
        self.assertEqual(
            take_states[2]["sideEffects"][0]["value"]["mediaBinding"],
            take_states[3]["sideEffects"][0]["value"]["mediaBinding"],
        )

    def test_failures_have_exact_command_identity_and_no_synthetic_success_shape(self):
        failure_codes = []
        for case in self.fixture["cases"]:
            if case["finalStatus"] != "FAILED":
                continue
            raw = self.raw_web_document(case)
            trace = oracle.normalize_web_trace(
                raw, case["executableArtifact"], self.identity_for(raw)
            )
            state = trace["observations"][-1]["state"]
            self.assertEqual(state["variant"], "FAILURE")
            self.assertEqual(state["afterState"]["runtimeStatus"], "FAILED")
            self.assertIsNone(state["afterState"]["schedulerComplete"])
            self.assertRegex(state["command"]["commandSha256"], oracle.SHA256)
            failure_codes.append(state["failure"]["code"])
        self.assertEqual(failure_codes, [
            "MISSING_OPCODE_PORT",
            "INVALID_NATIVE_COMPLETION_STATUS",
            "INVALID_NATIVE_RNG_RESULT",
            "CLOCK_PORT_EXCEPTION",
        ])

    def test_strict_schema_order_ancestry_and_ledger_identity_fail_closed(self):
        case = self.fixture["cases"][0]
        raw = self.raw_web_document(case)
        expected = self.identity_for(raw)

        broken = copy.deepcopy(raw)
        broken["receipts"][0]["invented"] = True
        with self.assertRaisesRegex(oracle.SemanticOracleError, "success receipt fields"):
            oracle.normalize_web_trace(broken, case["executableArtifact"], expected)

        broken = copy.deepcopy(raw)
        broken["receipts"][0]["ancestry"].append("CHARACTER_SCRIPT:fake/fake")
        with self.assertRaisesRegex(oracle.SemanticOracleError, "call ancestry"):
            oracle.normalize_web_trace(broken, case["executableArtifact"], expected)

        wait_case = next(row for row in self.fixture["cases"] if "wait-random" in row["semanticCaseId"])
        broken = self.raw_web_document(wait_case)
        broken["receipts"][0]["randomSamples"][0]["sequence"] = 1
        with self.assertRaisesRegex(oracle.SemanticOracleError, "RNG sample 0 fields"):
            oracle.normalize_web_trace(
                broken, wait_case["executableArtifact"], self.identity_for(broken)
            )

        broken = self.raw_web_document(wait_case)
        broken["receipts"][0]["outcome"]["wait"]["timer"] = 0.1
        with self.assertRaisesRegex(oracle.SemanticOracleError, "not an exact float32"):
            oracle.normalize_web_trace(
                broken, wait_case["executableArtifact"], self.identity_for(broken)
            )

        broken = self.raw_web_document(wait_case)
        broken["receipts"][0]["outcome"]["wait"]["delta"] = 0.20000000298023224
        with self.assertRaisesRegex(oracle.SemanticOracleError, "WAIT delta differs"):
            oracle.normalize_web_trace(
                broken, wait_case["executableArtifact"], self.identity_for(broken)
            )

        broken = self.raw_web_document(wait_case)
        broken["receipts"][0]["delta"] = 0.1
        broken["receipts"][0]["outcome"]["wait"]["delta"] = 0.1
        with self.assertRaisesRegex(oracle.SemanticOracleError, "not an exact float32"):
            oracle.normalize_web_trace(
                broken, wait_case["executableArtifact"], self.identity_for(broken)
            )

        broken = copy.deepcopy(raw)
        broken["executableScriptSha256"] = "0" * 64
        wrong_expected = self.identity_for(raw)
        wrong_expected["sourceHashes"]["sceneDispatchContract"] = "0" * 64
        with self.assertRaisesRegex(oracle.SemanticOracleError, "identity mismatch: sourceHashes"):
            oracle.normalize_web_trace(broken, case["executableArtifact"], wrong_expected)

    def test_test_fixture_cannot_be_relabelled_as_production_evidence(self):
        case = self.fixture["cases"][0]
        raw = self.raw_web_document(case, evidence_mode="PRODUCTION")
        with self.assertRaisesRegex(
            oracle.SemanticOracleError,
            "fields differ|expected ledger identity",
        ):
            oracle.normalize_web_trace(raw, case["executableArtifact"])
        with self.assertRaisesRegex(
            oracle.SemanticOracleError, "fields differ|source-bound"
        ):
            oracle.normalize_web_trace(
                raw, case["executableArtifact"], self.identity_for(raw)
            )
        synthetic_bytes = json.dumps(case["executableArtifact"]).encode("utf-8")
        with self.assertRaisesRegex(
            oracle.SemanticOracleError,
            "fields differ|source hash differs",
        ):
            oracle.normalize_web_trace(
                raw, case["executableArtifact"], self.identity_for(raw),
                executable_source_bytes=synthetic_bytes,
            )

    def test_production_source_and_executable_body_claims_use_distinct_raw_protocols(self):
        self.assertNotEqual(
            oracle.WEB_SOURCE_RAW_PROTOCOL,
            oracle.WEB_RAW_PROTOCOL,
        )
        case = self.fixture["cases"][0]
        for evidence_class in ("UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY"):
            raw = self.raw_web_document(case, evidence_mode="PRODUCTION")
            raw["evidenceClass"] = evidence_class
            raw["claimId"] = f"{evidence_class}:{raw['artifactKey']}"
            oracle._validate_identity(raw, "WEB")

        invalid = self.raw_web_document(case, evidence_mode="PRODUCTION")
        invalid["evidenceClass"] = "FORGED_DISPATCH"
        invalid["claimId"] = "FORGED_DISPATCH:invented"
        with self.assertRaisesRegex(oracle.SemanticOracleError, "evidence class is unsupported"):
            oracle._validate_identity(invalid, "WEB")

    def test_production_mission_dispatch_receipt_is_independently_normalized(self):
        from tools.miel_vliegt import scene_semantic_coverage as coverage

        ledger = coverage.generate()
        record = next(
            row for row in ledger["records"]
            if row["evidenceClass"] == "MISSION_DISPATCH"
            and row["expectation"]["route"] == "BARN"
        )
        expectation = record["expectation"]
        executable_bytes = coverage.DEFAULT_EXECUTABLE.read_bytes()
        executable = json.loads(executable_bytes)
        script = next(
            row for row in executable["scripts"]
            if script_key(row) == expectation["artifactKey"]
        )
        source_hashes = {
            key: ledger["sources"][source]["sha256"] for key, source in {
                "sceneDispatchContract": "sceneDispatchContract",
                "udsSceneScripts": "udsSceneScripts",
                "executableUdspSceneScripts": "executableUdspSceneScripts",
            }.items()
        }
        capture_provenance = coverage.expected_web_dispatch_capture_provenance(
            record, edition=ledger["edition"], candidate_identity={
                "candidateVersion": "unit-test-unproven",
                "captureBundleSha256": "a" * 64,
            }, plan_document=current_dispatch_plan(ledger),
        )
        mission_state_key = (
            f"{expectation['missionKey']}|{expectation['missionPhase']}|"
            f"{expectation['nativeActionOrdinal']}"
        )
        result = {
            "schema": 1, "sequence": 1, "trigger": "MISSION_ACTION",
            "action": "STARTED", "route": "BARN", "locationId": None,
            "artifactKey": expectation["artifactKey"], "duplicate": False,
        }
        raw = {
            "schema": 1, "protocol": oracle.WEB_RAW_PROTOCOL,
            "evidenceMode": "PRODUCTION", "producer": "WEB",
            "edition": ledger["edition"], "claimId": record["id"],
            "evidenceClass": record["evidenceClass"], "semanticCaseId": None,
            "sourceHashes": source_hashes,
            "subjectSha256": coverage.evidence_subject_sha256(record),
            "expectationSha256": coverage.evidence_expectation_sha256(record),
            "artifactKey": expectation["artifactKey"],
            "executableScriptSha256": oracle.canonical_sha256(script),
            "captureProvenance": capture_provenance,
            "receipts": [{
                "schema": 1, "sequence": 1, "semanticStatus": "UNPROVEN",
                "event": {
                    "trigger": "MISSION_ACTION",
                    "missionKey": expectation["missionKey"],
                    "missionPhase": expectation["missionPhase"],
                    "nativeActionOrdinal": expectation["nativeActionOrdinal"],
                },
                "before": {"sequence": 0},
                "result": result,
                "after": {
                    "sequence": 1,
                    "appliedMissionActions": {
                        mission_state_key: {
                            key: value for key, value in result.items()
                            if key not in {"schema", "sequence", "trigger"}
                        }
                    },
                },
            }],
        }
        normalized = oracle.normalize_web_trace(
            raw, executable, self.identity_for(raw),
            executable_source_bytes=executable_bytes,
            expected_expectation=expectation,
            expected_capture_provenance=capture_provenance,
        )
        self.assertEqual(normalized["observations"][0]["state"]["effect"], {
            "selection": "MISSION_ACTION_SELECTED",
            "route": "BARN",
            "artifactKey": expectation["artifactKey"],
        })
        missing_provenance = copy.deepcopy(raw)
        missing_provenance.pop("captureProvenance")
        with self.assertRaisesRegex(
            oracle.SemanticOracleError, "web semantic document fields differ",
        ):
            oracle.normalize_web_trace(
                missing_provenance, executable, self.identity_for(missing_provenance),
                executable_source_bytes=executable_bytes,
                expected_expectation=expectation,
                expected_capture_provenance=capture_provenance,
            )
        stale_provenance = copy.deepcopy(raw)
        stale_provenance["captureProvenance"]["runtimeSha256"] = "f" * 64
        with self.assertRaisesRegex(
            oracle.SemanticOracleError, "capture provenance differs from expected",
        ):
            oracle.normalize_web_trace(
                stale_provenance, executable, self.identity_for(stale_provenance),
                executable_source_bytes=executable_bytes,
                expected_expectation=expectation,
                expected_capture_provenance=capture_provenance,
            )
        stale_candidate = copy.deepcopy(raw)
        stale_candidate["captureProvenance"]["captureBundleSha256"] = "f" * 64
        with self.assertRaisesRegex(
            oracle.SemanticOracleError, "capture provenance differs from expected",
        ):
            oracle.normalize_web_trace(
                stale_candidate, executable, self.identity_for(stale_candidate),
                executable_source_bytes=executable_bytes,
                expected_expectation=expectation,
                expected_capture_provenance=capture_provenance,
            )
        forged = copy.deepcopy(raw)
        forged["receipts"][0]["result"]["route"] = "FLIGHT"
        with self.assertRaisesRegex(oracle.SemanticOracleError, "differs from expectation"):
            oracle.normalize_web_trace(
                forged, executable, self.identity_for(forged),
                executable_source_bytes=executable_bytes,
                expected_expectation=expectation,
                expected_capture_provenance=capture_provenance,
            )
        duplicate = copy.deepcopy(raw)
        duplicate["receipts"].append(copy.deepcopy(duplicate["receipts"][0]))
        duplicate["receipts"][1]["sequence"] = 2
        with self.assertRaisesRegex(oracle.SemanticOracleError, "exactly one receipt"):
            oracle.normalize_web_trace(
                duplicate, executable, self.identity_for(duplicate),
                executable_source_bytes=executable_bytes,
                expected_expectation=expectation,
                expected_capture_provenance=capture_provenance,
            )

    def test_every_location_policy_selector_has_a_fail_closed_normalization_path(self):
        from tools.miel_vliegt import scene_semantic_coverage as coverage

        ledger = coverage.generate()
        records = [
            row for row in ledger["records"]
            if row["evidenceClass"] == "LOCATION_POLICY"
        ]
        executable_bytes = coverage.DEFAULT_EXECUTABLE.read_bytes()
        executable = json.loads(executable_bytes)
        scripts = {script_key(row): row for row in executable["scripts"]}
        source_hashes = {
            "sceneDispatchContract": ledger["sources"]["sceneDispatchContract"]["sha256"],
            "udsSceneScripts": ledger["sources"]["udsSceneScripts"]["sha256"],
            "executableUdspSceneScripts": ledger["sources"]["executableUdspSceneScripts"]["sha256"],
        }
        capture_plan = current_dispatch_plan(ledger)
        seen = set()
        for record in records:
            expectation = record["expectation"]
            capture_provenance = coverage.expected_web_dispatch_capture_provenance(
                record, edition=ledger["edition"], candidate_identity={
                    "candidateVersion": "unit-test-unproven",
                    "captureBundleSha256": "a" * 64,
                }, plan_document=capture_plan,
            )
            selector = expectation["selector"]
            seen.add(selector)
            location_id = expectation["locationId"]
            before = {
                "sequence": 0,
                "finalMissionState": 0,
                "grotte": {"refuelArmed": False, "refuelConsumed": False},
                "raymond": {"firstChallenge": True, "challengeResult": 0},
                "exhibition": {"outroRequested": False, "projectedMapX": 0},
            }
            if "FINAL_MISSION_STATE_EQ_3" in selector:
                before["finalMissionState"] = 3
            if "SUBSEQUENT_CHALLENGE" in selector:
                before["raymond"]["firstChallenge"] = False
            if "RESULT_EQ_2" in selector:
                before["raymond"]["challengeResult"] = 2
            if "RESULT_NE_2" in selector:
                before["raymond"]["challengeResult"] = 1
            if "REFUEL_ARMED" in selector:
                before["grotte"]["refuelArmed"] = True
            if "OUTRO_REQUESTED" in selector:
                before["exhibition"]["outroRequested"] = True
            if "900_LTE_PROJECTED_X_LT_2200" in selector:
                before["exhibition"]["projectedMapX"] = 900
            elif "PROJECTED_X_GTE_2200" in selector:
                before["exhibition"]["projectedMapX"] = 2200
            elif "PROJECTED_X_LT_900" in selector:
                before["exhibition"]["projectedMapX"] = 899.5
            completion = selector.startswith(("ROOT_COMPLETE_", "CHALLENGE_ROOT_COMPLETE_"))
            event = (
                {"trigger": "DERIVED_STATE", "kind": "ROOT_COMPLETE", "route": "GROUND", "locationId": location_id}
                if completion else {"trigger": "LOCATION_ENTER", "locationId": location_id}
            )
            artifact_key = expectation["artifactKey"]
            result = {
                "schema": 1, "sequence": 1,
                "trigger": event["trigger"],
                "action": "EXPECTED_ABSENCE" if artifact_key is None else "ADVANCED" if completion else "STARTED",
                "route": "GROUND", "locationId": location_id,
                "artifactKey": artifact_key,
            }
            raw = {
                "schema": 1, "protocol": oracle.WEB_RAW_PROTOCOL,
                "evidenceMode": "PRODUCTION", "producer": "WEB",
                "edition": ledger["edition"], "claimId": record["id"],
                "evidenceClass": record["evidenceClass"], "semanticCaseId": None,
                "sourceHashes": source_hashes,
                "subjectSha256": coverage.evidence_subject_sha256(record),
                "expectationSha256": coverage.evidence_expectation_sha256(record),
                "artifactKey": artifact_key,
                "executableScriptSha256": (
                    oracle.canonical_sha256(scripts[artifact_key])
                    if artifact_key is not None else None
                ),
                "captureProvenance": capture_provenance,
                "receipts": [{
                    "schema": 1, "sequence": 1, "semanticStatus": "UNPROVEN",
                    "event": event, "before": before, "result": result,
                    "after": {
                        "sequence": 1,
                        "locations": {str(location_id): {"activeRoot": artifact_key}},
                    },
                }],
            }
            trace = oracle.normalize_web_trace(
                raw, executable, self.identity_for(raw),
                executable_source_bytes=executable_bytes,
                expected_expectation=expectation,
                expected_capture_provenance=capture_provenance,
            )
            self.assertEqual(
                trace["observations"][0]["state"]["effect"]["outcome"],
                expectation["outcome"],
            )
        self.assertEqual(len(records), 42)
        self.assertEqual(len(seen), 14)

    def test_native_hook_capability_gap_is_explicit_and_labels_are_never_copied(self):
        case = self.fixture["cases"][0]
        web_raw = self.raw_web_document(case)
        native_raw = {
            key: copy.deepcopy(value)
            for key, value in web_raw.items()
            if key not in {"receipts"}
        }
        native_raw.update({
            "protocol": oracle.NATIVE_RAW_PROTOCOL,
            "producer": "NATIVE",
            "supportStatus": "UNSUPPORTED_HOOK_FACTS",
            "hookCapabilities": {
                field: field in {"clock", "delta"}
                for field in oracle.NATIVE_CAPABILITY_FIELDS
            },
            "events": [{
                "inventedNormalizedState": {
                    "variant": "COMMAND", "opcode": "WAIT", "parity": "MATCH"
                }
            }],
        })
        with self.assertRaisesRegex(
            oracle.SemanticOracleUnsupported,
            "UNSUPPORTED_HOOK_FACTS:.*executableCommandIndex.*scriptKey",
        ):
            oracle.normalize_native_trace(
                native_raw, case["executableArtifact"], self.identity_for(native_raw)
            )
        self.assertFalse(hasattr(oracle, "native_test_document_from_observations"))

    def test_differential_is_diagnostic_and_never_parity_eligible(self):
        case = self.fixture["cases"][0]
        raw = self.raw_web_document(case)
        web = oracle.normalize_web_trace(
            raw, case["executableArtifact"], self.identity_for(raw)
        )
        native = copy.deepcopy(web)
        native["producer"] = "NATIVE"
        match = oracle.compare_normalized_traces(native, web)
        self.assertEqual(match["result"], "TEST_ONLY_MATCH")
        self.assertFalse(match["parityEligible"])
        native["observations"][0]["state"]["afterState"]["runtimeStatus"] = "FAILED"
        difference = oracle.compare_normalized_traces(native, web)
        self.assertEqual(difference["result"], "DIFFER")
        self.assertIn("afterState.runtimeStatus", difference["firstDivergence"]["path"])

        invalid = copy.deepcopy(web)
        invalid["producer"] = "NATIVE"
        invalid["observations"][0]["state"]["rng"]["invented"] = []
        with self.assertRaisesRegex(oracle.SemanticOracleError, "RNG transcript fields"):
            oracle.compare_normalized_traces(invalid, web)

        invalid = copy.deepcopy(web)
        invalid["producer"] = "NATIVE"
        effects = invalid["observations"][0]["state"]["sideEffects"]
        effects.append(copy.deepcopy(effects[0]))
        with self.assertRaisesRegex(oracle.SemanticOracleError, "side-effect transcript"):
            oracle.compare_normalized_traces(invalid, web)

        invalid = copy.deepcopy(web)
        invalid["producer"] = "NATIVE"
        invalid["observations"][0]["state"]["sideEffects"][0]["sequence"] = False
        with self.assertRaisesRegex(oracle.SemanticOracleError, "side-effect transcript"):
            oracle.compare_normalized_traces(invalid, web)

        parallel_case = next(
            row for row in self.fixture["cases"] if "node-parallel" in row["semanticCaseId"]
        )
        parallel_raw = self.raw_web_document(parallel_case)
        parallel = oracle.normalize_web_trace(
            parallel_raw, parallel_case["executableArtifact"],
            self.identity_for(parallel_raw),
        )
        invalid = copy.deepcopy(parallel)
        invalid["producer"] = "NATIVE"
        branch = invalid["observations"][0]["state"]["branches"][0]
        ancestry = branch["callAncestry"]
        ancestry.insert(0, ancestry[0])
        branch["depth"] += 1
        with self.assertRaisesRegex(oracle.SemanticOracleError, "branch ancestry"):
            oracle.compare_normalized_traces(invalid, parallel)

    def test_parallel_runtime_parent_indices_are_exact_not_lower_bounds(self):
        case = next(
            row for row in self.fixture["cases"] if "node-parallel" in row["semanticCaseId"]
        )
        raw = self.raw_web_document(case)
        raw["receipts"][1]["outcome"]["branches"][0]["parents"][-1]["childIndex"] = 0
        raw["receipts"][1]["scheduler"]["children"] = copy.deepcopy(
            raw["receipts"][1]["outcome"]["branches"]
        )
        with self.assertRaisesRegex(oracle.SemanticOracleError, "parent path differs"):
            oracle.normalize_web_trace(
                raw, case["executableArtifact"], self.identity_for(raw)
            )

    def test_parallel_rng_envelope_is_global_but_branch_sequences_remain_local(self):
        case = next(
            row for row in self.fixture["cases"] if "node-parallel" in row["semanticCaseId"]
        )
        raw = self.raw_web_document(case)
        receipt = raw["receipts"][0]
        branches = receipt["outcome"]["branches"]
        branches[0]["randomSamples"] = [
            {"sequence": 0, "kind": "NATIVE_RAND_U15", "value": 1}
        ]
        branches[1]["randomSamples"] = [
            {"sequence": 0, "kind": "NATIVE_RAND_U15", "value": 2}
        ]
        receipt["scheduler"]["children"] = copy.deepcopy(branches)
        receipt["randomSamples"] = [
            {"sequence": 0, "kind": "NATIVE_RAND_U15", "value": 1},
            {"sequence": 1, "kind": "NATIVE_RAND_U15", "value": 2},
        ]

        trace = oracle.normalize_web_trace(
            raw, case["executableArtifact"], self.identity_for(raw)
        )
        state = trace["observations"][0]["state"]
        self.assertEqual(state["rng"]["samples"], receipt["randomSamples"])
        self.assertEqual([
            branch["rng"]["samples"][0]["sequence"] for branch in state["branches"]
        ], [0, 0])

        broken = copy.deepcopy(raw)
        broken["receipts"][0]["randomSamples"][1]["sequence"] = 0
        with self.assertRaisesRegex(
            oracle.SemanticOracleError, "NODE_PARALLEL RNG envelope differs"
        ):
            oracle.normalize_web_trace(
                broken, case["executableArtifact"], self.identity_for(broken)
            )


if __name__ == "__main__":
    unittest.main()
