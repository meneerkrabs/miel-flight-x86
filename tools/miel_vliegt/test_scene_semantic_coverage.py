#!/usr/bin/env python3
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import scene_semantic_coverage as coverage
from tools.miel_vliegt import scene_semantic_evidence_batches as batches


class SceneSemanticCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = coverage.generate()

    def setUp(self):
        self.ledger = copy.deepcopy(self.generated)
        self.temporary = tempfile.TemporaryDirectory(dir=coverage.ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.evidence_directory = Path(self.temporary.name)

    def test_web_runtime_producer_is_selected_by_evidence_class(self):
        self.assertEqual(
            coverage.web_runtime_producer({"evidenceClass": "UDSP_EXECUTABLE_BODY"}),
            coverage.WEB_RUNTIME_PRODUCER,
        )
        self.assertEqual(
            coverage.web_runtime_producer({"evidenceClass": "MISSION_DISPATCH"}),
            coverage.WEB_DISPATCH_RUNTIME_PRODUCER,
        )
        self.assertEqual(
            coverage.web_runtime_producer({"evidenceClass": "LOCATION_POLICY"}),
            coverage.WEB_DISPATCH_RUNTIME_PRODUCER,
        )
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "unknown web semantic producer"):
            coverage.web_runtime_producer({"evidenceClass": "FORGED"})

    def test_candidate_version_parser_has_byte_preserving_line_rules(self):
        for ending in ("\n", "\r\n"):
            self.assertEqual(
                coverage.parse_web_candidate_version_text(
                    "Miel Monteur Vliegt Edition (fi, candidate-9)" + ending
                ),
                "candidate-9",
            )
        for invalid in (
            "Miel Monteur Vliegt Edition (fi, candidate-9)\rBuilt: fixed",
            "\ufeffMiel Monteur Vliegt Edition (fi, candidate-9)\n",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                coverage.SemanticCoverageError
            ):
                coverage.parse_web_candidate_version_text(invalid)

    def test_dispatch_candidate_is_source_bound_but_cannot_promote(self):
        record = next(
            row for row in self.ledger["records"]
            if row["evidenceClass"] == "MISSION_DISPATCH"
            and row["expectation"]["route"] == "BARN"
        )
        expectation = record["expectation"]
        executable_bytes = coverage.DEFAULT_EXECUTABLE.read_bytes()
        executable = json.loads(executable_bytes)
        script = next(
            row for row in executable["scripts"]
            if f"{row['type']}:{row['domainId']}/{row['dispatchId']}" \
            == expectation["artifactKey"]
        )
        bundle_path = self.evidence_directory / "candidate-bundle.js"
        bundle_path.write_bytes(b"unit-test-candidate-bundle")
        version_path = self.evidence_directory / "candidate-version.txt"
        version_path.write_text(
            "Miel Monteur Vliegt Edition (fi, unit-test-unproven)\n",
            encoding="utf-8",
        )
        candidate_identity = {
            "candidateVersion": "unit-test-unproven",
            "captureBundleSha256": coverage.sha256_file(bundle_path),
        }
        with self.assertRaisesRegex(
            coverage.SemanticCoverageError, "candidate build identity is required"
        ):
            coverage.expected_web_dispatch_capture_provenance(
                record, edition=self.ledger["edition"],
            )
        test_plan = batches.build_plan(
            self.ledger,
            ledger_source=batches._source(coverage.DEFAULT_LEDGER, coverage.SCHEMA),
        )
        capture_provenance = coverage.expected_web_dispatch_capture_provenance(
            record, edition=self.ledger["edition"],
            candidate_identity=candidate_identity,
            plan_document=test_plan,
        )
        key = (
            f"{expectation['missionKey']}|{expectation['missionPhase']}|"
            f"{expectation['nativeActionOrdinal']}"
        )
        effect = {
            "action": "STARTED", "route": "BARN", "locationId": None,
            "artifactKey": expectation["artifactKey"], "duplicate": False,
        }
        raw = {
            "schema": 1,
            "protocol": coverage.udsp_semantic_oracle.WEB_RAW_PROTOCOL,
            "evidenceMode": "PRODUCTION",
            "producer": "WEB",
            "edition": self.ledger["edition"],
            "claimId": record["id"],
            "evidenceClass": record["evidenceClass"],
            "semanticCaseId": None,
            "sourceHashes": self.source_hashes(),
            "subjectSha256": coverage.evidence_subject_sha256(record),
            "expectationSha256": coverage.evidence_expectation_sha256(record),
            "artifactKey": expectation["artifactKey"],
            "executableScriptSha256": (
                coverage.udsp_semantic_oracle.canonical_sha256(script)
            ),
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
                "result": {
                    "schema": 1, "sequence": 1, "trigger": "MISSION_ACTION",
                    **effect,
                },
                "after": {
                    "sequence": 1,
                    "appliedMissionActions": {key: effect},
                },
            }],
        }
        identity = {
            field: copy.deepcopy(raw[field])
            for field in coverage.udsp_semantic_oracle.IDENTITY_FIELDS
        }
        observations = coverage.udsp_semantic_oracle.normalize_web_trace(
            raw, executable, identity,
            executable_source_bytes=executable_bytes,
            expected_expectation=expectation,
            expected_capture_provenance=capture_provenance,
        )["observations"]
        web_build = {
            "path": coverage._repo_path(coverage.WEB_BUILD_RECEIPT),
            "sha256": coverage.sha256_file(coverage.WEB_BUILD_RECEIPT),
        }
        runtime_producer = {
            "path": coverage._repo_path(coverage.WEB_DISPATCH_RUNTIME_PRODUCER),
            "sha256": coverage.sha256_file(coverage.WEB_DISPATCH_RUNTIME_PRODUCER),
        }
        candidate_build = {
            "schema": 1,
            "protocol": coverage.WEB_DISPATCH_CANDIDATE_BUILD_PROTOCOL,
            "semanticStatus": "UNPROVEN",
            "parityEligible": False,
            "productionProvenance": (
                "CANDIDATE_ONLY_NO_SOURCE_TO_BUNDLE_ATTESTATION"
            ),
            **candidate_identity,
            "versionTextSha256": coverage.sha256_file(version_path),
            "webTransitionBuildSha256": coverage.sha256_file(
                coverage.WEB_BUILD_RECEIPT
            ),
            "semanticLedgerSha256": coverage.sha256_file(coverage.DEFAULT_LEDGER),
            "captureBundle": {
                "path": bundle_path.relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(bundle_path),
            },
            "versionText": {
                "path": version_path.relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(version_path),
            },
            "webTransitionBuild": {
                "path": coverage._repo_path(coverage.WEB_BUILD_RECEIPT),
                "sha256": coverage.sha256_file(coverage.WEB_BUILD_RECEIPT),
            },
        }
        plan_path = self.evidence_directory / "candidate-plan.json"
        plan_path.write_text(json.dumps(test_plan), encoding="utf-8")
        candidate_build.update({
            "semanticPlanSha256": coverage.sha256_file(plan_path),
            "semanticLedger": {
                "path": coverage._repo_path(coverage.DEFAULT_LEDGER),
                "sha256": coverage.sha256_file(coverage.DEFAULT_LEDGER),
            },
            "semanticPlan": {
                "path": plan_path.relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(plan_path),
            },
        })
        candidate_build_path = self.evidence_directory / "candidate-build.json"
        candidate_build_path.write_text(json.dumps(candidate_build), encoding="utf-8")
        candidate_build_reference = {
            "path": candidate_build_path.relative_to(coverage.ROOT).as_posix(),
            "sha256": coverage.sha256_file(candidate_build_path),
        }

        def write_capture(document, suffix):
            raw_path = self.evidence_directory / f"dispatch-{suffix}.raw.json"
            raw_path.write_text(json.dumps(document), encoding="utf-8")
            raw_reference = {
                "path": raw_path.relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(raw_path),
            }
            receipt = {
                "schema": 1, "protocol": coverage.WEB_CAPTURE_PROTOCOL,
                "result": "PASS", "captureStatus": "PRODUCTION_COMPLETE",
                "producer": "WEB", "edition": self.ledger["edition"],
                "claimId": record["id"], "evidenceClass": record["evidenceClass"],
                "sourceHashes": self.source_hashes(),
                "subjectSha256": coverage.evidence_subject_sha256(record),
                "expectationSha256": coverage.evidence_expectation_sha256(record),
                "observationsSha256": coverage.semantic_observations_sha256(observations),
                "rawTrace": raw_reference,
                "rawTraceProtocol": coverage.udsp_semantic_oracle.WEB_RAW_PROTOCOL,
                "webBuild": web_build,
                "runtimeProducer": runtime_producer,
                "candidateBuild": candidate_build_reference,
            }
            receipt_path = self.evidence_directory / f"dispatch-{suffix}.capture.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            return {
                "path": receipt_path.relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(receipt_path),
            }

        lowering = self.ledger["policy"]["executableLowering"]
        arguments = {
            "producer": "WEB", "record": record,
            "edition": self.ledger["edition"], "source_hashes": self.source_hashes(),
            "subject_sha256": coverage.evidence_subject_sha256(record),
            "expectation_sha256": coverage.evidence_expectation_sha256(record),
            "observations": observations,
            "provenance": {"webBuild": web_build, "runtimeProducer": runtime_producer},
            "capture_paths": set(), "capture_hashes": set(),
            "native_command_contract": lowering["sources"]["nativeCommands"],
            "native_executable_sha256": lowering["sourceIdentities"]["nativeExecutableSha256"],
            "executable_artifact": executable,
            "executable_source_bytes": executable_bytes,
        }
        validated_identity, validated_plan = (
            coverage._validate_web_dispatch_candidate_build(
                candidate_build_reference
            )
        )
        self.assertEqual(validated_identity, candidate_identity)
        self.assertEqual(validated_plan, test_plan)
        with self.assertRaisesRegex(
            coverage.SemanticCoverageError,
            "candidate-only capture cannot promote",
        ):
            coverage._validate_capture_receipt(
                write_capture(raw, "candidate-only"), **arguments,
            )
        bundle_path.write_bytes(b"candidate-bundle-mutated-after-capture")
        with self.assertRaisesRegex(
            coverage.SemanticCoverageError,
            "candidate bundle artifact hash mismatch",
        ):
            coverage._validate_web_dispatch_candidate_build(
                candidate_build_reference
            )

    def validate(self, ledger=None, *, allow_test_provenance=True):
        return coverage.validate_ledger(
            self.ledger if ledger is None else ledger,
            allow_test_provenance=allow_test_provenance,
        )

    def source_hashes(self):
        return {
            "sceneDispatchContract": self.ledger["sources"]["sceneDispatchContract"]["sha256"],
            "udsSceneScripts": self.ledger["sources"]["udsSceneScripts"]["sha256"],
            "executableUdspSceneScripts": self.ledger["sources"]["executableUdspSceneScripts"]["sha256"],
        }

    def evidence(self, record, *, evidence_id=None):
        identity = evidence_id or f"evidence:{record['id']}"
        source_hashes = self.source_hashes()
        expectation_sha256 = coverage.evidence_expectation_sha256(record)
        subject_sha256 = coverage.evidence_subject_sha256(record)
        observation = {
            "schema": 1,
            "record": "semantic_observation",
            "sequence": 0,
            "evidenceClass": record["evidenceClass"],
            "claimId": record["id"],
            "subjectSha256": subject_sha256,
            "expectationSha256": expectation_sha256,
            "state": {"semanticStatus": "MATCHED"},
        }
        stem = hashlib.sha256(record["id"].encode()).hexdigest()
        trace_paths = {}
        for producer in ("NATIVE", "WEB"):
            provenance = {
                "schema": 1,
                "protocol": "miel-vliegt-scene-semantic-producer-provenance",
                "producer": producer,
                "mode": "TEST_FIXTURE",
                "result": "PASS",
                "claimId": record["id"],
                "evidenceClass": record["evidenceClass"],
                "edition": self.ledger["edition"],
                "sourceHashes": source_hashes,
                "subjectSha256": subject_sha256,
                "expectationSha256": expectation_sha256,
                "observationsSha256": coverage.semantic_observations_sha256([observation]),
                "captureProtocol": "UNIT_TEST_ONLY",
            }
            provenance_path = (
                self.evidence_directory / f"{stem}.{producer.lower()}.provenance.json"
            )
            provenance_path.write_text(
                json.dumps(provenance, sort_keys=True), encoding="utf-8"
            )
            document = {
                "schema": 1,
                "protocol": "miel-vliegt-scene-semantic-trace",
                "producer": producer,
                "claimId": record["id"],
                "evidenceClass": record["evidenceClass"],
                "edition": self.ledger["edition"],
                "sourceHashes": source_hashes,
                "subjectSha256": subject_sha256,
                "expectationSha256": expectation_sha256,
                "producerProvenance": {
                    "path": provenance_path.relative_to(coverage.ROOT).as_posix(),
                    "sha256": coverage.sha256_file(provenance_path),
                },
                "observations": [observation],
            }
            path = self.evidence_directory / f"{stem}.{producer.lower()}.json"
            path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
            trace_paths[producer] = path
        receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-scene-semantic-differential",
            "result": "PASS",
            "evidenceId": identity,
            "evidenceClass": record["evidenceClass"],
            "claimId": record["id"],
            "edition": self.ledger["edition"],
            "sourceHashes": source_hashes,
            "subjectSha256": subject_sha256,
            "expectationSha256": expectation_sha256,
            "nativeTrace": {
                "path": trace_paths["NATIVE"].relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(trace_paths["NATIVE"]),
            },
            "webTrace": {
                "path": trace_paths["WEB"].relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(trace_paths["WEB"]),
            },
            "observationsSha256": coverage.semantic_observations_sha256([observation]),
        }
        path = self.evidence_directory / f"{stem}.receipt.json"
        path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        return {
            "evidenceId": identity,
            "path": path.relative_to(coverage.ROOT).as_posix(),
            "sha256": coverage.sha256_file(path),
            "evidenceClass": record["evidenceClass"],
            "claimId": record["id"],
            "edition": self.ledger["edition"],
            "sourceHashes": source_hashes,
            "subjectSha256": subject_sha256,
            "expectationSha256": expectation_sha256,
        }

    def rewrite_receipt(self, evidence, mutate):
        path = coverage.ROOT / evidence["path"]
        receipt = json.loads(path.read_text(encoding="utf-8"))
        mutate(receipt)
        path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        evidence["sha256"] = coverage.sha256_file(path)
        return receipt

    def rewrite_trace(self, evidence, producer, mutate):
        receipt_path = coverage.ROOT / evidence["path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        field = "nativeTrace" if producer == "NATIVE" else "webTrace"
        trace_path = coverage.ROOT / receipt[field]["path"]
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        mutate(trace)
        provenance_reference = trace.get("producerProvenance")
        if isinstance(provenance_reference, dict):
            provenance_path = coverage.ROOT / provenance_reference["path"]
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            provenance["observationsSha256"] = coverage.semantic_observations_sha256(
                trace.get("observations", [])
            )
            provenance_path.write_text(
                json.dumps(provenance, sort_keys=True), encoding="utf-8"
            )
            provenance_reference["sha256"] = coverage.sha256_file(provenance_path)
        trace_path.write_text(json.dumps(trace, sort_keys=True), encoding="utf-8")
        receipt[field]["sha256"] = coverage.sha256_file(trace_path)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        evidence["sha256"] = coverage.sha256_file(receipt_path)
        return trace

    def rewrite_provenance(self, evidence, producer, mutate):
        receipt_path = coverage.ROOT / evidence["path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        field = "nativeTrace" if producer == "NATIVE" else "webTrace"
        trace_path = coverage.ROOT / receipt[field]["path"]
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        provenance_path = coverage.ROOT / trace["producerProvenance"]["path"]
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        mutate(provenance)
        provenance_path.write_text(
            json.dumps(provenance, sort_keys=True), encoding="utf-8"
        )
        trace["producerProvenance"]["sha256"] = coverage.sha256_file(provenance_path)
        trace_path.write_text(json.dumps(trace, sort_keys=True), encoding="utf-8")
        receipt[field]["sha256"] = coverage.sha256_file(trace_path)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        evidence["sha256"] = coverage.sha256_file(receipt_path)
        return provenance

    def upgrade_provenance_to_complete_capture(
        self, evidence, record, producer, *, raw_document=None,
    ):
        differential_path = coverage.ROOT / evidence["path"]
        differential = json.loads(differential_path.read_text(encoding="utf-8"))
        trace_field = "nativeTrace" if producer == "NATIVE" else "webTrace"
        trace_path = coverage.ROOT / differential[trace_field]["path"]
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        observations_sha256 = coverage.semantic_observations_sha256(trace["observations"])
        raw_protocol = f"miel-vliegt-{producer.lower()}-scene-semantic-raw"
        raw = copy.deepcopy(raw_document) if raw_document is not None else {
            "schema": 1,
            "protocol": raw_protocol,
            "producer": producer,
            "evidenceMode": "PRODUCTION",
            "edition": self.ledger["edition"],
            "claimId": record["id"],
            "evidenceClass": record["evidenceClass"],
            "semanticCaseId": None,
            "sourceHashes": self.source_hashes(),
            "subjectSha256": coverage.evidence_subject_sha256(record),
            "expectationSha256": coverage.evidence_expectation_sha256(record),
        }
        if producer == "NATIVE" and raw_document is None:
            artifact_key = record["id"].removeprefix("UDSP_EXECUTABLE_BODY:")
            executable = json.loads(
                coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8")
            )
            executable_script = next(
                script for script in executable["scripts"]
                if f"{script['type']}:{script['domainId']}/{script['dispatchId']}" == artifact_key
            )
            raw.update({
                "artifactKey": artifact_key,
                "executableScriptSha256": coverage.udsp_semantic_oracle.canonical_sha256(
                    executable_script
                ),
                "supportStatus": "UNSUPPORTED_HOOK_FACTS",
                "hookCapabilities": {
                    field: False
                    for field in coverage.udsp_semantic_oracle.NATIVE_CAPABILITY_FIELDS
                },
                "events": [{"captureEvent": "synthetic-regression-only"}],
            })
        elif producer == "WEB" and raw_document is None:
            raw.update({
                "artifactKey": "synthetic-web-is-not-normalizable",
                "executableScriptSha256": "0" * 64,
                "receipts": [],
            })
        stem = hashlib.sha256(f"{record['id']}:{producer}".encode()).hexdigest()
        raw_path = self.evidence_directory / f"{stem}.raw.json"
        raw_path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
        raw_reference = {
            "path": raw_path.relative_to(coverage.ROOT).as_posix(),
            "sha256": coverage.sha256_file(raw_path),
        }
        capture = {
            "schema": 1,
            "protocol": (
                coverage.NATIVE_CAPTURE_PROTOCOL
                if producer == "NATIVE" else coverage.WEB_CAPTURE_PROTOCOL
            ),
            "result": "PASS",
            "captureStatus": "PRODUCTION_COMPLETE",
            "producer": producer,
            "edition": self.ledger["edition"],
            "claimId": record["id"],
            "evidenceClass": record["evidenceClass"],
            "sourceHashes": self.source_hashes(),
            "subjectSha256": coverage.evidence_subject_sha256(record),
            "expectationSha256": coverage.evidence_expectation_sha256(record),
            "observationsSha256": observations_sha256,
            "rawTrace": raw_reference,
            "rawTraceProtocol": raw_protocol,
        }
        lowering = self.ledger["policy"]["executableLowering"]
        if producer == "NATIVE":
            observer_hook = {
                "path": coverage._repo_path(coverage.NATIVE_OBSERVER_HOOK),
                "sha256": coverage.sha256_file(coverage.NATIVE_OBSERVER_HOOK),
            }
            observer_launcher = {
                "path": coverage._repo_path(coverage.NATIVE_OBSERVER_LAUNCHER),
                "sha256": coverage.sha256_file(coverage.NATIVE_OBSERVER_LAUNCHER),
            }
            observer_dll_path = self.evidence_directory / f"{stem}.observer.dll"
            launcher_binary_path = self.evidence_directory / f"{stem}.launcher.exe"
            observer_dll_path.write_bytes(b"MZsynthetic-observer-regression")
            launcher_binary_path.write_bytes(b"MZsynthetic-launcher-regression")
            capture.update({
                "executableSha256": lowering["sourceIdentities"][
                    "nativeExecutableSha256"
                ],
                "nativeCommandContract": lowering["sources"]["nativeCommands"],
                "observerHook": observer_hook,
                "observerLauncherSource": observer_launcher,
                "observerDll": {
                    "path": observer_dll_path.relative_to(coverage.ROOT).as_posix(),
                    "sha256": coverage.sha256_file(observer_dll_path),
                },
                "launcherBinary": {
                    "path": launcher_binary_path.relative_to(coverage.ROOT).as_posix(),
                    "sha256": coverage.sha256_file(launcher_binary_path),
                },
            })
        else:
            capture.update({
                "webBuild": {
                    "path": coverage._repo_path(coverage.WEB_BUILD_RECEIPT),
                    "sha256": coverage.sha256_file(coverage.WEB_BUILD_RECEIPT),
                },
                "runtimeProducer": {
                    "path": coverage._repo_path(coverage.WEB_RUNTIME_PRODUCER),
                    "sha256": coverage.sha256_file(coverage.WEB_RUNTIME_PRODUCER),
                },
            })
        capture_path = self.evidence_directory / f"{stem}.capture.json"
        capture_path.write_text(json.dumps(capture, sort_keys=True), encoding="utf-8")
        capture_reference = {
            "path": capture_path.relative_to(coverage.ROOT).as_posix(),
            "sha256": coverage.sha256_file(capture_path),
        }

        def promote(provenance):
            provenance.update({
                "mode": "CAPTURED",
                "captureProtocol": capture["protocol"],
                "captureReceipt": capture_reference,
            })
            if producer == "NATIVE":
                provenance.update({
                    "executableSha256": capture["executableSha256"],
                    "nativeCommandContract": capture["nativeCommandContract"],
                    "observerHook": capture["observerHook"],
                    "observerLauncher": capture["observerLauncherSource"],
                })
            else:
                provenance.update({
                    "webBuild": capture["webBuild"],
                    "runtimeProducer": capture["runtimeProducer"],
                })

        self.rewrite_provenance(evidence, producer, promote)

    def promote(self, record, **overrides):
        record["status"] = "PROVEN"
        evidence = self.evidence(record)
        evidence.update(overrides)
        record["evidence"] = [evidence]

    def native_oracle_documents(self):
        fixture = json.loads((
            coverage.ROOT / "tools/miel_vliegt/fixtures/udsp_semantic_oracle_cases.json"
        ).read_text(encoding="utf-8"))
        case = fixture["cases"][0]
        executable = case["executableArtifact"]
        entry = case["entry"]
        artifact_key = f"{entry['type']}:{entry['domainId']}/{entry['dispatchId']}"
        script = next(
            row for row in executable["scripts"]
            if f"{row['type']}:{row['domainId']}/{row['dispatchId']}" == artifact_key
        )
        common = {
            "schema": 1,
            "evidenceMode": "TEST_ONLY",
            "edition": case["edition"],
            "claimId": case["claimId"],
            "evidenceClass": "UDSP_SEMANTIC_CASE",
            "semanticCaseId": case["semanticCaseId"],
            "sourceHashes": fixture["sourceHashes"],
            "subjectSha256": case["artifactSha256"],
            "expectationSha256": case["receiptsSha256"],
            "artifactKey": artifact_key,
            "executableScriptSha256": coverage.udsp_semantic_oracle.canonical_sha256(script),
        }
        web = {
            **common,
            "protocol": coverage.udsp_semantic_oracle.WEB_RAW_PROTOCOL,
            "producer": "WEB",
            "receipts": copy.deepcopy(case["receipts"]),
        }
        native_events = []
        for receipt in case["receipts"]:
            event = copy.deepcopy(receipt)
            event.pop("semanticStatus")
            event["scriptKey"] = event.pop("script")
            event["event"] = (
                "COMMAND_FAILURE" if "failure" in event else "COMMAND"
            )
            native_events.append(event)
        native = {
            **common,
            "protocol": coverage.udsp_semantic_oracle.NATIVE_RAW_PROTOCOL,
            "producer": "NATIVE",
            "supportStatus": coverage.udsp_semantic_oracle.NATIVE_SUPPORTED_STATUS,
            "hookCapabilities": {
                field: True
                for field in coverage.udsp_semantic_oracle.NATIVE_CAPABILITY_FIELDS
            },
            "events": native_events,
        }
        return executable, native, web

    def production_native_web_documents(self, record):
        executable = json.loads(coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8"))
        artifact_key = record["expectation"]["artifactKey"]
        script = next(
            row for row in executable["scripts"]
            if f"{row['type']}:{row['domainId']}/{row['dispatchId']}" == artifact_key
        )
        command = script["commands"][0]
        receipt = {
            "schema": 1,
            "sequence": 1,
            "semanticStatus": "UNPROVEN",
            "script": artifact_key,
            "ancestry": [artifact_key],
            "depth": 0,
            "commandIndex": command["executableCommandIndex"],
            "executableCommandIndex": command["executableCommandIndex"],
            "sourceCommandIndex": command["sourceCommandIndex"],
            "opcode": command["sourceOpcode"],
            "scheduler": {
                "node": command["sourceNode"],
                "repeat": command["loop"],
                "complete": False,
                "resetCount": 0,
                "parents": [{"node": None, "repeat": False, "childIndex": 0}],
            },
            "before": "RUNNING",
            "after": "RUNNING",
            "clock": 0,
            "delta": 0,
            "randomSamples": [],
            "outcome": {"completionStatus": "PENDING"},
        }
        common = {
            "schema": 1,
            "evidenceMode": "PRODUCTION",
            "edition": self.ledger["edition"],
            "claimId": record["id"],
            "evidenceClass": record["evidenceClass"],
            "semanticCaseId": None,
            "sourceHashes": self.source_hashes(),
            "subjectSha256": coverage.evidence_subject_sha256(record),
            "expectationSha256": coverage.evidence_expectation_sha256(record),
            "artifactKey": artifact_key,
            "executableScriptSha256": coverage.udsp_semantic_oracle.canonical_sha256(script),
        }
        web = {
            **common,
            "protocol": coverage.udsp_semantic_oracle.WEB_RAW_PROTOCOL,
            "producer": "WEB",
            "receipts": [receipt],
        }
        web["executionRoute"] = "EXECUTABLE_ARTIFACT_RUNTIME"
        web["runtimeSessionSha256"] = coverage.udsp_semantic_oracle.canonical_sha256({
            "protocol": "miel-vliegt-web-scene-runtime-session",
            "route": web["executionRoute"],
            "claimId": web["claimId"],
            "subjectSha256": web["subjectSha256"],
            "expectationSha256": web["expectationSha256"],
            "executableScriptSha256": web["executableScriptSha256"],
        })
        web["eventOccurrenceIds"] = [
            coverage.udsp_semantic_oracle.canonical_sha256({
                "protocol": "miel-vliegt-web-scene-event-occurrence",
                "runtimeSessionSha256": web["runtimeSessionSha256"],
                "sequence": sequence,
                "receiptSha256": coverage.udsp_semantic_oracle.canonical_sha256(item),
            })
            for sequence, item in enumerate(web["receipts"])
        ]
        native_event = copy.deepcopy(receipt)
        native_event.pop("semanticStatus")
        native_event["scriptKey"] = native_event.pop("script")
        native_event["event"] = "COMMAND"
        native = {
            **common,
            "protocol": coverage.udsp_semantic_oracle.NATIVE_RAW_PROTOCOL,
            "producer": "NATIVE",
            "supportStatus": coverage.udsp_semantic_oracle.NATIVE_SUPPORTED_STATUS,
            "hookCapabilities": {
                field: True
                for field in coverage.udsp_semantic_oracle.NATIVE_CAPABILITY_FIELDS
            },
            "events": [native_event],
        }
        identity = {
            field: copy.deepcopy(native[field])
            for field in coverage.udsp_semantic_oracle.IDENTITY_FIELDS
        }
        observations = coverage.udsp_semantic_oracle.normalize_native_trace(
            native, executable, identity,
            executable_source_bytes=coverage.DEFAULT_EXECUTABLE.read_bytes(),
        )["observations"]
        return native, web, observations

    def shared_session_evidence(self, first, second):
        """Build two claim slices over disjoint events in one producer session."""

        source_hashes = self.source_hashes()
        result = {first["id"]: {}, second["id"]: {}}
        records = (first, second)
        for producer in ("NATIVE", "WEB"):
            events = []
            for sequence, record in enumerate(records):
                event = {
                    "schema": 1,
                    "record": "semantic_session_event",
                    "sequence": sequence,
                    "state": {"semanticStatus": "MATCHED", "occurrence": sequence},
                }
                events.append(event)
            session = {
                "schema": 1,
                "protocol": coverage.SEMANTIC_SESSION_PROTOCOL,
                "producer": producer,
                "edition": self.ledger["edition"],
                "sourceHashes": source_hashes,
                "events": events,
            }
            session_path = self.evidence_directory / f"shared.{producer.lower()}.session.json"
            session_path.write_text(json.dumps(session, sort_keys=True), encoding="utf-8")
            session_reference = {
                "path": session_path.relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(session_path),
            }
            for event_index, record in enumerate(records):
                expectation_sha256 = coverage.evidence_expectation_sha256(record)
                subject_sha256 = coverage.evidence_subject_sha256(record)
                event_hash = coverage._canonical_sha(events[event_index])
                observation = {
                    "schema": 1,
                    "record": "semantic_observation",
                    "sequence": 0,
                    "claimId": record["id"],
                    "evidenceClass": record["evidenceClass"],
                    "subjectSha256": subject_sha256,
                    "expectationSha256": expectation_sha256,
                    "state": copy.deepcopy(events[event_index]["state"]),
                }
                slice_identity = {
                    "claimId": record["id"],
                    "subjectSha256": subject_sha256,
                    "expectationSha256": expectation_sha256,
                    "eventIndices": [event_index],
                    "eventHashes": [event_hash],
                }
                provenance = {
                    "schema": 1,
                    "protocol": coverage.PRODUCER_PROVENANCE_PROTOCOL,
                    "producer": producer,
                    "mode": "TEST_FIXTURE",
                    "result": "PASS",
                    "claimId": record["id"],
                    "evidenceClass": record["evidenceClass"],
                    "edition": self.ledger["edition"],
                    "sourceHashes": source_hashes,
                    "subjectSha256": subject_sha256,
                    "expectationSha256": expectation_sha256,
                    "observationsSha256": coverage.semantic_observations_sha256([observation]),
                    "captureProtocol": "UNIT_TEST_ONLY",
                }
                stem = hashlib.sha256(f"slice:{producer}:{record['id']}".encode()).hexdigest()
                provenance_path = self.evidence_directory / f"{stem}.provenance.json"
                provenance_path.write_text(json.dumps(provenance, sort_keys=True), encoding="utf-8")
                trace = {
                    "schema": 1,
                    "protocol": coverage.SEMANTIC_TRACE_PROTOCOL,
                    "producer": producer,
                    "claimId": record["id"],
                    "evidenceClass": record["evidenceClass"],
                    "edition": self.ledger["edition"],
                    "sourceHashes": source_hashes,
                    "subjectSha256": subject_sha256,
                    "expectationSha256": expectation_sha256,
                    "producerProvenance": {
                        "path": provenance_path.relative_to(coverage.ROOT).as_posix(),
                        "sha256": coverage.sha256_file(provenance_path),
                    },
                    "sessionSlice": {
                        "session": session_reference,
                        **slice_identity,
                        "sliceSha256": coverage._canonical_sha(slice_identity),
                    },
                }
                trace_path = self.evidence_directory / f"{stem}.trace.json"
                trace_path.write_text(json.dumps(trace, sort_keys=True), encoding="utf-8")
                result[record["id"]][producer] = (trace_path, observation)

        for record in records:
            native_path, observation = result[record["id"]]["NATIVE"]
            web_path, _ = result[record["id"]]["WEB"]
            evidence_id = f"evidence:{record['id']}"
            receipt = {
                "schema": 1,
                "protocol": coverage.SEMANTIC_DIFFERENTIAL_PROTOCOL,
                "result": "PASS",
                "evidenceId": evidence_id,
                "evidenceClass": record["evidenceClass"],
                "claimId": record["id"],
                "edition": self.ledger["edition"],
                "sourceHashes": source_hashes,
                "subjectSha256": coverage.evidence_subject_sha256(record),
                "expectationSha256": coverage.evidence_expectation_sha256(record),
                "nativeTrace": {
                    "path": native_path.relative_to(coverage.ROOT).as_posix(),
                    "sha256": coverage.sha256_file(native_path),
                },
                "webTrace": {
                    "path": web_path.relative_to(coverage.ROOT).as_posix(),
                    "sha256": coverage.sha256_file(web_path),
                },
                "observationsSha256": coverage.semantic_observations_sha256([observation]),
            }
            receipt_path = self.evidence_directory / f"{hashlib.sha256(evidence_id.encode()).hexdigest()}.receipt.json"
            receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
            record["status"] = "PROVEN"
            record["evidence"] = [{
                "evidenceId": evidence_id,
                "path": receipt_path.relative_to(coverage.ROOT).as_posix(),
                "sha256": coverage.sha256_file(receipt_path),
                "evidenceClass": record["evidenceClass"],
                "claimId": record["id"],
                "edition": self.ledger["edition"],
                "sourceHashes": source_hashes,
                "subjectSha256": coverage.evidence_subject_sha256(record),
                "expectationSha256": coverage.evidence_expectation_sha256(record),
            }]

    def test_production_udsp_body_requires_complete_expectation_specific_command_coverage(self):
        executable = json.loads(
            coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8")
        )
        for evidence_class in ("UDSP_SCRIPT_BODY", "UDSP_EXECUTABLE_BODY"):
            record = next(
                row for row in self.ledger["records"]
                if row["evidenceClass"] == evidence_class
            )
            artifact_key = record["expectation"]["artifactKey"]
            script = next(
                row for row in executable["scripts"]
                if f"{row['type']}:{row['domainId']}/{row['dispatchId']}" == artifact_key
            )
            observations = [{
                "state": {"command": {
                    "executableCommandIndex": command["executableCommandIndex"],
                    "sourceCommandIndex": command["sourceCommandIndex"],
                    "commandSha256": coverage.udsp_semantic_oracle.canonical_sha256(command),
                }}
            } for command in script["commands"]]
            coverage._validate_runtime_claim_coverage(
                record, observations, executable,
            )
            with self.assertRaisesRegex(
                coverage.SemanticCoverageError, "do not cover the claim",
            ):
                coverage._validate_runtime_claim_coverage(
                    record, observations[:-1], executable,
                )

        mission = next(
            row for row in self.ledger["records"]
            if row["evidenceClass"] == "MISSION_DISPATCH"
        )
        with self.assertRaisesRegex(
            coverage.SemanticCoverageError, "dispatch observations do not cover",
        ):
            coverage._validate_runtime_claim_coverage(mission, [], executable)

    def test_generated_inventory_is_exact_and_entirely_unproven(self):
        self.assertEqual(self.ledger["counts"], {
            "UDSP_SCRIPT_BODY": 238,
            "UDSP_EXECUTABLE_BODY": 238,
            "MISSION_DISPATCH": 113,
            "LOCATION_POLICY": 42,
        })
        self.assertEqual(len(self.ledger["records"]), 631)
        self.assertTrue(all(row["status"] == "UNPROVEN" for row in self.ledger["records"]))
        self.assertTrue(all(row["evidence"] == [] for row in self.ledger["records"]))
        report = self.validate()
        self.assertFalse(report.complete)
        self.assertEqual(report.proven, {name: 0 for name in coverage.CLASSES})

    def test_body_claims_pin_every_location_and_character_script_body_and_ast(self):
        rows = [row for row in self.ledger["records"] if row["evidenceClass"] == "UDSP_SCRIPT_BODY"]
        self.assertEqual(len(rows), 238)
        self.assertEqual(len({row["expectation"]["artifactKey"] for row in rows}), 238)
        self.assertEqual(
            {row["expectation"]["scriptType"] for row in rows},
            {"LOCATION_SCRIPT", "CHARACTER_SCRIPT"},
        )
        self.assertEqual(
            sum(row["expectation"]["scriptType"] == "CHARACTER_SCRIPT" for row in rows),
            74,
        )
        for row in rows:
            expected = row["expectation"]
            self.assertRegex(expected["scriptSha256"], coverage.SHA256)
            self.assertRegex(expected["commandsSha256"], coverage.SHA256)
            self.assertRegex(expected["structureSha256"], coverage.SHA256)
            self.assertEqual(expected["counts"]["commands"] >= 0, True)

    def test_executable_claims_pin_every_lowered_location_and_character_body(self):
        rows = [
            row for row in self.ledger["records"]
            if row["evidenceClass"] == "UDSP_EXECUTABLE_BODY"
        ]
        self.assertEqual(len(rows), 238)
        self.assertEqual(len({row["expectation"]["artifactKey"] for row in rows}), 238)
        self.assertEqual(
            sum(row["expectation"]["scriptType"] == "CHARACTER_SCRIPT" for row in rows),
            74,
        )
        totals = {"rawCommandNodes": 0, "executableCommandNodes": 0, "removedCommandNodes": 0}
        for row in rows:
            expected = row["expectation"]
            self.assertRegex(expected["sourceScriptSha256"], coverage.SHA256)
            self.assertRegex(expected["executableScriptSha256"], coverage.SHA256)
            self.assertRegex(expected["commandsSha256"], coverage.SHA256)
            self.assertRegex(expected["structureSha256"], coverage.SHA256)
            self.assertRegex(expected["removedCommandsSha256"], coverage.SHA256)
            self.assertEqual(
                len(expected["commandSha256"]), expected["counts"]["executableCommandNodes"],
            )
            self.assertTrue(all(coverage.SHA256.fullmatch(value) for value in expected["commandSha256"]))
            self.assertEqual(
                len(expected["removedSourceCommandIndices"]),
                expected["counts"]["removedCommandNodes"],
            )
            for name in totals:
                totals[name] += expected["counts"][name]
        self.assertEqual(totals, {
            "rawCommandNodes": 2320,
            "executableCommandNodes": 2302,
            "removedCommandNodes": 18,
        })
        self.assertEqual(
            self.ledger["policy"]["executableLowering"]["counts"],
            json.loads(coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8"))["counts"],
        )
        self.assertEqual(
            self.ledger["policy"]["executableLowering"]["artifactSha256"],
            self.ledger["sources"]["executableUdspSceneScripts"]["sha256"],
        )

    def test_all_mission_dispatch_identities_are_unique_and_opcode_exact(self):
        rows = [row for row in self.ledger["records"] if row["evidenceClass"] == "MISSION_DISPATCH"]
        self.assertEqual(len(rows), 113)
        self.assertEqual(len({row["id"] for row in rows}), 113)
        by_opcode = {}
        for row in rows:
            opcode = row["expectation"]["opcode"]
            by_opcode[opcode] = by_opcode.get(opcode, 0) + 1
        self.assertEqual(by_opcode, {
            "PLAY_BARNSCRIPT": 7,
            "PLAY_OUTRO": 1,
            "PLAY_SCRIPT": 96,
            "PLAY_SCRIPTMODEFLY": 9,
        })

    def test_policy_outcomes_cover_all_five_policy_families(self):
        rows = [row for row in self.ledger["records"] if row["evidenceClass"] == "LOCATION_POLICY"]
        by_policy = {}
        for row in rows:
            policy = row["expectation"]["policy"]
            by_policy[policy] = by_policy.get(policy, 0) + 1
        self.assertEqual(by_policy, {
            "GENERIC": 28,
            "GROTTE_REFUEL": 3,
            "RAYMOND_CHALLENGE": 4,
            "EXHIBITION_SELECTOR": 6,
            "BESPOKE_NO_UDSP": 1,
        })
        mygghanget = next(row for row in rows if row["expectation"]["domainId"] == "mygghanget")
        self.assertEqual(
            mygghanget["expectation"]["selector"],
            "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE",
        )
        self.assertIsNone(mygghanget["expectation"]["artifactKey"])
        selectors = {
            row["expectation"]["outcome"]: row["expectation"]["selector"]
            for row in rows if row["expectation"]["domainId"] == "varldsutstallning"
        }
        self.assertEqual(selectors, coverage.POLICY_SELECTORS["EXHIBITION_SELECTOR"])

    def test_checked_in_ledger_is_exactly_regenerated(self):
        checked_in = json.loads(coverage.DEFAULT_LEDGER.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, self.generated)
        report = coverage.load_and_validate()
        self.assertEqual(report.total, 631)

    def test_missing_duplicate_and_unknown_claims_fail_closed(self):
        missing = copy.deepcopy(self.ledger)
        removed = missing["records"].pop()
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "missing semantic coverage claim"):
            self.validate(missing)

        duplicate = copy.deepcopy(self.ledger)
        duplicate["records"].append(copy.deepcopy(duplicate["records"][0]))
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "duplicate semantic coverage claim"):
            self.validate(duplicate)

        unknown = copy.deepcopy(self.ledger)
        unknown["records"][-1]["id"] = "LOCATION_POLICY:unknown:unknown"
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "unknown semantic coverage claim"):
            self.validate(unknown)
        self.assertTrue(removed["id"])

    def test_expectation_and_evidence_class_cannot_cross_claim_boundaries(self):
        broken = copy.deepcopy(self.ledger)
        broken["records"][0]["expectation"]["commandsSha256"] = "0" * 64
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "expectation drifted"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        raw = next(row for row in broken["records"] if row["evidenceClass"] == "UDSP_SCRIPT_BODY")
        executable = next(
            row for row in broken["records"]
            if row["evidenceClass"] == "UDSP_EXECUTABLE_BODY"
        )
        self.promote(executable)
        executable["evidence"][0]["evidenceClass"] = raw["evidenceClass"]
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "class mismatch"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        broken["records"][0]["evidenceClass"] = "MISSION_DISPATCH"
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "expectation drifted"):
            self.validate(broken)

    def test_unproven_must_be_empty_and_proven_must_have_evidence(self):
        broken = copy.deepcopy(self.ledger)
        broken["records"][0]["evidence"] = [self.evidence(broken["records"][0])]
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "unproven claim carries evidence"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        broken["records"][0]["status"] = "PROVEN"
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "proven claim has no evidence"):
            self.validate(broken)

    def test_evidence_edition_class_claim_and_source_hashes_are_bound(self):
        cases = (
            ({"edition": "other-edition"}, "edition mismatch"),
            ({"evidenceClass": "MISSION_DISPATCH"}, "class mismatch"),
            ({"claimId": "UDSP_SCRIPT_BODY:other"}, "claim mismatch"),
            ({"sourceHashes": {
                "sceneDispatchContract": "0" * 64,
                "udsSceneScripts": self.ledger["sources"]["udsSceneScripts"]["sha256"],
                "executableUdspSceneScripts": self.ledger["sources"]["executableUdspSceneScripts"]["sha256"],
            }}, "source hash mismatch"),
        )
        for overrides, message in cases:
            with self.subTest(message=message):
                broken = copy.deepcopy(self.ledger)
                self.promote(broken["records"][0], **overrides)
                with self.assertRaisesRegex(coverage.SemanticCoverageError, message):
                    self.validate(broken)

    def test_evidence_id_or_payload_reuse_across_claims_fails(self):
        for shared_field in ("evidenceId", "sha256"):
            with self.subTest(shared_field=shared_field):
                broken = copy.deepcopy(self.ledger)
                first, second = broken["records"][0:2]
                self.promote(first)
                self.promote(second)
                second["evidence"][0][shared_field] = first["evidence"][0][shared_field]
                with self.assertRaisesRegex(coverage.SemanticCoverageError, "evidence reused across claims"):
                    self.validate(broken)

    def test_hash_bound_shared_sessions_allow_disjoint_claim_slices(self):
        first, second = self.ledger["records"][0:2]
        self.shared_session_evidence(first, second)
        report = self.validate()
        self.assertEqual(report.proven[first["evidenceClass"]], 2)

    def test_complete_native_facts_normalize_and_match_web_independently(self):
        executable, native, web = self.native_oracle_documents()
        identity = {
            field: copy.deepcopy(native[field])
            for field in coverage.udsp_semantic_oracle.IDENTITY_FIELDS
        }
        native_trace = coverage.udsp_semantic_oracle.normalize_native_trace(
            native, executable, identity
        )
        web_identity = {
            field: copy.deepcopy(web[field])
            for field in coverage.udsp_semantic_oracle.IDENTITY_FIELDS
        }
        web_trace = coverage.udsp_semantic_oracle.normalize_web_trace(
            web, executable, web_identity
        )
        self.assertEqual(native_trace["observations"], web_trace["observations"])
        comparison = coverage.udsp_semantic_oracle.compare_normalized_traces(
            native_trace, web_trace
        )
        self.assertEqual(comparison["result"], "TEST_ONLY_MATCH")
        self.assertFalse(comparison["parityEligible"])

    def test_exact_native_normalization_removes_only_the_redundant_capture_reject(self):
        record = next(
            row for row in self.ledger["records"]
            if row["id"] == "UDSP_EXECUTABLE_BODY:CHARACTER_SCRIPT:buffa/stand"
        )
        self.promote(record)
        native_raw, web_raw, observations = self.production_native_web_documents(record)
        for producer in ("NATIVE", "WEB"):
            self.rewrite_trace(
                record["evidence"][0], producer,
                lambda trace: trace.update(observations=copy.deepcopy(observations)),
            )
        self.rewrite_receipt(
            record["evidence"][0],
            lambda receipt: receipt.update(
                observationsSha256=coverage.semantic_observations_sha256(observations)
            ),
        )
        self.upgrade_provenance_to_complete_capture(
            record["evidence"][0], record, "NATIVE", raw_document=native_raw
        )
        self.upgrade_provenance_to_complete_capture(
            record["evidence"][0], record, "WEB", raw_document=web_raw
        )
        report = self.validate(allow_test_provenance=False)
        self.assertEqual(report.proven[record["evidenceClass"]], 1)

        native_raw["events"][0]["executableCommandIndex"] = 999
        broken = copy.deepcopy(self.ledger)
        broken_record = next(row for row in broken["records"] if row["id"] == record["id"])
        # The positive artifact remains immutable; a separately mutated raw
        # event is rejected by the oracle before it can affect the ledger.
        identity = {
            field: copy.deepcopy(native_raw[field])
            for field in coverage.udsp_semantic_oracle.IDENTITY_FIELDS
        }
        executable = json.loads(coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(
            coverage.udsp_semantic_oracle.SemanticOracleError, "command"
        ):
            coverage.udsp_semantic_oracle.normalize_native_trace(
                native_raw, executable, identity,
                executable_source_bytes=coverage.DEFAULT_EXECUTABLE.read_bytes(),
            )
        self.assertEqual(broken_record["status"], "PROVEN")

    def test_complete_native_fact_identity_and_sequence_mutations_fail(self):
        for mutation, message in (
            (lambda raw: raw["events"][0].update(scriptKey="LOCATION_SCRIPT:fake/main"), "ancestry|script"),
            (lambda raw: raw["events"][0].update(executableCommandIndex=999), "command"),
            (lambda raw: raw["events"][0].update(sequence=2), "sequence"),
        ):
            with self.subTest(message=message):
                executable, native, _ = self.native_oracle_documents()
                mutation(native)
                identity = {
                    field: copy.deepcopy(native[field])
                    for field in coverage.udsp_semantic_oracle.IDENTITY_FIELDS
                }
                with self.assertRaisesRegex(
                    coverage.udsp_semantic_oracle.SemanticOracleError, message
                ):
                    coverage.udsp_semantic_oracle.normalize_native_trace(
                        native, executable, identity
                    )

    def test_shared_session_occurrence_cannot_satisfy_two_claims(self):
        first, second = self.ledger["records"][0:2]
        self.shared_session_evidence(first, second)
        evidence = second["evidence"][0]
        receipt_path = coverage.ROOT / evidence["path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        for field in ("nativeTrace", "webTrace"):
            trace_path = coverage.ROOT / receipt[field]["path"]
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            session_path = coverage.ROOT / trace["sessionSlice"]["session"]["path"]
            session = json.loads(session_path.read_text(encoding="utf-8"))
            event = session["events"][0]
            identity = {
                "claimId": second["id"],
                "subjectSha256": coverage.evidence_subject_sha256(second),
                "expectationSha256": coverage.evidence_expectation_sha256(second),
                "eventIndices": [0],
                "eventHashes": [coverage._canonical_sha(event)],
            }
            trace["sessionSlice"].update(identity)
            trace["sessionSlice"]["sliceSha256"] = coverage._canonical_sha(identity)
            trace_path.write_text(json.dumps(trace, sort_keys=True), encoding="utf-8")
            receipt[field]["sha256"] = coverage.sha256_file(trace_path)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        evidence["sha256"] = coverage.sha256_file(receipt_path)
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "session occurrence reused"):
            self.validate()

    def test_shared_session_slice_hash_and_event_hash_are_binding(self):
        for field in ("sliceSha256", "eventHashes"):
            with self.subTest(field=field):
                broken = copy.deepcopy(self.ledger)
                first, second = broken["records"][0:2]
                self.shared_session_evidence(first, second)
                evidence = first["evidence"][0]
                receipt_path = coverage.ROOT / evidence["path"]
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                trace_path = coverage.ROOT / receipt["nativeTrace"]["path"]
                trace = json.loads(trace_path.read_text(encoding="utf-8"))
                if field == "sliceSha256":
                    trace["sessionSlice"][field] = "0" * 64
                else:
                    trace["sessionSlice"][field][0] = "0" * 64
                trace_path.write_text(json.dumps(trace, sort_keys=True), encoding="utf-8")
                receipt["nativeTrace"]["sha256"] = coverage.sha256_file(trace_path)
                receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
                evidence["sha256"] = coverage.sha256_file(receipt_path)
                with self.assertRaisesRegex(coverage.SemanticCoverageError, "session slice"):
                    self.validate(broken)

    def test_one_exact_typed_native_web_pass_triplet_can_promote(self):
        record = self.ledger["records"][0]
        self.promote(record)
        report = self.validate()
        self.assertEqual(report.proven[record["evidenceClass"]], 1)

    def test_test_fixture_provenance_is_explicitly_non_production(self):
        record = self.ledger["records"][0]
        self.promote(record)
        with self.assertRaisesRegex(
            coverage.SemanticCoverageError, "test-only producer provenance"
        ):
            self.validate(allow_test_provenance=False)

    def test_trace_without_hashed_producer_provenance_cannot_promote(self):
        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        self.rewrite_trace(
            record["evidence"][0], "NATIVE",
            lambda trace: trace.pop("producerProvenance"),
        )
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "producer provenance"):
            self.validate(broken)

    def test_production_provenance_requires_a_hashed_capture_receipt(self):
        for producer in ("NATIVE", "WEB"):
            with self.subTest(producer=producer):
                broken = copy.deepcopy(self.ledger)
                record = broken["records"][0]
                self.promote(record)

                def make_captured(provenance):
                    provenance["mode"] = "CAPTURED"
                    if producer == "NATIVE":
                        lowering = broken["policy"]["executableLowering"]
                        provenance.update({
                            "captureProtocol": coverage.NATIVE_CAPTURE_PROTOCOL,
                            "executableSha256": lowering["sourceIdentities"][
                                "nativeExecutableSha256"
                            ],
                            "nativeCommandContract": lowering["sources"]["nativeCommands"],
                            "observerHook": {
                                "path": coverage._repo_path(coverage.NATIVE_OBSERVER_HOOK),
                                "sha256": coverage.sha256_file(coverage.NATIVE_OBSERVER_HOOK),
                            },
                            "observerLauncher": {
                                "path": coverage._repo_path(coverage.NATIVE_OBSERVER_LAUNCHER),
                                "sha256": coverage.sha256_file(
                                    coverage.NATIVE_OBSERVER_LAUNCHER
                                ),
                            },
                        })
                    else:
                        provenance.update({
                            "captureProtocol": coverage.WEB_CAPTURE_PROTOCOL,
                            "webBuild": {
                                "path": coverage._repo_path(coverage.WEB_BUILD_RECEIPT),
                                "sha256": coverage.sha256_file(coverage.WEB_BUILD_RECEIPT),
                            },
                            "runtimeProducer": {
                                "path": coverage._repo_path(coverage.WEB_RUNTIME_PRODUCER),
                                "sha256": coverage.sha256_file(
                                    coverage.WEB_RUNTIME_PRODUCER
                                ),
                            },
                        })

                self.rewrite_provenance(record["evidence"][0], producer, make_captured)
                with self.assertRaisesRegex(
                    coverage.SemanticCoverageError, "provenance has an invalid schema"
                ):
                    self.validate(broken, allow_test_provenance=True)

    def test_semantic_validator_has_no_edition_specific_native_contract_map(self):
        source = Path(coverage.__file__).read_text(encoding="utf-8")
        self.assertNotIn("NATIVE_EDITION_CONTRACTS", source)
        self.assertNotIn('"miel-vliegt-de-wereld-rond-nl":', source)

    def test_synthetic_production_receipts_remain_fail_closed(self):
        record = next(
            row for row in self.ledger["records"]
            if row["evidenceClass"] == "UDSP_EXECUTABLE_BODY"
        )
        self.promote(record)
        for producer in ("NATIVE", "WEB"):
            self.upgrade_provenance_to_complete_capture(
                record["evidence"][0], record, producer
            )
        with self.assertRaisesRegex(
            coverage.SemanticCoverageError,
            "native raw-to-normalized semantic unsupported: UNSUPPORTED_HOOK_FACTS",
        ):
            self.validate(allow_test_provenance=False)

    def test_producer_provenance_hash_and_claim_binding_are_enforced(self):
        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        receipt_path = coverage.ROOT / record["evidence"][0]["path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        trace_path = coverage.ROOT / receipt["nativeTrace"]["path"]
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        trace["producerProvenance"]["sha256"] = "0" * 64
        trace_path.write_text(json.dumps(trace, sort_keys=True), encoding="utf-8")
        receipt["nativeTrace"]["sha256"] = coverage.sha256_file(trace_path)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        record["evidence"][0]["sha256"] = coverage.sha256_file(receipt_path)
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "artifact hash mismatch"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        receipt_path = coverage.ROOT / record["evidence"][0]["path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        trace_path = coverage.ROOT / receipt["nativeTrace"]["path"]
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        provenance_path = coverage.ROOT / trace["producerProvenance"]["path"]
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["result"] = "FAIL"
        provenance_path.write_text(json.dumps(provenance, sort_keys=True), encoding="utf-8")
        trace["producerProvenance"]["sha256"] = coverage.sha256_file(provenance_path)
        trace_path.write_text(json.dumps(trace, sort_keys=True), encoding="utf-8")
        receipt["nativeTrace"]["sha256"] = coverage.sha256_file(trace_path)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        record["evidence"][0]["sha256"] = coverage.sha256_file(receipt_path)
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "metadata mismatch"):
            self.validate(broken)

    def test_legacy_dummy_and_one_sided_evidence_cannot_promote(self):
        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        record["status"] = "PROVEN"
        path = self.evidence_directory / "dummy.json"
        path.write_text(json.dumps({
            "schema": 1,
            "evidenceId": "dummy",
            "evidenceClass": record["evidenceClass"],
            "claimId": record["id"],
            "edition": broken["edition"],
            "sourceHashes": self.source_hashes(),
            "observations": [{"kind": "test-fixture"}],
        }), encoding="utf-8")
        record["evidence"] = [{
            "evidenceId": "dummy",
            "path": path.relative_to(coverage.ROOT).as_posix(),
            "sha256": coverage.sha256_file(path),
            "evidenceClass": record["evidenceClass"],
            "claimId": record["id"],
            "edition": broken["edition"],
            "sourceHashes": self.source_hashes(),
            "subjectSha256": coverage.evidence_subject_sha256(record),
            "expectationSha256": coverage.evidence_expectation_sha256(record),
        }]
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "differential"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        self.rewrite_receipt(record["evidence"][0], lambda receipt: receipt.pop("webTrace"))
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "differential"):
            self.validate(broken)

    def test_non_pass_and_non_independent_differentials_cannot_promote(self):
        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        self.rewrite_receipt(record["evidence"][0], lambda receipt: receipt.update(result="FAIL"))
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "PASS"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        self.rewrite_receipt(
            record["evidence"][0],
            lambda receipt: receipt.update(webTrace=copy.deepcopy(receipt["nativeTrace"])),
        )
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "independent"):
            self.validate(broken)

    def test_raw_pointer_bearing_or_divergent_observations_cannot_promote(self):
        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        for producer in ("NATIVE", "WEB"):
            self.rewrite_trace(
                record["evidence"][0], producer,
                lambda trace: trace["observations"][0]["state"].update(
                    node="0x12345678"
                ),
            )
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "raw pointer"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        self.rewrite_trace(
            record["evidence"][0], "WEB",
            lambda trace: trace["observations"][0]["state"].update(
                semanticStatus="DIVERGED"
            ),
        )
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "differ"):
            self.validate(broken)

    def test_subject_and_expectation_hashes_are_bound_at_every_layer(self):
        for field, message in (
            ("subjectSha256", "subject hash mismatch"),
            ("expectationSha256", "expectation hash mismatch"),
        ):
            with self.subTest(field=field):
                broken = copy.deepcopy(self.ledger)
                record = broken["records"][0]
                self.promote(record)
                record["evidence"][0][field] = "0" * 64
                with self.assertRaisesRegex(coverage.SemanticCoverageError, message):
                    self.validate(broken)

    def test_native_or_web_trace_reuse_across_claims_fails(self):
        broken = copy.deepcopy(self.ledger)
        first, second = broken["records"][0:2]
        self.promote(first)
        self.promote(second)
        first_receipt = json.loads(
            (coverage.ROOT / first["evidence"][0]["path"]).read_text(encoding="utf-8")
        )
        self.rewrite_receipt(
            second["evidence"][0],
            lambda receipt: receipt.update(nativeTrace=copy.deepcopy(first_receipt["nativeTrace"])),
        )
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "trace reused across claims"):
            self.validate(broken)

    def test_evidence_artifact_hash_and_embedded_identity_are_verified(self):
        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        evidence_path = coverage.ROOT / record["evidence"][0]["path"]
        evidence_path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "artifact hash mismatch"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        record = broken["records"][0]
        self.promote(record)
        evidence_path = coverage.ROOT / record["evidence"][0]["path"]
        document = json.loads(evidence_path.read_text(encoding="utf-8"))
        document["claimId"] = "UDSP_SCRIPT_BODY:other"
        evidence_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        record["evidence"][0]["sha256"] = coverage.sha256_file(evidence_path)
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "artifact metadata mismatch"):
            self.validate(broken)

    def test_top_level_edition_and_pinned_hash_drift_fail(self):
        broken = copy.deepcopy(self.ledger)
        broken["edition"] = "other-edition"
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "edition drifted"):
            self.validate(broken)

        broken = copy.deepcopy(self.ledger)
        broken["sources"]["udsSceneScripts"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "sources drifted"):
            self.validate(broken)

    def test_input_source_hash_link_mismatch_fails_generation(self):
        with tempfile.TemporaryDirectory(dir=coverage.ROOT) as temporary:
            directory = Path(temporary)
            dispatch_path = directory / "dispatch.json"
            udsp_path = directory / "udsp.json"
            dispatch = json.loads(coverage.DEFAULT_DISPATCH.read_text(encoding="utf-8"))
            udsp_path.write_text(coverage.DEFAULT_UDSP.read_text(encoding="utf-8"), encoding="utf-8")
            dispatch["sources"]["udsp"]["sha256"] = "0" * 64
            dispatch_path.write_text(json.dumps(dispatch), encoding="utf-8")
            with self.assertRaisesRegex(coverage.SemanticCoverageError, "source hashes differ"):
                coverage.generate(dispatch_path, udsp_path)

    def test_policy_roots_routes_and_expected_absences_are_independently_enforced(self):
        dispatch = json.loads(coverage.DEFAULT_DISPATCH.read_text(encoding="utf-8"))
        udsp = json.loads(coverage.DEFAULT_UDSP.read_text(encoding="utf-8"))
        executable = json.loads(coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8"))
        sources = self.ledger["sources"]

        broken = copy.deepcopy(dispatch)
        broken["routes"]["GROUND"]["enqueue"] = "APPEND"
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "routes drifted"):
            coverage.build_ledger(
                broken, udsp, executable,
                dispatch_source=sources["sceneDispatchContract"],
                udsp_source=sources["udsSceneScripts"],
                executable_source=sources["executableUdspSceneScripts"],
            )

        broken = copy.deepcopy(dispatch)
        broken["expectedAbsences"].pop()
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "expected absences drifted"):
            coverage.build_ledger(
                broken, udsp, executable,
                dispatch_source=sources["sceneDispatchContract"],
                udsp_source=sources["udsSceneScripts"],
                executable_source=sources["executableUdspSceneScripts"],
            )

        broken = copy.deepcopy(dispatch)
        raymond = next(row for row in broken["locations"] if row["domainId"] == "raymond_rajser")
        raymond["specialRoots"].pop()
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "policy/root inventory drifted"):
            coverage.build_ledger(
                broken, udsp, executable,
                dispatch_source=sources["sceneDispatchContract"],
                udsp_source=sources["udsSceneScripts"],
                executable_source=sources["executableUdspSceneScripts"],
            )

        broken = copy.deepcopy(dispatch)
        broken["missionActions"][0]["route"] = "FLIGHT"
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "opcode/route drifted"):
            coverage.build_ledger(
                broken, udsp, executable,
                dispatch_source=sources["sceneDispatchContract"],
                udsp_source=sources["udsSceneScripts"],
                executable_source=sources["executableUdspSceneScripts"],
            )

    def test_executable_inventory_indices_takes_and_identities_fail_closed(self):
        dispatch = json.loads(coverage.DEFAULT_DISPATCH.read_text(encoding="utf-8"))
        udsp = json.loads(coverage.DEFAULT_UDSP.read_text(encoding="utf-8"))
        executable = json.loads(coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8"))
        sources = self.ledger["sources"]

        def build(value):
            return coverage.build_ledger(
                dispatch, udsp, value,
                dispatch_source=sources["sceneDispatchContract"],
                udsp_source=sources["udsSceneScripts"],
                executable_source=sources["executableUdspSceneScripts"],
            )

        broken = copy.deepcopy(executable)
        target = next(
            index for index, row in enumerate(broken["scripts"])
            if row["type"] == "LOCATION_SCRIPT"
        )
        broken["scripts"].pop(target)
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "script inventory drifted"):
            build(broken)

        broken = copy.deepcopy(executable)
        broken["removedCommands"][0]["sourceCommandIndex"] += 1
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "removed command source drifted"):
            build(broken)

        broken = copy.deepcopy(executable)
        multi_take = next(
            command for script in broken["scripts"] for command in script["commands"]
            if command.get("nativeOpcode") == 6
        )
        multi_take["takes"].reverse()
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "multi-take lowering drifted"):
            build(broken)

        broken = copy.deepcopy(executable)
        barn = next(
            command for script in broken["scripts"] for command in script["commands"]
            if command.get("nativeOpcode") == 14 and len(command.get("takes", [])) > 1
        )
        barn["takes"].reverse()
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "barn take lowering drifted"):
            build(broken)

        broken = copy.deepcopy(executable)
        broken["scripts"][0]["structure"]["children"][0]["children"][0]["command"] = 99
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "structure lowering drifted"):
            build(broken)

        broken = copy.deepcopy(executable)
        broken["sourceIdentities"]["nativeVoiceExecutableSha256"] = "0" * 64
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "identity mismatch"):
            build(broken)

    def test_executable_artifact_and_nested_source_hashes_are_pinned(self):
        broken = copy.deepcopy(self.ledger)
        broken["sources"]["executableUdspSceneScripts"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "sources drifted"):
            self.validate(broken)

        executable = json.loads(coverage.DEFAULT_EXECUTABLE.read_text(encoding="utf-8"))
        executable["sources"]["assets"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(coverage.SemanticCoverageError, "source hash drifted"):
            coverage.build_ledger(
                json.loads(coverage.DEFAULT_DISPATCH.read_text(encoding="utf-8")),
                json.loads(coverage.DEFAULT_UDSP.read_text(encoding="utf-8")),
                executable,
                dispatch_source=self.ledger["sources"]["sceneDispatchContract"],
                udsp_source=self.ledger["sources"]["udsSceneScripts"],
                executable_source=self.ledger["sources"]["executableUdspSceneScripts"],
            )

    def test_cli_validates_and_reports_fail_closed_status(self):
        result = subprocess.run(
            ["python3", str(Path(coverage.__file__)), "--json"],
            cwd=coverage.ROOT, check=True, capture_output=True, text=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["unproven"], self.ledger["counts"])
        self.assertFalse(report["complete"])


if __name__ == "__main__":
    unittest.main()
