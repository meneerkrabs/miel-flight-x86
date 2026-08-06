import copy
import json
import unittest
from collections import Counter
from pathlib import Path

from tools.miel_vliegt import scene_semantic_evidence_batches as batches


class SceneSemanticEvidenceBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = batches.generate()
        cls.checked = json.loads(batches.DEFAULT_OUTPUT.read_text(encoding="utf-8"))

    def rehash(self, plan):
        for batch in plan["batches"]:
            for job in batch["jobs"]:
                job["scenarioSha256"] = batches.canonical_sha256(job["scenario"])
                job.pop("jobSha256", None)
                job["jobSha256"] = batches.canonical_sha256(job)
            batch["jobsSha256"] = batches.canonical_sha256([
                job["jobSha256"] for job in batch["jobs"]
            ])
        plan.pop("manifestSha256", None)
        plan["manifestSha256"] = batches.canonical_sha256(plan)

    def test_checked_plan_is_deterministic_and_schema_exact(self):
        self.assertEqual(self.checked, self.generated)
        self.assertEqual(batches.generate(), self.generated)
        self.assertEqual(batches.validate_plan(self.checked), {
            "claims": 631,
            "batches": 41,
            "byEvidenceClass": {
                "UDSP_SCRIPT_BODY": 238,
                "UDSP_EXECUTABLE_BODY": 238,
                "MISSION_DISPATCH": 113,
                "LOCATION_POLICY": 42,
            },
        })
        self.assertEqual(
            self.checked["sources"]["generator"]["sha256"],
            batches.coverage.sha256_file(Path(batches.__file__)),
        )
        self.assertEqual(
            self.checked["sources"]["nativeDispatchHookContract"]["sha256"],
            batches.coverage.sha256_file(
                batches.native_dispatch_hook_contract.DEFAULT_OUTPUT
            ),
        )
        self.assertEqual(
            self.checked["sources"]["webSceneDispatchCaptureExecutor"]["sha256"],
            batches.coverage.sha256_file(
                batches.WEB_DISPATCH_CAPTURE_EXECUTOR
            ),
        )
        self.assertEqual(
            self.checked["sources"]["webSceneDispatchCandidateBridge"]["sha256"],
            batches.coverage.sha256_file(batches.WEB_DISPATCH_CANDIDATE_BRIDGE),
        )
        self.assertEqual(
            self.checked["sources"]["webSceneDispatchRuntime"]["sha256"],
            batches.coverage.sha256_file(batches.WEB_DISPATCH_RUNTIME),
        )
        self.assertEqual(
            self.checked["sources"]["semanticOracle"]["sha256"],
            batches.coverage.sha256_file(batches.SEMANTIC_ORACLE),
        )
        self.assertEqual(
            self.checked["sources"]["webDispatchCandidateArtifactWriter"]["sha256"],
            batches.coverage.sha256_file(
                batches.WEB_DISPATCH_CANDIDATE_WRITER
            ),
        )
        self.assertEqual(
            self.checked["sources"]["webTransitionBuild"]["sha256"],
            batches.coverage.sha256_file(batches.WEB_TRANSITION_BUILD),
        )

    def test_batches_cover_every_target_claim_once_in_stable_chunks(self):
        jobs = [job for batch in self.generated["batches"] for job in batch["jobs"]]
        self.assertEqual(len(jobs), 631)
        self.assertEqual(len({job["claimId"] for job in jobs}), 631)
        by_class = {
            evidence_class: [
                batch for batch in self.generated["batches"]
                if batch["evidenceClass"] == evidence_class
            ]
            for evidence_class in batches.TARGET_CLASSES
        }
        self.assertEqual([len(row["jobs"]) for row in by_class["UDSP_SCRIPT_BODY"]],
                         [16] * 14 + [14])
        self.assertEqual([len(row["jobs"]) for row in by_class["UDSP_EXECUTABLE_BODY"]],
                         [16] * 14 + [14])
        self.assertEqual([len(row["jobs"]) for row in by_class["MISSION_DISPATCH"]],
                         [16] * 7 + [1])
        self.assertEqual([len(row["jobs"]) for row in by_class["LOCATION_POLICY"]],
                         [16, 16, 10])
        for evidence_class, class_batches in by_class.items():
            expected_ids = [
                f"{evidence_class.lower()}:{ordinal:03d}"
                for ordinal in range(len(class_batches))
            ]
            self.assertEqual([row["id"] for row in class_batches], expected_ids)

    def test_jobs_are_capture_requirements_and_cannot_promote_claims(self):
        slice_ids = set()
        statuses = Counter()
        for batch in self.generated["batches"]:
            for job in batch["jobs"]:
                self.assertEqual(
                    job["captureCapability"],
                    batches.CLASS_CAPTURE_CAPABILITIES[job["evidenceClass"]],
                )
                self.assertEqual(job["status"], job["captureCapability"]["status"])
                statuses[job["status"]] += 1
                self.assertNotIn("evidence", job)
                self.assertFalse(job["acceptance"]["planMayPromoteClaim"])
                self.assertEqual(
                    [row["producer"] for row in job["captureSlices"]], ["NATIVE", "WEB"]
                )
                current = {row["sliceId"] for row in job["captureSlices"]}
                self.assertEqual(len(current), 2)
                self.assertTrue(slice_ids.isdisjoint(current))
                slice_ids.update(current)
        self.assertEqual(len(slice_ids), 1262)
        self.assertEqual(statuses, Counter({
            "PENDING_INDEPENDENT_NATIVE_WEB_DIFFERENTIAL": 476,
            "BLOCKED_MISSING_NATIVE_MISSION_DISPATCH_PRODUCER": 113,
            "BLOCKED_MISSING_NATIVE_LOCATION_POLICY_PRODUCER": 42,
        }))

    def test_scenarios_bind_executable_mission_and_policy_claim_shapes(self):
        jobs = [job for batch in self.generated["batches"] for job in batch["jobs"]]
        source = next(job for job in jobs if job["evidenceClass"] == "UDSP_SCRIPT_BODY")
        source_count = source["scenario"]["coverage"]["requiredSourceCommandIndices"]
        self.assertEqual(source_count, list(range(len(source_count))))
        self.assertTrue(source["scenario"]["coverage"]["executableClaimEventReuseForbidden"])
        executable = next(job for job in jobs if job["evidenceClass"] == "UDSP_EXECUTABLE_BODY")
        count = len(executable["scenario"]["coverage"]["requiredCommandSha256"])
        self.assertEqual(
            executable["scenario"]["coverage"]["requiredExecutableCommandIndices"],
            list(range(count)),
        )
        mission = next(job for job in jobs if job["evidenceClass"] == "MISSION_DISPATCH")
        self.assertEqual(mission["scenario"]["driver"], "DISPATCH_MISSION_PHASE_ACTION")
        self.assertIn("nativeActionOrdinal", mission["scenario"]["trigger"])
        policy = next(job for job in jobs if job["evidenceClass"] == "LOCATION_POLICY")
        selector = policy["scenario"]["trigger"]["selector"]
        self.assertEqual(policy["scenario"]["setupPredicates"], batches.POLICY_PREDICATES[selector])
        policy_selectors = {
            job["scenario"]["trigger"]["selector"]
            for job in jobs if job["evidenceClass"] == "LOCATION_POLICY"
        }
        self.assertEqual(policy_selectors, set(batches.POLICY_PREDICATES))

    def test_source_and_executable_claims_never_share_capture_events(self):
        jobs = [job for batch in self.generated["batches"] for job in batch["jobs"]]
        by_claim = {job["claimId"]: job for job in jobs}
        source_jobs = [job for job in jobs if job["evidenceClass"] == "UDSP_SCRIPT_BODY"]
        for source in source_jobs:
            artifact_key = source["scenario"]["artifactKey"]
            executable = by_claim[f"UDSP_EXECUTABLE_BODY:{artifact_key}"]
            self.assertEqual(source["scenario"]["artifactKey"], executable["scenario"]["artifactKey"])
            self.assertNotEqual(source["scenarioSha256"], executable["scenarioSha256"])
            self.assertTrue(
                {row["sliceId"] for row in source["captureSlices"]}.isdisjoint(
                    {row["sliceId"] for row in executable["captureSlices"]}
                )
            )
            source_web = next(
                row for row in source["captureSlices"] if row["producer"] == "WEB"
            )
            executable_web = next(
                row for row in executable["captureSlices"]
                if row["producer"] == "WEB"
            )
            self.assertEqual(
                source_web["rawProtocol"],
                "miel-vliegt-web-source-scene-semantic-raw",
            )
            self.assertEqual(
                executable_web["rawProtocol"],
                "miel-vliegt-web-scene-semantic-raw",
            )

    def test_manifest_job_and_scenario_hashes_reject_mutation(self):
        mutated = copy.deepcopy(self.generated)
        mutated["batches"][0]["jobs"][0]["scenario"]["driver"] = "INVENTED_DRIVER"
        mutated["manifestSha256"] = batches.canonical_sha256({
            key: value for key, value in mutated.items() if key != "manifestSha256"
        })
        with self.assertRaisesRegex(batches.SemanticEvidenceBatchError, "job hash drifted"):
            batches.validate_plan(mutated)

        fully_rehashed = copy.deepcopy(self.generated)
        fully_rehashed["batches"][0]["jobs"][0]["scenario"]["driver"] = "INVENTED_DRIVER"
        self.rehash(fully_rehashed)
        with self.assertRaisesRegex(
            batches.SemanticEvidenceBatchError, "differs from edition-pinned claims"
        ):
            batches.validate_plan(fully_rehashed)

    def test_schema_and_edition_mutations_fail_closed(self):
        malformed = copy.deepcopy(self.generated)
        malformed["batches"][0]["jobs"][0]["inventedEvidence"] = []
        self.rehash(malformed)
        with self.assertRaisesRegex(batches.SemanticEvidenceBatchError, "job schema drifted"):
            batches.validate_plan(malformed)

        wrong_edition = copy.deepcopy(self.generated)
        wrong_edition["edition"] = "another-edition"
        self.rehash(wrong_edition)
        with self.assertRaisesRegex(
            batches.SemanticEvidenceBatchError, "differs from edition-pinned claims"
        ):
            batches.validate_plan(wrong_edition)

    def test_reused_native_web_or_cross_claim_slices_are_rejected(self):
        same_producers = copy.deepcopy(self.generated)
        job = same_producers["batches"][0]["jobs"][0]
        job["captureSlices"][1]["sliceId"] = job["captureSlices"][0]["sliceId"]
        self.rehash(same_producers)
        with self.assertRaisesRegex(batches.SemanticEvidenceBatchError, "capture slice reused"):
            batches.validate_plan(same_producers)

        cross_claim = copy.deepcopy(self.generated)
        first, second = cross_claim["batches"][0]["jobs"][:2]
        second["captureSlices"][0]["sliceId"] = first["captureSlices"][0]["sliceId"]
        self.rehash(cross_claim)
        with self.assertRaisesRegex(batches.SemanticEvidenceBatchError, "capture slice reused"):
            batches.validate_plan(cross_claim)

    def test_plan_cannot_smuggle_evidence_or_proven_status(self):
        evidence = copy.deepcopy(self.generated)
        job = evidence["batches"][0]["jobs"][0]
        job["evidence"] = [{"result": "PASS"}]
        self.rehash(evidence)
        with self.assertRaisesRegex(batches.SemanticEvidenceBatchError, "job schema drifted"):
            batches.validate_plan(evidence)

        promoted = copy.deepcopy(self.generated)
        promoted["batches"][0]["jobs"][0]["status"] = "PROVEN"
        self.rehash(promoted)
        with self.assertRaisesRegex(
            batches.SemanticEvidenceBatchError, "capture capability|fail-closed",
        ):
            batches.validate_plan(promoted)


if __name__ == "__main__":
    unittest.main()
