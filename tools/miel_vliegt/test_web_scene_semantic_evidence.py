import copy
from collections import Counter
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import web_scene_semantic_evidence as evidence


class WebSceneSemanticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            evidence.DEFAULT_OUTPUT.read_text(encoding="utf-8")
        )

    def test_tracked_manifest_is_exact_regenerable_and_fail_closed(self):
        counts = evidence.validate_manifest(self.manifest)
        self.assertEqual(counts, {
            "jobs": 631,
            "captured": 261,
            "blocked": 370,
            "byEvidenceClassAndStatus": {
                "LOCATION_POLICY:CAPTURED_CANDIDATE": 42,
                "MISSION_DISPATCH:CAPTURED_CANDIDATE": 113,
                "UDSP_EXECUTABLE_BODY:BLOCKED": 185,
                "UDSP_EXECUTABLE_BODY:CAPTURED_CANDIDATE": 53,
                "UDSP_SCRIPT_BODY:BLOCKED": 185,
                "UDSP_SCRIPT_BODY:CAPTURED_CANDIDATE": 53,
            },
            "byBlocker": {
                "WEB_HEADLESS_ROUTE_COMPLETION_UNOBSERVED": 286,
                "WEB_HEADLESS_RUNTIME_FAILED": 84,
            },
        })
        self.assertEqual(evidence.check_regeneration(), counts)
        self.assertFalse(self.manifest["parityEligible"])
        self.assertFalse(self.manifest["promotionAllowed"])
        self.assertEqual(self.manifest["nativeComparison"], "NOT_RUN")

    def test_every_job_has_one_unique_web_slot_and_no_artifact_is_reused(self):
        records = self.manifest["records"]
        self.assertEqual(len(records), 631)
        self.assertEqual(len({row["jobSha256"] for row in records}), 631)
        self.assertEqual(len({row["webSliceId"] for row in records}), 631)
        references = [
            row["artifact"]["sha256"]
            for row in records if row["artifact"] is not None
        ]
        self.assertEqual(len(references), 261)
        self.assertEqual(len(set(references)), len(references))
        self.assertNotIn(
            "WEB_SOURCE_AST_RUNTIME_ROUTE_MISSING",
            self.manifest["counts"]["byBlocker"],
        )
        self.assertEqual(Counter(
            row["status"]
            for row in records if row["evidenceClass"] == "UDSP_SCRIPT_BODY"
        ), Counter({"BLOCKED": 185, "CAPTURED_CANDIDATE": 53}))
        self.assertTrue(all(
            row["status"] == "CAPTURED_CANDIDATE"
            for row in records
            if row["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}
        ))

    def test_rng_routes_record_real_runtime_decisions_without_completion(self):
        route_blockers = [
            row["blocker"]
            for row in self.manifest["records"]
            if (row.get("blocker") or {}).get("code")
            == "WEB_HEADLESS_ROUTE_COMPLETION_UNOBSERVED"
        ]
        selections = [
            observation["rngSelection"]
            for blocker in route_blockers
            for observation in blocker.get("routeObservations", [])
            if observation.get("route") == "TYPED_RUNTIME_RNG_MEDIA_SELECTION"
        ]
        pending = [
            (row["claimId"], observation)
            for row in self.manifest["records"]
            if (row.get("blocker") or {}).get("code")
            == "WEB_HEADLESS_ROUTE_COMPLETION_UNOBSERVED"
            for observation in row["blocker"].get("pendingRngSelections", [])
        ]
        observed_claims = {
            row["claimId"]
            for row in self.manifest["records"]
            if any(
                observation.get("route") == "TYPED_RUNTIME_RNG_MEDIA_SELECTION"
                for observation in (row.get("blocker") or {}).get(
                    "routeObservations", []
                )
            )
        }
        pending_claims = {
            claim_id
            for claim_id, _observation in pending
        }
        self.assertEqual(len(selections), 80)
        self.assertEqual(len(observed_claims), 80)
        self.assertEqual(len(pending), 42)
        self.assertEqual(len(pending_claims - observed_claims), 8)
        self.assertTrue(all(
            selection["interface"] == "rng.nextInt"
            and selection["input"] == 0
            and selection["algorithm"] == "NEXT_INT_MOD_TAKE_COUNT"
            and selection["index"] == selection["input"] % selection["modulus"]
            and isinstance(selection["assetKey"], str)
            for selection in selections
        ))
        self.assertEqual(
            {
                observation["opcode"]
                for _claim_id, observation in pending
                if observation["nativeOpcode"] == 14
            },
            {"PLAY_MULLEBARNSOUND"},
        )
        self.assertTrue(all(
            row["status"] != "CAPTURED_CANDIDATE"
            for row in self.manifest["records"]
            if (row.get("blocker") or {}).get("code")
            == "WEB_HEADLESS_ROUTE_COMPLETION_UNOBSERVED"
        ))

    def test_source_route_is_distinct_hash_bound_and_covers_source_indices(self):
        records = {row["claimId"]: row for row in self.manifest["records"]}
        artifact_key = "LOCATION_SCRIPT:atle_artillerist/allphotostaken"
        source_row = records[f"UDSP_SCRIPT_BODY:{artifact_key}"]
        executable_row = records[f"UDSP_EXECUTABLE_BODY:{artifact_key}"]
        source_artifact = json.loads(
            (evidence.ROOT / source_row["artifact"]["path"]).read_text()
        )
        executable_artifact = json.loads(
            (evidence.ROOT / executable_row["artifact"]["path"]).read_text()
        )
        source_raw = json.loads(
            (evidence.ROOT / source_artifact["raw"]["path"]).read_text()
        )
        executable_raw = json.loads(
            (evidence.ROOT / executable_artifact["raw"]["path"]).read_text()
        )
        self.assertEqual(
            source_raw["protocol"],
            "miel-vliegt-web-source-scene-semantic-raw",
        )
        self.assertEqual(
            source_raw["executionRoute"],
            "SOURCE_ARTIFACT_LOWERED_RUNTIME",
        )
        self.assertEqual(source_artifact["observedSourceCommandIndices"], [0])
        self.assertEqual(
            source_artifact["loweredAbsentSourceCommandIndices"], []
        )
        self.assertNotEqual(
            source_raw["runtimeSessionSha256"],
            executable_raw["runtimeSessionSha256"],
        )
        self.assertTrue(
            set(source_raw["eventOccurrenceIds"]).isdisjoint(
                executable_raw["eventOccurrenceIds"]
            )
        )
        removed = records[
            "UDSP_SCRIPT_BODY:LOCATION_SCRIPT:atle_artillerist/talk"
        ]["blocker"]
        self.assertEqual(removed["loweredAbsentSourceCommandIndices"], [4])
        self.assertEqual(
            removed["executionRoute"], "SOURCE_ARTIFACT_LOWERED_RUNTIME"
        )

    def test_manifest_tampering_and_cross_job_reuse_are_rejected(self):
        tampered = copy.deepcopy(self.manifest)
        tampered["records"][0]["jobSha256"] = "0" * 64
        tampered["manifestSha256"] = evidence.canonical_sha256({
            key: value for key, value in tampered.items()
            if key != "manifestSha256"
        })
        with self.assertRaisesRegex(
            evidence.WebSceneSemanticEvidenceError, "job binding"
        ):
            evidence.validate_manifest(tampered)

        reused = copy.deepcopy(self.manifest)
        captured = [
            row for row in reused["records"] if row["artifact"] is not None
        ]
        captured[1]["artifact"] = copy.deepcopy(captured[0]["artifact"])
        reused["manifestSha256"] = evidence.canonical_sha256({
            key: value for key, value in reused.items()
            if key != "manifestSha256"
        })
        with self.assertRaisesRegex(
            evidence.WebSceneSemanticEvidenceError, "binding|reused"
        ):
            evidence.validate_manifest(reused)

        source_reused = copy.deepcopy(self.manifest)
        source = next(
            row for row in source_reused["records"]
            if row["status"] == "CAPTURED_CANDIDATE"
            and row["evidenceClass"] == "UDSP_SCRIPT_BODY"
        )
        executable = next(
            row for row in source_reused["records"]
            if row["status"] == "CAPTURED_CANDIDATE"
            and row["claimId"] == source["claimId"].replace(
                "UDSP_SCRIPT_BODY:", "UDSP_EXECUTABLE_BODY:", 1
            )
        )
        source["artifact"] = copy.deepcopy(executable["artifact"])
        source_reused["manifestSha256"] = evidence.canonical_sha256({
            key: value for key, value in source_reused.items()
            if key != "manifestSha256"
        })
        with self.assertRaisesRegex(
            evidence.WebSceneSemanticEvidenceError, "binding|reused"
        ):
            evidence.validate_manifest(source_reused)

    def test_capture_rejects_slot_reordering_and_fake_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            capture_path = Path(directory) / "capture.json"
            capture = evidence.run_headless_capture(capture_path)
        plan = evidence.batches.generate()
        self.assertEqual(evidence.validate_capture(capture, plan), {
            "jobs": 631, "captured": 261, "blocked": 370,
        })

        reordered = copy.deepcopy(capture)
        reordered["slots"][0], reordered["slots"][1] = (
            reordered["slots"][1], reordered["slots"][0]
        )
        reordered["captureSha256"] = evidence.javascript_sorted_sha256({
            key: value for key, value in reordered.items()
            if key != "captureSha256"
        })
        with self.assertRaisesRegex(
            evidence.WebSceneSemanticEvidenceError, "slot binding"
        ):
            evidence.validate_capture(reordered, plan)

        promoted = copy.deepcopy(capture)
        promoted["parityEligible"] = True
        promoted["captureSha256"] = evidence.javascript_sorted_sha256({
            key: value for key, value in promoted.items()
            if key != "captureSha256"
        })
        with self.assertRaisesRegex(
            evidence.WebSceneSemanticEvidenceError, "identity"
        ):
            evidence.validate_capture(promoted, plan)

        event_reuse = copy.deepcopy(capture)
        source = next(
            row for row in event_reuse["slots"]
            if row["status"] == "CAPTURED_CANDIDATE"
            and row["evidenceClass"] == "UDSP_SCRIPT_BODY"
        )
        executable = next(
            row for row in event_reuse["slots"]
            if row["status"] == "CAPTURED_CANDIDATE"
            and row["claimId"] == source["claimId"].replace(
                "UDSP_SCRIPT_BODY:", "UDSP_EXECUTABLE_BODY:", 1
            )
        )
        source["rawDocument"]["runtimeSessionSha256"] = (
            executable["rawDocument"]["runtimeSessionSha256"]
        )
        source["rawDocument"]["eventOccurrenceIds"] = copy.deepcopy(
            executable["rawDocument"]["eventOccurrenceIds"]
        )
        event_reuse["captureSha256"] = evidence.javascript_sorted_sha256({
            key: value for key, value in event_reuse.items()
            if key != "captureSha256"
        })
        with self.assertRaisesRegex(
            evidence.WebSceneSemanticEvidenceError, "events are reused"
        ):
            evidence.validate_capture(event_reuse, plan)


if __name__ == "__main__":
    unittest.main()
