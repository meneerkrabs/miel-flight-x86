import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_dispatch_capture_job as jobs
from tools.miel_vliegt import scene_semantic_evidence_batches as batches


class NativeDispatchCaptureJobTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compilation = jobs.compile_targets()

    def _rehash_target(self, target):
        target["targetSha256"] = jobs.canonical_sha256({
            key: value for key, value in target.items() if key != "targetSha256"
        })

    def _rehash_compilation(self, compilation):
        compilation["targetsSha256"] = jobs.canonical_sha256([
            target["targetSha256"] for target in compilation["targets"]
        ])
        compilation["compilationSha256"] = jobs.canonical_sha256({
            key: value
            for key, value in compilation.items()
            if key != "compilationSha256"
        })

    def _assert_rejected(self, mutate):
        changed = copy.deepcopy(self.compilation)
        mutate(changed)
        self._rehash_compilation(changed)
        with self.assertRaises(jobs.NativeDispatchCaptureJobError):
            jobs.validate_compilation(changed)

    def test_compiles_exact_dispatch_population_fail_closed(self):
        result = jobs.validate_compilation(self.compilation)
        self.assertEqual(
            result,
            {"targets": 155, "MISSION_DISPATCH": 113, "LOCATION_POLICY": 42},
        )
        self.assertEqual(self.compilation["status"], "NOT_EXECUTED")
        self.assertIs(self.compilation["parityEligible"], False)
        counts = {}
        for target in self.compilation["targets"]:
            counts[target["evidenceClass"]] = counts.get(
                target["evidenceClass"], 0
            ) + 1
            self.assertEqual(target["status"], "NOT_EXECUTED")
            self.assertIs(target["parityEligible"], False)
        self.assertEqual(counts, {"MISSION_DISPATCH": 113, "LOCATION_POLICY": 42})

    def test_output_is_canonical_ascii_json_with_document_and_target_hashes(self):
        encoded = jobs.canonical_ascii_bytes(self.compilation)
        encoded.decode("ascii")
        self.assertEqual(json.loads(encoded), self.compilation)
        self.assertNotIn(b" ", encoded)
        self.assertEqual(
            self.compilation["compilationSha256"],
            jobs.canonical_sha256({
                key: value
                for key, value in self.compilation.items()
                if key != "compilationSha256"
            }),
        )
        for target in self.compilation["targets"]:
            self.assertEqual(
                target["targetSha256"],
                jobs.canonical_sha256({
                    key: value
                    for key, value in target.items()
                    if key != "targetSha256"
                }),
            )

    def test_mission_target_binds_every_typed_trigger_field(self):
        target = next(
            row for row in self.compilation["targets"]
            if row["evidenceClass"] == "MISSION_DISPATCH"
        )
        self.assertEqual(set(target["trigger"]), {
            "sourcePath", "missionKey", "missionId", "missionPhase",
            "nativeActionOrdinal", "opcode", "route", "domainId",
            "scriptId", "artifactKey", "actionHookFamily", "actionEvent",
        })
        self.assertTrue(target["trigger"]["missionKey"].endswith(
            ":" + target["trigger"]["sourcePath"]
        ))

    def test_location_target_binds_selector_hook_event_and_predicates(self):
        targets = [
            row for row in self.compilation["targets"]
            if row["evidenceClass"] == "LOCATION_POLICY"
        ]
        for target in targets:
            self.assertEqual(set(target["trigger"]), {
                "locationId", "domainId", "mode", "policy", "outcome",
                "selector", "setupPredicates", "artifactKey",
                "selectorHookFamily", "selectorEvent",
            })
            self.assertIn(
                target["trigger"]["selector"], jobs.SELECTOR_CAPTURE_TARGETS
            )
            expected = jobs.SELECTOR_CAPTURE_TARGETS[
                target["trigger"]["selector"]
            ]
            self.assertEqual(target["trigger"]["selectorHookFamily"], expected[0])
            self.assertEqual(target["trigger"]["selectorEvent"], expected[1])

    def test_mission_action_openings_cover_all_four_exact_hook_families(self):
        targets = [
            row for row in self.compilation["targets"]
            if row["evidenceClass"] == "MISSION_DISPATCH"
        ]
        observed = set()
        for target in targets:
            trigger = target["trigger"]
            key = (trigger["opcode"], trigger["route"])
            expected = jobs.ACTION_CAPTURE_TARGETS[key]
            self.assertEqual(trigger["actionHookFamily"], expected[0])
            self.assertEqual(trigger["actionEvent"], expected[1])
            observed.add(trigger["actionHookFamily"])
        self.assertEqual(observed, {
            "ACTION_GROUND", "ACTION_BARN", "ACTION_FLIGHT", "ACTION_OUTRO",
        })

    def test_exhibition_targets_open_only_at_event_six_setter(self):
        exhibition = [
            row for row in self.compilation["targets"]
            if row["evidenceClass"] == "LOCATION_POLICY"
            and row["trigger"]["policy"] == "EXHIBITION_SELECTOR"
        ]
        self.assertEqual(len(exhibition), 6)
        for target in exhibition:
            self.assertEqual(
                target["trigger"]["selectorHookFamily"],
                "EXHIBITION_STATE_SETTER",
            )
            self.assertEqual(target["trigger"]["selectorEvent"], {
                "kind": "INTEGER_ARGUMENT",
                "semanticEvent": "LOCATION_ENTER",
                "argument": 6,
            })

    def test_invalid_mission_opcode_route_combination_fails_closed(self):
        plan = json.loads(batches.DEFAULT_OUTPUT.read_text(encoding="utf-8"))
        job = copy.deepcopy(next(
            job for batch in plan["batches"] for job in batch["jobs"]
            if job["evidenceClass"] == "MISSION_DISPATCH"
        ))
        job["scenario"]["trigger"]["route"] = "BARN"
        with self.assertRaisesRegex(
            jobs.NativeDispatchCaptureJobError,
            "opcode/route is unsupported",
        ):
            jobs._mission_trigger(job)

    def test_every_common_binding_mutation_is_rejected_after_rehash(self):
        fields = (
            "planManifestSha256", "capturePlanSha256", "jobId", "jobSha256",
            "claimId", "claimSha256", "subjectSha256", "expectationSha256",
            "scenarioSha256", "nativeSliceId", "nativeSliceSha256",
            "evidenceClass", "status", "parityEligible",
        )
        for field in fields:
            with self.subTest(field=field):
                def mutate(compilation, field=field):
                    target = compilation["targets"][0]
                    target[field] = (
                        True if field == "parityEligible"
                        else "0" * 64 if field.endswith("Sha256")
                        else "DIFFERS"
                    )
                    self._rehash_target(target)
                self._assert_rejected(mutate)

    def test_every_mission_trigger_binding_mutation_is_rejected(self):
        mission_index = next(
            index for index, row in enumerate(self.compilation["targets"])
            if row["evidenceClass"] == "MISSION_DISPATCH"
        )
        fields = tuple(self.compilation["targets"][mission_index]["trigger"])
        for field in fields:
            with self.subTest(field=field):
                def mutate(compilation, field=field):
                    target = compilation["targets"][mission_index]
                    current = target["trigger"][field]
                    if isinstance(current, str):
                        replacement = current + "x"
                    elif isinstance(current, dict):
                        replacement = dict(current, kind="INVENTED")
                    else:
                        replacement = current + 1
                    target["trigger"][field] = replacement
                    self._rehash_target(target)
                self._assert_rejected(mutate)

    def test_every_location_trigger_binding_mutation_is_rejected(self):
        location_index = next(
            index for index, row in enumerate(self.compilation["targets"])
            if row["evidenceClass"] == "LOCATION_POLICY"
        )
        fields = tuple(self.compilation["targets"][location_index]["trigger"])
        for field in fields:
            with self.subTest(field=field):
                def mutate(compilation, field=field):
                    target = compilation["targets"][location_index]
                    current = target["trigger"][field]
                    if current is None:
                        replacement = "LOCATION_SCRIPT:invented/x"
                    elif isinstance(current, list):
                        replacement = current + ["INVENTED"]
                    elif isinstance(current, dict):
                        replacement = dict(current, kind="INVENTED")
                    elif isinstance(current, str):
                        replacement = current + "x"
                    else:
                        replacement = current + 1
                    target["trigger"][field] = replacement
                    self._rehash_target(target)
                self._assert_rejected(mutate)

    def test_wrong_selector_and_hook_family_are_rejected(self):
        location_index = next(
            index for index, row in enumerate(self.compilation["targets"])
            if row["evidenceClass"] == "LOCATION_POLICY"
        )
        for field, value in (
            ("selector", "UNSUPPORTED_SELECTOR"),
            ("selectorHookFamily", "MISSION_ACTION_EXECUTE"),
            ("selectorEvent", {"kind": "FUNCTION_ENTRY", "semanticEvent": "WRONG"}),
        ):
            with self.subTest(field=field):
                def mutate(compilation, field=field, value=value):
                    target = compilation["targets"][location_index]
                    target["trigger"][field] = value
                    self._rehash_target(target)
                self._assert_rejected(mutate)

    def test_duplicate_target_identity_is_rejected(self):
        def mutate(compilation):
            compilation["targets"][1] = copy.deepcopy(compilation["targets"][0])
        self._assert_rejected(mutate)

    def test_extra_fields_are_rejected_even_when_rehashed(self):
        def target_extra(compilation):
            target = compilation["targets"][0]
            target["invented"] = True
            self._rehash_target(target)
        self._assert_rejected(target_extra)

        changed = copy.deepcopy(self.compilation)
        changed["invented"] = True
        changed["compilationSha256"] = jobs.canonical_sha256({
            key: value for key, value in changed.items() if key != "compilationSha256"
        })
        with self.assertRaises(jobs.NativeDispatchCaptureJobError):
            jobs.validate_compilation(changed)

    def test_plan_drift_and_unsupported_class_fail_closed(self):
        plan = json.loads(batches.DEFAULT_OUTPUT.read_text(encoding="utf-8"))
        mission_batch = next(
            row for row in plan["batches"]
            if row["evidenceClass"] == "MISSION_DISPATCH"
        )
        mission_batch["jobs"][0]["scenario"]["trigger"]["route"] = "INVENTED"
        job = mission_batch["jobs"][0]
        job["scenarioSha256"] = batches.canonical_sha256(job["scenario"])
        job["jobSha256"] = batches.canonical_sha256({
            key: value for key, value in job.items() if key != "jobSha256"
        })
        mission_batch["jobsSha256"] = batches.canonical_sha256([
            row["jobSha256"] for row in mission_batch["jobs"]
        ])
        plan["manifestSha256"] = batches.canonical_sha256({
            key: value for key, value in plan.items() if key != "manifestSha256"
        })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            with self.assertRaises(jobs.NativeDispatchCaptureJobError):
                jobs.compile_targets(path)

        unsupported = copy.deepcopy(self.compilation)
        unsupported["targets"][0]["evidenceClass"] = "UDSP_SCRIPT_BODY"
        self._rehash_target(unsupported["targets"][0])
        self._rehash_compilation(unsupported)
        with self.assertRaises(jobs.NativeDispatchCaptureJobError):
            jobs.validate_compilation(unsupported)


if __name__ == "__main__":
    unittest.main()
