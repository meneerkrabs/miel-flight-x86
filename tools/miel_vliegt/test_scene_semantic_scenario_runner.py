import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import scene_semantic_scenario_runner as runner


class SceneSemanticScenarioRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.batch_plan = runner.load_checked_batch_plan()
        cls.claim = cls.batch_plan["batches"][0]["jobs"][0]["claimId"]

    def one_run(self):
        return runner.build_run_plan(
            self.batch_plan, claim_ids=[self.claim],
        )

    def test_plan_is_deterministic_complete_and_fail_closed(self):
        first = self.one_run()
        second = self.one_run()
        self.assertEqual(first, second)
        self.assertEqual(runner.validate_run_plan(first, self.batch_plan), {
            "runs": 1, "channels": 5,
        })
        run = first["runs"][0]
        self.assertEqual(
            [row["channel"] for row in run["channels"]],
            list(runner.CHANNELS),
        )
        self.assertTrue(next(
            row for row in run["channels"] if row["channel"] == "semantic"
        )["required"])
        self.assertFalse(first["parityEligible"])
        self.assertFalse(run["promotionAllowed"])

    def test_plan_tampering_is_rejected(self):
        value = self.one_run()
        value["runs"][0]["claimId"] = "invented"
        value["planSha256"] = runner.canonical_sha256({
            key: item for key, item in value.items() if key != "planSha256"
        })
        with self.assertRaisesRegex(runner.ScenarioRunnerError, "checked job"):
            runner.validate_run_plan(value, self.batch_plan)

    def test_framebuffers_import_through_uniform_path_without_promotion(self):
        plan = self.one_run()
        run_id = plan["runs"][0]["id"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = []
            for producer, byte in (("NATIVE", b"\x01\x02\x03\xff"),
                                   ("WEB", b"\x01\x02\x03\xff")):
                raw_name = f"{producer.lower()}.rgba"
                raw = root / raw_name
                raw.write_bytes(byte)
                manifest = {
                    "schema": 1,
                    "protocol": "miel-vliegt-framebuffer",
                    "width": 1,
                    "height": 1,
                    "row_stride": 4,
                    "pixel_format": "rgba8",
                    "origin": "top-left",
                    "alpha_mode": "straight",
                    "data": {
                        "path": raw_name,
                        "sha256": hashlib.sha256(byte).hexdigest(),
                    },
                }
                manifest_name = f"{producer.lower()}.json"
                manifest_path = root / manifest_name
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                artifacts.append({
                    "runId": run_id,
                    "producer": producer,
                    "channel": "framebuffer",
                    "adapter": "framebuffer-manifest",
                    "path": manifest_name,
                    "sha256": runner.sha256_file(manifest_path),
                })
            imported = runner.import_captures(
                plan, {
                    "schema": 1,
                    "protocol": runner.IMPORT_PROTOCOL,
                    "planSha256": plan["planSha256"],
                    "artifacts": artifacts,
                },
                evidence_root=root,
                batch_plan=self.batch_plan,
            )
            self.assertEqual(imported["status"], "INCOMPLETE")
            self.assertEqual(len(imported["missingRequiredSlots"]), 2)
            differential = runner.compare_imported(imported)
            self.assertEqual(
                differential["comparisons"][0]["result"], "CANDIDATE_MATCH",
            )
            self.assertFalse(differential["parityEligible"])

    def test_cross_slot_artifact_reuse_is_rejected(self):
        plan = self.one_run()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "trace.json"
            path.write_text("{}", encoding="utf-8")
            common = {
                "runId": plan["runs"][0]["id"],
                "channel": "framebuffer",
                "adapter": "framebuffer-manifest",
                "path": path.name,
                "sha256": runner.sha256_file(path),
            }
            manifest = {
                "schema": 1,
                "protocol": runner.IMPORT_PROTOCOL,
                "planSha256": plan["planSha256"],
                "artifacts": [
                    {**common, "producer": "NATIVE"},
                    {**common, "producer": "WEB"},
                ],
            }
            with self.assertRaisesRegex(runner.ScenarioRunnerError, "reused"):
                runner.import_captures(
                    plan, manifest, evidence_root=root,
                    batch_plan=self.batch_plan,
                )

    def test_missing_or_mismatched_producers_never_become_match(self):
        plan = self.one_run()
        row = {
            "schema": 1,
            "protocol": runner.NORMALIZED_PROTOCOL,
            "runId": plan["runs"][0]["id"],
            "jobId": plan["runs"][0]["jobId"],
            "claimId": plan["runs"][0]["claimId"],
            "producer": "NATIVE",
            "channel": "body",
            "adapter": "native-body-trace",
            "raw": {"path": "x", "sha256": "0" * 64, "size": 1},
            "payload": {"status": "INCOMPLETE"},
            "payloadSha256": runner.canonical_sha256({"status": "INCOMPLETE"}),
            "parityEligible": False,
        }
        result = runner.compare_imported({"normalized": [row]})
        self.assertEqual(
            result["comparisons"][0]["result"],
            "NOT_COMPARABLE_MISSING_PRODUCER",
        )
        self.assertEqual(result["status"], "INCOMPLETE_OR_DIVERGED")


if __name__ == "__main__":
    unittest.main()
