import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.miel_vliegt import flight_domain_promotion as promotion
from tools.miel_vliegt import flight_scenario_completion_adapter as adapter
from tools.miel_vliegt import flight_trace_differential as differential
from tools.miel_vliegt import native_scenario_artifacts as artifacts


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FlightDomainPromotionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.content = self.root / "content/miel_vliegt"
        self.content.mkdir(parents=True)
        self.artifact_root = self.root / "receipts/flight-domain-candidates"
        self.suite_path = self.root / "calibrated-suite-run.json"
        self.suite_path.write_text('{"suite":"candidate"}\n', encoding="utf-8")
        self.adapter_report = {
            "report_sha256": "c" * 64,
            "status": "BLOCKED",
        }
        self.adapter_path = self.root / "completion-adapter.json"
        self.adapter_path.write_text(
            json.dumps(self.adapter_report), encoding="utf-8",
        )
        self.executable_sha256 = "e" * 64
        self.native = self._native_evidence()
        self.trace_contract = self._write_trace_contract()
        self.review_path = self._write_review()

    @staticmethod
    def _trace(scenario_id: str, capture_kind: str) -> dict:
        return {
            "protocol": differential.PROTOCOL,
            "version": differential.VERSION,
            "capture_kind": capture_kind,
            "source": {"producer": capture_kind},
            "scenario": {"id": scenario_id},
            "frames": [{
                "frame": 0,
                "time_seconds": 0.0,
                "inputs": {},
                "events": [],
                "numeric": {
                    "timing": {
                        "deltaSeconds": 1.0 / 60.0,
                    },
                },
            }],
        }

    def _native_evidence(self) -> dict:
        scenarios = {}
        for index, scenario_id in enumerate(artifacts.SCENARIO_ID_ORDER):
            semantic_sha256 = f"{index + 1:064x}"
            scenarios[scenario_id] = {
                "run_1": {
                    "sha256": f"{100 + index:064x}",
                    "receipt": {"semantic_sha256": semantic_sha256},
                    "native_trace": self._trace(scenario_id, "native"),
                },
                "run_2": {
                    "sha256": f"{200 + index:064x}",
                    "receipt": {"semantic_sha256": semantic_sha256},
                    "native_trace": self._trace(scenario_id, "native"),
                },
            }
        return {
            "path": str(self.suite_path),
            "sha256": sha256(self.suite_path),
            "status": adapter.NATIVE_SUITE_STATUS,
            "production_claim": False,
            "executable_sha256": self.executable_sha256,
            "scenarios": scenarios,
        }

    def _write_trace_contract(self) -> dict:
        scenarios = []
        for scenario_id in artifacts.SCENARIO_ID_ORDER:
            path = self.content / f"web-{scenario_id}.json"
            path.write_text(
                json.dumps(self._trace(scenario_id, "web")),
                encoding="utf-8",
            )
            scenarios.append({
                "id": scenario_id,
                "domains": ["timing"],
                "web_output": path.relative_to(self.root).as_posix(),
            })
        contract = {
            "schema": 1,
            "source_identity": {
                "executable_sha256": self.executable_sha256,
            },
            "scenarios": scenarios,
        }
        (self.content / "flight_runtime_trace_contract.json").write_text(
            json.dumps(contract), encoding="utf-8",
        )
        return contract

    def _review_value(self) -> dict:
        return {
            "schema": promotion.VERSION,
            "protocol": promotion.REVIEW_PROTOCOL,
            "decision": "APPROVED",
            "production_observer": True,
            "native_suite_sha256": sha256(self.suite_path),
            "completion_adapter_sha256": sha256(self.adapter_path),
            "completion_adapter_report_sha256":
                self.adapter_report["report_sha256"],
            "executable_sha256": self.executable_sha256,
            "reviewer": {
                "id": "reviewer@example.invalid",
                "role": "independent-evidence-reviewer",
            },
            "reviewed_at": "2026-07-20T10:00:00+02:00",
            "statement": promotion.REVIEW_STATEMENT,
            "scenarios": promotion._review_scenario_projection(self.native),
        }

    def _write_review(self, value=None) -> Path:
        path = self.content / "reviewed-production-observer.json"
        path.write_text(
            json.dumps(value or self._review_value()), encoding="utf-8",
        )
        return path

    def build(self):
        with patch.object(
            promotion.adapter, "validate_native_suite", return_value=self.native,
        ), patch.object(
            promotion.adapter, "validate_report", side_effect=lambda value: value,
        ), patch.object(
            promotion.adapter, "build_report", return_value=self.adapter_report,
        ):
            return promotion.build_candidates(
                native_suite_path=self.suite_path,
                completion_adapter_path=self.adapter_path,
                reviewed_observer_receipt_path=self.review_path,
                artifact_root=self.artifact_root,
                root=self.root,
            )

    def test_matching_domains_emit_non_promotable_content_addressed_candidates(self):
        report = promotion.validate_candidate_report(
            self.build(), root=self.root,
        )

        self.assertEqual(report["status"], "CANDIDATES_READY")
        self.assertFalse(report["promotion_allowed"])
        self.assertEqual(report["summary"]["match_candidates"], 7)
        self.assertTrue(report["policy"]["review_receipt_is_external_input"])
        self.assertFalse(report["policy"]["bulk_promotion"])
        for scenario in report["scenarios"]:
            domain = scenario["domains"][0]
            self.assertEqual(domain["status"], "MATCH_CANDIDATE")
            candidate_path = self.root / domain["candidate"]["path"]
            self.assertEqual(sha256(candidate_path), domain["candidate"]["sha256"])
            candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
            self.assertFalse(candidate["promotion_allowed"])
            self.assertEqual(candidate["production_observer_review"],
                             report["sources"]["production_observer_review"])
            self.assertNotEqual(
                candidate["native_trace"], candidate["web_trace"],
            )

    def test_missing_or_repository_external_review_fails_closed(self):
        self.review_path.unlink()
        with self.assertRaisesRegex(
            promotion.PromotionError, "review receipt.*missing",
        ):
            self.build()

        outside = Path(tempfile.gettempdir()) / "external-flight-review.json"
        outside.write_text(json.dumps(self._review_value()), encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        self.review_path = outside
        with self.assertRaisesRegex(promotion.PromotionError, "escapes"):
            self.build()

    def test_automation_cannot_self_approve_native_observation(self):
        review = self._review_value()
        review["reviewer"]["role"] = "AUTOMATION"
        self.review_path = self._write_review(review)
        with self.assertRaisesRegex(promotion.PromotionError, "external review"):
            self.build()

    def test_review_must_bind_every_exact_repeat_in_order(self):
        review = self._review_value()
        review["scenarios"][0]["run_2_sha256"] = "f" * 64
        self.review_path = self._write_review(review)
        with self.assertRaisesRegex(
            promotion.PromotionError, "exact ordered approval",
        ):
            self.build()

    def test_stale_completion_adapter_is_rejected_before_candidates_are_written(self):
        with patch.object(
            promotion.adapter, "validate_native_suite", return_value=self.native,
        ), patch.object(
            promotion.adapter, "validate_report", side_effect=lambda value: value,
        ), patch.object(
            promotion.adapter,
            "build_report",
            return_value={"report_sha256": "d" * 64, "status": "BLOCKED"},
        ):
            with self.assertRaisesRegex(
                promotion.PromotionError, "fresh projection",
            ):
                promotion.build_candidates(
                    native_suite_path=self.suite_path,
                    completion_adapter_path=self.adapter_path,
                    reviewed_observer_receipt_path=self.review_path,
                    artifact_root=self.artifact_root,
                    root=self.root,
                )
        self.assertFalse(self.artifact_root.exists())

    def test_native_and_web_capture_kinds_cannot_be_swapped(self):
        scenario_id = artifacts.SCENARIO_ID_ORDER[0]
        self.native["scenarios"][scenario_id]["run_1"]["native_trace"] = \
            self._trace(scenario_id, "web")
        with self.assertRaisesRegex(
            promotion.PromotionError, "native trace provenance",
        ):
            self.build()

        self.native = self._native_evidence()
        web_path = self.root / self.trace_contract["scenarios"][0]["web_output"]
        web_path.write_text(
            json.dumps(self._trace(scenario_id, "native")),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            promotion.PromotionError, "canonical web trace provenance",
        ):
            self.build()

    def test_divergence_and_missing_web_trace_remain_reviewable_blockers(self):
        scenario_id = artifacts.SCENARIO_ID_ORDER[0]
        web_path = self.root / self.trace_contract["scenarios"][0]["web_output"]
        web = json.loads(web_path.read_text(encoding="utf-8"))
        web["frames"][0]["time_seconds"] = 1.0
        web_path.write_text(json.dumps(web), encoding="utf-8")
        self.trace_contract["scenarios"][1]["web_output"] = None
        (self.content / "flight_runtime_trace_contract.json").write_text(
            json.dumps(self.trace_contract), encoding="utf-8",
        )

        report = promotion.validate_candidate_report(
            self.build(), root=self.root,
        )

        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["summary"]["blocked_or_diverged"], 2)
        diverged = report["scenarios"][0]["domains"][0]
        self.assertEqual(diverged["status"], "DIVERGED")
        self.assertIsNotNone(diverged["candidate"])
        missing = report["scenarios"][1]["domains"][0]
        self.assertEqual(missing["status"], "BLOCKED")
        self.assertIsNone(missing["candidate"])
        self.assertIn("no web trace", missing["first_divergence"]["reason"])

    def test_artifact_root_must_remain_inside_repository(self):
        with tempfile.TemporaryDirectory() as outside:
            self.artifact_root = Path(outside)
            with self.assertRaisesRegex(promotion.PromotionError, "escapes"):
                self.build()

    def test_rehashed_false_match_is_rejected_by_replayed_differential(self):
        report = self.build()
        row = report["scenarios"][0]["domains"][0]
        candidate_path = self.root / row["candidate"]["path"]
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        candidate["status"] = "DIVERGED"
        candidate["first_divergence"] = {
            "frame": 0,
            "path": "invented",
            "reason": "invented",
            "native": 1,
            "web": 2,
        }
        forged_path = candidate_path.with_name("forged.json")
        forged_path.write_text(json.dumps(candidate), encoding="utf-8")
        row["status"] = "DIVERGED"
        row["first_divergence"] = candidate["first_divergence"]
        row["candidate"] = {
            "path": forged_path.relative_to(self.root).as_posix(),
            "sha256": sha256(forged_path),
        }
        report["summary"]["match_candidates"] -= 1
        report["summary"]["blocked_or_diverged"] += 1
        report["status"] = "BLOCKED"
        payload = {
            key: value for key, value in report.items()
            if key != "report_sha256"
        }
        report["report_sha256"] = promotion._canonical_sha256(payload)

        with self.assertRaisesRegex(
            promotion.PromotionError, "candidate differential drifted",
        ):
            promotion.validate_candidate_report(report, root=self.root)


if __name__ == "__main__":
    unittest.main()
