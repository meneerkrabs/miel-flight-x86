#!/usr/bin/env python3
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import (
    natural_transition_trace,
    scene_coverage,
    scene_parity_promotion as promotion,
    scene_semantic_coverage,
)


EDITION = natural_transition_trace.EDITION


class SceneParityPromotionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=promotion.ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidates = self.root / "candidates"
        self.candidates.mkdir()
        self.artifacts = self.root / "artifacts"

    def reference(self, path: Path) -> dict[str, str]:
        return {
            "path": path.relative_to(promotion.ROOT).as_posix(),
            "sha256": promotion.sha256_file(path),
        }

    def candidate(
        self, kind: str, target: str, native: Path, web: Path, *,
        edition: str = EDITION,
    ) -> Path:
        document = {
            "schema": 1,
            "protocol": promotion.CANDIDATE_PROTOCOL,
            "kind": kind,
            "edition": edition,
            "target": target,
            "nativeTrace": self.reference(native),
            "webTrace": self.reference(web),
        }
        path = self.candidates / f"{kind.lower()}-{len(list(self.candidates.iterdir()))}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def mode_trace(self, producer: str, *, pixel: str = "1" * 64) -> Path:
        scene = "mode_login"
        lifecycle = [
            {
                "sequence": index,
                "tick": index,
                "phase": phase,
                "state": {"scene": scene, "phase": phase, "ready": True},
            }
            for index, phase in enumerate(scene_coverage.BODY_LIFECYCLE_PHASES)
        ]
        document = {
            "schema": 1,
            "protocol": scene_coverage.BODY_TRACE_PROTOCOL,
            "producer": producer,
            "edition": EDITION,
            "scene": scene,
            "capture_id": f"{producer.lower()}-mode-login-unit",
            "subject_sha256": (
                natural_transition_trace.NATIVE_EXECUTABLE_SHA256
                if producer == "NATIVE"
                else natural_transition_trace.WEB_BUILD_SHA256
            ),
            "result": "PASS",
            "lifecycle": lifecycle,
            "render_checkpoints": [{
                "id": "mode-login-render",
                "tick": 3,
                "width": 640,
                "height": 480,
                "canonical_rgba_sha256": pixel,
            }],
            "coverage": {
                "required_lifecycle_phases":
                    list(scene_coverage.BODY_LIFECYCLE_PHASES),
                "observed_lifecycle_phases":
                    list(scene_coverage.BODY_LIFECYCLE_PHASES),
                "render_checkpoint_ids": ["mode-login-render"],
            },
        }
        path = self.root / f"{producer.lower()}-mode.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def semantic_traces(self) -> tuple[str, Path, Path]:
        ledger = scene_semantic_coverage.generate()
        record = ledger["records"][0]
        source_hashes = {
            "sceneDispatchContract":
                ledger["sources"]["sceneDispatchContract"]["sha256"],
            "udsSceneScripts": ledger["sources"]["udsSceneScripts"]["sha256"],
            "executableUdspSceneScripts":
                ledger["sources"]["executableUdspSceneScripts"]["sha256"],
        }
        subject = scene_semantic_coverage.evidence_subject_sha256(record)
        expectation = scene_semantic_coverage.evidence_expectation_sha256(record)
        observation = {
            "schema": 1,
            "record": "semantic_observation",
            "sequence": 0,
            "claimId": record["id"],
            "evidenceClass": record["evidenceClass"],
            "subjectSha256": subject,
            "expectationSha256": expectation,
            "state": {"semanticStatus": "MATCHED"},
        }
        paths = []
        for producer in ("NATIVE", "WEB"):
            provenance = {
                "schema": 1,
                "protocol": scene_semantic_coverage.PRODUCER_PROVENANCE_PROTOCOL,
                "producer": producer,
                "mode": "TEST_FIXTURE",
                "result": "PASS",
                "claimId": record["id"],
                "evidenceClass": record["evidenceClass"],
                "edition": ledger["edition"],
                "sourceHashes": source_hashes,
                "subjectSha256": subject,
                "expectationSha256": expectation,
                "observationsSha256":
                    scene_semantic_coverage.semantic_observations_sha256([observation]),
                "captureProtocol": "UNIT_TEST_ONLY",
            }
            provenance_path = self.root / f"{producer.lower()}-provenance.json"
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            trace = {
                "schema": 1,
                "protocol": scene_semantic_coverage.SEMANTIC_TRACE_PROTOCOL,
                "producer": producer,
                "claimId": record["id"],
                "evidenceClass": record["evidenceClass"],
                "edition": ledger["edition"],
                "sourceHashes": source_hashes,
                "subjectSha256": subject,
                "expectationSha256": expectation,
                "producerProvenance": self.reference(provenance_path),
                "observations": [observation],
            }
            path = self.root / f"{producer.lower()}-semantic.json"
            path.write_text(json.dumps(trace), encoding="utf-8")
            paths.append(path)
        return record["id"], paths[0], paths[1]

    def web_transition_trace(self, edge: str) -> Path:
        identity = natural_transition_trace.canonical_identity(
            edge,
            natural_transition_trace.EDGES[edge]["address"],
        )
        capture_id = f"web-gameplay-{edge}"
        raw_path = self.root / f"{capture_id}.raw.ndjson"
        common = {
            "schema": 1,
            "protocol": "miel-web-scene-transition-runtime",
            "capture_id": capture_id,
            "scenario": edge,
            "build_sha256": natural_transition_trace.WEB_BUILD_SHA256,
            "debug_entry": False,
            "evidence_scope": natural_transition_trace.SCOPE,
        }
        raw_records = [
            {**common, "record": "session.start", "sequence": 0, "tick": 0},
            {
                **common,
                "record": "scene_transition",
                "sequence": 1,
                "tick": 0,
                "edge": edge,
                "source_scene": identity["source_scene"],
                "scene": identity["scene"],
                "transition_site": identity["transition_site"],
                "transition_trigger": identity["transition_trigger"],
                "transition_predicate": identity["transition_predicate"],
                "native_edge": edge,
                "native_transition_site": identity["transition_site"],
                "classification": "EXACT_NATIVE_CONTRACT_EDGE",
                "parity_eligible":
                    natural_transition_trace.EDGES[edge]["parity_eligible"] is True,
            },
            {
                **common,
                "record": "session.complete",
                "sequence": 2,
                "tick": 0,
                "result": "PASS",
            },
        ]
        raw_path.write_text(
            "\n".join(
                json.dumps(record, separators=(",", ":"))
                for record in raw_records
            ) + "\n",
            encoding="utf-8",
        )
        normalized_path = self.root / f"{capture_id}.ndjson"
        normalized_records = [
            {
                "schema": natural_transition_trace.VERSION,
                "protocol": natural_transition_trace.PROTOCOL,
                "record": "capture_start",
                "edition": natural_transition_trace.EDITION,
                "entry_driver": "web-gameplay",
                "capture_id": capture_id,
                "scenario": edge,
                "producer": "web-scene-manager",
                "subject_sha256": natural_transition_trace.WEB_BUILD_SHA256,
                "raw_trace": {
                    "path": raw_path.name,
                    "sha256": promotion.sha256_file(raw_path),
                },
                "debug_entry": False,
                "evidence_scope": natural_transition_trace.SCOPE,
            },
            {
                "schema": natural_transition_trace.VERSION,
                "protocol": natural_transition_trace.PROTOCOL,
                "record": "scene_transition",
                "edition": natural_transition_trace.EDITION,
                "entry_driver": "web-gameplay",
                "capture_id": capture_id,
                "sequence": 1,
                "tick": 0,
                "debug_entry": False,
                "evidence_scope": natural_transition_trace.SCOPE,
                **identity,
            },
            {
                "schema": natural_transition_trace.VERSION,
                "protocol": natural_transition_trace.PROTOCOL,
                "record": "capture_complete",
                "edition": natural_transition_trace.EDITION,
                "entry_driver": "web-gameplay",
                "capture_id": capture_id,
                "final_sequence": 2,
                "result": "PASS",
                "debug_entry": False,
                "evidence_scope": natural_transition_trace.SCOPE,
            },
        ]
        normalized_path.write_text(
            "\n".join(json.dumps(record) for record in normalized_records) + "\n",
            encoding="utf-8",
        )
        return normalized_path

    def install_three_candidates(self, *, web_mode_pixel: str = "1" * 64):
        native_mode = self.mode_trace("NATIVE")
        web_mode = self.mode_trace("WEB", pixel=web_mode_pixel)
        self.candidate("MODE", "mode_login", native_mode, web_mode)
        self.candidate(
            "NATURAL_EDGE",
            "startup.login",
            promotion.ROOT
            / "tools/miel_vliegt/fixtures/native_natural_transition_fixture.ndjson",
            self.web_transition_trace("startup.login"),
        )
        claim_id, native_semantic, web_semantic = self.semantic_traces()
        self.candidate(
            "SEMANTIC_CLAIM", claim_id, native_semantic, web_semantic,
            edition=scene_semantic_coverage.generate()["edition"],
        )
        return claim_id

    def test_one_batch_recomputes_and_validates_all_three_promotion_kinds(self):
        claim_id = self.install_three_candidates()
        report, scene, semantic = promotion.build_batch(
            candidate_dir=self.candidates,
            artifact_root=self.artifacts,
            allow_test_provenance=True,
        )
        self.assertEqual(report["counts"]["items"], 701)
        self.assertEqual(report["counts"]["pass"], 3)
        self.assertEqual(report["counts"]["blocked"], 698)
        passed = {
            (row["kind"], row["target"])
            for row in report["records"] if row["status"] == "PASS"
        }
        self.assertEqual(passed, {
            ("MODE", "mode_login"),
            ("NATURAL_EDGE", "startup.login"),
            ("SEMANTIC_CLAIM", claim_id),
        })
        self.assertEqual(
            promotion._find_mode_claim(
                scene, EDITION, "mode_login",
            )["gates"]["BODY_PARITY"]["status"],
            "PARITY_PROVEN",
        )
        self.assertEqual(
            promotion._find_edge_claim(
                scene, EDITION, "startup.login",
            )["status"],
            "PARITY_PROVEN",
        )
        self.assertEqual(
            promotion._find_semantic_claim(semantic, claim_id)["status"],
            "PROVEN",
        )
        self.assertTrue(list(self.artifacts.rglob("*.json")))
        scene_output = self.root / "promoted-scene.json"
        semantic_output = self.root / "promoted-semantic.json"
        promotion._atomic_write(scene_output, scene)
        promotion._atomic_write(semantic_output, semantic)
        finalized = promotion.finalize_report(
            report, scene_output=scene_output, semantic_output=semantic_output,
            applied=False,
        )
        self.assertEqual(
            promotion.validate_report(
                finalized, allow_test_provenance=True,
            )["pass"],
            3,
        )
        tampered = json.loads(json.dumps(finalized))
        tampered["counts"]["pass"] = 4
        with self.assertRaisesRegex(promotion.PromotionError, "hash differs"):
            promotion.validate_report(
                tampered, allow_test_provenance=True,
            )

    def test_failed_candidate_is_blocked_without_partial_ledger_promotion(self):
        self.install_three_candidates(web_mode_pixel="2" * 64)
        report, scene, _semantic = promotion.build_batch(
            candidate_dir=self.candidates,
            artifact_root=self.artifacts,
            allow_test_provenance=True,
        )
        mode = next(
            row for row in report["records"]
            if row["kind"] == "MODE" and row["target"] == "mode_login"
        )
        self.assertEqual(mode["status"], "BLOCKED")
        self.assertIn("mode differential differs", mode["blocker"])
        self.assertEqual(
            promotion._find_mode_claim(
                scene, EDITION, "mode_login",
            )["gates"]["BODY_PARITY"]["status"],
            "UNPROVEN",
        )
        self.assertEqual(report["counts"]["pass"], 2)

    def test_hash_drift_duplicate_targets_and_unknown_targets_fail_closed(self):
        native = self.mode_trace("NATIVE")
        web = self.mode_trace("WEB")
        path = self.candidate("MODE", "mode_login", native, web)
        document = json.loads(path.read_text())
        document["nativeTrace"]["sha256"] = "0" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(promotion.PromotionError, "hash-drifted"):
            promotion.build_batch(
                candidate_dir=self.candidates,
                artifact_root=self.artifacts,
                allow_test_provenance=True,
            )

        path.unlink()
        self.candidate("MODE", "not_a_mode", native, web)
        with self.assertRaisesRegex(promotion.PromotionError, "unknown inventory"):
            promotion.build_batch(
                candidate_dir=self.candidates,
                artifact_root=self.artifacts,
                allow_test_provenance=True,
            )

    def test_trace_artifact_cannot_be_reused_for_another_target(self):
        native = self.mode_trace("NATIVE")
        web = self.mode_trace("WEB")
        self.candidate("MODE", "mode_login", native, web)
        self.candidate("MODE", "mode_barn", native, web)
        with self.assertRaisesRegex(
            promotion.PromotionError, "reused across candidates"
        ):
            promotion.build_batch(
                candidate_dir=self.candidates,
                artifact_root=self.artifacts,
                allow_test_provenance=True,
            )

    def test_production_batch_rejects_test_only_semantic_provenance(self):
        claim_id, native, web = self.semantic_traces()
        self.candidate(
            "SEMANTIC_CLAIM", claim_id, native, web,
            edition=scene_semantic_coverage.generate()["edition"],
        )
        report, _scene, semantic = promotion.build_batch(
            candidate_dir=self.candidates,
            artifact_root=self.artifacts,
            allow_test_provenance=False,
        )
        row = next(
            row for row in report["records"]
            if row["kind"] == "SEMANTIC_CLAIM" and row["target"] == claim_id
        )
        self.assertEqual(row["status"], "BLOCKED")
        self.assertIn("test-only producer provenance", row["blocker"])
        self.assertEqual(
            promotion._find_semantic_claim(semantic, claim_id)["status"],
            "UNPROVEN",
        )

    def test_checked_contract_schemas_preserve_fail_closed_protocol_fields(self):
        schema_root = promotion.ROOT / "tools/miel_vliegt/schemas"
        candidate = json.loads(
            (schema_root / "scene-parity-candidate.schema.json").read_text()
        )
        report = json.loads(
            (schema_root / "scene-parity-promotion.schema.json").read_text()
        )
        self.assertEqual(
            candidate["properties"]["protocol"]["const"],
            promotion.CANDIDATE_PROTOCOL,
        )
        self.assertEqual(
            report["properties"]["protocol"]["const"], promotion.PROTOCOL,
        )
        policy = report["properties"]["policy"]["properties"]
        self.assertEqual(policy["candidateIsEvidence"], {"const": False})
        self.assertEqual(
            policy["nativeParityPromotionRequiresPass"], {"const": True},
        )


if __name__ == "__main__":
    unittest.main()
