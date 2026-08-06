#!/usr/bin/env python3
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.select_successful_proof_reuse import (
    ASSET_PROOF_STEPS,
    ASSET_REUSE_AUTHORIZATION_STEP,
    FLIGHT_PROOF_STEPS,
    ORACLE_WORKFLOW_PATH,
    evaluate_proof_run,
    successful_ancestral_run_ids,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return result.stdout.strip()


class SuccessfulProofReuseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        self.primary_branch = git(self.root, "symbolic-ref", "--short", "HEAD")
        git(self.root, "config", "user.name", "Proof Test")
        git(self.root, "config", "user.email", "proof@example.invalid")
        self.commits = []
        for index in range(3):
            (self.root / "state").write_text(str(index), encoding="utf-8")
            git(self.root, "add", "state")
            git(self.root, "commit", "-qm", f"state {index}")
            self.commits.append(git(self.root, "rev-parse", "HEAD"))

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def workflow_run(run_id, sha, *, conclusion="success", status="completed", path=ORACLE_WORKFLOW_PATH):
        return {
            "id": run_id,
            "head_sha": sha,
            "status": status,
            "conclusion": conclusion,
            "path": path,
        }

    @staticmethod
    def jobs(*names, conclusion="success"):
        return {"jobs": [{
            "conclusion": conclusion,
            "steps": [{"name": name, "conclusion": conclusion} for name in names],
        }]}

    def test_failed_run_cannot_launder_a_successful_proof_step(self):
        failed = self.workflow_run(12, self.commits[1], conclusion="failure")
        with self.assertRaisesRegex(ValueError, "did not complete successfully"):
            evaluate_proof_run(
                failed,
                self.jobs(*FLIGHT_PROOF_STEPS),
                root=self.root,
                expected_run_id=12,
            )

    def test_failed_run_is_skipped_when_selecting_automatic_candidates(self):
        document = {"workflow_runs": [
            self.workflow_run(13, self.commits[1], conclusion="failure"),
            self.workflow_run(12, self.commits[0]),
        ]}
        self.assertEqual(
            successful_ancestral_run_ids(document, root=self.root), [12],
        )

    def test_manual_run_id_binds_exact_successful_run_and_proof_groups(self):
        run = self.workflow_run(23, self.commits[1])
        result = evaluate_proof_run(
            run,
            self.jobs(*(FLIGHT_PROOF_STEPS + ASSET_PROOF_STEPS)),
            root=self.root,
            expected_run_id=23,
        )
        self.assertEqual(result.run_id, 23)
        self.assertEqual(result.head_sha, self.commits[1])
        self.assertTrue(result.flight)
        self.assertTrue(result.assets)
        with self.assertRaisesRegex(ValueError, "does not match requested"):
            evaluate_proof_run(
                run, self.jobs(*FLIGHT_PROOF_STEPS),
                root=self.root, expected_run_id=24,
            )

    def test_non_ancestral_success_is_not_an_automatic_candidate(self):
        git(self.root, "checkout", "-qb", "other", self.commits[0])
        (self.root / "other").write_text("other", encoding="utf-8")
        git(self.root, "add", "other")
        git(self.root, "commit", "-qm", "other")
        unrelated = git(self.root, "rev-parse", "HEAD")
        git(self.root, "checkout", "-q", self.primary_branch)
        document = {"workflow_runs": [
            self.workflow_run(30, unrelated),
            self.workflow_run(29, self.commits[0]),
        ]}
        self.assertEqual(
            successful_ancestral_run_ids(document, root=self.root), [29],
        )

    def test_missing_candidate_fails_closed_without_head_parent_fallback(self):
        with self.assertRaisesRegex(ValueError, "no successful ancestral"):
            successful_ancestral_run_ids(
                {"workflow_runs": [self.workflow_run(40, self.commits[1], conclusion="failure")]},
                root=self.root,
            )
        self.assertEqual(
            successful_ancestral_run_ids(
                {"workflow_runs": []}, root=self.root, require_candidate=False,
            ),
            [],
        )

    def test_malformed_successful_candidate_fails_closed(self):
        malformed = self.workflow_run(41, "not-a-sha")
        with self.assertRaisesRegex(ValueError, "canonical head_sha"):
            successful_ancestral_run_ids(
                {"workflow_runs": [malformed]}, root=self.root,
            )

    def test_incomplete_or_failed_step_group_is_not_reusable(self):
        run = self.workflow_run(50, self.commits[1])
        partial = self.jobs(*FLIGHT_PROOF_STEPS, *ASSET_PROOF_STEPS[:-1])
        result = evaluate_proof_run(run, partial, root=self.root)
        self.assertTrue(result.flight)
        self.assertFalse(result.assets)

        jobs = self.jobs(*FLIGHT_PROOF_STEPS)
        jobs["jobs"][0]["conclusion"] = "failure"
        self.assertFalse(evaluate_proof_run(run, jobs, root=self.root).flight)

    def test_receipt_only_run_cannot_launder_asset_proof_authority(self):
        run = self.workflow_run(51, self.commits[1])
        receipt_only_steps = tuple(
            step
            for step in ASSET_PROOF_STEPS
            if step != ASSET_REUSE_AUTHORIZATION_STEP
        ) + ("Regenerate candidate boat presentation receipt family",)

        receipt_only = evaluate_proof_run(
            run,
            self.jobs(*receipt_only_steps),
            root=self.root,
        )
        self.assertFalse(receipt_only.flight)
        self.assertFalse(receipt_only.assets)

        normal = evaluate_proof_run(
            run,
            self.jobs(*ASSET_PROOF_STEPS),
            root=self.root,
        )
        self.assertTrue(normal.assets)

    def test_another_workflow_cannot_supply_proofs(self):
        run = self.workflow_run(60, self.commits[1], path=".github/workflows/other.yml")
        with self.assertRaisesRegex(ValueError, "does not belong"):
            evaluate_proof_run(run, self.jobs(*FLIGHT_PROOF_STEPS), root=self.root)

    def test_deploy_workflow_uses_exact_successful_run_selector(self):
        workflow = (REPO_ROOT / ".github/workflows/deploy-oracle.yml").read_text(
            encoding="utf-8",
        )
        proof_block = workflow.split(
            "      - name: Validate reusable heavy-proof receipt", 1,
        )[1].split("      - name: Maintain runner disk headroom", 1)[0]
        self.assertNotIn("HEAD^", proof_block)
        self.assertNotIn("PUSH_BASELINE", proof_block)
        self.assertIn("status=success", proof_block)
        self.assertIn("actions/workflows/deploy-oracle.yml/runs", proof_block)
        self.assertIn("select_successful_proof_reuse.py", proof_block)
        self.assertIn("--expected-run-id", proof_block)
        self.assertIn("--require-reusable", proof_block)

    def test_asset_reuse_authorization_is_normal_only_and_source_verifying(self):
        workflow = (REPO_ROOT / ".github/workflows/deploy-oracle.yml").read_text(
            encoding="utf-8",
        )
        authorization = workflow.split(
            f"      - name: {ASSET_REUSE_AUTHORIZATION_STEP}", 1,
        )[1].split("      - name:", 1)[0]
        self.assertIn(
            "inputs.regenerate_boat_presentation_receipts != true",
            authorization,
        )
        self.assertIn("--check", authorization)

    def test_proof_reuse_always_revalidates_semantic_capture_plan(self):
        workflow = (REPO_ROOT / ".github/workflows/deploy-oracle.yml").read_text(
            encoding="utf-8",
        )
        revalidation = workflow.split(
            "      - name: Revalidate hydrated or reconstructed flight proofs", 1,
        )[1].split("      - name: Build production image", 1)[0]
        self.assertIn(
            "tools.miel_vliegt.test_scene_semantic_evidence_batches",
            revalidation,
        )
        self.assertIn(
            "python3 tools/miel_vliegt/scene_semantic_evidence_batches.py",
            revalidation,
        )


if __name__ == "__main__":
    unittest.main()
