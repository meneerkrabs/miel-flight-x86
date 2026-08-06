#!/usr/bin/env python3
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.select_successful_parity_baseline import select_baseline


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    return result.stdout.strip()


class SuccessfulParityBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        self.primary_branch = git(self.root, "symbolic-ref", "--short", "HEAD")
        git(self.root, "config", "user.name", "Parity Test")
        git(self.root, "config", "user.email", "parity@example.invalid")
        self.commits = []
        for index in range(3):
            (self.root / "state").write_text(str(index), encoding="utf-8")
            git(self.root, "add", "state")
            git(self.root, "commit", "-qm", f"state {index}")
            self.commits.append(git(self.root, "rev-parse", "HEAD"))

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def workflow_run(sha, *, conclusion="success", status="completed"):
        return {"head_sha": sha, "status": status, "conclusion": conclusion}

    def test_failed_commit_cannot_launder_regression_on_next_commit(self):
        first, failed, _current = self.commits
        document = {"workflow_runs": [
            self.workflow_run(failed, conclusion="failure"),
            self.workflow_run(first),
        ]}
        self.assertEqual(
            select_baseline(document, root=self.root), first,
        )

    def test_manual_rerun_may_use_successful_current_commit(self):
        current = self.commits[-1]
        document = {"workflow_runs": [self.workflow_run(current)]}
        self.assertEqual(
            select_baseline(document, root=self.root), current,
        )

    def test_non_ancestral_success_is_skipped(self):
        main = self.commits[-1]
        git(self.root, "checkout", "-qb", "other", self.commits[0])
        (self.root / "other").write_text("other", encoding="utf-8")
        git(self.root, "add", "other")
        git(self.root, "commit", "-qm", "other")
        unrelated = git(self.root, "rev-parse", "HEAD")
        git(self.root, "checkout", "-q", self.primary_branch)
        document = {"workflow_runs": [
            self.workflow_run(unrelated), self.workflow_run(self.commits[0]),
        ]}
        self.assertEqual(
            select_baseline(document, root=self.root, current=main),
            self.commits[0],
        )

    def test_missing_successful_ancestor_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "no successful ancestral"):
            select_baseline({"workflow_runs": []}, root=self.root)

    def test_malformed_success_hash_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "canonical head_sha"):
            select_baseline(
                {"workflow_runs": [self.workflow_run("not-a-sha")]}, root=self.root,
            )


if __name__ == "__main__":
    unittest.main()
