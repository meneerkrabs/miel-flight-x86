#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import web_dispatch_candidate_artifacts as artifacts


class WebDispatchCandidateArtifactTests(unittest.TestCase):
    def test_candidate_version_is_derived_from_exact_version_bytes(self):
        self.assertEqual(
            artifacts._candidate_version(
                b"Miel Monteur Boten Edition (nl, candidate-123)\nBuilt: fixed\n"
            ),
            "candidate-123",
        )
        self.assertEqual(
            artifacts._candidate_version(
                b"Miel Monteur Vliegt Edition (fi, flight-candidate-9)\n"
            ),
            "flight-candidate-9",
        )
        self.assertEqual(
            artifacts._candidate_version(
                b"Miel Monteur Vliegt Edition (fi, flight-candidate-9)\r\n"
            ),
            "flight-candidate-9",
        )
        for invalid in (
            b"\xff\n",
            b"\xef\xbb\xbfMiel Monteur Vliegt Edition (fi, flight-candidate-9)\n",
            b"Miel Monteur Vliegt Edition (fi, flight-candidate-9)\rBuilt: fixed",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                artifacts.WebDispatchCandidateArtifactError
            ):
                artifacts._candidate_version(invalid)
        with self.assertRaisesRegex(
            artifacts.WebDispatchCandidateArtifactError, "identity is invalid"
        ):
            artifacts._candidate_version(
                b"Miel Monteur Boten Edition (nl, dev)\n"
            )

    def test_incomplete_capture_never_creates_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "artifacts"
            capture = {
                "schema": 1,
                "protocol": artifacts.CAPTURE_PROTOCOL,
                "semanticStatus": "UNPROVEN",
                "parityEligible": False,
                "productionProvenance": artifacts.PRODUCTION_PROVENANCE,
                "candidate": {},
                "ledgerSha256": "0" * 64,
                "planSha256": "0" * 64,
                "documents": [],
            }
            with self.assertRaisesRegex(
                artifacts.WebDispatchCandidateArtifactError,
                "plan/ledger binding differs",
            ):
                artifacts.stage_candidate_artifacts(
                    json.dumps(capture).encode(), b"{}", b"{}", b"bundle",
                    b"Miel Monteur Boten Edition (nl, candidate-123)\n",
                    b"{}", output,
                )
            self.assertFalse(output.exists())

    def test_content_addressed_write_rejects_existing_digest_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = artifacts._write_content_addressed(
                root, "raw", ".json", b"same bytes"
            )
            self.assertRegex(reference["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual((root / reference["path"]).read_bytes(), b"same bytes")

    def test_candidate_urls_must_share_one_versioned_origin(self):
        valid = {
            "bundleUrl": "https://candidate.test/bundle.js?v=candidate-123",
            "versionUrl": "https://candidate.test/version.txt",
            "webTransitionBuildUrl": (
                "https://candidate.test/assets/web_transition_build.json"
            ),
        }
        artifacts._validate_candidate_urls(valid, "candidate-123")
        invalid_urls = (
            "https://other.test/bundle.js?v=candidate-123",
            "https://candidate.test/nested/bundle.js?v=candidate-123",
            "https://candidate.test/bundle.js?v=candidate-123&extra=1",
            "https://candidate.test/bundle.js?v=candidate-123&v=candidate-123",
            "https://candidate.test/bundle.js?v=candidate-123#fragment",
            "https://user@candidate.test/bundle.js?v=candidate-123",
        )
        for bundle_url in invalid_urls:
            with self.subTest(bundle_url=bundle_url), self.assertRaisesRegex(
                artifacts.WebDispatchCandidateArtifactError, "immutable build"
            ):
                artifacts._validate_candidate_urls(
                    {**valid, "bundleUrl": bundle_url}, "candidate-123"
                )


if __name__ == "__main__":
    unittest.main()
