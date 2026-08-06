#!/usr/bin/env python3
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tools.miel_vliegt import verify_native_dispatch_run as verifier
from tools.miel_vliegt.test_native_dispatch_capture_manifest import (
    EXECUTABLE_SHA,
    HEAD_SHA,
    PLAN_SHA,
    REPOSITORY,
    WORKFLOW,
    build_bundle,
)


class ApiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        document = self.server.routes.get(self.path)
        if document is None:
            self.send_error(404)
            return
        if isinstance(document, bytes):
            body = document
            content_type = "application/zip"
        else:
            body = json.dumps(document).encode("utf-8")
            content_type = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class NativeDispatchRunVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive, cls.build = build_bundle()

    def setUp(self):
        self.digest = "sha256:" + hashlib.sha256(self.archive).hexdigest()
        root = "/repos/cgnl/miel.js"
        self.routes = {
            f"{root}/actions/runs/1234": {
                "id": 1234,
                "run_attempt": 2,
                "head_sha": HEAD_SHA,
                "head_branch": "master",
                "event": "workflow_dispatch",
                "path": WORKFLOW,
                "status": "completed",
                "conclusion": "success",
                "repository": {"id": 991, "full_name": REPOSITORY},
                "head_repository": {"id": 991, "full_name": REPOSITORY},
            },
            f"{root}/actions/runs/1234/attempts/2/jobs?per_page=100": {
                "total_count": 1,
                "jobs": [{
                    "id": 7788,
                    "run_id": 1234,
                    "head_sha": HEAD_SHA,
                    "name": "capture-native-dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "runner_id": 77,
                    "runner_name": "oracle-miel-arm64-1",
                    "runner_group_id": 88,
                    "runner_group_name": "oracle-native-capture",
                    "labels": ["self-hosted", "linux", "ARM64", "oracle-miel"],
                }],
            },
            f"{root}/actions/artifacts/5678": {
                "id": 5678,
                "name": "native-dispatch-1234-2",
                "expired": False,
                "digest": self.digest,
                "workflow_run": {
                    "id": 1234,
                    "head_sha": HEAD_SHA,
                    "head_branch": "master",
                },
            },
            f"{root}/actions/artifacts/5678/zip": self.archive,
        }
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
        self.server.routes = self.routes
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = verifier.GitHubApiClient(
            "test-token",
            base_url=f"http://127.0.0.1:{self.server.server_port}/",
            allow_insecure_for_tests=True,
        )
        self.policy = verifier.VerificationPolicy(
            repository=REPOSITORY,
            repository_id=991,
            workflow_path=WORKFLOW,
            head_sha=HEAD_SHA,
            run_id=1234,
            run_attempt=2,
            capture_job_name="capture-native-dispatch",
            capture_job_id=7788,
            runner_id=77,
            runner_group_id=88,
            runner_group_name="oracle-native-capture",
            runner_labels=("self-hosted", "linux", "ARM64", "oracle-miel"),
            artifact_id=5678,
            artifact_name="native-dispatch-1234-2",
            artifact_digest=self.digest,
            plan_manifest_sha256=PLAN_SHA,
            executable_sha256=EXECUTABLE_SHA,
            producer_build_sha256=self.build["producerBuildSha256"],
            observer_binary_sha256=self.build["observerBinary"]["sha256"],
            build_sha256=self.build["buildSha256"],
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_live_api_chain_yields_metadata_correlated_candidate_only(self):
        receipt, archive = verifier.verify_online(self.policy, self.client)
        self.assertEqual(archive, self.archive)
        self.assertEqual(receipt["status"], "RUN_METADATA_CORRELATED_CANDIDATE")
        self.assertEqual(receipt["metadataSource"], "MOCK_HTTP_TEST_ONLY")
        self.assertEqual(
            receipt["correlationStatus"],
            "NON_AUTHORITATIVE_ARTIFACT_JOB_ATTEMPT_CORRELATION",
        )
        self.assertFalse(receipt["productionClaim"])
        self.assertFalse(receipt["parityEligible"])
        self.assertEqual(receipt["claimCount"], 155)
        self.assertEqual(receipt["observedWorkflowJob"]["runnerId"], 77)
        self.assertIn(
            "/repos/cgnl/miel.js/actions/artifacts/5678/zip",
            self.server.requests,
        )

    def test_runner_identity_is_allowlisted_exactly(self):
        jobs_path = (
            "/repos/cgnl/miel.js/actions/runs/1234/attempts/2/jobs?per_page=100"
        )
        self.routes[jobs_path]["jobs"][0]["runner_id"] = 999
        with self.assertRaisesRegex(
            verifier.NativeDispatchRunVerificationError, "runner_id differs"
        ):
            verifier.verify_online(self.policy, self.client)
        self.assertNotIn(
            "/repos/cgnl/miel.js/actions/artifacts/5678/zip",
            self.server.requests,
        )

    def test_capture_job_substitution_fails(self):
        jobs_path = (
            "/repos/cgnl/miel.js/actions/runs/1234/attempts/2/jobs?per_page=100"
        )
        self.routes[jobs_path]["jobs"][0]["id"] = 7789
        with self.assertRaisesRegex(
            verifier.NativeDispatchRunVerificationError, "capture job id differs"
        ):
            verifier.verify_online(self.policy, self.client)

    def test_downloaded_bytes_must_match_api_and_policy_digest(self):
        self.routes["/repos/cgnl/miel.js/actions/artifacts/5678/zip"] = \
            self.archive + b"changed"
        with self.assertRaisesRegex(
            verifier.NativeDispatchRunVerificationError,
            "downloaded artifact digest differs",
        ):
            verifier.verify_online(self.policy, self.client)

    def test_workflow_ref_and_attempt_are_exact(self):
        self.routes["/repos/cgnl/miel.js/actions/runs/1234"]["head_branch"] = "feature"
        with self.assertRaisesRegex(
            verifier.NativeDispatchRunVerificationError,
            "workflow run head_branch differs",
        ):
            verifier.verify_online(self.policy, self.client)

    def test_run_attempt_substitution_fails(self):
        self.routes["/repos/cgnl/miel.js/actions/runs/1234"]["run_attempt"] = 1
        with self.assertRaisesRegex(
            verifier.NativeDispatchRunVerificationError,
            "workflow run run_attempt differs",
        ):
            verifier.verify_online(self.policy, self.client)

    def test_local_metadata_fixture_is_not_an_input_surface(self):
        destinations = {action.dest for action in verifier._parser()._actions}
        self.assertNotIn("metadata", destinations)
        self.assertNotIn("metadata_fixture", destinations)
        self.assertNotIn("accepted_json", destinations)
        with self.assertRaisesRegex(
            verifier.NativeDispatchRunVerificationError, "token is required"
        ):
            verifier.GitHubApiClient("")

    def test_non_github_http_is_test_only_and_never_production(self):
        receipt, _ = verifier.verify_online(self.policy, self.client)
        self.assertEqual(receipt["metadataSource"], "MOCK_HTTP_TEST_ONLY")
        self.assertTrue(receipt["promotionBlockers"])

    def test_artifact_cannot_inherit_observed_job_or_attempt_trust(self):
        self.routes["/repos/cgnl/miel.js/actions/artifacts/5678"][
            "workflow_run"
        ]["run_attempt"] = 1
        receipt, _ = verifier.verify_online(self.policy, self.client)
        self.assertNotIn("captureJob", receipt)
        self.assertNotIn("artifact", receipt)
        self.assertEqual(
            receipt["status"], "RUN_METADATA_CORRELATED_CANDIDATE"
        )
        self.assertFalse(receipt["parityEligible"])


if __name__ == "__main__":
    unittest.main()
