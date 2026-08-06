#!/usr/bin/env python3
"""Correlate one native dispatch candidate with live GitHub API metadata.

GitHub's artifact API does not authoritatively bind an artifact to a particular
job or run attempt.  The output is therefore intentionally only
``RUN_METADATA_CORRELATED_CANDIDATE``.  It is not a verified or production
credential.  There is deliberately no caller-authored metadata input.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from tools.miel_vliegt import native_dispatch_capture_manifest as manifests
except ModuleNotFoundError:  # Direct script execution.
    import native_dispatch_capture_manifest as manifests


GITHUB_API = "https://api.github.com/"
OUTPUT_PROTOCOL = "miel-vliegt-run-metadata-correlated-native-dispatch-candidate"
OUTPUT_STATUS = "RUN_METADATA_CORRELATED_CANDIDATE"
API_VERSION = "2022-11-28"
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
API_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_JSON_RESPONSE = 2 * 1024 * 1024


class _SafeRedirectHandler(HTTPRedirectHandler):
    """Never forward the GitHub token to artifact blob-storage redirects."""

    def redirect_request(self, request, fp, code, msg, headers, new_url):
        redirected = super().redirect_request(request, fp, code, msg, headers, new_url)
        if redirected is not None:
            old = urlparse(request.full_url)
            new = urlparse(new_url)
            if (old.scheme, old.netloc) != (new.scheme, new.netloc):
                redirected.remove_header("Authorization")
        return redirected


class NativeDispatchRunVerificationError(ValueError):
    """Live GitHub state or candidate content differs from policy."""


@dataclass(frozen=True)
class VerificationPolicy:
    repository: str
    repository_id: int
    workflow_path: str
    head_sha: str
    run_id: int
    run_attempt: int
    capture_job_name: str
    capture_job_id: int
    runner_id: int
    runner_group_id: int
    runner_group_name: str
    runner_labels: tuple[str, ...]
    artifact_id: int
    artifact_name: str
    artifact_digest: str
    plan_manifest_sha256: str
    executable_sha256: str
    producer_build_sha256: str
    observer_binary_sha256: str
    build_sha256: str

    def validate(self) -> None:
        if REPOSITORY.fullmatch(self.repository) is None:
            raise NativeDispatchRunVerificationError("repository is invalid")
        if not self.workflow_path.startswith(".github/workflows/") \
                or ".." in self.workflow_path.split("/"):
            raise NativeDispatchRunVerificationError("workflow path is invalid")
        if manifests.GIT_SHA.fullmatch(self.head_sha) is None:
            raise NativeDispatchRunVerificationError("head SHA is invalid")
        for label, value in (
            ("repository ID", self.repository_id),
            ("run ID", self.run_id), ("run attempt", self.run_attempt),
            ("capture job ID", self.capture_job_id),
            ("runner ID", self.runner_id),
            ("runner group ID", self.runner_group_id),
            ("artifact ID", self.artifact_id),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise NativeDispatchRunVerificationError(f"{label} is invalid")
        for label, value in (
            ("capture job name", self.capture_job_name),
            ("runner group name", self.runner_group_name),
            ("artifact name", self.artifact_name),
        ):
            if not isinstance(value, str) or not value or not value.isascii():
                raise NativeDispatchRunVerificationError(f"{label} is invalid")
        if not self.runner_labels or len(set(self.runner_labels)) != len(self.runner_labels) \
                or any(not isinstance(item, str) or not item or not item.isascii()
                       for item in self.runner_labels):
            raise NativeDispatchRunVerificationError("runner labels are invalid")
        if API_DIGEST.fullmatch(self.artifact_digest) is None:
            raise NativeDispatchRunVerificationError("artifact digest is invalid")
        for label, value in (
            ("plan manifest", self.plan_manifest_sha256),
            ("executable", self.executable_sha256),
            ("producer build", self.producer_build_sha256),
            ("observer binary", self.observer_binary_sha256),
            ("build", self.build_sha256),
        ):
            if manifests.SHA256.fullmatch(value) is None:
                raise NativeDispatchRunVerificationError(f"{label} hash is invalid")


class GitHubApiClient:
    """Small authenticated GitHub JSON/binary client; no fixture-file path."""

    def __init__(
        self, token: str, *, base_url: str = GITHUB_API,
        allow_insecure_for_tests: bool = False,
    ) -> None:
        if not isinstance(token, str) or not token:
            raise NativeDispatchRunVerificationError("GitHub API token is required")
        parsed = urlparse(base_url)
        if parsed.scheme != "https" and not allow_insecure_for_tests:
            raise NativeDispatchRunVerificationError("GitHub API must use HTTPS")
        if not parsed.netloc:
            raise NativeDispatchRunVerificationError("GitHub API origin is invalid")
        self.base_url = base_url.rstrip("/") + "/"
        self.official = self.base_url == GITHUB_API
        self._allow_insecure_for_tests = allow_insecure_for_tests
        self._token = token
        self._opener = build_opener(_SafeRedirectHandler())

    def _request(self, path: str, *, accept: str) -> bytes:
        url = urljoin(self.base_url, path.lstrip("/"))
        request = Request(url, headers={
            "Accept": accept,
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "miel-native-dispatch-verifier/1",
        })
        try:
            with self._opener.open(request, timeout=30) as response:
                final = urlparse(response.geturl())
                origin = urlparse(self.base_url)
                if accept == "application/vnd.github+json" \
                        and (final.scheme, final.netloc) != (origin.scheme, origin.netloc):
                    raise NativeDispatchRunVerificationError(
                        "GitHub JSON request escaped the API origin"
                    )
                if accept != "application/vnd.github+json" \
                        and final.scheme != "https" and not self._allow_insecure_for_tests:
                    raise NativeDispatchRunVerificationError(
                        "artifact download did not use HTTPS"
                    )
                limit = (
                    MAX_JSON_RESPONSE if accept == "application/vnd.github+json"
                    else manifests.MAX_ARCHIVE_SIZE
                )
                length = response.headers.get("Content-Length")
                if length is not None:
                    try:
                        if int(length, 10) > limit:
                            raise NativeDispatchRunVerificationError(
                                "GitHub API response is too large"
                            )
                    except ValueError as error:
                        raise NativeDispatchRunVerificationError(
                            "GitHub API response length is invalid"
                        ) from error
                data = response.read(limit + 1)
                if len(data) > limit:
                    raise NativeDispatchRunVerificationError(
                        "GitHub API response is too large"
                    )
                return data
        except NativeDispatchRunVerificationError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            raise NativeDispatchRunVerificationError(
                f"GitHub API request failed: {path}"
            ) from error

    def json(self, path: str) -> dict[str, Any]:
        data = self._request(path, accept="application/vnd.github+json")
        try:
            value = json.loads(data.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NativeDispatchRunVerificationError(
                f"GitHub API returned invalid JSON: {path}"
            ) from error
        if not isinstance(value, dict):
            raise NativeDispatchRunVerificationError(
                f"GitHub API returned a non-object: {path}"
            )
        return value

    def binary(self, path: str) -> bytes:
        return self._request(path, accept="application/octet-stream")


def _repository_path(repository: str) -> str:
    owner, name = repository.split("/", 1)
    return f"repos/{quote(owner, safe='')}/{quote(name, safe='')}"


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise NativeDispatchRunVerificationError(f"{label} differs")


def verify_online(
    policy: VerificationPolicy, client: GitHubApiClient,
) -> tuple[dict[str, Any], bytes]:
    """Retrieve authoritative metadata and bytes, then return a candidate receipt."""

    policy.validate()
    root = _repository_path(policy.repository)
    run = client.json(f"{root}/actions/runs/{policy.run_id}")
    expected_run = {
        "id": policy.run_id,
        "run_attempt": policy.run_attempt,
        "head_sha": policy.head_sha,
        "head_branch": "master",
        "event": "workflow_dispatch",
        "path": policy.workflow_path,
        "status": "completed",
        "conclusion": "success",
    }
    for field, expected in expected_run.items():
        _require_equal(run.get(field), expected, f"workflow run {field}")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if not isinstance(repository, dict) or not isinstance(head_repository, dict) \
            or repository.get("full_name") != policy.repository \
            or head_repository.get("full_name") != policy.repository \
            or repository.get("id") != policy.repository_id \
            or head_repository.get("id") != policy.repository_id:
        raise NativeDispatchRunVerificationError("workflow repository identity differs")

    jobs_path = (
        f"{root}/actions/runs/{policy.run_id}/attempts/"
        f"{policy.run_attempt}/jobs?{urlencode({'per_page': 100})}"
    )
    jobs_document = client.json(jobs_path)
    jobs = jobs_document.get("jobs")
    if not isinstance(jobs, list) or jobs_document.get("total_count") != len(jobs) \
            or len(jobs) > 100:
        raise NativeDispatchRunVerificationError("workflow jobs response is incomplete")
    matches = [job for job in jobs if isinstance(job, dict)
               and job.get("name") == policy.capture_job_name]
    if len(matches) != 1:
        raise NativeDispatchRunVerificationError("capture job is not unique")
    job = matches[0]
    for field, expected in {
        "id": policy.capture_job_id,
        "run_id": policy.run_id,
        "head_sha": policy.head_sha,
        "status": "completed",
        "conclusion": "success",
        "runner_id": policy.runner_id,
        "runner_group_id": policy.runner_group_id,
        "runner_group_name": policy.runner_group_name,
    }.items():
        _require_equal(job.get(field), expected, f"capture job {field}")
    if set(job.get("labels", [])) != set(policy.runner_labels) \
            or len(job.get("labels", [])) != len(policy.runner_labels):
        raise NativeDispatchRunVerificationError("capture job runner labels differ")
    runner_name = job.get("runner_name")
    if not isinstance(runner_name, str) or not runner_name:
        raise NativeDispatchRunVerificationError("capture job runner identity is incomplete")

    artifact = client.json(f"{root}/actions/artifacts/{policy.artifact_id}")
    for field, expected in {
        "id": policy.artifact_id,
        "name": policy.artifact_name,
        "expired": False,
        "digest": policy.artifact_digest,
    }.items():
        _require_equal(artifact.get(field), expected, f"capture artifact {field}")
    artifact_run = artifact.get("workflow_run")
    if not isinstance(artifact_run, dict) \
            or artifact_run.get("id") != policy.run_id \
            or artifact_run.get("head_sha") != policy.head_sha \
            or artifact_run.get("head_branch") != "master":
        raise NativeDispatchRunVerificationError("artifact workflow binding differs")
    archive = client.binary(f"{root}/actions/artifacts/{policy.artifact_id}/zip")
    archive_digest = f"sha256:{manifests.sha256_bytes(archive)}"
    if archive_digest != policy.artifact_digest:
        raise NativeDispatchRunVerificationError("downloaded artifact digest differs")

    candidate = manifests.validate_candidate_archive(archive)
    capture = candidate.manifest
    for field, expected in {
        "repository": policy.repository,
        "workflowPath": policy.workflow_path,
        "ref": "refs/heads/master",
        "headSha": policy.head_sha,
        "runId": policy.run_id,
        "runAttempt": policy.run_attempt,
        "captureJobName": policy.capture_job_name,
    }.items():
        _require_equal(capture.get(field), expected, f"capture manifest {field}")
    build = candidate.build
    for actual, expected, label in (
        (build["buildSha256"], policy.build_sha256, "capture build hash"),
        (build["executableSha256"], policy.executable_sha256, "capture executable hash"),
        (build["producerBuildSha256"], policy.producer_build_sha256,
         "capture producer build hash"),
        (build["observerBinary"]["sha256"], policy.observer_binary_sha256,
         "capture observer binary hash"),
    ):
        _require_equal(actual, expected, label)
    plan_hashes = {row["planManifestSha256"] for row in candidate.processes}
    _require_equal(plan_hashes, {policy.plan_manifest_sha256}, "capture plan hash")

    receipt = {
        "schema": 1,
        "protocol": OUTPUT_PROTOCOL,
        "status": OUTPUT_STATUS,
        "productionClaim": False,
        "parityEligible": False,
        "metadataSource": (
            "LIVE_GITHUB_API" if client.official else "MOCK_HTTP_TEST_ONLY"
        ),
        "correlationStatus": "NON_AUTHORITATIVE_ARTIFACT_JOB_ATTEMPT_CORRELATION",
        "repository": {
            "fullName": policy.repository,
            "id": policy.repository_id,
        },
        "workflow": {
            "path": policy.workflow_path,
            "ref": "refs/heads/master",
            "headSha": policy.head_sha,
            "runId": policy.run_id,
            "runAttempt": policy.run_attempt,
        },
        "observedWorkflowJob": {
            "id": policy.capture_job_id,
            "name": policy.capture_job_name,
            "runnerId": policy.runner_id,
            "runnerName": runner_name,
            "runnerGroupId": policy.runner_group_id,
            "runnerGroupName": policy.runner_group_name,
            "runnerLabels": sorted(policy.runner_labels),
        },
        "observedRunArtifact": {
            "id": policy.artifact_id,
            "name": policy.artifact_name,
            "digest": policy.artifact_digest,
            "archiveSha256": candidate.archive_sha256,
        },
        "captureManifestSha256": candidate.manifest_sha256,
        "buildSha256": candidate.build["buildSha256"],
        "planManifestSha256": policy.plan_manifest_sha256,
        "claimCount": manifests.CLAIM_COUNT,
        "processReceiptsSha256": candidate.process_receipts_sha256,
        "rawLogsSha256": candidate.raw_logs_sha256,
        "promotionBlockers": [
            "GitHub artifact metadata has no authoritative job or run-attempt binding",
            "candidate receipt is neither verified nor production trust",
            "a cryptographic GitHub artifact attestation must bind artifact, "
            "workflow, run, attempt, and job identity",
            "trusted runner policy and artifact-attestation entitlement are external configuration",
        ],
    }
    return receipt, archive


def _positive(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("value must be a positive integer") from error
    if parsed <= 0 or str(parsed) != value:
        raise argparse.ArgumentTypeError("value must be a canonical positive integer")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True, type=_positive)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--run-id", required=True, type=_positive)
    parser.add_argument("--run-attempt", required=True, type=_positive)
    parser.add_argument("--capture-job-name", required=True)
    parser.add_argument("--capture-job-id", required=True, type=_positive)
    parser.add_argument("--runner-id", required=True, type=_positive)
    parser.add_argument("--runner-group-id", required=True, type=_positive)
    parser.add_argument("--runner-group-name", required=True)
    parser.add_argument("--runner-label", action="append", required=True)
    parser.add_argument("--artifact-id", required=True, type=_positive)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--plan-manifest-sha256", required=True)
    parser.add_argument("--executable-sha256", required=True)
    parser.add_argument("--producer-build-sha256", required=True)
    parser.add_argument("--observer-binary-sha256", required=True)
    parser.add_argument("--build-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    policy = VerificationPolicy(
        repository=args.repository,
        repository_id=args.repository_id,
        workflow_path=args.workflow_path,
        head_sha=args.head_sha,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        capture_job_name=args.capture_job_name,
        capture_job_id=args.capture_job_id,
        runner_id=args.runner_id,
        runner_group_id=args.runner_group_id,
        runner_group_name=args.runner_group_name,
        runner_labels=tuple(args.runner_label),
        artifact_id=args.artifact_id,
        artifact_name=args.artifact_name,
        artifact_digest=args.artifact_digest,
        plan_manifest_sha256=args.plan_manifest_sha256,
        executable_sha256=args.executable_sha256,
        producer_build_sha256=args.producer_build_sha256,
        observer_binary_sha256=args.observer_binary_sha256,
        build_sha256=args.build_sha256,
    )
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        receipt, _archive = verify_online(policy, GitHubApiClient(token))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(manifests.canonical_bytes(receipt) + b"\n")
    except NativeDispatchRunVerificationError as error:
        print(f"native dispatch verification failed: {error}", file=sys.stderr)
        return 1
    print(OUTPUT_STATUS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
