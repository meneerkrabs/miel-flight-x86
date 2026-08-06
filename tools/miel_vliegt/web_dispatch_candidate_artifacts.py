#!/usr/bin/env python3
"""Validate and atomically stage one browser dispatch candidate capture.

The staged artifacts are intentionally not parity evidence.  They preserve the
candidate bytes and independently normalized receipts so a later native/web
differential can decide whether promotion is justified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

try:
    from tools.miel_vliegt import scene_semantic_coverage as coverage
    from tools.miel_vliegt import udsp_semantic_oracle as oracle
except ModuleNotFoundError:  # Direct script execution.
    import scene_semantic_coverage as coverage
    import udsp_semantic_oracle as oracle


ROOT = Path(__file__).resolve().parents[2]
EXECUTABLE = ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json"
CAPTURE_PROTOCOL = "miel-vliegt-web-dispatch-candidate-capture"
BUILD_PROTOCOL = coverage.WEB_DISPATCH_CANDIDATE_BUILD_PROTOCOL
RECEIPT_PROTOCOL = "miel-vliegt-web-dispatch-candidate-receipt"
RUN_PROTOCOL = "miel-vliegt-web-dispatch-candidate-run"
PRODUCTION_PROVENANCE = "CANDIDATE_ONLY_NO_SOURCE_TO_BUNDLE_ATTESTATION"


class WebDispatchCandidateArtifactError(ValueError):
    """Raised when candidate bytes or capture output are not exact."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("ascii")


def _read_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WebDispatchCandidateArtifactError(f"{label} is not JSON") from error
    if not isinstance(value, dict):
        raise WebDispatchCandidateArtifactError(f"{label} is not an object")
    return value


def _write_content_addressed(
    root: Path, group: str, suffix: str, data: bytes,
) -> dict[str, str]:
    digest = _sha(data)
    relative = Path(group) / f"{digest}{suffix}"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != data:
        raise WebDispatchCandidateArtifactError("content-address collision")
    path.write_bytes(data)
    return {"path": relative.as_posix(), "sha256": digest}


def _candidate_version(version_bytes: bytes) -> str:
    try:
        text = version_bytes.decode("utf-8")
    except UnicodeError as error:
        raise WebDispatchCandidateArtifactError("candidate version bytes are invalid") from error
    try:
        return coverage.parse_web_candidate_version_text(text)
    except coverage.SemanticCoverageError as error:
        raise WebDispatchCandidateArtifactError(
            "candidate version identity is invalid"
        ) from error


def _validate_candidate_urls(candidate: dict[str, Any], version: str) -> None:
    bundle = urlsplit(candidate.get("bundleUrl", ""))
    version_url = urlsplit(candidate.get("versionUrl", ""))
    web_build = urlsplit(candidate.get("webTransitionBuildUrl", ""))
    if bundle.scheme not in {"http", "https"} or not bundle.netloc \
            or bundle.username or bundle.password or bundle.fragment \
            or version_url.username or version_url.password or version_url.fragment \
            or web_build.username or web_build.password or web_build.fragment \
            or (version_url.scheme, version_url.netloc) != (bundle.scheme, bundle.netloc) \
            or (web_build.scheme, web_build.netloc) != (bundle.scheme, bundle.netloc) \
            or bundle.path != "/bundle.js" \
            or parse_qs(bundle.query, keep_blank_values=True) != {"v": [version]} \
            or version_url.path != "/version.txt" or version_url.query \
            or web_build.path != "/assets/web_transition_build.json" \
            or web_build.query:
        raise WebDispatchCandidateArtifactError("candidate URLs are not one immutable build")


def _validate_web_build_bytes(web_build_bytes: bytes) -> None:
    build = _read_json_bytes(web_build_bytes, "web transition build")
    if set(build) != {"schema", "protocol", "inputs", "build_sha256"} \
            or build.get("schema") != 1 \
            or build.get("protocol") != "miel-web-scene-transition-build" \
            or not isinstance(build.get("inputs"), list):
        raise WebDispatchCandidateArtifactError("web transition build schema differs")
    identity = {key: build[key] for key in ("schema", "protocol", "inputs")}
    digest = _sha(json.dumps(
        identity, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii"))
    if build.get("build_sha256") != digest:
        raise WebDispatchCandidateArtifactError("web transition build self-hash differs")


def stage_candidate_artifacts(
    capture_bytes: bytes, ledger_bytes: bytes, plan_bytes: bytes,
    bundle_bytes: bytes, version_bytes: bytes, web_build_bytes: bytes,
    output: Path,
) -> dict[str, Any]:
    capture = _read_json_bytes(capture_bytes, "candidate capture")
    required = {
        "schema", "protocol", "semanticStatus", "parityEligible", "candidate",
        "productionProvenance", "ledgerSha256", "planSha256", "documents",
    }
    if set(capture) != required or capture.get("schema") != 1 \
            or capture.get("protocol") != CAPTURE_PROTOCOL \
            or capture.get("semanticStatus") != "UNPROVEN" \
            or capture.get("parityEligible") is not False \
            or capture.get("productionProvenance") != PRODUCTION_PROVENANCE:
        raise WebDispatchCandidateArtifactError("candidate capture schema differs")
    executable_bytes = EXECUTABLE.read_bytes()
    ledger = _read_json_bytes(ledger_bytes, "semantic ledger")
    plan = _read_json_bytes(plan_bytes, "semantic plan")
    executable = _read_json_bytes(executable_bytes, "executable scripts")
    if capture.get("ledgerSha256") != _sha(ledger_bytes) \
            or capture.get("planSha256") != _sha(plan_bytes) \
            or plan.get("manifestSha256") != coverage._canonical_sha({
                key: value for key, value in plan.items() if key != "manifestSha256"
            }):
        raise WebDispatchCandidateArtifactError("candidate plan/ledger binding differs")
    candidate = capture.get("candidate")
    candidate_fields = {
        "candidateVersion", "captureBundleSha256", "versionTextSha256",
        "webTransitionBuildSha256", "bundleUrl", "versionUrl",
        "webTransitionBuildUrl",
    }
    version = _candidate_version(version_bytes)
    _validate_candidate_urls(candidate, version)
    _validate_web_build_bytes(web_build_bytes)
    bundle_sha = _sha(bundle_bytes)
    version_sha = _sha(version_bytes)
    web_build_sha = _sha(web_build_bytes)
    if not isinstance(candidate, dict) or set(candidate) != candidate_fields \
            or candidate.get("candidateVersion") != version \
            or candidate.get("captureBundleSha256") != bundle_sha \
            or candidate.get("versionTextSha256") != version_sha \
            or candidate.get("webTransitionBuildSha256") != web_build_sha \
            or web_build_bytes != (ROOT / "content/miel_vliegt/web_transition_build.json").read_bytes():
        raise WebDispatchCandidateArtifactError("candidate build bytes differ from bridge")
    candidate_identity = {
        "candidateVersion": version,
        "captureBundleSha256": bundle_sha,
    }

    documents = capture.get("documents")
    if not isinstance(documents, list) or len(documents) != 155:
        raise WebDispatchCandidateArtifactError("candidate capture must contain 155 documents")
    claim_ids = [row.get("claimId") for row in documents if isinstance(row, dict)]
    if len(claim_ids) != 155 or len(set(claim_ids)) != 155:
        raise WebDispatchCandidateArtifactError("candidate claim inventory is not unique")
    records = {row["id"]: row for row in ledger["records"]}
    expected_claims = {
        row["id"] for row in ledger["records"]
        if row["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}
    }
    if set(claim_ids) != expected_claims:
        raise WebDispatchCandidateArtifactError("candidate claim inventory differs")

    output = output.resolve()
    if output.exists():
        raise WebDispatchCandidateArtifactError("candidate output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        bundle_ref = _write_content_addressed(stage, "build/blobs", ".js", bundle_bytes)
        version_ref = _write_content_addressed(stage, "build/blobs", ".txt", version_bytes)
        web_build_ref = _write_content_addressed(
            stage, "build/blobs", ".json", web_build_bytes
        )
        ledger_ref = _write_content_addressed(
            stage, "build/blobs", ".json", ledger_bytes
        )
        plan_ref = _write_content_addressed(
            stage, "build/blobs", ".json", plan_bytes
        )
        def build_child(reference: dict[str, str]) -> dict[str, str]:
            return {
                "path": Path(reference["path"]).relative_to("build").as_posix(),
                "sha256": reference["sha256"],
            }
        build = {
            "schema": 1,
            "protocol": BUILD_PROTOCOL,
            "semanticStatus": "UNPROVEN",
            "parityEligible": False,
            "productionProvenance": PRODUCTION_PROVENANCE,
            **candidate_identity,
            "versionTextSha256": version_sha,
            "webTransitionBuildSha256": web_build_sha,
            "semanticLedgerSha256": _sha(ledger_bytes),
            "semanticPlanSha256": _sha(plan_bytes),
            "captureBundle": build_child(bundle_ref),
            "versionText": build_child(version_ref),
            "webTransitionBuild": build_child(web_build_ref),
            "semanticLedger": build_child(ledger_ref),
            "semanticPlan": build_child(plan_ref),
        }
        build_ref = _write_content_addressed(
            stage, "build", ".json", _json_bytes(build)
        )
        receipts = []
        raw_hashes: set[str] = set()
        for document in sorted(documents, key=lambda row: row["claimId"]):
            record = records[document["claimId"]]
            identity = {key: document[key] for key in oracle.IDENTITY_FIELDS}
            expected_provenance = coverage.expected_web_dispatch_capture_provenance(
                record, edition=ledger["edition"],
                candidate_identity=candidate_identity,
                plan_document=plan,
            )
            normalized = oracle.normalize_web_trace(
                document, executable, identity,
                executable_source_bytes=executable_bytes,
                expected_expectation=record["expectation"],
                expected_capture_provenance=expected_provenance,
            )
            raw_ref = _write_content_addressed(
                stage, "raw", ".json", _json_bytes(document)
            )
            if raw_ref["sha256"] in raw_hashes:
                raise WebDispatchCandidateArtifactError("candidate raw hash is reused")
            raw_hashes.add(raw_ref["sha256"])
            receipt = {
                "schema": 1,
                "protocol": RECEIPT_PROTOCOL,
                "semanticStatus": "UNPROVEN",
                "parityEligible": False,
                "productionProvenance": PRODUCTION_PROVENANCE,
                "claimId": record["id"],
                "evidenceClass": record["evidenceClass"],
                "subjectSha256": document["subjectSha256"],
                "expectationSha256": document["expectationSha256"],
                "normalizedSha256": oracle.canonical_sha256(normalized),
                "raw": raw_ref,
                "candidateBuild": build_ref,
            }
            receipts.append(_write_content_addressed(
                stage, "receipts", ".json", _json_bytes(receipt)
            ))
        if len({row["sha256"] for row in receipts}) != 155:
            raise WebDispatchCandidateArtifactError("candidate receipt hash is reused")
        run = {
            "schema": 1,
            "protocol": RUN_PROTOCOL,
            "semanticStatus": "UNPROVEN",
            "parityEligible": False,
            "productionProvenance": PRODUCTION_PROVENANCE,
            "candidateBuild": build_ref,
            "ledgerSha256": _sha(ledger_bytes),
            "planSha256": _sha(plan_bytes),
            "counts": {
                "claims": 155,
                "missionDispatch": sum(
                    row["evidenceClass"] == "MISSION_DISPATCH" for row in documents
                ),
                "locationPolicy": sum(
                    row["evidenceClass"] == "LOCATION_POLICY" for row in documents
                ),
            },
            "receipts": receipts,
        }
        run_ref = _write_content_addressed(stage, "run", ".json", _json_bytes(run))
        index = {
            "schema": 1,
            "protocol": RUN_PROTOCOL,
            "semanticStatus": "UNPROVEN",
            "parityEligible": False,
            "productionProvenance": PRODUCTION_PROVENANCE,
            "run": run_ref,
        }
        (stage / "index.json").write_bytes(_json_bytes(index))
        os.replace(stage, output)
        return index
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--version", type=Path, required=True)
    parser.add_argument("--web-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = stage_candidate_artifacts(
        args.capture.read_bytes(), args.ledger.read_bytes(), args.plan.read_bytes(),
        args.bundle.read_bytes(), args.version.read_bytes(),
        args.web_build.read_bytes(), args.output,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
