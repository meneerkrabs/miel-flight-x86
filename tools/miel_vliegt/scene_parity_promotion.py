#!/usr/bin/env python3
"""Batch, validate and optionally apply scene parity promotions.

Candidate manifests only point at independent native and web traces.  This
tool recomputes the differential receipt, injects it into a copy of the owning
ledger and runs that ledger's authoritative validator before reporting PASS.
It never calls a capture backend and never treats a candidate as evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import (
        natural_transition_trace,
        scene_coverage,
        scene_semantic_coverage,
    )
except ModuleNotFoundError:
    import natural_transition_trace
    import scene_coverage
    import scene_semantic_coverage


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCENE_LEDGER = scene_coverage.DEFAULT_LEDGER
DEFAULT_SEMANTIC_LEDGER = scene_semantic_coverage.DEFAULT_LEDGER
PROTOCOL = "miel-vliegt-scene-parity-promotion"
CANDIDATE_PROTOCOL = "miel-vliegt-scene-parity-candidate"
KINDS = ("MODE", "NATURAL_EDGE", "SEMANTIC_CLAIM")
SHA256 = frozenset("0123456789abcdef")


class PromotionError(ValueError):
    """Raised when a promotion batch or artifact is ambiguous."""


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= SHA256


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PromotionError(f"cannot read {label}: {path}") from error
    if not isinstance(value, dict):
        raise PromotionError(f"{label} must be an object")
    return value


def _repo_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError as error:
        raise PromotionError(f"promotion artifact escapes repository: {path}") from error


def _reference(path: Path) -> dict[str, Any]:
    return {"path": _repo_path(path), "sha256": sha256_file(path)}


def _resolve_reference(reference: Any, label: str) -> Path:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"} \
            or not isinstance(reference.get("path"), str) \
            or Path(reference["path"]).is_absolute() \
            or not _is_sha256(reference.get("sha256")):
        raise PromotionError(f"{label} reference is invalid")
    path = (ROOT / reference["path"]).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as error:
        raise PromotionError(f"{label} escapes repository") from error
    if not path.is_file() or sha256_file(path) != reference["sha256"]:
        raise PromotionError(f"{label} is missing or hash-drifted")
    return path


def _write_content_addressed(
    artifact_root: Path, group: str, document: dict[str, Any],
) -> tuple[Path, dict[str, str]]:
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    path = artifact_root / group / f"{digest}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != encoded:
        raise PromotionError("content-addressed promotion artifact collision")
    path.write_bytes(encoded)
    return path, {"path": _repo_path(path), "sha256": digest}


def _validate_scene_document(document: dict[str, Any]) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".json", dir=ROOT, delete=False,
    ) as stream:
        path = Path(stream.name)
        json.dump(document, stream, ensure_ascii=False)
    try:
        scene_coverage.validate_ledger(path)
    finally:
        path.unlink(missing_ok=True)


def _candidate_key(candidate: dict[str, Any]) -> tuple[str, str, str]:
    return candidate["kind"], candidate["edition"], candidate["target"]


def load_candidates(directory: Path) -> tuple[
    dict[tuple[str, str, str], dict[str, Any]], list[dict[str, Any]]
]:
    if not directory.is_dir():
        raise PromotionError(f"promotion candidate directory is unavailable: {directory}")
    indexed = {}
    sources = []
    trace_identities: set[tuple[str, str]] = set()
    for path in sorted(directory.glob("*.json")):
        candidate = _load(path, "promotion candidate")
        required = {
            "schema", "protocol", "kind", "edition", "target",
            "nativeTrace", "webTrace",
        }
        if set(candidate) != required or candidate.get("schema") != 1 \
                or candidate.get("protocol") != CANDIDATE_PROTOCOL \
                or candidate.get("kind") not in KINDS \
                or not isinstance(candidate.get("edition"), str) \
                or not candidate["edition"] \
                or not isinstance(candidate.get("target"), str) \
                or not candidate["target"]:
            raise PromotionError(f"promotion candidate fields differ: {path}")
        _resolve_reference(candidate["nativeTrace"], f"{path.name} native trace")
        _resolve_reference(candidate["webTrace"], f"{path.name} web trace")
        if candidate["nativeTrace"] == candidate["webTrace"]:
            raise PromotionError(f"promotion candidate reuses one trace: {path}")
        identities = {
            (candidate[field]["path"], candidate[field]["sha256"])
            for field in ("nativeTrace", "webTrace")
        }
        if trace_identities & identities:
            raise PromotionError(
                f"promotion trace is reused across candidates: {path}"
            )
        trace_identities.update(identities)
        key = _candidate_key(candidate)
        if key in indexed:
            raise PromotionError(f"duplicate promotion candidate: {key}")
        indexed[key] = {**candidate, "_source": _reference(path)}
        sources.append(_reference(path))
    return indexed, sources


def _find_mode_claim(
    document: dict[str, Any], edition: str, scene: str,
) -> dict[str, Any]:
    edition_row = document.get("editions", {}).get(edition)
    if not isinstance(edition_row, dict) or edition_row.get("game") != "flight":
        raise PromotionError(f"unknown flight edition: {edition}")
    matches = [
        row for row in edition_row.get("claims", [])
        if isinstance(row, dict) and row.get("scene") == scene
    ]
    if len(matches) != 1:
        raise PromotionError(f"unknown mode claim: {edition}:{scene}")
    return matches[0]


def _find_edge_claim(
    document: dict[str, Any], edition: str, edge: str,
) -> dict[str, Any]:
    matches = [
        row for row in document.get("flight_transition_claims", {}).get(edition, [])
        if isinstance(row, dict) and row.get("edge") == edge
    ]
    if len(matches) != 1:
        raise PromotionError(f"unknown natural edge claim: {edition}:{edge}")
    return matches[0]


def _find_semantic_claim(document: dict[str, Any], claim_id: str) -> dict[str, Any]:
    matches = [
        row for row in document.get("records", [])
        if isinstance(row, dict) and row.get("id") == claim_id
    ]
    if len(matches) != 1:
        raise PromotionError(f"unknown semantic claim: {claim_id}")
    return matches[0]


def _catalog_add(
    document: dict[str, Any], identifier: str, kind: str, reference: dict[str, str],
) -> None:
    catalog = document["parity_evidence"]
    if identifier in catalog:
        raise PromotionError(f"promotion evidence ID already exists: {identifier}")
    catalog[identifier] = {"kind": kind, **reference}


def _promotion_id(kind: str, edition: str, target: str) -> str:
    return hashlib.sha256(
        f"{kind}\0{edition}\0{target}".encode("utf-8")
    ).hexdigest()[:24]


def _promote_mode(
    document: dict[str, Any], candidate: dict[str, Any], artifact_root: Path,
) -> tuple[dict[str, Any], list[Path]]:
    edition, scene = candidate["edition"], candidate["target"]
    native_path = _resolve_reference(candidate["nativeTrace"], "native mode trace")
    web_path = _resolve_reference(candidate["webTrace"], "web mode trace")
    native = scene_coverage._load_mode_body_trace(native_path, f"native:{scene}")
    web = scene_coverage._load_mode_body_trace(web_path, f"web:{scene}")
    if native["producer"] != "NATIVE" or web["producer"] != "WEB" \
            or native["edition"] != edition or web["edition"] != edition \
            or native["scene"] != scene or web["scene"] != scene \
            or native["capture_id"] == web["capture_id"] \
            or native["subject_sha256"] \
            != natural_transition_trace.NATIVE_EXECUTABLE_SHA256 \
            or web["subject_sha256"] != natural_transition_trace.WEB_BUILD_SHA256:
        raise PromotionError(f"mode trace provenance differs: {edition}:{scene}")
    if scene_coverage._canonical_bytes(scene_coverage._body_comparable(native)) \
            != scene_coverage._canonical_bytes(scene_coverage._body_comparable(web)):
        raise PromotionError(f"mode differential differs: {edition}:{scene}")
    receipt = {
        "schema": 2,
        "protocol": scene_coverage.BODY_DIFFERENTIAL_PROTOCOL,
        "edition": edition,
        "scene": scene,
        "native_trace_sha256": candidate["nativeTrace"]["sha256"],
        "web_trace_sha256": candidate["webTrace"]["sha256"],
        "comparator": scene_coverage.BODY_COMPARATOR,
        "comparison_policy": scene_coverage.BODY_COMPARISON_POLICY,
        "comparison_policy_sha256": scene_coverage._canonical_sha256(
            scene_coverage.BODY_COMPARISON_POLICY
        ),
        "result": "PASS",
    }
    receipt_path, receipt_ref = _write_content_addressed(
        artifact_root, "mode", receipt,
    )
    promoted = copy.deepcopy(document)
    prefix = _promotion_id("mode", edition, scene)
    native_id, web_id, receipt_id = (
        f"promotion:{prefix}:native",
        f"promotion:{prefix}:web",
        f"promotion:{prefix}:differential",
    )
    _catalog_add(promoted, native_id, "native-trace", candidate["nativeTrace"])
    _catalog_add(promoted, web_id, "web-trace", candidate["webTrace"])
    _catalog_add(promoted, receipt_id, "differential-receipt", receipt_ref)
    claim = _find_mode_claim(promoted, edition, scene)
    claim["gates"]["BODY_PARITY"] = {
        "status": "PARITY_PROVEN",
        "evidence": [native_id, web_id, receipt_id],
        "blocker": None,
    }
    try:
        _validate_scene_document(promoted)
    except Exception:
        receipt_path.unlink(missing_ok=True)
        raise
    return promoted, [receipt_path]


def _promote_edge(
    document: dict[str, Any], candidate: dict[str, Any], artifact_root: Path,
) -> tuple[dict[str, Any], list[Path]]:
    edition, edge = candidate["edition"], candidate["target"]
    native_path = _resolve_reference(candidate["nativeTrace"], "native edge trace")
    web_path = _resolve_reference(candidate["webTrace"], "web edge trace")
    receipt = natural_transition_trace.compare(native_path, web_path)
    if receipt["edition"] != edition or receipt["edge"] != edge:
        raise PromotionError(f"natural edge provenance differs: {edition}:{edge}")
    receipt_path, receipt_ref = _write_content_addressed(
        artifact_root, "natural-edge", receipt,
    )
    promoted = copy.deepcopy(document)
    prefix = _promotion_id("edge", edition, edge)
    native_id, web_id, receipt_id = (
        f"promotion:{prefix}:native",
        f"promotion:{prefix}:web",
        f"promotion:{prefix}:differential",
    )
    _catalog_add(
        promoted, native_id, "native-transition-trace", candidate["nativeTrace"],
    )
    _catalog_add(
        promoted, web_id, "web-transition-trace", candidate["webTrace"],
    )
    _catalog_add(
        promoted, receipt_id, "transition-differential-receipt", receipt_ref,
    )
    claim = _find_edge_claim(promoted, edition, edge)
    claim.update(status="PARITY_PROVEN", evidence=[native_id, web_id, receipt_id])
    try:
        _validate_scene_document(promoted)
    except Exception:
        receipt_path.unlink(missing_ok=True)
        raise
    return promoted, [receipt_path]


def _semantic_trace_observations(
    trace: dict[str, Any], *, producer: str, record: dict[str, Any],
    document: dict[str, Any],
) -> list[dict[str, Any]]:
    if "observations" in trace:
        observations = trace["observations"]
        if not isinstance(observations, list):
            raise PromotionError("semantic trace observations are invalid")
        return observations
    if "sessionSlice" not in trace:
        raise PromotionError("semantic trace has no observations or session slice")
    source_hashes = {
        "sceneDispatchContract":
            document["sources"]["sceneDispatchContract"]["sha256"],
        "udsSceneScripts": document["sources"]["udsSceneScripts"]["sha256"],
        "executableUdspSceneScripts":
            document["sources"]["executableUdspSceneScripts"]["sha256"],
    }
    observations, _identity = scene_semantic_coverage._validate_session_slice(
        trace["sessionSlice"], producer=producer, record=record,
        edition=document["edition"], source_hashes=source_hashes,
        subject_sha256=scene_semantic_coverage.evidence_subject_sha256(record),
        expectation_sha256=scene_semantic_coverage.evidence_expectation_sha256(record),
        session_occurrences=set(),
    )
    return observations


def _promote_semantic(
    document: dict[str, Any], candidate: dict[str, Any], artifact_root: Path,
    *, allow_test_provenance: bool,
) -> tuple[dict[str, Any], list[Path]]:
    edition, claim_id = candidate["edition"], candidate["target"]
    if edition != document["edition"]:
        raise PromotionError(f"semantic edition differs: {edition}")
    record = _find_semantic_claim(document, claim_id)
    native_path = _resolve_reference(candidate["nativeTrace"], "native semantic trace")
    web_path = _resolve_reference(candidate["webTrace"], "web semantic trace")
    native = _load(native_path, "native semantic trace")
    web = _load(web_path, "web semantic trace")
    native_observations = _semantic_trace_observations(
        native, producer="NATIVE", record=record, document=document,
    )
    web_observations = _semantic_trace_observations(
        web, producer="WEB", record=record, document=document,
    )
    if native_observations != web_observations:
        raise PromotionError(f"semantic differential differs: {claim_id}")
    source_hashes = {
        "sceneDispatchContract":
            document["sources"]["sceneDispatchContract"]["sha256"],
        "udsSceneScripts": document["sources"]["udsSceneScripts"]["sha256"],
        "executableUdspSceneScripts":
            document["sources"]["executableUdspSceneScripts"]["sha256"],
    }
    evidence_id = f"promotion:{_promotion_id('semantic', edition, claim_id)}"
    receipt = {
        "schema": 1,
        "protocol": scene_semantic_coverage.SEMANTIC_DIFFERENTIAL_PROTOCOL,
        "result": "PASS",
        "evidenceId": evidence_id,
        "evidenceClass": record["evidenceClass"],
        "claimId": claim_id,
        "edition": edition,
        "sourceHashes": source_hashes,
        "subjectSha256": scene_semantic_coverage.evidence_subject_sha256(record),
        "expectationSha256":
            scene_semantic_coverage.evidence_expectation_sha256(record),
        "nativeTrace": candidate["nativeTrace"],
        "webTrace": candidate["webTrace"],
        "observationsSha256":
            scene_semantic_coverage.semantic_observations_sha256(native_observations),
    }
    receipt_path, receipt_ref = _write_content_addressed(
        artifact_root, "semantic", receipt,
    )
    promoted = copy.deepcopy(document)
    promoted_record = _find_semantic_claim(promoted, claim_id)
    promoted_record.update(
        status="PROVEN",
        evidence=[{
            "evidenceId": evidence_id,
            **receipt_ref,
            "evidenceClass": record["evidenceClass"],
            "claimId": claim_id,
            "edition": edition,
            "sourceHashes": source_hashes,
            "subjectSha256": receipt["subjectSha256"],
            "expectationSha256": receipt["expectationSha256"],
        }],
    )
    try:
        scene_semantic_coverage.validate_ledger(
            promoted, allow_test_provenance=allow_test_provenance,
        )
    except Exception:
        receipt_path.unlink(missing_ok=True)
        raise
    return promoted, [receipt_path]


def _inventory(
    scene_document: dict[str, Any], semantic_document: dict[str, Any],
) -> list[tuple[str, str, str]]:
    rows = []
    for edition, data in scene_document["editions"].items():
        if data.get("game") == "flight":
            rows.extend(("MODE", edition, row["scene"]) for row in data["claims"])
    for edition, claims in scene_document["flight_transition_claims"].items():
        rows.extend(("NATURAL_EDGE", edition, row["edge"]) for row in claims)
    rows.extend(
        ("SEMANTIC_CLAIM", semantic_document["edition"], row["id"])
        for row in semantic_document["records"]
    )
    return sorted(rows)


def _is_promoted(
    key: tuple[str, str, str], scene_document: dict[str, Any],
    semantic_document: dict[str, Any],
) -> bool:
    kind, edition, target = key
    if kind == "MODE":
        return (
            _find_mode_claim(scene_document, edition, target)
            ["gates"]["BODY_PARITY"]["status"] == "PARITY_PROVEN"
        )
    if kind == "NATURAL_EDGE":
        return _find_edge_claim(
            scene_document, edition, target,
        )["status"] == "PARITY_PROVEN"
    return _find_semantic_claim(semantic_document, target)["status"] == "PROVEN"


def build_batch(
    *, candidate_dir: Path, artifact_root: Path,
    scene_ledger_path: Path = DEFAULT_SCENE_LEDGER,
    semantic_ledger_path: Path = DEFAULT_SEMANTIC_LEDGER,
    allow_test_provenance: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    scene_coverage.validate_ledger(scene_ledger_path)
    semantic_document = _load(semantic_ledger_path, "semantic coverage ledger")
    scene_semantic_coverage.validate_ledger(
        semantic_document, allow_test_provenance=allow_test_provenance,
    )
    scene_document = _load(scene_ledger_path, "scene coverage ledger")
    _scene_snapshot_path, scene_snapshot = _write_content_addressed(
        artifact_root, "batch-input", scene_document,
    )
    _semantic_snapshot_path, semantic_snapshot = _write_content_addressed(
        artifact_root, "batch-input", semantic_document,
    )
    candidates, candidate_sources = load_candidates(candidate_dir)
    inventory = _inventory(scene_document, semantic_document)
    unknown = sorted(set(candidates) - set(inventory))
    if unknown:
        raise PromotionError(f"promotion candidates target unknown inventory: {unknown[0]}")

    failures: dict[tuple[str, str, str], str] = {}
    for key in inventory:
        candidate = candidates.get(key)
        if candidate is None or _is_promoted(key, scene_document, semantic_document):
            continue
        created: list[Path] = []
        try:
            if key[0] == "MODE":
                promoted, created = _promote_mode(
                    scene_document, candidate, artifact_root,
                )
                scene_document = promoted
            elif key[0] == "NATURAL_EDGE":
                promoted, created = _promote_edge(
                    scene_document, candidate, artifact_root,
                )
                scene_document = promoted
            else:
                promoted, created = _promote_semantic(
                    semantic_document, candidate, artifact_root,
                    allow_test_provenance=allow_test_provenance,
                )
                semantic_document = promoted
        except (
            PromotionError,
            scene_coverage.SceneCoverageError,
            scene_semantic_coverage.SemanticCoverageError,
            ValueError,
        ) as error:
            for path in created:
                path.unlink(missing_ok=True)
            failures[key] = f"VALIDATION_FAILED:{error}"

    rows = []
    for key in inventory:
        passed = _is_promoted(key, scene_document, semantic_document)
        rows.append({
            "kind": key[0],
            "edition": key[1],
            "target": key[2],
            "status": "PASS" if passed else "BLOCKED",
            "blocker": None if passed else failures.get(
                key, "MISSING_VALIDATED_NATIVE_WEB_CANDIDATE",
            ),
            "candidate": candidates.get(key, {}).get("_source"),
        })
    counts = Counter((row["kind"], row["status"]) for row in rows)
    report = {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": "PASS" if all(row["status"] == "PASS" for row in rows) else "BLOCKED",
        "policy": {
            "candidateIsEvidence": False,
            "nativeWebTracesMustBeIndependent": True,
            "differentialIsRecomputed": True,
            "authoritativeLedgerValidatorRequired": True,
            "testProvenanceAccepted": allow_test_provenance,
            "nativeParityPromotionRequiresPass": True,
        },
        "sources": {
            "sceneLedger": scene_snapshot,
            "semanticLedger": semantic_snapshot,
            "generator": _reference(Path(__file__)),
            "candidates": candidate_sources,
        },
        "counts": {
            "items": len(rows),
            "pass": sum(row["status"] == "PASS" for row in rows),
            "blocked": sum(row["status"] == "BLOCKED" for row in rows),
            "byKindAndStatus": {
                f"{kind}:{status}": count
                for (kind, status), count in sorted(counts.items())
            },
        },
        "records": rows,
    }
    report["reportSha256"] = canonical_sha256(report)
    return report, scene_document, semantic_document


def finalize_report(
    report: dict[str, Any], *, scene_output: Path, semantic_output: Path,
    applied: bool,
) -> dict[str, Any]:
    finalized = copy.deepcopy(report)
    finalized["outputs"] = {
        "sceneLedger": _reference(scene_output),
        "semanticLedger": _reference(semantic_output),
    }
    finalized["applied"] = applied
    finalized["reportSha256"] = canonical_sha256({
        key: value for key, value in finalized.items() if key != "reportSha256"
    })
    return finalized


def validate_report(
    report: dict[str, Any], *, allow_test_provenance: bool = False,
) -> dict[str, int]:
    required = {
        "schema", "protocol", "status", "policy", "sources", "counts",
        "records", "reportSha256", "outputs", "applied",
    }
    if not isinstance(report, dict) or set(report) != required \
            or report.get("schema") != 1 or report.get("protocol") != PROTOCOL \
            or type(report.get("applied")) is not bool:
        raise PromotionError("promotion report shape differs")
    expected_policy = {
        "candidateIsEvidence": False,
        "nativeWebTracesMustBeIndependent": True,
        "differentialIsRecomputed": True,
        "authoritativeLedgerValidatorRequired": True,
        "testProvenanceAccepted": report.get("policy", {}).get(
            "testProvenanceAccepted"
        ),
        "nativeParityPromotionRequiresPass": True,
    }
    if report.get("policy") != expected_policy \
            or type(expected_policy["testProvenanceAccepted"]) is not bool \
            or expected_policy["testProvenanceAccepted"] and not allow_test_provenance:
        raise PromotionError("promotion report policy differs")
    unhashed = {
        key: value for key, value in report.items() if key != "reportSha256"
    }
    if report.get("reportSha256") != canonical_sha256(unhashed):
        raise PromotionError("promotion report hash differs")
    sources = report.get("sources")
    if not isinstance(sources, dict) or set(sources) != {
        "sceneLedger", "semanticLedger", "generator", "candidates",
    } or not isinstance(sources["candidates"], list):
        raise PromotionError("promotion report sources differ")
    for label in ("sceneLedger", "semanticLedger", "generator"):
        _resolve_reference(sources[label], f"promotion {label} source")
    candidate_refs = {
        (reference.get("path"), reference.get("sha256"))
        for reference in sources["candidates"]
        if isinstance(reference, dict)
    }
    if len(candidate_refs) != len(sources["candidates"]):
        raise PromotionError("promotion candidate source inventory differs")
    for reference in sources["candidates"]:
        _resolve_reference(reference, "promotion candidate source")
    outputs = report.get("outputs")
    if not isinstance(outputs, dict) or set(outputs) != {
        "sceneLedger", "semanticLedger",
    }:
        raise PromotionError("promotion report outputs differ")
    scene_path = _resolve_reference(outputs["sceneLedger"], "promoted scene ledger")
    semantic_path = _resolve_reference(
        outputs["semanticLedger"], "promoted semantic ledger",
    )
    scene_coverage.validate_ledger(scene_path)
    semantic_document = _load(semantic_path, "promoted semantic ledger")
    scene_semantic_coverage.validate_ledger(
        semantic_document, allow_test_provenance=allow_test_provenance,
    )
    scene_document = _load(scene_path, "promoted scene ledger")
    inventory = _inventory(scene_document, semantic_document)
    records = report.get("records")
    if not isinstance(records, list) or len(records) != len(inventory):
        raise PromotionError("promotion report record inventory differs")
    by_key = {}
    for row in records:
        if not isinstance(row, dict) or set(row) != {
            "kind", "edition", "target", "status", "blocker", "candidate",
        }:
            raise PromotionError("promotion report record shape differs")
        key = row["kind"], row["edition"], row["target"]
        if key in by_key or key not in inventory \
                or row["status"] not in {"PASS", "BLOCKED"} \
                or (row["status"] == "PASS") != _is_promoted(
                    key, scene_document, semantic_document,
                ) \
                or (row["status"] == "PASS" and row["blocker"] is not None) \
                or (row["status"] == "BLOCKED"
                    and not isinstance(row["blocker"], str)):
            raise PromotionError(f"promotion report record differs: {key}")
        candidate = row["candidate"]
        if candidate is not None and (
            not isinstance(candidate, dict)
            or (candidate.get("path"), candidate.get("sha256")) not in candidate_refs
        ):
            raise PromotionError(f"promotion report candidate differs: {key}")
        by_key[key] = row
    if set(by_key) != set(inventory):
        raise PromotionError("promotion report inventory is incomplete")
    counts = {
        "items": len(records),
        "pass": sum(row["status"] == "PASS" for row in records),
        "blocked": sum(row["status"] == "BLOCKED" for row in records),
        "byKindAndStatus": {
            f"{kind}:{status}": count
            for (kind, status), count in sorted(Counter(
                (row["kind"], row["status"]) for row in records
            ).items())
        },
    }
    if report.get("counts") != counts \
            or report.get("status") != (
                "PASS" if counts["pass"] == counts["items"] else "BLOCKED"
            ):
        raise PromotionError("promotion report counts differ")
    return counts


def _atomic_write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False,
    ) as stream:
        temporary = Path(stream.name)
        stream.write(encoded)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--scene-ledger", type=Path, default=DEFAULT_SCENE_LEDGER)
    parser.add_argument("--semantic-ledger", type=Path, default=DEFAULT_SEMANTIC_LEDGER)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--require-all", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    artifact_root = (
        args.artifact_root.resolve()
        if args.artifact_root else output.parent / "scene_parity_promotion_artifacts"
    )
    report, scene_document, semantic_document = build_batch(
        candidate_dir=args.candidates.resolve(),
        artifact_root=artifact_root,
        scene_ledger_path=args.scene_ledger.resolve(),
        semantic_ledger_path=args.semantic_ledger.resolve(),
    )
    scene_output = (
        args.scene_ledger.resolve()
        if args.apply else output.with_suffix(".scene-ledger.json")
    )
    semantic_output = (
        args.semantic_ledger.resolve()
        if args.apply else output.with_suffix(".semantic-ledger.json")
    )
    _atomic_write(scene_output, scene_document)
    _atomic_write(semantic_output, semantic_document)
    report = finalize_report(
        report, scene_output=scene_output, semantic_output=semantic_output,
        applied=args.apply,
    )
    validate_report(report)
    _atomic_write(output, report)
    print(json.dumps(report["counts"], sort_keys=True))
    return 1 if args.require_all and report["status"] != "PASS" else 0


if __name__ == "__main__":
    raise SystemExit(main())
