#!/usr/bin/env python3
"""Prepare reviewed, content-addressed flight-domain parity candidates.

The calibrated FEX suite and its completion adapter are candidate evidence.
This tool validates both again, requires a separately authored review receipt
that binds every cold native repeat, materializes immutable native/web traces,
and runs the canonical per-domain comparator.

It does not update either runtime contract and every emitted domain receipt
keeps ``promotion_allowed`` false.  A later, separately reviewed authority may
consume matching candidates; this command cannot approve its own input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import flight_scenario_completion_adapter as adapter
    from tools.miel_vliegt import flight_trace_differential as differential
    from tools.miel_vliegt import native_scenario_artifacts as artifacts
except ModuleNotFoundError:
    import flight_scenario_completion_adapter as adapter
    import flight_trace_differential as differential
    import native_scenario_artifacts as artifacts


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "miel-vliegt-flight-domain-promotion-candidates"
CANDIDATE_PROTOCOL = "miel-vliegt-flight-domain-parity-candidate"
REVIEW_PROTOCOL = "miel-vliegt-reviewed-production-observer-receipt"
VERSION = 1
COMPARATOR = "flight_trace_differential.compare_trace_domain"
REVIEW_STATEMENT = (
    "I reviewed both exact native runs for every listed scenario and approve "
    "their use as production-observer inputs to candidate differential review."
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PromotionError(ValueError):
    """The supplied review, evidence, or comparison input failed closed."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise PromotionError("promotion evidence is not canonical JSON") from error


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PromotionError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise PromotionError(f"{label} contains non-finite number {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PromotionError(f"cannot read {label}: {path}") from error
    if not isinstance(value, dict):
        raise PromotionError(f"{label} must contain an object")
    return value


def _strict(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        actual = set(value) if isinstance(value, dict) else set()
        raise PromotionError(
            f"{label} fields differ: missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise PromotionError(f"{label} must be a lowercase SHA-256")
    return value


def _inside(root: Path, path: Path, label: str, *, must_exist: bool = True) -> Path:
    root = root.resolve()
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise PromotionError(f"{label} escapes the repository") from error
    if must_exist and not path.is_file():
        raise PromotionError(f"{label} is missing: {path}")
    return path


def _repo_reference(root: Path, path: Path) -> dict[str, str]:
    path = _inside(root, path, "promotion artifact")
    return {
        "path": path.relative_to(root.resolve()).as_posix(),
        "sha256": _sha256(path),
    }


def _resolve_repo_reference(root: Path, reference: Any, label: str) -> Path:
    reference = _strict(reference, {"path", "sha256"}, label)
    if not isinstance(reference["path"], str) or not reference["path"] \
            or Path(reference["path"]).is_absolute():
        raise PromotionError(f"{label}.path must be repository-relative")
    path = _inside(root, root / reference["path"], label)
    if _sha256(path) != _hash(reference["sha256"], f"{label}.sha256"):
        raise PromotionError(f"{label} hash drifted")
    return path


def _write_content_addressed(
    root: Path,
    artifact_root: Path,
    group: str,
    document: dict[str, Any],
) -> tuple[Path, dict[str, str]]:
    artifact_root = _inside(
        root, artifact_root, "artifact root", must_exist=False,
    )
    encoded = _canonical_bytes(document)
    digest = hashlib.sha256(encoded).hexdigest()
    path = artifact_root / group / f"{digest}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != encoded:
        raise PromotionError("content-addressed artifact collision")
    path.write_bytes(encoded)
    return path, _repo_reference(root, path)


def _validate_adapter(
    native_suite_path: Path,
    completion_adapter_path: Path,
    native: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    supplied = adapter.validate_report(
        _load(completion_adapter_path, "completion adapter")
    )
    recomputed = adapter.validate_report(adapter.build_report(
        native_suite_path,
        root=root,
        native_evidence=native,
    ))
    if _canonical_bytes(supplied) != _canonical_bytes(recomputed):
        raise PromotionError(
            "completion adapter differs from a fresh projection of the native suite"
        )
    return supplied


def _review_scenario_projection(
    native: dict[str, Any],
) -> list[dict[str, str]]:
    rows = []
    for scenario_id in artifacts.SCENARIO_ID_ORDER:
        scenario = native["scenarios"][scenario_id]
        first = scenario["run_1"]
        second = scenario["run_2"]
        rows.append({
            "scenario": scenario_id,
            "run_1_sha256": _hash(first["sha256"], f"{scenario_id}.run_1"),
            "run_2_sha256": _hash(second["sha256"], f"{scenario_id}.run_2"),
            "semantic_sha256": _hash(
                first["receipt"]["semantic_sha256"],
                f"{scenario_id}.semantic_sha256",
            ),
        })
        if second["receipt"]["semantic_sha256"] != rows[-1]["semantic_sha256"]:
            raise PromotionError(
                f"{scenario_id}: exact native repeats have different semantics"
            )
    return rows


def validate_review_receipt(
    path: Path,
    *,
    root: Path,
    native_suite_path: Path,
    completion_adapter_path: Path,
    completion_report: dict[str, Any],
    native: dict[str, Any],
) -> dict[str, Any]:
    """Validate an external review without creating or modifying it."""

    path = _inside(root, path, "production-observer review receipt")
    review = _strict(_load(path, "production-observer review receipt"), {
        "schema", "protocol", "decision", "production_observer",
        "native_suite_sha256", "completion_adapter_sha256",
        "completion_adapter_report_sha256", "executable_sha256",
        "reviewer", "reviewed_at", "statement", "scenarios",
    }, "production-observer review receipt")
    if review["schema"] != VERSION or review["protocol"] != REVIEW_PROTOCOL \
            or review["decision"] != "APPROVED" \
            or review["production_observer"] is not True \
            or review["statement"] != REVIEW_STATEMENT:
        raise PromotionError("production-observer review is not an explicit approval")
    if review["native_suite_sha256"] != _sha256(native_suite_path) \
            or review["completion_adapter_sha256"] \
                != _sha256(completion_adapter_path) \
            or review["completion_adapter_report_sha256"] \
                != completion_report["report_sha256"] \
            or review["executable_sha256"] != native["executable_sha256"]:
        raise PromotionError("production-observer review source binding drifted")
    reviewer = _strict(review["reviewer"], {"id", "role"}, "reviewer")
    if not all(isinstance(reviewer[field], str) and reviewer[field].strip()
               for field in reviewer):
        raise PromotionError("reviewer identity and role must be non-empty")
    if reviewer["role"].strip().casefold() in {"tool", "automation", "self"}:
        raise PromotionError("production-observer approval must be external review")
    if not isinstance(review["reviewed_at"], str):
        raise PromotionError("reviewed_at must be an RFC3339 timestamp")
    try:
        reviewed_at = datetime.fromisoformat(
            review["reviewed_at"].replace("Z", "+00:00")
        )
    except ValueError as error:
        raise PromotionError("reviewed_at must be an RFC3339 timestamp") from error
    if reviewed_at.tzinfo is None:
        raise PromotionError("reviewed_at must include a timezone")
    expected_scenarios = _review_scenario_projection(native)
    if review["scenarios"] != expected_scenarios:
        raise PromotionError(
            "production-observer review is not an exact ordered approval of all scenarios"
        )
    return review


def _tolerance_document(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"default": 0.0, "domains": {}, "paths": {}}
    value = _load(path, "tolerance policy")
    differential.TolerancePolicy.from_mapping(value)
    return value


def _divergence(value: differential.Divergence | None) -> dict[str, Any] | None:
    if value is None:
        return None
    result = {
        "frame": value.frame,
        "path": value.path,
        "reason": value.reason,
        "native": value.native,
        "web": value.web,
    }
    if value.tolerance is not None:
        result["tolerance"] = {
            "absolute": value.tolerance.absolute,
            "relative": value.tolerance.relative,
        }
    return result


def _trace_contract(root: Path) -> tuple[Path, dict[str, Any]]:
    path = root / "content/miel_vliegt/flight_runtime_trace_contract.json"
    return path, _load(path, "runtime trace contract")


def build_candidates(
    *,
    native_suite_path: Path,
    completion_adapter_path: Path,
    reviewed_observer_receipt_path: Path,
    artifact_root: Path,
    root: Path = ROOT,
    tolerance_path: Path | None = None,
) -> dict[str, Any]:
    """Build immutable diagnostic candidates without promoting a ledger."""

    root = root.resolve()
    native_suite_path = native_suite_path.resolve()
    completion_adapter_path = completion_adapter_path.resolve()
    native = adapter.validate_native_suite(native_suite_path)
    completion_report = _validate_adapter(
        native_suite_path, completion_adapter_path, native, root,
    )
    review = validate_review_receipt(
        reviewed_observer_receipt_path,
        root=root,
        native_suite_path=native_suite_path,
        completion_adapter_path=completion_adapter_path,
        completion_report=completion_report,
        native=native,
    )

    trace_contract_path, trace_contract = _trace_contract(root)
    trace_rows = {
        row.get("id"): row
        for row in trace_contract.get("scenarios", [])
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    if list(trace_rows) != list(artifacts.SCENARIO_ID_ORDER):
        raise PromotionError("runtime trace contract scenario inventory drifted")

    tolerance = _tolerance_document(tolerance_path)
    tolerance_policy = differential.TolerancePolicy.from_mapping(tolerance)
    _, tolerance_ref = _write_content_addressed(
        root, artifact_root, "policies", tolerance,
    )
    _, adapter_ref = _write_content_addressed(
        root, artifact_root, "completion-adapter", completion_report,
    )
    review_ref = _repo_reference(root, reviewed_observer_receipt_path)
    trace_contract_ref = _repo_reference(root, trace_contract_path)

    scenario_rows = []
    matched = 0
    total = 0
    for scenario_id in artifacts.SCENARIO_ID_ORDER:
        canonical = trace_rows[scenario_id]
        native_trace = native["scenarios"][scenario_id]["run_1"]["native_trace"]
        differential.validate_trace(native_trace, f"{scenario_id}.native")
        if native_trace["capture_kind"] != "native" \
                or native_trace["scenario"].get("id") != scenario_id:
            raise PromotionError(f"{scenario_id}: native trace provenance is invalid")
        _, native_ref = _write_content_addressed(
            root, artifact_root, f"traces/native/{scenario_id}", native_trace,
        )

        web_output = canonical.get("web_output")
        domain_rows = []
        materialized_web_ref = None
        canonical_web_ref = None
        web = None
        if web_output:
            if not isinstance(web_output, str) or Path(
                web_output.split("#", 1)[0]
            ).is_absolute():
                raise PromotionError(f"{scenario_id}: canonical web trace escapes repository")
            web_path = _inside(
                root,
                root / web_output.split("#", 1)[0],
                f"{scenario_id} canonical web trace",
            )
            web = differential.load_trace(web_path)
            if web["capture_kind"] != "web" \
                    or web["scenario"].get("id") != scenario_id:
                raise PromotionError(
                    f"{scenario_id}: canonical web trace provenance is invalid"
                )
            canonical_web_ref = _repo_reference(root, web_path)
            _, materialized_web_ref = _write_content_addressed(
                root, artifact_root, f"traces/web/{scenario_id}", web,
            )

        domains = canonical.get("domains")
        if not isinstance(domains, list) or not domains \
                or any(domain not in differential.TRACE_DOMAINS for domain in domains):
            raise PromotionError(f"{scenario_id}: canonical domains are invalid")
        for domain in domains:
            total += 1
            if web is None:
                domain_rows.append({
                    "domain": domain,
                    "status": "BLOCKED",
                    "frames_compared": 0,
                    "first_divergence": {
                        "frame": None,
                        "path": "web_output",
                        "reason": "canonical runtime contract has no web trace",
                        "native": native_ref,
                        "web": None,
                    },
                    "candidate": None,
                })
                continue
            report = differential.compare_trace_domain(
                native_trace, web, domain, tolerance_policy,
            )
            status = "MATCH_CANDIDATE" if report.matches else "DIVERGED"
            matched += int(report.matches)
            candidate = {
                "schema": VERSION,
                "protocol": CANDIDATE_PROTOCOL,
                "status": status,
                "promotion_allowed": False,
                "scenario": scenario_id,
                "domain": domain,
                "native_trace": native_ref,
                "web_trace": materialized_web_ref,
                "canonical_web_trace": canonical_web_ref,
                "native_suite_sha256": native["sha256"],
                "completion_adapter": adapter_ref,
                "production_observer_review": review_ref,
                "tolerance_policy": tolerance_ref,
                "comparator": COMPARATOR,
                "frames_compared": report.frames_compared,
                "first_divergence": _divergence(report.divergence),
            }
            _, candidate_ref = _write_content_addressed(
                root,
                artifact_root,
                f"domains/{scenario_id}/{domain}",
                candidate,
            )
            domain_rows.append({
                "domain": domain,
                "status": status,
                "frames_compared": report.frames_compared,
                "first_divergence": candidate["first_divergence"],
                "candidate": candidate_ref,
            })
        scenario_rows.append({
            "id": scenario_id,
            "native_trace": native_ref,
            "canonical_web_output": web_output,
            "canonical_web_trace": canonical_web_ref,
            "materialized_web_trace": materialized_web_ref,
            "domains": domain_rows,
        })

    result = {
        "schema": VERSION,
        "protocol": PROTOCOL,
        "status": "CANDIDATES_READY" if matched == total else "BLOCKED",
        "promotion_allowed": False,
        "policy": {
            "candidate_is_evidence": False,
            "candidate_can_update_runtime_contract": False,
            "review_receipt_is_external_input": True,
            "bulk_promotion": False,
            "fixture_as_native": False,
            "missing_web_trace": "BLOCKED",
            "divergence": "BLOCKED",
        },
        "sources": {
            "native_suite_sha256": native["sha256"],
            "completion_adapter": adapter_ref,
            "production_observer_review": review_ref,
            "runtime_trace_contract": trace_contract_ref,
            "tolerance_policy": tolerance_ref,
            "executable_sha256": native["executable_sha256"],
            "reviewer": review["reviewer"],
        },
        "summary": {
            "scenarios": len(scenario_rows),
            "domain_checks": total,
            "match_candidates": matched,
            "blocked_or_diverged": total - matched,
        },
        "scenarios": scenario_rows,
    }
    result["report_sha256"] = _canonical_sha256(result)
    return result


def validate_candidate_report(
    report: dict[str, Any],
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    root = root.resolve()
    report = _strict(report, {
        "schema", "protocol", "status", "promotion_allowed", "policy",
        "sources", "summary", "scenarios", "report_sha256",
    }, "promotion candidate report")
    if report["schema"] != VERSION or report["protocol"] != PROTOCOL \
            or report["promotion_allowed"] is not False:
        raise PromotionError("unsupported or promotable candidate report")
    if report["policy"] != {
        "candidate_is_evidence": False,
        "candidate_can_update_runtime_contract": False,
        "review_receipt_is_external_input": True,
        "bulk_promotion": False,
        "fixture_as_native": False,
        "missing_web_trace": "BLOCKED",
        "divergence": "BLOCKED",
    }:
        raise PromotionError("promotion candidate policy drifted")
    payload = {
        key: value for key, value in report.items() if key != "report_sha256"
    }
    if report["report_sha256"] != _canonical_sha256(payload):
        raise PromotionError("promotion candidate report hash drifted")
    sources = _strict(report["sources"], {
        "native_suite_sha256", "completion_adapter",
        "production_observer_review", "runtime_trace_contract",
        "tolerance_policy", "executable_sha256", "reviewer",
    }, "promotion candidate sources")
    for field in ("native_suite_sha256", "executable_sha256"):
        _hash(sources[field], f"sources.{field}")
    source_paths = {}
    for field in (
        "completion_adapter", "production_observer_review",
        "runtime_trace_contract", "tolerance_policy",
    ):
        source_paths[field] = _resolve_repo_reference(
            root, sources[field], f"sources.{field}",
        )
    trace_contract = _load(
        source_paths["runtime_trace_contract"],
        "runtime trace contract",
    )
    tolerance_policy = differential.load_tolerance_policy(
        source_paths["tolerance_policy"]
    )
    review = _load(
        source_paths["production_observer_review"],
        "production-observer review receipt",
    )
    if review.get("protocol") != REVIEW_PROTOCOL \
            or review.get("decision") != "APPROVED" \
            or review.get("production_observer") is not True \
            or review.get("reviewer") != sources["reviewer"]:
        raise PromotionError("production-observer review source drifted")
    canonical_rows = trace_contract.get("scenarios", [])
    if not isinstance(canonical_rows, list) \
            or [row.get("id") for row in canonical_rows if isinstance(row, dict)] \
                != list(artifacts.SCENARIO_ID_ORDER):
        raise PromotionError("runtime trace contract scenario inventory drifted")
    canonical_scenarios = {
        row.get("id"): row
        for row in canonical_rows
        if isinstance(row, dict)
    }
    scenarios = report["scenarios"]
    if not isinstance(scenarios, list) \
            or [row.get("id") for row in scenarios] \
                != list(artifacts.SCENARIO_ID_ORDER):
        raise PromotionError("promotion candidate scenario inventory drifted")
    for scenario in scenarios:
        scenario = _strict(scenario, {
            "id", "native_trace", "canonical_web_output",
            "canonical_web_trace", "materialized_web_trace", "domains",
        }, "promotion candidate scenario")
        scenario_id = scenario["id"]
        canonical = canonical_scenarios.get(scenario_id)
        if not isinstance(canonical, dict):
            raise PromotionError(f"{scenario_id}: canonical scenario is missing")
        if scenario["canonical_web_output"] != canonical.get("web_output"):
            raise PromotionError(f"{scenario_id}: canonical web output drifted")
        native_path = _resolve_repo_reference(
            root, scenario["native_trace"], f"{scenario_id}.native_trace",
        )
        native = differential.load_trace(native_path)
        if native["capture_kind"] != "native" \
                or native["scenario"].get("id") != scenario_id:
            raise PromotionError(f"{scenario_id}: materialized native trace is invalid")
        if scenario["canonical_web_output"] is None:
            if scenario["canonical_web_trace"] is not None \
                    or scenario["materialized_web_trace"] is not None:
                raise PromotionError(
                    f"{scenario_id}: absent canonical web trace was materialized"
                )
            web = None
        else:
            canonical_web_path = _resolve_repo_reference(
                root,
                scenario["canonical_web_trace"],
                f"{scenario_id}.canonical_web_trace",
            )
            if canonical_web_path != (
                root / scenario["canonical_web_output"].split("#", 1)[0]
            ).resolve():
                raise PromotionError(
                    f"{scenario_id}: canonical web reference path drifted"
                )
            materialized_web_path = _resolve_repo_reference(
                root,
                scenario["materialized_web_trace"],
                f"{scenario_id}.materialized_web_trace",
            )
            if _canonical_bytes(_load(canonical_web_path, "canonical web trace")) \
                    != _canonical_bytes(
                        _load(materialized_web_path, "materialized web trace")
                    ):
                raise PromotionError(
                    f"{scenario_id}: materialized web trace differs from canonical"
                )
            web = differential.load_trace(materialized_web_path)
            if web["capture_kind"] != "web" \
                    or web["scenario"].get("id") != scenario_id:
                raise PromotionError(
                    f"{scenario_id}: materialized web trace is invalid"
                )
        expected_domains = canonical.get("domains")
        domains = scenario["domains"]
        if not isinstance(domains, list) \
                or [row.get("domain") for row in domains] != expected_domains:
            raise PromotionError(f"{scenario_id}: domain inventory drifted")
        for domain_row in domains:
            domain_row = _strict(domain_row, {
                "domain", "status", "frames_compared",
                "first_divergence", "candidate",
            }, f"{scenario_id} domain")
            domain = domain_row["domain"]
            if web is None:
                if domain_row["status"] != "BLOCKED" \
                        or domain_row["candidate"] is not None:
                    raise PromotionError(
                        f"{scenario_id}:{domain}: missing web trace is not blocked"
                    )
                continue
            candidate_path = _resolve_repo_reference(
                root,
                domain_row["candidate"],
                f"{scenario_id}:{domain}.candidate",
            )
            candidate = _strict(_load(candidate_path, "domain candidate"), {
                "schema", "protocol", "status", "promotion_allowed",
                "scenario", "domain", "native_trace", "web_trace",
                "canonical_web_trace", "native_suite_sha256",
                "completion_adapter", "production_observer_review",
                "tolerance_policy", "comparator", "frames_compared",
                "first_divergence",
            }, f"{scenario_id}:{domain} candidate")
            if candidate["schema"] != VERSION \
                    or candidate["protocol"] != CANDIDATE_PROTOCOL \
                    or candidate["promotion_allowed"] is not False \
                    or candidate["scenario"] != scenario_id \
                    or candidate["domain"] != domain \
                    or candidate["native_trace"] != scenario["native_trace"] \
                    or candidate["web_trace"] \
                        != scenario["materialized_web_trace"] \
                    or candidate["canonical_web_trace"] \
                        != scenario["canonical_web_trace"] \
                    or candidate["native_suite_sha256"] \
                        != sources["native_suite_sha256"] \
                    or candidate["completion_adapter"] \
                        != sources["completion_adapter"] \
                    or candidate["production_observer_review"] \
                        != sources["production_observer_review"] \
                    or candidate["tolerance_policy"] \
                        != sources["tolerance_policy"] \
                    or candidate["comparator"] != COMPARATOR \
                    or candidate["status"] != domain_row["status"] \
                    or candidate["frames_compared"] \
                        != domain_row["frames_compared"] \
                    or candidate["first_divergence"] \
                        != domain_row["first_divergence"]:
                raise PromotionError(
                    f"{scenario_id}:{domain}: candidate binding drifted"
                )
            comparison = differential.compare_trace_domain(
                native, web, domain, tolerance_policy,
            )
            expected_status = (
                "MATCH_CANDIDATE" if comparison.matches else "DIVERGED"
            )
            if candidate["status"] != expected_status \
                    or candidate["frames_compared"] \
                        != comparison.frames_compared \
                    or candidate["first_divergence"] \
                        != _divergence(comparison.divergence):
                raise PromotionError(
                    f"{scenario_id}:{domain}: candidate differential drifted"
                )
    domain_rows = [
        domain for scenario in scenarios
        for domain in scenario.get("domains", [])
    ]
    matches = sum(row.get("status") == "MATCH_CANDIDATE" for row in domain_rows)
    summary = {
        "scenarios": len(scenarios),
        "domain_checks": len(domain_rows),
        "match_candidates": matches,
        "blocked_or_diverged": len(domain_rows) - matches,
    }
    if report["summary"] != summary:
        raise PromotionError("promotion candidate summary drifted")
    expected = (
        "CANDIDATES_READY"
        if matches == len(domain_rows) and domain_rows
        else "BLOCKED"
    )
    if report["status"] != expected:
        raise PromotionError("promotion candidate status drifted")
    if any(
        row.get("status") == "MATCH_CANDIDATE"
        and not isinstance(row.get("candidate"), dict)
        for row in domain_rows
    ):
        raise PromotionError("matching domain has no candidate receipt")
    return report


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(_canonical_bytes(report))
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-suite", required=True, type=Path)
    parser.add_argument("--completion-adapter", required=True, type=Path)
    parser.add_argument(
        "--reviewed-observer-receipt", required=True, type=Path,
        help="pre-existing, repository-contained external review receipt",
    )
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--tolerances",
        type=Path,
        help="optional explicit comparator policy; omitted means exact",
    )
    parser.add_argument(
        "--require-all", action="store_true",
        help="return one unless every registered scenario domain matches",
    )
    args = parser.parse_args(argv)
    try:
        report = validate_candidate_report(build_candidates(
            native_suite_path=args.native_suite,
            completion_adapter_path=args.completion_adapter,
            reviewed_observer_receipt_path=args.reviewed_observer_receipt,
            artifact_root=args.artifact_root,
            tolerance_path=args.tolerances,
        ), root=ROOT)
        _write_report(args.output, report)
    except (
        PromotionError,
        adapter.AdapterError,
        artifacts.ArtifactError,
        OSError,
        ValueError,
    ) as error:
        print(f"INVALID FLIGHT DOMAIN PROMOTION INPUT: {error}", file=sys.stderr)
        return 2
    print(
        f"{report['status']}: {report['summary']['match_candidates']}/"
        f"{report['summary']['domain_checks']} domain candidates match"
    )
    if args.require_all and report["status"] != "CANDIDATES_READY":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
