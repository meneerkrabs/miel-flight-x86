#!/usr/bin/env python3
"""Reject cross-commit regressions in native ownership, evidence and engine coverage."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FILES = {
    "contracts": "content/miel_vliegt/native_behavior_contracts.json",
    "seeds": "content/miel_vliegt/native_function_seeds.json",
    "ledger": "content/miel_vliegt/flight_parity_ledger_v2.json",
    "engine": "content/miel_vliegt/engine_implementation.json",
    "runtime": "content/miel_vliegt/flight_runtime_parity_contract.json",
}
OPTIONAL_FILES = {
    "analysis_receipt": "content/miel_vliegt/native_analysis_receipt.json",
    "completion": "content/miel_vliegt/flight_cleanroom_completion.json",
}
OWNERSHIP_RANK = {"unassigned": 0, "candidate": 1, "reviewed": 2}
EVIDENCE_RANKS = {
    "source": {"UNMAPPED": 0, "PINNED": 1},
    "native_behavior": {"UNMAPPED": 0, "PINNED": 1, "CONTRACTED": 2},
    "reachability": {"UNPROVEN": 0, "STATIC": 1, "DYNAMIC": 2},
    "runtime": {"MISSING": 0, "SUBSTITUTED": 1, "IMPLEMENTED": 2},
    "replay": {"NONE": 0, "PASS": 1},
    "differential": {"NONE": 0, "PASS": 1},
}
STATUS_RANK = {"MISSING": 0, "EQUIVALENT": 1}
ENGINE_RANK = {"MISSING": 0, "PARTIAL": 1, "EQUIVALENT": 2}
PROOF_RANK = {
    "MISSING": 0, "BLOCKED_NATIVE_OBSERVATION": 0,
    "STATIC_EQUIVALENT": 1, "EMULATED_EQUIVALENT": 2, "NATIVE_DIFFERENTIAL": 3,
}
RUNTIME_PROOF_RANK = {
    "BLOCKED_NATIVE_REFERENCE": 0,
    "WEB_POLICY_ONLY": 0,
    "PROVEN_STATIC": 1,
    "TRACE_EQUIVALENT": 2,
    "PIXEL_EQUIVALENT": 2,
}
COMPLETION_DIMENSION_FLOORS = {
    "modes": 22,
    "locations": 18,
    "gameplay_runtimes": 9,
    "semantic_claims": 631,
    "natural_edges": 48,
    "subsystems": 10,
    "assets": 3,
    "production_wiring": 33,
    "native_functions": 1369,
}
SHA256_LENGTH = 64
RUNTIME_CORRECTIONS = "content/miel_vliegt/runtime_evidence_corrections.json"
RUNTIME_CORRECTION_PROTOCOL = "miel-vliegt-reviewed-runtime-evidence-corrections"
RUNTIME_CORRECTION_REVIEWERS = {"parity-review"}
COMPLETION_PROOF_CORRECTIONS = (
    "content/miel_vliegt/completion_proof_corrections.json"
)
COMPLETION_PROOF_CORRECTION_PROTOCOL = (
    "miel-vliegt-reviewed-completion-proof-corrections"
)
PARITY_ADMISSION_PROTOCOL = "miel-vliegt-reviewed-native-parity-admissions"
PARITY_REVIEWERS = {"parity-review"}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_revision(revision: str, relative: str, root: Path = ROOT) -> dict[str, Any]:
    process = subprocess.run(
        ["git", "show", f"{revision}:{relative}"], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if process.returncode:
        raise ValueError(f"cannot read parity baseline {revision}:{relative}: {process.stderr.strip()}")
    value = json.loads(process.stdout)
    if not isinstance(value, dict):
        raise ValueError(f"parity baseline is not an object: {revision}:{relative}")
    return value


def load_optional_revision(
    revision: str, relative: str, root: Path = ROOT,
) -> dict[str, Any] | None:
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}:{relative}"], cwd=root,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if exists.returncode:
        return None
    # Parse/shape errors are evidence corruption, never absence.
    return load_revision(revision, relative, root)


def _rows(document: dict[str, Any], key: str, id_key: str = "id") -> dict[str, dict[str, Any]]:
    rows = document.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"ratchet document has no {key} array")
    result = {row.get(id_key): row for row in rows}
    if None in result or len(result) != len(rows) \
            or any(not isinstance(identifier, str) or not identifier for identifier in result):
        raise ValueError(f"ratchet document has invalid {key} ids")
    return result


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SHA256_LENGTH \
        and all(character in "0123456789abcdef" for character in value.lower())


def _completion_introduction_errors(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["completion introduction is not an object"]
    try:
        dimensions = _rows(document, "dimensions")
    except ValueError as error:
        return [f"completion introduction is invalid: {error}"]
    if set(dimensions) != set(COMPLETION_DIMENSION_FLOORS):
        return ["completion introduction differs from canonical dimensions"]
    errors = []
    for identifier, floor in COMPLETION_DIMENSION_FLOORS.items():
        dimension = dimensions[identifier]
        try:
            items = _rows(dimension, "items")
        except ValueError as error:
            errors.append(f"completion introduction is invalid: {identifier}: {error}")
            continue
        required = dimension.get("required")
        if not isinstance(required, int) or required < floor or required != len(items):
            errors.append(
                f"completion introduction is below canonical floor: {identifier} "
                f"{required!r}<{floor}"
            )
        for item_id, item in items.items():
            if item.get("status") not in {"COMPLETE", "BLOCKED"}:
                errors.append(f"completion introduction has unknown status: {identifier}:{item_id}")
            if not _valid_sha256(item.get("subject_sha256")):
                errors.append(f"completion introduction lacks subject identity: {identifier}:{item_id}")
            proof = item.get("proof_sha256")
            if item.get("status") == "COMPLETE" and not _valid_sha256(proof):
                errors.append(f"completion introduction lacks proof identity: {identifier}:{item_id}")
            if proof is not None and not _valid_sha256(proof):
                errors.append(f"completion introduction has invalid proof identity: {identifier}:{item_id}")
    summary = document.get("summary")
    if not isinstance(summary, dict) or summary.get("dimensions") != len(dimensions):
        errors.append("completion introduction has invalid derived summary")
    return errors


def _canonical_set_hash(values: set[str]) -> str:
    encoded = json.dumps(
        sorted(values), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_object_hash(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _hash_bound_evidence(evidence: Any, root: Path) -> bool:
    if not isinstance(evidence, list) or not evidence:
        return False
    for identity in evidence:
        if not isinstance(identity, dict) \
                or set(identity) not in (
                    {"path", "sha256"},
                    {"path", "json_pointer", "sha256"},
                ) \
                or not isinstance(identity.get("path"), str) \
                or Path(identity["path"]).is_absolute() \
                or not _valid_sha256(identity.get("sha256")):
            return False
        path = (root / identity["path"]).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            return False
        if not path.is_file():
            return False
        if "json_pointer" not in identity:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            pointer = identity["json_pointer"]
            if not isinstance(pointer, str) or not pointer.startswith("/"):
                return False
            try:
                value: Any = json.loads(path.read_text())
                for encoded_part in pointer[1:].split("/"):
                    part = encoded_part.replace("~1", "/").replace("~0", "~")
                    if isinstance(value, list):
                        value = value[int(part)]
                    else:
                        value = value[part]
                digest = _canonical_object_hash(value)
            except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                return False
        if digest != identity["sha256"]:
            return False
    return True


def _runtime_corrections(
    document: Any, runtime: Any, root: Path,
) -> tuple[dict[tuple[str, str], dict[str, Any]], list[str]]:
    if document is None:
        return {}, []
    if not isinstance(document, dict) or document.get("schema") != 1 \
            or document.get("protocol") != RUNTIME_CORRECTION_PROTOCOL \
            or not isinstance(document.get("corrections"), list):
        return {}, ["invalid runtime evidence correction document"]
    required = {
        "checkpoint", "field", "old", "old_sha256", "new", "new_sha256",
        "reason", "evidence", "approved_by",
    }
    checkpoints = {
        row.get("id"): row for row in runtime.get("checkpoints", [])
        if isinstance(row, dict)
    } if isinstance(runtime, dict) else {}
    result = {}
    errors = []
    for row in document["corrections"]:
        if not isinstance(row, dict) or set(row) != required:
            errors.append("invalid reviewed runtime evidence correction")
            continue
        key = (row.get("checkpoint"), row.get("field"))
        old = row.get("old")
        new = row.get("new")
        evidence = row.get("evidence")
        if not all(isinstance(value, str) and value for value in key) \
                or key in result or row.get("field") != "native_functions" \
                or not isinstance(old, list) or not isinstance(new, list) \
                or any(not isinstance(value, str) or not value for value in [*old, *new]) \
                or old != sorted(set(old)) or new != sorted(set(new)) \
                or row.get("old_sha256") != _canonical_set_hash(set(old)) \
                or row.get("new_sha256") != _canonical_set_hash(set(new)) \
                or not isinstance(row.get("reason"), str) or not row["reason"].strip() \
                or row.get("approved_by") not in RUNTIME_CORRECTION_REVIEWERS \
                or not isinstance(evidence, list) or not evidence \
                or set(checkpoints.get(row.get("checkpoint"), {}).get(
                    row.get("field"), [],
                )) != set(new):
            errors.append(f"invalid reviewed runtime evidence correction: {key}")
            continue
        if not _hash_bound_evidence(evidence, root):
            errors.append(f"runtime evidence correction is not hash-bound: {key}")
            continue
        result[key] = row
    return result, errors


def _completion_proof_corrections(
    document: Any, completion: Any, root: Path,
) -> tuple[dict[tuple[str, str], dict[str, Any]], list[str]]:
    if document is None:
        return {}, []
    if not isinstance(document, dict) or document.get("schema") != 1 \
            or document.get("protocol") != COMPLETION_PROOF_CORRECTION_PROTOCOL \
            or not isinstance(document.get("corrections"), list):
        return {}, ["invalid completion proof correction document"]
    try:
        dimensions = _rows(completion, "dimensions")
    except (AttributeError, TypeError, ValueError):
        return {}, ["invalid completion proof correction target"]
    result: dict[tuple[str, str], dict[str, Any]] = {}
    errors = []
    required = {"dimension", "items", "reason", "evidence", "approved_by"}
    item_required = {
        "item", "subject_sha256", "old_proof_sha256", "new_proof_sha256",
    }
    for correction in document["corrections"]:
        if not isinstance(correction, dict) or set(correction) != required \
                or not isinstance(correction.get("dimension"), str) \
                or not correction["dimension"] \
                or not isinstance(correction.get("items"), list) \
                or not correction["items"] \
                or not isinstance(correction.get("reason"), str) \
                or not correction["reason"].strip() \
                or correction.get("approved_by") not in PARITY_REVIEWERS:
            errors.append("invalid reviewed completion proof correction")
            continue
        dimension_id = correction["dimension"]
        try:
            current_items = _rows(dimensions.get(dimension_id, {}), "items")
        except ValueError:
            errors.append(
                f"invalid reviewed completion proof correction: {dimension_id}"
            )
            continue
        if not _hash_bound_evidence(correction.get("evidence"), root):
            errors.append(
                f"completion proof correction is not hash-bound: {dimension_id}"
            )
            continue
        for item in correction["items"]:
            old_proofs = item.get("old_proof_sha256") if isinstance(item, dict) else None
            if isinstance(old_proofs, str):
                old_proofs = [old_proofs]
            if not isinstance(item, dict) or set(item) != item_required \
                    or not isinstance(item.get("item"), str) or not item["item"] \
                    or not isinstance(old_proofs, list) or not old_proofs \
                    or old_proofs != sorted(set(old_proofs)) \
                    or not all(_valid_sha256(value) for value in old_proofs) \
                    or not _valid_sha256(item.get("subject_sha256")) \
                    or not _valid_sha256(item.get("new_proof_sha256")):
                errors.append(
                    f"invalid reviewed completion proof correction: {dimension_id}"
                )
                continue
            key = (dimension_id, item["item"])
            current_item = current_items.get(item["item"], {})
            if key in result or current_item.get("status") != "COMPLETE" \
                    or current_item.get("subject_sha256") != item["subject_sha256"] \
                    or current_item.get("proof_sha256") != item["new_proof_sha256"]:
                errors.append(
                    f"invalid reviewed completion proof correction: {key}"
                )
                continue
            result[key] = {**item, "old_proof_sha256": old_proofs}
    return result, errors


def compare(
    baseline: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    admissions: dict[str, Any],
    baseline_revision: str,
    root: Path = ROOT,
) -> list[str]:
    errors: list[str] = []
    if admissions.get("schema") != 2 \
            or admissions.get("protocol") != PARITY_ADMISSION_PROTOCOL:
        return ["unsupported native parity debt-admission schema"]

    def admitted_rows(
        key: str,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        rows = admissions.get(key, [])
        active = {}
        historical = {}
        for row in rows:
            required = {
                "id", "identity_sha256", "reason", "evidence",
                "approved_by", "baseline",
            }
            if not isinstance(row, dict) or set(row) != required \
                    or not all(
                        isinstance(row[field], str) and row[field].strip()
                        for field in ("id", "reason", "approved_by", "baseline")
                    ) \
                    or not _valid_sha256(row.get("identity_sha256")) \
                    or row.get("approved_by") not in PARITY_REVIEWERS:
                errors.append(f"invalid reviewed debt admission in {key}")
                continue
            if not _hash_bound_evidence(row.get("evidence"), root):
                errors.append(f"debt admission is not hash-bound in {key}: {row['id']}")
                continue
            destination = (
                active if row["baseline"] == baseline_revision else historical
            )
            if row["id"] in active or row["id"] in historical:
                errors.append(f"duplicate reviewed debt admission in {key}: {row['id']}")
                continue
            destination[row["id"]] = row
        return active, historical

    admitted_functions, historical_functions = admitted_rows("new_functions")
    admitted_calls, historical_calls = admitted_rows("new_indirect_call_sites")
    admitted_branches, historical_branches = admitted_rows(
        "new_indirect_branch_sites"
    )
    runtime_corrections, correction_errors = _runtime_corrections(
        current.get("runtime_corrections"), current.get("runtime"), root,
    )
    errors.extend(correction_errors)
    completion_corrections, completion_correction_errors = (
        _completion_proof_corrections(
            current.get("completion_proof_corrections"),
            current.get("completion"),
            root,
        )
    )
    errors.extend(completion_correction_errors)
    used_completion_corrections: set[tuple[str, str]] = set()

    old_completion = baseline.get("completion")
    new_completion = current.get("completion")
    if old_completion is None:
        errors.extend(_completion_introduction_errors(new_completion))
    else:
        if new_completion is None:
            errors.append("flight clean-room completion matrix disappeared")
        else:
            old_dimensions = _rows(old_completion, "dimensions")
            new_dimensions = _rows(new_completion, "dimensions")
            for dimension_id, old_dimension in old_dimensions.items():
                new_dimension = new_dimensions.get(dimension_id)
                if new_dimension is None:
                    errors.append(f"completion dimension disappeared: {dimension_id}")
                    continue
                if new_dimension.get("evidence_requirement") != old_dimension.get("evidence_requirement"):
                    errors.append(f"completion evidence requirement changed: {dimension_id}")
                old_items = _rows(old_dimension, "items")
                new_items = _rows(new_dimension, "items")
                missing = sorted(set(old_items) - set(new_items))
                if missing:
                    errors.append(
                        f"completion evidence ids disappeared: {dimension_id}:{missing}"
                    )
                regressed = sorted(
                    identifier for identifier, item in old_items.items()
                    if item.get("status") == "COMPLETE"
                    and new_items.get(identifier, {}).get("status") != "COMPLETE"
                )
                if regressed:
                    errors.append(
                        f"completion evidence regressed: {dimension_id}:{regressed}"
                    )
                for item_id, old_item in old_items.items():
                    new_item = new_items.get(item_id)
                    if new_item is None:
                        continue
                    old_subject = old_item.get("subject_sha256")
                    new_subject = new_item.get("subject_sha256")
                    if old_subject is not None and new_subject != old_subject:
                        errors.append(
                            f"completion subject changed: {dimension_id}:{item_id}"
                        )
                    old_proof = old_item.get("proof_sha256")
                    if old_item.get("status") == "COMPLETE" and old_proof is not None \
                            and new_item.get("proof_sha256") != old_proof:
                        correction = completion_corrections.get(
                            (dimension_id, item_id)
                        )
                        if correction is None \
                                or correction["subject_sha256"] != old_subject \
                                or old_proof not in correction["old_proof_sha256"] \
                                or correction["new_proof_sha256"] \
                                != new_item.get("proof_sha256"):
                            errors.append(
                                "completion proof identity changed: "
                                f"{dimension_id}:{item_id}"
                            )
                        else:
                            used_completion_corrections.add(
                                (dimension_id, item_id)
                            )
                    else:
                        correction = completion_corrections.get(
                            (dimension_id, item_id)
                        )
                        if correction is not None \
                                and old_item.get("status") == "COMPLETE" \
                                and old_subject == correction["subject_sha256"] \
                                and old_proof == correction["new_proof_sha256"]:
                            # The selected successful baseline already contains
                            # this exact reviewed rotation. Keep the immutable
                            # history without treating it as a fresh bypass.
                            used_completion_corrections.add(
                                (dimension_id, item_id)
                            )
                    old_members = old_item.get("members")
                    new_members = new_item.get("members")
                    if old_members is not None:
                        if not isinstance(old_members, dict) or not isinstance(new_members, dict):
                            errors.append(
                                f"completion member identity invalid: {dimension_id}:{item_id}"
                            )
                        else:
                            missing_members = sorted(set(old_members) - set(new_members))
                            if missing_members:
                                errors.append(
                                    "completion members disappeared: "
                                    f"{dimension_id}:{item_id}:{missing_members}"
                                )
                            changed_members = sorted(
                                member for member, digest in old_members.items()
                                if member in new_members and new_members[member] != digest
                            )
                            if changed_members:
                                errors.append(
                                    "completion member identity changed: "
                                    f"{dimension_id}:{item_id}:{changed_members}"
                                )
                old_complete = sum(
                    item.get("status") == "COMPLETE" for item in old_items.values()
                )
                new_complete = sum(
                    item.get("status") == "COMPLETE" for item in new_items.values()
                )
                if new_complete < old_complete:
                    errors.append(
                        f"completion count regressed: {dimension_id} "
                        f"{old_complete}->{new_complete}"
                    )
            unused_completion_corrections = (
                set(completion_corrections) - used_completion_corrections
            )
            unused_completion_corrections = {
                key for key in unused_completion_corrections
                if _rows(
                    old_dimensions.get(key[0], {}), "items"
                ).get(key[1], {}).get("status") == "COMPLETE"
            }
            if unused_completion_corrections:
                errors.append(
                    "unused completion proof corrections: "
                    f"{sorted(unused_completion_corrections)}"
                )

    old_receipt = baseline.get("analysis_receipt")
    new_receipt = current.get("analysis_receipt")
    if old_receipt is not None:
        if new_receipt is None:
            errors.append("tracked native analysis receipt disappeared")
        else:
            old_exact = {row["address"]: row for row in old_receipt["functions"]}
            new_exact = {row["address"]: row for row in new_receipt["functions"]}
            for address, old in old_exact.items():
                new = new_exact.get(address)
                if new is None:
                    errors.append(f"native analyzed function disappeared: {address}")
                    continue
                for field in ("end", "sha256"):
                    if new.get(field) != old.get(field):
                        errors.append(f"native analyzed identity changed: {address}.{field}")
                before = old["ownership_status"]
                after = new["ownership_status"]
                if OWNERSHIP_RANK[after] < OWNERSHIP_RANK[before]:
                    errors.append(f"native ownership regressed: {address} {before}->{after}")
                old_disposition = old["ownership_disposition"]
                new_disposition = new["ownership_disposition"]
                if old_disposition != "UNKNOWN" and new_disposition != old_disposition:
                    errors.append(
                        f"native ownership disposition changed: {address} "
                        f"{old_disposition}->{new_disposition}"
                    )
            unexpected = set(new_exact) - set(old_exact) - set(admitted_functions)
            if unexpected:
                errors.append(f"new native analyzed functions lack admission: {sorted(unexpected)}")
            for field, admitted in (
                ("unresolved_indirect_calls", admitted_calls),
                ("unresolved_indirect_branches", admitted_branches),
            ):
                added = set(new_receipt[field]) - set(old_receipt[field]) - set(admitted)
                if added:
                    errors.append(f"new native {field} lack admission: {sorted(added)}")
                admission_kind = (
                    "unresolved_indirect_call"
                    if field == "unresolved_indirect_calls"
                    else "unresolved_indirect_branch"
                )
                introduced = set(new_receipt[field]) - set(old_receipt[field])
                for site_id, admission in admitted.items():
                    if site_id not in introduced:
                        errors.append(
                            f"unused reviewed debt admission in {field}: {site_id}"
                        )
                    elif admission["identity_sha256"] != _canonical_object_hash({
                        "kind": admission_kind,
                        "address": site_id,
                    }):
                        errors.append(
                            f"native site admission identity changed: {site_id}"
                        )
            for field, historical, admission_kind in (
                (
                    "unresolved_indirect_calls",
                    historical_calls,
                    "unresolved_indirect_call",
                ),
                (
                    "unresolved_indirect_branches",
                    historical_branches,
                    "unresolved_indirect_branch",
                ),
            ):
                old_sites = set(old_receipt[field])
                new_sites = set(new_receipt[field])
                for site_id, admission in historical.items():
                    if site_id not in old_sites or site_id not in new_sites \
                            or admission["identity_sha256"] \
                            != _canonical_object_hash({
                                "kind": admission_kind,
                                "address": site_id,
                            }):
                        errors.append(
                            f"invalid debt-admission baseline in {field}: {site_id}"
                        )

    def seed_functions(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {row["address"]: row for row in document.get("functions", [])}

    old_functions = seed_functions(baseline["seeds"])
    new_functions = seed_functions(current["seeds"])
    for function_id, old in old_functions.items():
        new = new_functions.get(function_id)
        if new is None:
            errors.append(f"reviewed native seed disappeared: {function_id}")
            continue
        for field in ("name", "module", "signature_sha256", "signature_length"):
            if new.get(field) != old.get(field):
                errors.append(f"reviewed native seed changed: {function_id}.{field}")
    for function_id, admission in admitted_functions.items():
        identity = new_functions.get(function_id)
        if function_id not in set(new_functions) - set(old_functions):
            errors.append(
                f"unused reviewed debt admission in new_functions: {function_id}"
            )
        elif identity is None:
            errors.append(f"admitted native function is absent: {function_id}")
        elif admission["identity_sha256"] != _canonical_object_hash(identity):
            errors.append(f"native function admission identity changed: {function_id}")
    for function_id, admission in historical_functions.items():
        old_identity = old_functions.get(function_id)
        new_identity = new_functions.get(function_id)
        if old_identity is None or new_identity != old_identity \
                or admission["identity_sha256"] \
                != _canonical_object_hash(old_identity):
            errors.append(
                f"invalid debt-admission baseline in new_functions: {function_id}"
            )
    unexpected_functions = (
        set(new_functions) - set(old_functions) - set(admitted_functions)
    )
    if unexpected_functions:
        errors.append(f"new reviewed native seeds lack admission: {sorted(unexpected_functions)}")

    old_coverage = baseline["ledger"].get("native_coverage", {})
    new_coverage = current["ledger"].get("native_coverage", {})
    for field, admissions_for_field in (
        ("unknown_function_ownership", admitted_functions),
        ("unresolved_indirect_call_sites", admitted_calls),
        ("unresolved_indirect_branch_sites", admitted_branches),
    ):
        before, after = old_coverage.get(field), new_coverage.get(field)
        if not isinstance(before, int) or not isinstance(after, int):
            errors.append(f"native coverage count missing: {field}")
        elif after > before + len(admissions_for_field):
            errors.append(f"native coverage debt increased: {field} {before}->{after}")
    if new_coverage.get("reviewed_game_owned", 0) < old_coverage.get("reviewed_game_owned", 0):
        errors.append("reviewed native game ownership decreased")

    old_records = _rows(baseline["ledger"], "records")
    new_records = _rows(current["ledger"], "records")
    old_contracts = _rows(baseline["contracts"], "behaviors")
    new_contracts = _rows(current["contracts"], "behaviors")
    for behavior_id, old in old_contracts.items():
        new = new_contracts.get(behavior_id)
        if new is None:
            errors.append(f"native behavior contract disappeared: {behavior_id}")
            continue
        for field in ("class", "minimum_evidence"):
            if new.get(field) != old.get(field):
                errors.append(f"native behavior contract changed: {behavior_id}.{field}")
        if new.get("native_units") != old.get("native_units"):
            errors.append(f"native behavior contract units changed: {behavior_id}")
        if not set(old.get("sources", [])).issubset(new.get("sources", [])):
            errors.append(f"native behavior contract evidence shrank: {behavior_id}.sources")
    for behavior_id, old in old_records.items():
        new = new_records.get(behavior_id)
        if new is None:
            errors.append(f"behavior disappeared: {behavior_id}")
            continue
        if old["disposition"] == "REQUIRED" and new["disposition"] != "REQUIRED":
            errors.append(f"required behavior was descoped/substituted: {behavior_id}")
        for facet, ranks in EVIDENCE_RANKS.items():
            before, after = old["evidence"][facet], new["evidence"][facet]
            if ranks[after] < ranks[before]:
                errors.append(f"behavior evidence regressed: {behavior_id}.{facet} {before}->{after}")
        before = old.get("derived_status")
        after = new.get("derived_status")
        if before not in STATUS_RANK or after not in STATUS_RANK:
            errors.append(f"unknown behavior status: {behavior_id} {before!r}->{after!r}")
        elif STATUS_RANK[after] < STATUS_RANK[before]:
            errors.append(f"behavior status regressed: {behavior_id} {before}->{after}")
        old_proof = old.get(
            "proof_level", "STATIC_EQUIVALENT" if before == "EQUIVALENT" else "MISSING"
        )
        new_proof = new.get(
            "proof_level", "STATIC_EQUIVALENT" if after == "EQUIVALENT" else "MISSING"
        )
        if old_proof not in PROOF_RANK or new_proof not in PROOF_RANK:
            errors.append(f"unknown behavior proof: {behavior_id} {old_proof!r}->{new_proof!r}")
        elif PROOF_RANK[new_proof] < PROOF_RANK[old_proof]:
            errors.append(f"behavior proof regressed: {behavior_id} {old_proof}->{new_proof}")

    def engine_rows(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
        rows = [*document.get("subsystems", []), *document.get("gameplay_runtimes", [])]
        return {row["id"]: row for row in rows}

    old_engine, new_engine = engine_rows(baseline["engine"]), engine_rows(current["engine"])
    for engine_id, old in old_engine.items():
        new = new_engine.get(engine_id)
        if new is None:
            errors.append(f"engine boundary disappeared: {engine_id}")
            continue
        before, after = old["disposition"], new["disposition"]
        if before not in ENGINE_RANK and before != "PLATFORM_SUBSTITUTION" \
                or after not in ENGINE_RANK and after != "PLATFORM_SUBSTITUTION":
            errors.append(f"unknown engine disposition: {engine_id} {before!r}->{after!r}")
        elif before == "PLATFORM_SUBSTITUTION" and after != before:
            errors.append(f"platform boundary changed disposition: {engine_id}")
        elif before != "PLATFORM_SUBSTITUTION" and after == "PLATFORM_SUBSTITUTION":
            errors.append(f"engine boundary was replaced by a platform substitution: {engine_id}")
        elif before in ENGINE_RANK and after in ENGINE_RANK and ENGINE_RANK[after] < ENGINE_RANK[before]:
            errors.append(f"engine boundary regressed: {engine_id} {before}->{after}")

    old_checkpoints = _rows(baseline["runtime"], "checkpoints")
    new_checkpoints = _rows(current["runtime"], "checkpoints")
    for checkpoint_id, old in old_checkpoints.items():
        new = new_checkpoints.get(checkpoint_id)
        if new is None:
            errors.append(f"flight runtime checkpoint disappeared: {checkpoint_id}")
            continue
        if new.get("domain") != old.get("domain"):
            errors.append(f"flight runtime checkpoint changed domain: {checkpoint_id}")
        before, after = old.get("status"), new.get("status")
        if before not in RUNTIME_PROOF_RANK or after not in RUNTIME_PROOF_RANK:
            errors.append(f"flight runtime checkpoint has unknown proof status: {checkpoint_id}")
        elif RUNTIME_PROOF_RANK[after] < RUNTIME_PROOF_RANK[before]:
            errors.append(f"flight runtime proof regressed: {checkpoint_id} {before}->{after}")
        if old.get("release_gate") is True and new.get("release_gate") is not True:
            errors.append(f"flight runtime release gate was weakened: {checkpoint_id}")
        for field in ("required_scenarios", "native_functions", "native_fields"):
            old_values = set(old.get(field, []))
            new_values = set(new.get(field, []))
            if not old_values.issubset(new_values):
                correction = runtime_corrections.get((checkpoint_id, field))
                if correction is None or set(correction["old"]) != old_values \
                        or set(correction["new"]) != new_values:
                    errors.append(f"flight runtime evidence shrank: {checkpoint_id}.{field}")
        for field in ("native_function", "native_address", "web_owner"):
            if old.get(field) is not None and new.get(field) != old.get(field):
                errors.append(f"flight runtime evidence pin changed: {checkpoint_id}.{field}")
        if old.get("assertion_limit") and not new.get("assertion_limit"):
            errors.append(f"flight runtime assertion limit disappeared: {checkpoint_id}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-revision", required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--admissions", type=Path,
        default=ROOT / "content/miel_vliegt/native_parity_debt_admissions.json",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    revision_process = subprocess.run(
        ["git", "rev-parse", "--verify", f"{args.baseline_revision}^{{commit}}"], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if revision_process.returncode:
        raise SystemExit(f"invalid parity baseline revision: {revision_process.stderr.strip()}")
    baseline_revision = revision_process.stdout.strip()
    baseline = {key: load_revision(baseline_revision, path, root) for key, path in FILES.items()}
    current = {key: load(root / path) for key, path in FILES.items()}
    current["runtime_corrections"] = load(root / RUNTIME_CORRECTIONS)
    current["completion_proof_corrections"] = load(
        root / COMPLETION_PROOF_CORRECTIONS
    )
    for key, path in OPTIONAL_FILES.items():
        baseline[key] = load_optional_revision(baseline_revision, path, root)
        current[key] = load(root / path)
    errors = compare(baseline, current, load(args.admissions), baseline_revision)
    if errors:
        raise SystemExit("native parity ratchet failed:\n- " + "\n- ".join(errors))
    print("native parity ratchet OK: ownership, control-flow, behavior and engine debt did not regress")


if __name__ == "__main__":
    main()
