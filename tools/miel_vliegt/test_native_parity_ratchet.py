#!/usr/bin/env python3
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.verify_native_parity_ratchet import (
    ROOT,
    _completion_proof_corrections,
    _hash_bound_evidence,
    compare,
    load,
    load_optional_revision,
)


def parity_fixture():
    """Small deterministic corpus for testing ratchet rules without private ISO output."""
    return {
        "contracts": {
            "behaviors": [{
                "id": "behavior.fixture", "class": "gameplay",
                "minimum_evidence": "native", "native_units": ["fn_fixture"],
                "sources": ["fixture"],
            }],
        },
        "seeds": {
            "functions": [{
                "address": "0x00100000", "name": "fixture", "module": "test",
                "signature_sha256": "a" * 64, "signature_length": 4,
            }],
        },
        "ledger": {
            "native_coverage": {
                "unknown_function_ownership": 10,
                "unresolved_indirect_call_sites": 20,
                "unresolved_indirect_branch_sites": 3,
                "reviewed_game_owned": 1,
            },
            "records": [{
                "id": "behavior.fixture", "disposition": "REQUIRED",
                "evidence": {
                    "source": "PINNED", "native_behavior": "CONTRACTED",
                    "reachability": "DYNAMIC", "runtime": "IMPLEMENTED",
                    "replay": "PASS", "differential": "PASS",
                },
                "derived_status": "EQUIVALENT",
                "proof_level": "NATIVE_DIFFERENTIAL",
            }],
        },
        "engine": {
            "subsystems": [],
            "gameplay_runtimes": [{"id": "runtime.fixture", "disposition": "PARTIAL"}],
        },
        "runtime": {
            "checkpoints": [{
                "id": "physics.fixture", "domain": "physics",
                "status": "BLOCKED_NATIVE_REFERENCE",
                "required_scenarios": ["takeoff"],
                "native_functions": ["0x0040e610"],
                "web_owner": "src/fixture.js",
                "assertion_limit": "Native response is not captured.",
                "release_gate": True,
            }],
        },
        "completion": {
            "dimensions": [{
                "id": "semantic_claims",
                "evidence_requirement": "CLAIM_BOUND_RUNTIME_SEMANTIC_EVIDENCE",
                "items": [
                    {"id": "claim.proven", "status": "COMPLETE"},
                    {"id": "claim.pending", "status": "BLOCKED"},
                ],
            }],
        },
        "analysis_receipt": {
            "functions": [{
                "address": "0x00100000", "end": "0x00100010", "sha256": "b" * 64,
                "ownership_status": "reviewed", "ownership_disposition": "GAME_OWNED",
            }],
            "unresolved_indirect_calls": ["0x00100004"],
            "unresolved_indirect_branches": ["0x00100008"],
        },
    }


class NativeParityRatchetTests(unittest.TestCase):
    def setUp(self):
        self.baseline_revision = "a" * 40
        self.current = parity_fixture()
        self.evidence_path = Path(
            "content/miel_vliegt/native_flight_state_layout.json"
        )
        self.evidence_sha = hashlib.sha256(
            self.evidence_path.read_bytes()
        ).hexdigest()
        self.admissions = {
            "schema": 2,
            "protocol": "miel-vliegt-reviewed-native-parity-admissions",
            "new_functions": [],
            "new_indirect_call_sites": [], "new_indirect_branch_sites": [],
        }

    def errors(self, baseline, current=None, admissions=None):
        return compare(
            baseline, current or self.current, admissions or self.admissions,
            self.baseline_revision,
        )

    def test_fixture_is_a_valid_noop_comparison(self):
        self.assertEqual(self.errors(copy.deepcopy(self.current)), [])

    def test_reviewed_ownership_cannot_regress(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["seeds"]["functions"][0]["name"] = "rewritten"
        self.assertTrue(any("native seed changed" in error for error in self.errors(baseline, current)))

    def test_new_indirect_site_requires_admission(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["ledger"]["native_coverage"]["unresolved_indirect_call_sites"] += 1
        self.assertTrue(any("coverage debt increased" in error for error in self.errors(baseline, current)))

    def test_exact_indirect_site_replacement_cannot_hide_behind_equal_totals(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["analysis_receipt"]["unresolved_indirect_calls"] = ["0x00100005"]
        self.assertTrue(any(
            "unresolved_indirect_calls" in error
            for error in self.errors(baseline, current)
        ))

    def test_exact_native_identity_and_ownership_cannot_regress(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["analysis_receipt"]["functions"][0]["sha256"] = "c" * 64
        current["analysis_receipt"]["functions"][0]["ownership_status"] = "candidate"
        errors = self.errors(baseline, current)
        self.assertTrue(any("analyzed identity changed" in error for error in errors))
        self.assertTrue(any("ownership regressed" in error for error in errors))

    def test_behavior_and_engine_evidence_cannot_regress(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        record = next(row for row in current["ledger"]["records"] if row["evidence"]["differential"] == "PASS")
        record["evidence"]["differential"] = "NONE"
        runtime = next(row for row in current["engine"]["gameplay_runtimes"] if row["disposition"] == "PARTIAL")
        runtime["disposition"] = "MISSING"
        errors = self.errors(baseline, current)
        self.assertTrue(any("evidence regressed" in error for error in errors))
        self.assertTrue(any("engine boundary regressed" in error for error in errors))

    def test_engine_cannot_escape_to_platform_substitution(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        runtime = next(row for row in current["engine"]["gameplay_runtimes"] if row["disposition"] == "PARTIAL")
        runtime["disposition"] = "PLATFORM_SUBSTITUTION"
        self.assertTrue(any(
            "replaced by a platform substitution" in error
            for error in self.errors(baseline, current)
        ))

    def test_native_behavior_contract_cannot_be_redefined(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["contracts"]["behaviors"][0]["native_units"] = []
        self.assertTrue(any(
            "contract units changed" in error
            for error in self.errors(baseline, current)
        ))

    def test_flight_runtime_gate_and_scenarios_cannot_shrink(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        checkpoint = current["runtime"]["checkpoints"][0]
        checkpoint["release_gate"] = False
        checkpoint["required_scenarios"] = []
        errors = self.errors(baseline, current)
        self.assertTrue(any("release gate was weakened" in error for error in errors))
        self.assertTrue(any("required_scenarios" in error for error in errors))

    def test_reviewed_runtime_identity_correction_is_exact_and_persistent(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        old = ["0x00401000", "0x00402000"]
        new = ["0x00403000"]
        baseline["runtime"]["checkpoints"][0]["native_functions"] = old
        current["runtime"]["checkpoints"][0]["native_functions"] = new
        evidence_path = Path("content/miel_vliegt/native_flight_state_layout.json")
        evidence_sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

        def set_hash(values):
            return hashlib.sha256(json.dumps(
                sorted(values), sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()

        correction = {
            "checkpoint": "physics.fixture",
            "field": "native_functions",
            "old": old,
            "old_sha256": set_hash(old),
            "new": new,
            "new_sha256": set_hash(new),
            "reason": "Replace a reviewed mislabel with its exact owner.",
            "evidence": [{"path": str(evidence_path), "sha256": evidence_sha}],
            "approved_by": "parity-review",
        }
        current["runtime_corrections"] = {
            "schema": 1,
            "protocol": "miel-vliegt-reviewed-runtime-evidence-corrections",
            "corrections": [correction],
        }
        self.assertFalse(any(
            "flight runtime evidence shrank" in error
            for error in self.errors(baseline, current)
        ))

        already_corrected = copy.deepcopy(current)
        self.assertEqual(self.errors(current, already_corrected), [])

        unreviewed = copy.deepcopy(current)
        unreviewed["runtime_corrections"]["corrections"][0]["new"] = ["0x00404000"]
        self.assertTrue(any(
            "invalid reviewed runtime evidence correction" in error
            for error in self.errors(baseline, unreviewed)
        ))

    def test_hash_bound_evidence_can_pin_a_stable_json_subtree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.json"
            artifact.write_text(json.dumps({
                "stable": {"address": "0x00401000"},
                "unrelated": 1,
            }), encoding="utf-8")
            stable_hash = hashlib.sha256(json.dumps(
                {"address": "0x00401000"},
                sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest()
            evidence = [{
                "path": "evidence.json",
                "json_pointer": "/stable",
                "sha256": stable_hash,
            }]
            self.assertTrue(_hash_bound_evidence(evidence, root))
            artifact.write_text(json.dumps({
                "stable": {"address": "0x00401000"},
                "unrelated": 2,
            }), encoding="utf-8")
            self.assertTrue(_hash_bound_evidence(evidence, root))
            artifact.write_text(json.dumps({
                "stable": {"address": "0x00402000"},
                "unrelated": 2,
            }), encoding="utf-8")
            self.assertFalse(_hash_bound_evidence(evidence, root))

    def test_flight_runtime_proof_cannot_regress(self):
        baseline = copy.deepcopy(self.current)
        baseline["runtime"]["checkpoints"][0]["status"] = "TRACE_EQUIVALENT"
        current = copy.deepcopy(self.current)
        self.assertTrue(any(
            "flight runtime proof regressed" in error
            for error in self.errors(baseline, current)
        ))

    def test_flight_runtime_checkpoint_cannot_disappear_or_change_owner(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["runtime"]["checkpoints"][0]["web_owner"] = "src/elsewhere.js"
        errors = self.errors(baseline, current)
        self.assertTrue(any("web_owner" in error for error in errors))
        current["runtime"]["checkpoints"] = []
        self.assertTrue(any(
            "runtime checkpoint disappeared" in error
            for error in self.errors(baseline, current)
        ))

    def test_completion_evidence_ids_and_proven_items_are_monotonic(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["completion"]["dimensions"][0]["items"] = [
            {"id": "claim.pending", "status": "BLOCKED"},
        ]
        errors = self.errors(baseline, current)
        self.assertTrue(any("evidence ids disappeared" in error for error in errors))
        self.assertTrue(any("evidence regressed" in error for error in errors))
        self.assertTrue(any("count regressed" in error for error in errors))

    def test_completion_may_add_or_promote_stable_evidence(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["completion"]["dimensions"][0]["items"][1]["status"] = "COMPLETE"
        current["completion"]["dimensions"][0]["items"].append({
            "id": "claim.new", "status": "BLOCKED",
        })
        self.assertEqual(self.errors(baseline, current), [])

    def test_completion_requirement_and_dimension_cannot_disappear(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["completion"]["dimensions"][0]["evidence_requirement"] = "WEAKER"
        self.assertTrue(any(
            "evidence requirement changed" in error
            for error in self.errors(baseline, current)
        ))
        current["completion"]["dimensions"] = []
        self.assertTrue(any(
            "completion dimension disappeared" in error
            for error in self.errors(baseline, current)
        ))

    def test_completion_subject_and_completed_proof_identity_cannot_change(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        for document in (baseline, current):
            for item in document["completion"]["dimensions"][0]["items"]:
                item["subject_sha256"] = "1" * 64
                item["proof_sha256"] = "2" * 64 if item["status"] == "COMPLETE" else None
        current["completion"]["dimensions"][0]["items"][0]["subject_sha256"] = "3" * 64
        current["completion"]["dimensions"][0]["items"][0]["proof_sha256"] = "4" * 64
        errors = self.errors(baseline, current)
        self.assertTrue(any("completion subject changed" in error for error in errors))
        self.assertTrue(any("completion proof identity changed" in error for error in errors))

    def test_completion_proof_rotation_requires_exact_hash_bound_correction(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        for document in (baseline, current):
            item = document["completion"]["dimensions"][0]["items"][0]
            item["subject_sha256"] = "1" * 64
            item["proof_sha256"] = "2" * 64
        current["completion"]["dimensions"][0]["items"][0]["proof_sha256"] = "3" * 64
        correction = {
            "dimension": "semantic_claims",
            "items": [{
                "item": "claim.proven",
                "subject_sha256": "1" * 64,
                "old_proof_sha256": "2" * 64,
                "new_proof_sha256": "3" * 64,
            }],
            "reason": "Rotate the proof after reviewed evidence improved.",
            "evidence": [{
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha,
            }],
            "approved_by": "parity-review",
        }
        current["completion_proof_corrections"] = {
            "schema": 1,
            "protocol": "miel-vliegt-reviewed-completion-proof-corrections",
            "corrections": [correction],
        }
        self.assertFalse(any(
            "completion proof identity changed" in error
            for error in self.errors(baseline, current)
        ))

        forged = copy.deepcopy(current)
        forged["completion_proof_corrections"]["corrections"][0][
            "items"
        ][0]["new_proof_sha256"] = "4" * 64
        forged_errors = self.errors(baseline, forged)
        self.assertTrue(any(
            "invalid reviewed completion proof correction" in error
            for error in forged_errors
        ))
        self.assertTrue(any(
            "completion proof identity changed" in error
            for error in forged_errors
        ))

        stale = copy.deepcopy(current)
        stale["completion_proof_corrections"]["corrections"][0][
            "evidence"
        ][0]["sha256"] = "0" * 64
        stale_errors = self.errors(baseline, stale)
        self.assertTrue(any(
            "completion proof correction is not hash-bound" in error
            for error in stale_errors
        ))
        self.assertTrue(any(
            "completion proof identity changed" in error
            for error in stale_errors
        ))

    def test_tracked_completion_proof_corrections_match_current_evidence(self):
        document = load(
            ROOT / "content/miel_vliegt/completion_proof_corrections.json"
        )
        completion = load(
            ROOT / "content/miel_vliegt/flight_cleanroom_completion.json"
        )
        corrections, errors = _completion_proof_corrections(
            document, completion, ROOT
        )
        expected = {
            (correction["dimension"], item["item"])
            for correction in document["corrections"]
            for item in correction["items"]
        }
        self.assertEqual(errors, [])
        self.assertEqual(set(corrections), expected)

    def test_unrelated_completion_proof_correction_is_rejected(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        for document, proof in ((baseline, "4" * 64), (current, "3" * 64)):
            item = document["completion"]["dimensions"][0]["items"][0]
            item["subject_sha256"] = "1" * 64
            item["proof_sha256"] = proof
        current["completion_proof_corrections"] = {
            "schema": 1,
            "protocol": "miel-vliegt-reviewed-completion-proof-corrections",
            "corrections": [{
                "dimension": "semantic_claims",
                "items": [{
                    "item": "claim.proven",
                    "subject_sha256": "1" * 64,
                    "old_proof_sha256": "2" * 64,
                    "new_proof_sha256": "3" * 64,
                }],
                "reason": "Unrelated proof rotation.",
                "evidence": [{
                    "path": str(self.evidence_path),
                    "sha256": self.evidence_sha,
                }],
                "approved_by": "parity-review",
            }],
        }
        errors = self.errors(baseline, current)
        self.assertTrue(any(
            "completion proof identity changed" in error for error in errors
        ))
        self.assertTrue(any(
            "unused completion proof corrections" in error for error in errors
        ))

    def test_applied_completion_proof_correction_may_remain_as_history(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        for document in (baseline, current):
            item = document["completion"]["dimensions"][0]["items"][0]
            item["subject_sha256"] = "1" * 64
            item["proof_sha256"] = "3" * 64
        current["completion_proof_corrections"] = {
            "schema": 1,
            "protocol": "miel-vliegt-reviewed-completion-proof-corrections",
            "corrections": [{
                "dimension": "semantic_claims",
                "items": [{
                    "item": "claim.proven",
                    "subject_sha256": "1" * 64,
                    "old_proof_sha256": "2" * 64,
                    "new_proof_sha256": "3" * 64,
                }],
                "reason": "Previously reviewed proof rotation.",
                "evidence": [{
                    "path": str(self.evidence_path),
                    "sha256": self.evidence_sha,
                }],
                "approved_by": "parity-review",
            }],
        }
        self.assertEqual(self.errors(baseline, current), [])

    def test_completion_correction_accepts_only_listed_predecessor_proofs(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        for document, proof in ((baseline, "4" * 64), (current, "3" * 64)):
            item = document["completion"]["dimensions"][0]["items"][0]
            item["subject_sha256"] = "1" * 64
            item["proof_sha256"] = proof
        current["completion_proof_corrections"] = {
            "schema": 1,
            "protocol": "miel-vliegt-reviewed-completion-proof-corrections",
            "corrections": [{
                "dimension": "semantic_claims",
                "items": [{
                    "item": "claim.proven",
                    "subject_sha256": "1" * 64,
                    "old_proof_sha256": ["2" * 64, "4" * 64],
                    "new_proof_sha256": "3" * 64,
                }],
                "reason": "Collapse two reviewed predecessors into one proof.",
                "evidence": [{
                    "path": str(self.evidence_path),
                    "sha256": self.evidence_sha,
                }],
                "approved_by": "parity-review",
            }],
        }
        self.assertEqual(self.errors(baseline, current), [])

        unlisted = copy.deepcopy(baseline)
        unlisted["completion"]["dimensions"][0]["items"][0][
            "proof_sha256"
        ] = "5" * 64
        errors = self.errors(unlisted, current)
        self.assertTrue(any(
            "completion proof identity changed" in error for error in errors
        ))
        self.assertTrue(any(
            "unused completion proof corrections" in error for error in errors
        ))

    def test_correction_for_baseline_blocked_item_is_dormant_not_unused(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        baseline_item = baseline["completion"]["dimensions"][0]["items"][1]
        current_item = current["completion"]["dimensions"][0]["items"][1]
        baseline_item["subject_sha256"] = "1" * 64
        baseline_item["proof_sha256"] = None
        current_item["status"] = "COMPLETE"
        current_item["subject_sha256"] = "1" * 64
        current_item["proof_sha256"] = "3" * 64
        current["completion_proof_corrections"] = {
            "schema": 1,
            "protocol": "miel-vliegt-reviewed-completion-proof-corrections",
            "corrections": [{
                "dimension": "semantic_claims",
                "items": [{
                    "item": "claim.pending",
                    "subject_sha256": "1" * 64,
                    "old_proof_sha256": ["2" * 64],
                    "new_proof_sha256": "3" * 64,
                }],
                "reason": "A later baseline may need this exact predecessor.",
                "evidence": [{
                    "path": str(self.evidence_path),
                    "sha256": self.evidence_sha,
                }],
                "approved_by": "parity-review",
            }],
        }
        self.assertEqual(self.errors(baseline, current), [])

    def test_asset_member_deletion_cannot_hide_behind_a_complete_aggregate(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        for document in (baseline, current):
            item = document["completion"]["dimensions"][0]["items"][0]
            item["members"] = {"absence:a": "a" * 64, "absence:b": "b" * 64}
        del current["completion"]["dimensions"][0]["items"][0]["members"]["absence:b"]
        self.assertTrue(any(
            "completion members disappeared" in error
            for error in self.errors(baseline, current)
        ))

    def test_first_completion_introduction_must_meet_canonical_floor(self):
        baseline = copy.deepcopy(self.current)
        baseline["completion"] = None
        current = copy.deepcopy(self.current)
        current["completion"] = {"dimensions": [], "summary": {"release_ready": True}}
        self.assertTrue(any(
            "completion introduction" in error
            for error in self.errors(baseline, current)
        ))

    def test_malformed_optional_baseline_is_not_treated_as_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"],
                           cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Parity Test"],
                           cwd=root, check=True)
            artifact = root / "completion.json"
            artifact.write_text("{not-json\n", encoding="utf-8")
            subprocess.run(["git", "add", "completion.json"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True,
            ).strip()
            with self.assertRaises(json.JSONDecodeError):
                load_optional_revision(revision, "completion.json", root)

    def test_unknown_statuses_fail_before_ranking(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        current["ledger"]["records"][0]["derived_status"] = "BOGUS"
        current["ledger"]["records"][0]["proof_level"] = "BOGUS"
        current["engine"]["gameplay_runtimes"][0]["disposition"] = "BOGUS"
        errors = self.errors(baseline, current)
        self.assertTrue(any("unknown behavior status" in error for error in errors))
        self.assertTrue(any("unknown behavior proof" in error for error in errors))
        self.assertTrue(any("unknown engine disposition" in error for error in errors))

    def test_admitted_new_function_is_visible_but_allowed(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        row = copy.deepcopy(current["seeds"]["functions"][0])
        row["address"] = "0x00ffffff"
        current["seeds"]["functions"].append(row)
        admissions = copy.deepcopy(self.admissions)
        admissions["new_functions"].append({
            "id": row["address"],
            "identity_sha256": hashlib.sha256(json.dumps(
                row, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
            "reason": "analyzer now recovers a previously hidden function",
            "evidence": [{
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha,
            }],
            "approved_by": "parity-review",
            "baseline": self.baseline_revision,
        })
        self.assertEqual(self.errors(baseline, current, admissions), [])

    def test_new_function_admission_is_bound_to_identity_and_evidence(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        row = copy.deepcopy(current["seeds"]["functions"][0])
        row["address"] = "0x00fffffc"
        current["seeds"]["functions"].append(row)
        admissions = copy.deepcopy(self.admissions)
        admissions["new_functions"].append({
            "id": row["address"],
            "identity_sha256": "0" * 64,
            "reason": "analyzer now recovers a previously hidden function",
            "evidence": [{
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha,
            }],
            "approved_by": "parity-review",
            "baseline": self.baseline_revision,
        })
        self.assertTrue(any(
            "admission identity changed" in error
            for error in self.errors(baseline, current, admissions)
        ))

        admissions["new_functions"][0]["identity_sha256"] = hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        admissions["new_functions"][0]["evidence"][0]["sha256"] = "0" * 64
        self.assertTrue(any(
            "debt admission is not hash-bound" in error
            for error in self.errors(baseline, current, admissions)
        ))

    def test_unused_new_function_admission_is_rejected(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        row = current["seeds"]["functions"][0]
        admissions = copy.deepcopy(self.admissions)
        admissions["new_functions"].append({
            "id": row["address"],
            "identity_sha256": hashlib.sha256(json.dumps(
                row, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
            "reason": "Admission must not outlive its exact introduction.",
            "evidence": [{
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha,
            }],
            "approved_by": "parity-review",
            "baseline": self.baseline_revision,
        })
        self.assertTrue(any(
            "unused reviewed debt admission in new_functions" in error
            for error in self.errors(baseline, current, admissions)
        ))

    def test_indirect_site_admission_is_exact_and_cannot_be_reused(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        site = "0x0010000c"
        current["analysis_receipt"]["unresolved_indirect_calls"].append(site)
        current["ledger"]["native_coverage"]["unresolved_indirect_call_sites"] += 1
        admissions = copy.deepcopy(self.admissions)
        admission = {
            "id": site,
            "identity_sha256": hashlib.sha256(json.dumps(
                {"kind": "unresolved_indirect_call", "address": site},
                sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
            "reason": "Admit one newly recovered unresolved call site.",
            "evidence": [{
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha,
            }],
            "approved_by": "parity-review",
            "baseline": self.baseline_revision,
        }
        admissions["new_indirect_call_sites"].append(admission)
        self.assertEqual(self.errors(baseline, current, admissions), [])

        forged = copy.deepcopy(admissions)
        forged["new_indirect_call_sites"][0]["identity_sha256"] = "0" * 64
        self.assertTrue(any(
            "native site admission identity changed" in error
            for error in self.errors(baseline, current, forged)
        ))

        orphan = copy.deepcopy(self.current)
        self.assertTrue(any(
            "unused reviewed debt admission in unresolved_indirect_calls" in error
            for error in self.errors(baseline, orphan, admissions)
        ))

    def test_empty_reason_cannot_admit_new_debt(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        row = copy.deepcopy(current["seeds"]["functions"][0])
        row["address"] = "0x00fffffe"
        current["seeds"]["functions"].append(row)
        admissions = copy.deepcopy(self.admissions)
        admissions["new_functions"].append({
            "id": row["address"], "identity_sha256": "0" * 64,
            "reason": "", "evidence": [],
            "approved_by": "nobody", "baseline": "0" * 40,
        })
        errors = self.errors(baseline, current, admissions)
        self.assertTrue(any("invalid reviewed debt admission" in error for error in errors))

    def test_admission_is_bound_to_the_loaded_baseline(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        row = copy.deepcopy(current["seeds"]["functions"][0])
        row["address"] = "0x00fffffd"
        current["seeds"]["functions"].append(row)
        admissions = copy.deepcopy(self.admissions)
        admissions["new_functions"].append({
            "id": row["address"],
            "identity_sha256": hashlib.sha256(json.dumps(
                row, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
            "reason": "analyzer now recovers a previously hidden function",
            "evidence": [{
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha,
            }],
            "approved_by": "parity-review",
            "baseline": "0" * 40,
        })
        errors = self.errors(baseline, current, admissions)
        self.assertTrue(any("debt-admission baseline" in error for error in errors))

    def test_exact_historical_function_admission_may_remain_as_history(self):
        baseline = copy.deepcopy(self.current)
        current = copy.deepcopy(self.current)
        row = current["seeds"]["functions"][0]
        admissions = copy.deepcopy(self.admissions)
        admissions["new_functions"].append({
            "id": row["address"],
            "identity_sha256": hashlib.sha256(json.dumps(
                row, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
            "reason": "Previously reviewed native function introduction.",
            "evidence": [{
                "path": str(self.evidence_path),
                "sha256": self.evidence_sha,
            }],
            "approved_by": "parity-review",
            "baseline": "0" * 40,
        })
        self.assertEqual(self.errors(baseline, current, admissions), [])


if __name__ == "__main__":
    unittest.main()
