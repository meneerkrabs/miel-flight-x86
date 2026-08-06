#!/usr/bin/env python3
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_boundary_clusters as clusters
from tools.miel_vliegt import native_reachability_closures as closures


ROOT = Path(__file__).resolve().parents[2]


def _hash(value: object) -> str:
    return hashlib.sha256(clusters.canonical(value)).hexdigest()


class NativeBoundaryClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code_map = json.loads(
            (ROOT / clusters.CODE_MAP).read_text(encoding="utf-8")
        )
        cls.import_audit = json.loads(
            (ROOT / clusters.IMPORT_AUDIT).read_text(encoding="utf-8")
        )
        cls.audit = clusters.build_from_root(ROOT)

    def test_current_inventory_is_clustered_without_false_promotions(self):
        self.assertEqual(self.audit["summary"]["functions"], 1369)
        self.assertEqual(self.audit["summary"]["candidateFunctions"], 740)
        self.assertEqual(self.audit["summary"]["candidateMemberships"], 935)
        self.assertEqual(self.audit["summary"]["candidates"], {
            "PROVEN_UNREACHABLE": 726,
            "IMPORT_BOUNDARY": 24,
            "COMPILER_SUBSTITUTION": 185,
        })
        self.assertEqual(self.audit["summary"]["promotable"], {
            "PROVEN_UNREACHABLE": 0,
            "IMPORT_BOUNDARY": 0,
            "COMPILER_SUBSTITUTION": 0,
        })
        self.assertEqual(self.audit["summary"]["overlap"], {
            "provenUnreachableAndImportBoundary": 21,
            "provenUnreachableAndCompilerSubstitution": 174,
            "importBoundaryAndCompilerSubstitution": 0,
        })
        self.assertEqual(self.audit["summary"]["compilerStructural"], {
            "candidateCount": 185,
            "exactlyDisposedCount": 185,
            "unresolvedCount": 0,
            "dispositions": {
                "CLOSED_COMPILER_CANDIDATE_GRAPH": 58,
                "EXTERNAL_IMPORT_TRANSFER_BOUNDARY": 18,
                "RECOVERED_NATIVE_AND_EXTERNAL_IMPORT_BOUNDARY": 6,
                "RECOVERED_NATIVE_CALL_BOUNDARY": 103,
            },
            "promotionCount": 0,
        })
        unreachable = next(
            row for row in self.audit["clusters"]
            if row["disposition"] == "PROVEN_UNREACHABLE"
        )
        self.assertEqual(
            unreachable["evidence"]["provenClosures"],
            ["roots", "callbacks", "vtables"],
        )
        self.assertEqual(
            unreachable["evidence"]["missingClosures"],
            ["indirectTargets"],
        )
        self.assertEqual(
            unreachable["evidence"]["closedClosureReachedCandidateCount"],
            726,
        )
        self.assertEqual(
            unreachable["evidence"]["remainingCandidates"],
            [],
        )
        compiler = next(
            row for row in self.audit["clusters"]
            if row["disposition"] == "COMPILER_SUBSTITUTION"
        )
        structural = compiler["evidence"]["structuralReview"]
        self.assertEqual(structural["reviewStatus"], "REVIEWED")
        self.assertEqual(
            structural["structuralClass"],
            "EXACT_RECOVERED_CONTROL_FLOW_BOUNDARIES",
        )
        self.assertEqual(structural["disposition"], "UNKNOWN")
        self.assertEqual(structural["reviewedMemberCount"], 185)
        self.assertEqual(structural["blockedMemberCount"], 0)
        self.assertEqual(structural["expandedBoundaryMemberCount"], 127)
        self.assertEqual(structural["resolvedExternalImportTransferCount"], 67)
        self.assertEqual(structural["resolvedStackParameterCallCount"], 3)
        self.assertEqual(structural["virtualBoundaryCorrectionMemberCount"], 1)
        self.assertEqual(structural["externalRecoveredTargetCount"], 39)
        self.assertEqual(structural["sccAtomicMemberCount"], 185)
        self.assertEqual(structural["runtimeImportMarkerMemberCount"], 3)
        self.assertEqual(structural["structuralDispositionCounts"], {
            "CLOSED_COMPILER_CANDIDATE_GRAPH": 58,
            "EXTERNAL_IMPORT_TRANSFER_BOUNDARY": 18,
            "RECOVERED_NATIVE_AND_EXTERNAL_IMPORT_BOUNDARY": 6,
            "RECOVERED_NATIVE_CALL_BOUNDARY": 103,
        })
        self.assertEqual(structural["blockedReasonCounts"], {})
        self.assertEqual(structural["blockedMembers"], [])
        self.assertEqual(
            {
                row["functionId"]: (
                    len(row["resolvedStackParameterCalls"]),
                    row["virtualExecutableBoundaryCorrection"] is not None,
                )
                for row in structural["reviewedMembers"]
                if row["functionId"] in {
                    "fn_004486cf", "fn_0044874f",
                    "fn_004487c3", "fn_0044b1e0",
                }
            },
            {
                "fn_004486cf": (1, False),
                "fn_0044874f": (1, False),
                "fn_004487c3": (1, False),
                "fn_0044b1e0": (0, True),
            },
        )
        self.assertTrue(all(
            row["semanticGameplayPromotion"] is False
            for row in structural["reviewedMembers"]
        ))
        self.assertTrue(all(
            row["scc"]["atomicWithinCompilerCandidates"]
            for row in structural["reviewedMembers"]
        ))
        self.assertFalse(
            structural["policy"]["semanticGameplayPromotion"]
        )
        self.assertEqual(compiler["evidence"]["promotableMembers"], [])
        imports = next(
            row for row in self.audit["clusters"]
            if row["disposition"] == "IMPORT_BOUNDARY"
        )
        import_review = imports["evidence"]["structuralReview"]
        self.assertEqual(import_review["reviewStatus"], "REVIEWED")
        self.assertEqual(
            import_review["structuralClass"],
            "EXACT_ONE_IMPORT_IAT_THUNK",
        )
        self.assertEqual(import_review["disposition"], "IMPORT_BOUNDARY")
        self.assertEqual(import_review["reviewedMemberCount"], 24)
        self.assertEqual(import_review["promotableMemberCount"], 0)
        self.assertFalse(
            import_review["policy"]["semanticGameplayPromotion"]
        )

    def test_tracked_audit_is_exactly_reproducible(self):
        tracked = json.loads(
            (ROOT / clusters.OUTPUT).read_text(encoding="utf-8")
        )
        self.assertEqual(clusters.validate(tracked, ROOT), self.audit)
        self.assertEqual(
            tracked["receiptSha256"],
            _hash({key: value for key, value in tracked.items()
                   if key != "receiptSha256"}),
        )

    def test_graph_or_import_identity_drift_fails_closed(self):
        for mutation in ("reachability", "callers", "import_hash", "import_status"):
            with self.subTest(mutation=mutation):
                code_map = copy.deepcopy(self.code_map)
                import_audit = copy.deepcopy(self.import_audit)
                code_hash = clusters.sha256_file(ROOT / clusters.CODE_MAP)
                if mutation == "reachability":
                    code_map["functions"][0]["entrypoint_reachable"] = False
                elif mutation == "callers":
                    target = code_map["functions"][0]["calls"][0]
                    target_row = next(
                        row for row in code_map["functions"] if row["id"] == target
                    )
                    target_row["callers"].remove(code_map["functions"][0]["id"])
                elif mutation == "import_hash":
                    import_audit["inputHashes"][clusters.CODE_MAP] = "0" * 64
                else:
                    import_audit["decisions"][0]["status"] = "COMPLETE"
                with self.assertRaises(clusters.NativeBoundaryClusterError):
                    clusters.build(
                        code_map, import_audit,
                        code_map_sha256=code_hash,
                        import_audit_sha256=clusters.sha256_file(
                            ROOT / clusters.IMPORT_AUDIT
                        ),
                    )

    def test_compiler_structural_review_rejects_branch_outside_recovered_code(self):
        function_index = json.loads(
            (ROOT / clusters.FUNCTION_INDEX).read_text(encoding="utf-8")
        )
        reviews = {
            name: json.loads(
                (ROOT / relative).read_text(encoding="utf-8")
            )
            for name, relative in closures.OUTPUTS.items()
        }
        current = clusters._compiler_structural_review(
            self.code_map, function_index, reviews,
            function_index_sha256=clusters.sha256_file(
                ROOT / clusters.FUNCTION_INDEX
            ),
        )
        self.assertEqual(current["reviewedMemberCount"], 185)
        mutated = copy.deepcopy(function_index)
        row = next(
            row for row in mutated["functions"]
            if row["address"] == "0x004486a0"
        )
        row["branch_sites"][0]["target"] = "0x00500000"
        changed = clusters._compiler_structural_review(
            self.code_map, mutated, reviews,
            function_index_sha256="0" * 64,
        )
        self.assertEqual(changed["reviewedMemberCount"], 184)
        blocked = next(
            row for row in changed["blockedMembers"]
            if row["functionId"] == "fn_004486a0"
        )
        self.assertIn(
            "DIRECT_BRANCH_TARGET_OUTSIDE_RECOVERED_FUNCTIONS",
            blocked["reasons"],
        )

    def test_repaired_import_resolution_forgery_is_rejected(self):
        function_index = json.loads(
            (ROOT / clusters.FUNCTION_INDEX).read_text(encoding="utf-8")
        )
        reviews = {
            name: json.loads(
                (ROOT / relative).read_text(encoding="utf-8")
            )
            for name, relative in closures.OUTPUTS.items()
        }
        indirect = reviews["indirectTargets"]
        row = next(
            row for row in indirect["evidence"]["resolvedExternalImportBranches"]
            if row["site"].startswith("indirect-branch:0x004485a0:")
        )
        row["symbol"] = "MSVCRT.dll!forged"
        indirect["reviewSha256"] = _hash({
            key: value for key, value in indirect.items()
            if key != "reviewSha256"
        })
        with self.assertRaisesRegex(
            clusters.NativeBoundaryClusterError,
            "resolved external import symbol differs",
        ):
            clusters._compiler_structural_review(
                self.code_map, function_index, reviews,
                function_index_sha256=clusters.sha256_file(
                    ROOT / clusters.FUNCTION_INDEX
                ),
            )

    def test_raw_section_padding_cannot_reopen_executable_coverage(self):
        function_index = json.loads(
            (ROOT / clusters.FUNCTION_INDEX).read_text(encoding="utf-8")
        )
        reviews = {
            name: json.loads(
                (ROOT / relative).read_text(encoding="utf-8")
            )
            for name, relative in closures.OUTPUTS.items()
        }
        correction = clusters._virtual_executable_boundary_correction(
            function_index,
            next(
                row for row in function_index["functions"]
                if row["address"] == "0x0044b1e0"
            ),
        )
        self.assertEqual(correction["virtualExecutableEnd"], "0x0044b1f5")
        self.assertEqual(correction["effectiveSpanBytes"], 21)
        self.assertEqual(correction["excludedFileAlignmentBytes"], 3595)

        mutated = copy.deepcopy(function_index)
        text = next(
            section for section in mutated["sections"]
            if section["name"] == ".text"
        )
        text["virtual_size"] += 1
        changed = clusters._compiler_structural_review(
            self.code_map, mutated, reviews,
            function_index_sha256="0" * 64,
        )
        self.assertEqual(changed["reviewedMemberCount"], 184)
        blocked = next(
            row for row in changed["blockedMembers"]
            if row["functionId"] == "fn_0044b1e0"
        )
        self.assertEqual(blocked["reasons"], ["INCOMPLETE_DECODE"])

    def test_external_native_targets_are_hash_bound_not_semantically_promoted(self):
        compiler = next(
            row for row in self.audit["clusters"]
            if row["disposition"] == "COMPILER_SUBSTITUTION"
        )
        reviewed = compiler["evidence"]["structuralReview"]["reviewedMembers"]
        expanded = [
            row for row in reviewed
            if row["structuralDisposition"] in {
                "RECOVERED_NATIVE_CALL_BOUNDARY",
                "RECOVERED_NATIVE_AND_EXTERNAL_IMPORT_BOUNDARY",
            }
        ]
        self.assertEqual(len(expanded), 109)
        self.assertTrue(all(row["externalRecoveredTargets"] for row in expanded))
        for row in expanded:
            self.assertFalse(row["semanticGameplayPromotion"])
            for target in row["externalRecoveredTargets"]:
                identity = {
                    key: target[key]
                    for key in (
                        "functionId", "nativeFunctionSha256", "scc",
                        "entrypointReachable", "kind", "ownershipDisposition",
                    )
                }
                self.assertEqual(target["identitySha256"], _hash(identity))

    def test_schema_forbids_structural_to_semantic_promotion(self):
        schema = json.loads(
            (ROOT / clusters.SCHEMA).read_text(encoding="utf-8")
        )
        clusters.validate_schema_guard(schema)
        forged = copy.deepcopy(schema)
        forged["$defs"]["compilerStructuralMember"]["properties"][
            "structuralDisposition"
        ]["enum"].append("COMPILER_SUBSTITUTION")
        with self.assertRaisesRegex(
            clusters.NativeBoundaryClusterError, "JSON schema policy differs"
        ):
            clusters.validate_schema_guard(forged)

    def test_import_structural_review_requires_one_exact_interface(self):
        function_index = json.loads(
            (ROOT / clusters.FUNCTION_INDEX).read_text(encoding="utf-8")
        )
        current = clusters._import_structural_review(
            self.code_map, function_index, self.import_audit,
            function_index_sha256=clusters.sha256_file(
                ROOT / clusters.FUNCTION_INDEX
            ),
        )
        self.assertEqual(current["reviewedMemberCount"], 24)
        mutated = copy.deepcopy(function_index)
        row = next(
            row for row in mutated["functions"]
            if row["address"] == "0x00447200"
        )
        row["imports"].append("MSVCRT.dll!malloc")
        with self.assertRaisesRegex(
            clusters.NativeBoundaryClusterError,
            "exact import-boundary structure differs",
        ):
            clusters._import_structural_review(
                self.code_map, mutated, self.import_audit,
                function_index_sha256="0" * 64,
            )

    def test_unreachable_receipt_stays_blocked_by_real_indirect_gaps(self):
        reviews = {
            name: json.loads(
                (ROOT / relative).read_text(encoding="utf-8")
            )
            for name, relative in closures.OUTPUTS.items()
        }
        closures.validate_all(reviews, root=ROOT)
        self.assertEqual(
            {
                name: review["reviewStatus"]
                for name, review in reviews.items()
            },
            {
                "roots": "CLOSED",
                "callbacks": "CLOSED",
                "vtables": "CLOSED",
                "indirectTargets": "OPEN",
            },
        )
        with self.assertRaisesRegex(
            clusters.NativeBoundaryClusterError,
            "indirectTargets closure review identity differs",
        ):
            clusters.build_unreachable_boundary(
                self.audit, self.code_map, reviews, root=ROOT,
            )

        forged = copy.deepcopy(reviews)
        indirect = forged["indirectTargets"]
        indirect["reviewStatus"] = "CLOSED"
        indirect["unresolvedPaths"] = []
        indirect["evidence"]["unresolvedPathCount"] = 0
        indirect["reviewSha256"] = _hash({
            key: value for key, value in indirect.items()
            if key != "reviewSha256"
        })
        with self.assertRaisesRegex(
            clusters.NativeBoundaryClusterError,
            "unresolved indexed calls were declared closed",
        ):
            clusters.build_unreachable_boundary(
                self.audit, self.code_map, forged, root=ROOT,
            )

    def test_check_mode_does_not_accept_a_stale_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.json"
            stale = copy.deepcopy(self.audit)
            stale["summary"]["promotable"]["PROVEN_UNREACHABLE"] = 726
            path.write_text(json.dumps(stale), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/miel_vliegt/native_boundary_clusters.py"),
                    "--root", str(ROOT),
                    "--output", str(path),
                    "--check",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("native boundary cluster audit drifted", result.stderr)


if __name__ == "__main__":
    unittest.main()
