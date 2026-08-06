import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.classify_native_graph import build, verify_resource_sources


def function(address, calls=(), **values):
    result = {
        "address": address,
        "end": f"0x{int(address, 16) + 16:08x}",
        "size": 16,
        "sha256": address[-8:] * 8,
        "name": None,
        "module": None,
        "calls": list(calls),
        "imports": [],
        "strings": [],
        "data_references": [],
        "unresolved_indirect_calls": [],
        "unresolved_direct_calls": [],
        "branch_sites": [],
        "basic_blocks": [{
            "id": f"bb_{int(address, 16):08x}", "start": address,
            "end": f"0x{int(address, 16) + 16:08x}", "size": 16,
            "instruction_count": 4, "decoded_instruction_bytes": 16,
            "unknown_skipdata_bytes": 0,
        }],
        "analysis_coverage": {
            "function_span_bytes": 16, "decoded_instruction_bytes": 16,
            "unknown_skipdata_bytes": 0, "uncovered_bytes": 0,
        },
    }
    result.update(values)
    return result


class NativeGraphClassificationTests(unittest.TestCase):
    def setUp(self):
        self.functions = [
            function("0x00401000", ["0x00401010", "0x00401030"], name="flight.seed", module="flight"),
            function("0x00401010", ["0x00401020"], unresolved_indirect_calls=[{"address": "0x00401014", "kind": "register"}]),
            function("0x00401020", ["0x00401010"]),
            function("0x00401030", size=6, imports=["KERNEL32.dll!Sleep"]),
            function("0x00448000"),
        ]
        self.index = {
            "schema": 1,
            "source": {"sha256": "a" * 64, "image_base": "0x00400000", "entrypoint": "0x00401000"},
            "counts": {
                "functions": len(self.functions), "executable_bytes": 80,
                "function_span_bytes": 80, "decoded_instruction_bytes": 80,
                "unknown_skipdata_bytes": 0, "uncovered_executable_bytes": 0,
            },
            "functions": self.functions,
        }
        self.seeds = {
            "schema": 1,
            "image_sha256": "a" * 64,
            "resource_inventory": {
                "sha256": hashlib.sha256(b"").hexdigest(),
                "counts": {
                    "DESCOPED": 0, "SOURCE_MISSING": 0, "SOURCE_NAMESPACE": 0,
                    "SOURCE_REFERENCED": 0,
                },
                "rules": [{
                    "id": "fixture", "prefix": "Data\\",
                    "disposition": "SOURCE_REFERENCED",
                    "evidence": "fixture resource",
                }],
            },
            "functions": [{"name": "flight.seed", "module": "flight", "address": "0x401000", "signature": "90"}],
        }

    def test_maps_every_function_without_inventing_gameplay_ownership(self):
        result = build(self.index, self.seeds)
        self.assertEqual(result["summary"]["functions"], 5)
        self.assertEqual(result["summary"]["stable_ids"], 5)
        rows = {row["address"]: row for row in result["functions"]}
        self.assertEqual(rows["0x00401000"]["ownership"]["status"], "reviewed")
        self.assertEqual(rows["0x00401010"]["ownership"]["status"], "candidate")
        self.assertEqual(rows["0x00448000"]["ownership"]["status"], "unassigned")
        self.assertEqual(rows["0x00401030"]["kind"]["value"], "import_thunk")
        self.assertEqual(rows["0x00448000"]["kind"]["value"], "compiler_runtime_candidate")

    def test_pins_scc_reachability_and_indirect_call_gaps(self):
        result = build(self.index, self.seeds)
        rows = {row["address"]: row for row in result["functions"]}
        self.assertEqual(rows["0x00401010"]["scc"], rows["0x00401020"]["scc"])
        self.assertEqual(result["summary"]["largest_scc"], 2)
        self.assertEqual(result["summary"]["cyclic_sccs"], 1)
        self.assertEqual(result["summary"]["entrypoint_reachable"], 4)
        self.assertEqual(result["summary"]["unresolved_indirect_call_sites"], 1)
        self.assertTrue(rows["0x00401010"]["has_unresolved_indirect_calls"])
        self.assertEqual(result["summary"]["basic_blocks"], 5)
        self.assertFalse(result["summary"]["executable_byte_coverage"]["semantic_coverage_claimed"])

    def test_rejects_indexes_without_indirect_call_accounting(self):
        broken = copy.deepcopy(self.index)
        del broken["functions"][0]["unresolved_indirect_calls"]
        with self.assertRaisesRegex(ValueError, "predates indirect-call accounting"):
            build(broken, self.seeds)

    def test_rejects_unknown_direct_call_targets(self):
        broken = copy.deepcopy(self.index)
        broken["functions"][0]["calls"].append("0x00409999")
        with self.assertRaisesRegex(ValueError, "unknown function targets"):
            build(broken, self.seeds)

    def test_classifies_every_native_data_resource_and_pins_inventory(self):
        self.functions[0]["strings"] = [{
            "address": "0x00450000", "value": "Data/Video/intro.avi",
        }]
        self.seeds["resource_inventory"] = {
            "sha256": hashlib.sha256(b"data\\video\\intro.avi").hexdigest(),
            "counts": {
                "DESCOPED": 0, "SOURCE_MISSING": 1, "SOURCE_NAMESPACE": 0,
                "SOURCE_REFERENCED": 0,
            },
            "rules": [
                {
                    "id": "default", "prefix": "Data\\",
                    "disposition": "SOURCE_REFERENCED",
                    "evidence": "decoded fixture source",
                },
                {
                    "id": "missing-intro", "exact": "Data\\Video\\intro.avi",
                    "disposition": "SOURCE_MISSING", "evidence": "absent from fixture media",
                },
            ],
        }
        result = build(self.index, self.seeds)
        self.assertEqual(
            result["summary"]["resources"]["dispositions"]["SOURCE_MISSING"], 1
        )
        self.assertTrue(result["summary"]["resources"]["all_classified"])
        self.assertEqual(result["resources"][0]["rule"], "missing-intro")

    def test_resource_inventory_drift_fails_before_broad_default_rule(self):
        self.functions[0]["strings"] = [{
            "address": "0x00450000", "value": "Data\\Video\\new.avi",
        }]
        with self.assertRaisesRegex(ValueError, "resource inventory drifted"):
            build(self.index, self.seeds)

    def test_concrete_source_reference_must_exist_but_template_is_explicit(self):
        resources = [
            {
                "path": "data\\graphics\\present.ccf", "kind": "concrete",
                "disposition": "SOURCE_REFERENCED",
            },
            {
                "path": "data\\graphics\\%s.ccf", "kind": "template",
                "disposition": "SOURCE_REFERENCED",
            },
        ]
        with tempfile.TemporaryDirectory() as raw_directory:
            source = Path(raw_directory)
            (source / "Data" / "Graphics").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "absent from the decoded source"):
                verify_resource_sources(source, resources)
            (source / "Data" / "Graphics" / "PRESENT.CCF").write_bytes(b"ccf")
            verify_resource_sources(source, resources)

    def test_source_missing_exception_expires_when_source_appears(self):
        resources = [{
            "path": "data\\video\\intro.avi", "kind": "concrete",
            "disposition": "SOURCE_MISSING",
        }]
        with tempfile.TemporaryDirectory() as raw_directory:
            source = Path(raw_directory)
            (source / "Data" / "Video").mkdir(parents=True)
            verify_resource_sources(source, resources)
            (source / "Data" / "Video" / "INTRO.AVI").write_bytes(b"avi")
            with self.assertRaisesRegex(ValueError, "now exist"):
                verify_resource_sources(source, resources)

    def test_native_directory_reference_is_proven_by_its_contents(self):
        resources = [{
            "path": "data\\sound\\login", "kind": "concrete",
            "disposition": "SOURCE_REFERENCED",
        }]
        with tempfile.TemporaryDirectory() as raw_directory:
            source = Path(raw_directory)
            (source / "data" / "sound" / "login").mkdir(parents=True)
            (source / "data" / "sound" / "login" / "theme.wav").write_bytes(b"wav")
            verify_resource_sources(source, resources)


if __name__ == "__main__":
    unittest.main()
