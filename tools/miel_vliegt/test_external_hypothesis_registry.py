import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import external_hypothesis_registry as registry_tool


class ExternalHypothesisRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = registry_tool.build_registry()
        cls.ratchet = registry_tool.load_json(registry_tool.DEFAULT_RATCHET)

    def test_pins_sources_and_records_license_boundaries(self):
        sources = {source["id"]: source for source in self.registry["sources"]}
        self.assertEqual(sources["openmulle"]["commit"], "9561d6b953b7f7821e5c50b3cfd36dcf51a4dabe")
        self.assertEqual(sources["openmulle"]["pin_role"], "DEFAULT_BRANCH_HEAD_AT_CAPTURE")
        self.assertEqual(sources["openmulle"]["license_expression"], "MIT OR Apache-2.0")
        self.assertEqual(sources["willywerkel"]["commit"], "ac37fa19a468143df58864986ccfe5384a48d339")
        self.assertEqual(sources["willywerkel"]["default_branch"], "master")
        self.assertEqual(sources["willywerkel"]["license_status"], "NO_LICENSE_FILE")
        self.assertEqual(sources["willywerkel"]["reuse_policy"], "FACTUAL_METADATA_ONLY_NO_COPY")
        self.assertEqual(sources["cc_tools"]["commit"], "e34efcd858ec4475fa03d3f8668fa4e26f9e780e")
        self.assertEqual(sources["cc_tools"]["license_expression"], "CC0-1.0")
        self.assertEqual(sources["cc_tools"]["source_role"], "SECONDARY_STRUCTURAL_ORACLE")
        self.assertFalse(sources["cc_tools"]["runtime_equivalence_eligible"])

    def test_all_external_claims_are_fail_closed(self):
        self.assertEqual(self.registry["parity_evidence_exports"], [])
        self.assertFalse(self.registry["evidence_policy"]["may_satisfy_parity_gate"])
        for item in self.registry["hypotheses"]:
            self.assertEqual(item["status"], "UNVERIFIED")
            self.assertFalse(item["parity_evidence_eligible"])
            self.assertEqual(item["source_id"], "willywerkel")
        self.assertEqual(registry_tool.validate_registry(self.registry, self.ratchet), [])

    def test_schema_itself_pins_the_fail_closed_boundary(self):
        schema = registry_tool.load_json(registry_tool.DEFAULT_SCHEMA)
        self.assertEqual(registry_tool.validate_schema_guard(schema), [])
        changed = copy.deepcopy(schema)
        changed["properties"]["hypotheses"]["items"]["properties"]["parity_evidence_eligible"]["const"] = True
        self.assertTrue(any("eligibility" in error for error in registry_tool.validate_schema_guard(changed)))

    def test_readme_facts_are_normalized_without_copied_payloads(self):
        encoded = json.dumps(self.registry)
        for forbidden in registry_tool.FORBIDDEN_KEYS:
            self.assertNotIn(f'"{forbidden}"', encoded)
        points = next(item for item in self.registry["hypotheses"] if item["id"] == "map.viktor.seismograph_bird")["claim"]["points"]
        self.assertEqual(points, [{
            "item_id": "seismograph_part.3",
            "x": 500,
            "y": -200,
            "placement_radius": 20,
            "interaction": "FLY_THROUGH_WHITE_BIRD_FLOCK",
        }])
        issue = next(item for item in self.registry["hypotheses"] if item["id"] == "issue2.erik.yarn")
        self.assertEqual(issue["source_locator"]["issue_id"], 2707042725)
        self.assertEqual(
            issue["source_locator"]["body_sha256"],
            "814e2bc5a5468ed3aece9209932f2304cbe76d23962bc799debc78e1d3083b7d",
        )

    def test_validator_rejects_parity_promotion(self):
        changed = copy.deepcopy(self.registry)
        changed["hypotheses"][0]["status"] = "VERIFIED"
        changed["hypotheses"][0]["parity_evidence_eligible"] = True
        errors = registry_tool.validate_registry(changed, self.ratchet)
        self.assertTrue(any("UNVERIFIED" in error for error in errors))
        self.assertTrue(any("cannot be parity evidence" in error for error in errors))

    def test_ratchet_rejects_deletion_and_semantic_drift(self):
        deleted = copy.deepcopy(self.registry)
        deleted["hypotheses"].pop()
        self.assertTrue(any("ratcheted hypothesis missing" in error for error in registry_tool.validate_registry(deleted, self.ratchet)))

        changed = copy.deepcopy(self.registry)
        changed["hypotheses"][0]["claim"]["points"][0]["x"] += 1
        self.assertTrue(any("ratcheted hypothesis changed" in error for error in registry_tool.validate_registry(changed, self.ratchet)))

    def test_builder_is_idempotent_and_check_mode_detects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "registry.json"
            base = [
                sys.executable,
                str(Path(registry_tool.__file__)),
                "--output", str(output),
                "--ratchet", str(registry_tool.DEFAULT_RATCHET),
                "--schema", str(registry_tool.DEFAULT_SCHEMA),
            ]
            subprocess.run(base, check=True, capture_output=True, text=True)
            first = output.read_bytes()
            subprocess.run(base, check=True, capture_output=True, text=True)
            self.assertEqual(output.read_bytes(), first)
            subprocess.run(base + ["--check"], check=True, capture_output=True, text=True)
            output.write_text("{}\n", encoding="utf-8")
            stale = subprocess.run(base + ["--check"], capture_output=True, text=True)
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("stale", stale.stdout)


if __name__ == "__main__":
    unittest.main()
