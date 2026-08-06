#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_import_replacements as replacements


ROOT = Path(__file__).resolve().parents[2]


class NativeImportReplacementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = replacements.build_from_root(ROOT)

    def test_tracked_audit_and_boundary_are_reproducible(self):
        self.assertEqual(replacements.load_json(ROOT / replacements.OUTPUT), self.audit)
        self.assertEqual(
            replacements.load_json(ROOT / replacements.BOUNDARY_OUTPUT),
            replacements.build_boundary(self.audit),
        )
        self.assertEqual(
            self.audit["summary"], {"audited": 24, "complete": 0, "unknown": 24},
        )
        self.assertEqual(replacements.build_boundary(self.audit)["claims"], [])

    def test_all_high_confidence_thunks_are_exact_and_fail_closed(self):
        index = replacements.load_json(ROOT / replacements.INDEX)
        code_map = replacements.load_json(ROOT / replacements.CODE_MAP)
        indexed = {
            replacements.function_id(row["address"]): row
            for row in index["functions"]
        }
        expected = {
            row["id"] for row in code_map["functions"]
            if row.get("kind", {}).get("value") == "import_thunk"
            and row.get("kind", {}).get("confidence") == "high"
        }
        decisions = {row["functionId"]: row for row in self.audit["decisions"]}
        self.assertEqual(set(decisions), expected)
        for identifier, decision in decisions.items():
            self.assertEqual(decision["status"], "UNKNOWN")
            self.assertEqual(decision["disposition"], "UNKNOWN")
            self.assertIsNone(decision["replacement"])
            self.assertEqual(
                decision["nativeInterfaces"],
                replacements.native_interfaces(identifier, indexed[identifier]),
            )
            self.assertEqual(len(decision["nativeInterfaces"]["imports"]), 1)

    def _fixture(self, directory: str):
        root = Path(directory)
        for relative in (
            replacements.INDEX, replacements.CODE_MAP, replacements.POLICY,
            replacements.RELEASE_BUILD,
        ):
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
        identifier = "fn_00401000"
        native_hash = hashlib.sha256(b"native").hexdigest()
        source = {
            "address": "0x00401000", "end": "0x00401006", "size": 6,
            "sha256": native_hash, "imports": ["TEST.dll!CreateService"],
        }
        index = {
            "schema": 1,
            "source": {"sha256": hashlib.sha256(b"exe").hexdigest()},
            "functions": [source],
        }
        code = {
            "schema": 1, "source": index["source"],
            "functions": [{
                "id": identifier, "address": source["address"],
                "sha256": native_hash,
                "kind": {"value": "import_thunk", "confidence": "high"},
            }],
        }
        module = root / "src/replacement.js"
        entrypoint = root / "src/release.js"
        receipt_path = root / "artifacts/execution.json"
        module.parent.mkdir(parents=True)
        receipt_path.parent.mkdir(parents=True)
        module.write_text("export function createService () { return true }\n", encoding="utf-8")
        entrypoint.write_text(
            "import { createService } from './replacement'\ncreateService()\n",
            encoding="utf-8",
        )
        (root / replacements.RELEASE_BUILD).write_text(
            "module.exports = { entry: './src/release.js' }\n", encoding="utf-8",
        )
        interfaces = replacements.native_interfaces(identifier, source)
        receipt = {
            "schema": 1,
            "protocol": replacements.EXECUTION_PROTOCOL,
            "status": "PASS",
            "functionId": identifier,
            "nativeInterfaces": interfaces,
            "replacementModule": "src/replacement.js",
            "replacementExport": "createService",
            "replacementSourceSha256": replacements.sha256_file(module),
            "productionEntrypoint": "src/release.js",
            "productionEntrypointSha256": replacements.sha256_file(entrypoint),
        }
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        policy = {
            "schema": 1,
            "protocol": "miel-vliegt-native-import-replacement-policy",
            "replacements": {identifier: {
                "nativeInterfaces": interfaces,
                "replacementOwner": "web-runtime",
                "replacementModule": "src/replacement.js",
                "replacementExport": "createService",
                "productionEntrypoint": "src/release.js",
                "executionReceipt": "artifacts/execution.json",
            }},
        }
        documents = {
            replacements.INDEX: index,
            replacements.CODE_MAP: code,
            replacements.POLICY: policy,
        }
        for relative, value in documents.items():
            (root / relative).write_text(json.dumps(value), encoding="utf-8")
        return root, index, code, policy, receipt, identifier

    def test_exact_executed_release_export_can_be_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            root, index, code, policy, _receipt, identifier = self._fixture(directory)
            audit = replacements.build(index, code, policy, root)
            decision = audit["decisions"][0]
            self.assertEqual(decision["functionId"], identifier)
            self.assertEqual(decision["status"], "COMPLETE")
            self.assertEqual(decision["disposition"], "IMPORT_BOUNDARY")
            boundary = replacements.build_boundary(audit)
            self.assertEqual(boundary["claims"][0]["functionId"], identifier)
            self.assertEqual(
                boundary["apiImportMapping"][0]["replacementExport"],
                "createService",
            )

    def test_promotion_mutations_fail_closed(self):
        mutations = (
            "native_interface", "source_hash", "entrypoint_hash",
            "missing_export", "entrypoint_import", "failed_execution",
            "module_escape",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root, index, code, policy, receipt, identifier = self._fixture(directory)
                if mutation == "native_interface":
                    policy["replacements"][identifier]["nativeInterfaces"]["imports"] = [
                        "TEST.dll!OtherService"
                    ]
                    (root / replacements.POLICY).write_text(json.dumps(policy), encoding="utf-8")
                elif mutation == "source_hash":
                    receipt["replacementSourceSha256"] = "0" * 64
                    (root / "artifacts/execution.json").write_text(json.dumps(receipt), encoding="utf-8")
                elif mutation == "entrypoint_hash":
                    receipt["productionEntrypointSha256"] = "0" * 64
                    (root / "artifacts/execution.json").write_text(json.dumps(receipt), encoding="utf-8")
                elif mutation == "missing_export":
                    (root / "src/replacement.js").write_text("function createService () {}\n", encoding="utf-8")
                elif mutation == "entrypoint_import":
                    (root / "src/release.js").write_text("createService()\n", encoding="utf-8")
                elif mutation == "failed_execution":
                    receipt["status"] = "FAIL"
                    (root / "artifacts/execution.json").write_text(json.dumps(receipt), encoding="utf-8")
                else:
                    policy["replacements"][identifier]["replacementModule"] = "../outside.js"
                    (root / replacements.POLICY).write_text(json.dumps(policy), encoding="utf-8")
                with self.assertRaises(ValueError):
                    replacements.build(index, code, policy, root)

    def test_audit_receipt_mutation_is_not_accepted(self):
        mutated = copy.deepcopy(self.audit)
        mutated["decisions"][0]["status"] = "COMPLETE"
        with self.assertRaisesRegex(ValueError, "audit drifted"):
            replacements.validate(mutated, ROOT)


if __name__ == "__main__":
    unittest.main()
