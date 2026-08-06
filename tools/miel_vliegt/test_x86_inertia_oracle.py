#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.x86_inertia_oracle import (
    CONTRACT,
    RECEIPT,
    ROOT,
    SCHEMA,
    build_receipt,
    validate_cc_binary,
    validate_contract,
    verify_artifact,
)


EXECUTABLE = ROOT / "tmp/miel-vliegt-native-local/MulleMeck.exe"
CC_DLL = ROOT / "tmp/miel-vliegt-native-local/Cc.dll"


class X86InertiaOracleTests(unittest.TestCase):
    def test_contract_pins_the_original_executable_cc_dll_and_closed_function(self):
        contract, matrix = validate_contract(ROOT)
        self.assertEqual(
            contract["sources"],
            {
                "executable_sha256":
                    "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2",
                "cc_dll_sha256":
                    "c7b0599de35db339c4a3acc56987e36c7b07ebf3553fb7511bc31d18d667c70e",
            },
        )
        self.assertEqual(contract["function"]["address"], "0x1002b810")
        calc_export = next(
            item for item in matrix["cc_api"]["exports"]
            if item["decorated_symbol"] == contract["function"]["symbol"]
        )
        self.assertEqual(calc_export["rva"], "0x0002b810")
        self.assertEqual(len(contract["function"]["static_slices"]), 4)
        self.assertEqual(len(matrix["configurations"]), 3)
        self.assertEqual(len(matrix["momenta"]), 5)
        if EXECUTABLE.exists() and CC_DLL.exists():
            validate_cc_binary(EXECUTABLE, CC_DLL, contract)

    def test_tracked_receipt_is_native_only_and_proves_every_basis_column(self):
        receipt = verify_artifact(RECEIPT, ROOT)
        self.assertEqual(receipt["case_count"], 15)
        self.assertEqual(receipt["basis_case_count"], 9)
        self.assertEqual(receipt["mixed_momentum_capture_count"], 3)
        self.assertFalse(receipt["parity_promotion"])
        self.assertIn(
            "web runtime equivalence or any parity promotion",
            receipt["evidence_scope"]["not_proven"],
        )

    @unittest.skipUnless(
        EXECUTABLE.exists() and CC_DLL.exists(),
        "private pinned native binaries are not present",
    )
    def test_private_binaries_reproduce_the_tracked_receipt_exactly(self):
        self.assertEqual(build_receipt(EXECUTABLE, CC_DLL, ROOT), verify_artifact(RECEIPT))

    def test_artifact_verifier_rejects_a_forged_angular_velocity(self):
        receipt = json.loads(RECEIPT.read_text())
        case = next(row for row in receipt["cases"] if row["momentum_id"] == "basis-x")
        case["output"]["angular_velocity_xyz_f32_bits"][0] = "0x3f000001"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "forged.json"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "self-hash drifted"):
                verify_artifact(path)

    def test_artifact_verifier_rejects_a_coherently_rehashed_wrong_basis(self):
        from tools.miel_vliegt import x86_inertia_oracle as oracle

        receipt = json.loads(RECEIPT.read_text())
        case = next(row for row in receipt["cases"] if row["momentum_id"] == "basis-x")
        case["output"]["angular_velocity_xyz_f32_bits"][0] = "0x3f000001"
        case["native_proof_sha256"] = oracle.sha256_bytes(oracle.canonical_json({
            "id": case["id"],
            "input": case["input"],
            "output": case["output"],
            "trace": case["trace"],
        }))
        receipt["receipt_sha256"] = oracle._receipt_hash(receipt)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "forged.json"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "basis column"):
                verify_artifact(path)

    def test_schema_is_strictly_native_only(self):
        schema = json.loads(SCHEMA.read_text())
        self.assertEqual(schema["properties"]["status"], {"const": "NATIVE_EVIDENCE_ONLY"})
        self.assertEqual(schema["properties"]["parity_promotion"], {"const": False})
        self.assertFalse(schema["additionalProperties"])

    def test_iso_regeneration_reexecutes_the_pinned_cc_dll_oracle(self):
        regeneration = (ROOT / "tools/miel_vliegt/regenerate_flight_content.sh").read_text()
        self.assertIn('x86_inertia_oracle.py" capture', regeneration)
        self.assertIn('--executable "$SYS/MulleMeck.exe"', regeneration)
        self.assertIn('--cc-dll "$SYS/Cc.dll"', regeneration)

    def test_contract_rejects_an_incorrect_inverse_body_tensor(self):
        contract = json.loads(CONTRACT.read_text())
        broken = copy.deepcopy(contract)
        broken["configurations"][0]["inverse_body_inertia"][0] = 0.25
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "content/miel_vliegt").mkdir(parents=True)
            contract_path = root / CONTRACT.relative_to(ROOT)
            contract_path.write_text(json.dumps(broken))
            source = ROOT / contract["source_identity"]
            layout = ROOT / contract["native_flight_state_layout"]
            cc_api = ROOT / contract["cc_api_contract"]
            (root / contract["source_identity"]).write_text(source.read_text())
            (root / contract["native_flight_state_layout"]).write_text(layout.read_text())
            (root / contract["cc_api_contract"]).write_text(cc_api.read_text())
            with self.assertRaisesRegex(ValueError, "not identity"):
                validate_contract(root)


if __name__ == "__main__":
    unittest.main()
