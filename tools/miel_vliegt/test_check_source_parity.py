#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.miel_vliegt import check_source_parity


class FlightSourceParityGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.iso = self.root / "Mielvliegt.iso"
        self.executable = self.root / "MulleMeck.exe"
        self.launcher = self.root / "Start_Mulle.exe"
        self.help_file = self.root / "MIELMONTEUR.HLP"
        self.cc_dll = self.root / "Cc.dll"
        self.udspack_dll = self.root / "UdsPack.dll"
        self.iso.write_bytes(b"iso")
        self.executable.write_bytes(b"exe")
        self.launcher.write_bytes(b"launcher")
        self.help_file.write_bytes(b"help")
        self.cc_dll.write_bytes(b"cc")
        self.udspack_dll.write_bytes(b"uds")

    def tearDown(self):
        self.temporary.cleanup()

    def identity(self):
        return {
            "iso": {"sha256": check_source_parity._sha256(self.iso)},
            "executable": {"sha256": check_source_parity._sha256(self.executable)},
            "launcher": {"sha256": check_source_parity._sha256(self.launcher)},
            "help_file": {"sha256": check_source_parity._sha256(self.help_file)},
            "cc_dll": {"sha256": check_source_parity._sha256(self.cc_dll)},
            "udspack_dll": {"sha256": check_source_parity._sha256(self.udspack_dll)},
        }

    def test_accepts_only_the_pinned_iso_executable_and_help(self):
        identity_path = self.root / "identity.json"
        identity_path.write_text(json.dumps(self.identity()), encoding="utf-8")
        with patch.object(check_source_parity, "IDENTITY_PATH", identity_path):
            self.assertEqual(
                check_source_parity._verify_identity(
                    self.iso, self.executable, self.launcher, self.help_file, self.cc_dll, self.udspack_dll
                ),
                self.identity(),
            )

    def test_wrong_iso_fails_with_explicit_identity_error(self):
        identity = self.identity()
        identity["iso"]["sha256"] = "0" * 64
        identity_path = self.root / "identity.json"
        identity_path.write_text(json.dumps(identity), encoding="utf-8")
        with patch.object(check_source_parity, "IDENTITY_PATH", identity_path):
            with self.assertRaisesRegex(ValueError, "wrong Miel Vliegt iso"):
                check_source_parity._verify_identity(
                    self.iso, self.executable, self.launcher, self.help_file, self.cc_dll, self.udspack_dll
                )

    def test_missing_extracted_data_fails_before_harvesting(self):
        identity_path = self.root / "identity.json"
        identity_path.write_text(json.dumps(self.identity()), encoding="utf-8")
        with patch.object(check_source_parity, "IDENTITY_PATH", identity_path):
            with self.assertRaisesRegex(ValueError, "missing extracted Miel Vliegt data"):
                check_source_parity.check(
                    self.root, self.iso, self.executable, self.launcher, self.help_file,
                    self.cc_dll, self.udspack_dll,
                )

    def test_contract_drift_is_a_hard_failure(self):
        contract_root = self.root / "contracts"
        contract_root.mkdir()
        (contract_root / "contract.json").write_text('{"schema": 1}\n', encoding="utf-8")
        with patch.object(check_source_parity, "CONTRACT_ROOT", contract_root):
            with self.assertRaisesRegex(ValueError, "flight source parity drifted"):
                check_source_parity._assert_contract("contract.json", {"schema": 2})

    def test_complete_gate_includes_the_dutch_help_contract(self):
        source = self.root / "source"
        (source / "data").mkdir(parents=True)
        contract_root = self.root / "contracts"
        contract_root.mkdir()
        harvested = {
            "uds_barn_contracts.json": {"barn": True},
            "uds_hangar_masks.json": {"masks": True},
            "uds_flight_contracts.json": {"counts": {"mission_declarations": 7}},
            "dutch_help_contract.json": {"help": True},
            "uds_flight_parts.json": {"counts": {"parts": 9}},
            "uds_flight_attachment_targets.json": {"parts": []},
            "ccf_material_contract.json": {"textures": []},
            "uds_flight_part_components.json": {"parts": []},
            "native_function_index.json": {"functions": []},
            "native_code_map.json": {
                "summary": {"functions": 0}, "resources": [], "functions": [],
            },
            "native_analysis_receipt.json": {
                "schema": 1, "source_sha256": None, "functions": [],
                "unresolved_indirect_calls": [], "unresolved_indirect_branches": [],
            },
            "native_engine_subsystems.json": {"summary": {"subsystems": 0}},
            "shipped_executable_inventory.json": {"schema_version": 1, "executables": []},
        }
        for name, value in harvested.items():
            compact = name in {
                "uds_flight_parts.json",
                "uds_flight_attachment_targets.json",
                "native_function_index.json",
                "native_code_map.json",
                "native_analysis_receipt.json",
                "native_engine_subsystems.json",
            }
            separators = (",", ":") if compact else None
            (contract_root / name).write_text(
                json.dumps(value, indent=None if compact else 2, separators=separators) + "\n",
                encoding="utf-8",
            )
        identity_path = self.root / "identity.json"
        identity_path.write_text(json.dumps(self.identity()), encoding="utf-8")
        seeds_path = self.root / "native-function-seeds.json"
        seeds_path.write_text(json.dumps({
            "image_sha256": self.identity()["executable"]["sha256"],
            "functions": [],
        }), encoding="utf-8")
        with (
            patch.object(check_source_parity, "IDENTITY_PATH", identity_path),
            patch.object(check_source_parity, "CONTRACT_ROOT", contract_root),
            patch.object(check_source_parity, "harvest_barn", return_value=harvested["uds_barn_contracts.json"]),
            patch.object(check_source_parity, "harvest_masks", return_value=harvested["uds_hangar_masks.json"]),
            patch.object(check_source_parity, "harvest_flight", return_value=harvested["uds_flight_contracts.json"]),
            patch.object(check_source_parity, "harvest_help", return_value=harvested["dutch_help_contract.json"]),
            patch.object(check_source_parity, "harvest_parts", return_value=harvested["uds_flight_parts.json"]),
            patch.object(check_source_parity, "project_attachments", return_value=harvested["uds_flight_attachment_targets.json"]),
            patch.object(check_source_parity, "harvest_ccf_materials", return_value=harvested["ccf_material_contract.json"]),
            patch.object(check_source_parity, "check_ccf_assets"),
            patch.object(check_source_parity, "harvest_components", return_value=harvested["uds_flight_part_components.json"]),
            patch.object(check_source_parity, "PeImage", return_value="pe-image"),
            patch.object(check_source_parity, "analyze_native", return_value=harvested["native_function_index.json"]),
            patch.object(check_source_parity, "build_native_map", return_value=harvested["native_code_map.json"]),
            patch.object(check_source_parity, "build_engine_subsystems", return_value=harvested["native_engine_subsystems.json"]),
            patch.object(check_source_parity, "analyze_executable_tree", return_value=harvested["shipped_executable_inventory.json"]),
            patch.object(check_source_parity, "FUNCTION_SEEDS_PATH", seeds_path),
        ):
            summary = check_source_parity.check(
                source, self.iso, self.executable, self.launcher, self.help_file,
                self.cc_dll, self.udspack_dll,
            )
        self.assertEqual(summary["contracts"], 13)


if __name__ == "__main__":
    unittest.main()
