#!/usr/bin/env python3
"""Regression tests for behavior/evidence parity enforcement."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.behavior_evidence import build_receipt, load_json_strict
from tools.miel_vliegt.verify_behavior_evidence import derived_proof_level, derived_status, validate


ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "content/miel_vliegt"


class BehaviorEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contracts = load_json_strict(CONTENT / "native_behavior_contracts.json")
        self.ledger = load_json_strict(CONTENT / "flight_parity_ledger_v2.json")
        self.code_map = load_json_strict(CONTENT / "native_code_map.json")
        self.suites = load_json_strict(CONTENT / "flight_behavior_test_suites.json")
        self.receipts = load_json_strict(CONTENT / "flight_behavior_test_receipts.json")

    def write(self, directory: Path, name: str, value: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def validate_values(self, directory: Path, **changes: object):
        values = {
            "contracts": self.contracts,
            "ledger": self.ledger,
            "code_map": self.code_map,
            "suites": self.suites,
            "receipts": self.receipts,
        }
        values.update(changes)
        paths = {key: self.write(directory, f"{key}.json", value) for key, value in values.items()}
        return validate(
            ROOT, paths["contracts"], paths["ledger"], paths["code_map"],
            paths["suites"], paths["receipts"], execute_receipts=False,
        )

    def test_reviewed_behavior_evidence_is_valid(self) -> None:
        counts = validate(
            ROOT,
            CONTENT / "native_behavior_contracts.json",
            CONTENT / "flight_parity_ledger_v2.json",
            CONTENT / "native_code_map.json",
            CONTENT / "flight_behavior_test_suites.json",
            CONTENT / "flight_behavior_test_receipts.json",
            execute_receipts=False,
        )
        self.assertEqual(counts, {"EQUIVALENT": 8, "MISSING": 3})

    def test_release_gate_rejects_the_current_unknown_native_frontier(self) -> None:
        with self.assertRaisesRegex(ValueError, "native-flight release blocked"):
            validate(
                ROOT,
                CONTENT / "native_behavior_contracts.json",
                CONTENT / "flight_parity_ledger_v2.json",
                CONTENT / "native_code_map.json",
                CONTENT / "flight_behavior_test_suites.json",
                CONTENT / "flight_behavior_test_receipts.json",
                execute_receipts=False,
                require_release_ready=True,
            )

    def test_strict_loader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text('{"schema":1,"schema":2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key 'schema'"):
                load_json_strict(path)

    def test_dynamic_behavior_cannot_derive_equivalent_from_replay(self) -> None:
        behavior = next(item for item in self.contracts["behaviors"] if item["class"] == "state_transition")
        record = {
            "disposition": "REQUIRED",
            "evidence": {
                "source": "PINNED", "native_behavior": "CONTRACTED",
                "reachability": "STATIC", "runtime": "IMPLEMENTED",
                "replay": "PASS", "differential": "NONE",
            },
        }
        self.assertEqual(derived_status(record, behavior), "MISSING")
        self.assertEqual(
            derived_proof_level(record, behavior, []),
            "BLOCKED_NATIVE_OBSERVATION",
        )

    def test_original_x86_receipt_derives_emulated_equivalence(self) -> None:
        behavior = next(
            item for item in self.contracts["behaviors"]
            if item["id"] == "airplane.complete_component_mask"
        )
        record = next(
            item for item in self.ledger["records"]
            if item["id"] == "airplane.complete_component_mask"
        )
        self.assertEqual(
            derived_proof_level(
                record, behavior, [{"protocol": "miel-vliegt-x86-micro-oracle"}]
            ),
            "EMULATED_EQUIVALENT",
        )

    def test_proof_level_cannot_be_promoted_by_editing_the_ledger(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["records"][0]["proof_level"] = "NATIVE_DIFFERENTIAL"
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(ValueError, "proof level drifted"):
                self.validate_values(Path(raw), ledger=ledger)

    def test_stale_runtime_hash_invalidates_receipt(self) -> None:
        receipts = copy.deepcopy(self.receipts)
        first = receipts["receipts"][0]
        path = next(iter(first["runtime_hashes"]))
        first["runtime_hashes"][path] = "0" * 64
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(ValueError, "stale executable receipt field runtime_hashes"):
                self.validate_values(Path(raw), receipts=receipts)

    def test_new_reviewed_game_owned_function_requires_behavior_coverage(self) -> None:
        code_map = copy.deepcopy(self.code_map)
        candidate = next(
            item for item in code_map["functions"] if item["ownership"]["status"] == "candidate"
        )
        candidate["ownership"]["status"] = "reviewed"
        candidate["ownership"]["disposition"] = "GAME_OWNED"
        code_map["summary"]["ownership"]["candidate"] -= 1
        code_map["summary"]["ownership"]["reviewed"] += 1
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(ValueError, "uncovered GAME_OWNED reviewed function"):
                self.validate_values(Path(raw), code_map=code_map)

    def test_reviewed_support_function_does_not_need_fake_gameplay_behavior(self) -> None:
        code_map = copy.deepcopy(self.code_map)
        candidate = next(
            item for item in code_map["functions"] if item["ownership"]["status"] == "candidate"
        )
        candidate["ownership"]["status"] = "reviewed"
        candidate["ownership"]["disposition"] = "ENGINE_OWNED"
        candidate["ownership"]["evidence"] = ["reviewed signature-pinned engine support boundary"]
        code_map["summary"]["ownership"]["candidate"] -= 1
        code_map["summary"]["ownership"]["reviewed"] += 1
        ledger = copy.deepcopy(self.ledger)
        ledger["native_coverage"]["candidate_game_owned"] -= 1
        ledger["native_coverage"]["unknown_function_ownership"] -= 1
        with tempfile.TemporaryDirectory() as raw:
            counts = self.validate_values(Path(raw), code_map=code_map, ledger=ledger)
        self.assertEqual(counts, {"EQUIVALENT": 8, "MISSING": 3})

    def test_new_native_unit_cannot_inherit_an_existing_micro_oracle_receipt(self) -> None:
        contracts = copy.deepcopy(self.contracts)
        code_map = copy.deepcopy(self.code_map)
        ledger = copy.deepcopy(self.ledger)
        candidate = next(
            item for item in code_map["functions"] if item["ownership"]["status"] == "candidate"
        )
        candidate["ownership"]["status"] = "reviewed"
        candidate["ownership"]["disposition"] = "GAME_OWNED"
        code_map["summary"]["ownership"]["candidate"] -= 1
        code_map["summary"]["ownership"]["reviewed"] += 1
        behavior = next(
            item for item in contracts["behaviors"]
            if item["id"] == "airplane.complete_component_mask"
        )
        behavior["native_units"].append(candidate["id"])
        ledger["native_coverage"]["reviewed_game_owned"] += 1
        ledger["native_coverage"]["candidate_game_owned"] -= 1
        ledger["native_coverage"]["unknown_function_ownership"] -= 1
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(ValueError, "does not cover the behavior native units"):
                self.validate_values(
                    Path(raw), contracts=contracts, code_map=code_map, ledger=ledger
                )

    def test_native_coverage_debt_cannot_be_hidden(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["native_coverage"]["unknown_function_ownership"] -= 1
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(ValueError, "unknown_function_ownership drifted"):
                self.validate_values(Path(raw), ledger=ledger)

    def test_receipt_builder_really_executes_and_hashes_inputs(self) -> None:
        suite = {
            "id": "unit.receipt",
            "contract_ids": ["airplane.complete_component_mask"],
            "mode": "replay",
            "command": [sys.executable, "-c", "print('receipt executed')"],
            "runtime_paths": ["tools/miel_vliegt/behavior_evidence.py"],
        }
        receipt = build_receipt(ROOT, suite, execute=True)
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(len(next(iter(receipt["runtime_hashes"].values()))), 64)

    def test_receipt_builder_uses_active_python_environment(self) -> None:
        suite = {
            "id": "unit.python-receipt",
            "contract_ids": ["airplane.complete_component_mask"],
            "mode": "replay",
            "command": [
                "python3", "-c",
                f"import sys; raise SystemExit(sys.executable != {sys.executable!r})",
            ],
            "runtime_paths": ["tools/miel_vliegt/behavior_evidence.py"],
        }
        receipt = build_receipt(ROOT, suite, execute=True)
        self.assertEqual(receipt["command"][0], "python3")
        self.assertEqual(receipt["result"], "PASS")


if __name__ == "__main__":
    unittest.main()
