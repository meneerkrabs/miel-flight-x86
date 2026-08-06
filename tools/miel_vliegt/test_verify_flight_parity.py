#!/usr/bin/env python3
"""Regression tests for the flight parity ledger gate."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.verify_flight_parity import validate


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "content/miel_vliegt/flight_parity_ledger.json"
CHECKPOINTS = ROOT / "content/miel_vliegt/flight_parity_checkpoints.json"


class FlightParityLedgerTests(unittest.TestCase):
    def write_json(self, directory: Path, name: str, value: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_reviewed_ledger_is_valid(self) -> None:
        counts = validate(ROOT, LEDGER, CHECKPOINTS)
        self.assertGreaterEqual(counts["EQUIVALENT"], 14)
        self.assertEqual(counts["MISSING"], 13)

    def test_rejects_unreviewed_missing_gap(self) -> None:
        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        extra = copy.deepcopy(next(record for record in ledger["records"] if record["status"] == "MISSING"))
        extra["id"] = "flight.unknown_gap"
        ledger["records"].append(extra)
        ledger["records"].sort(key=lambda record: record["id"])
        ledger["quality_floor"]["maximum_missing"] += 1
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write_json(Path(raw_directory), "ledger.json", ledger)
            with self.assertRaisesRegex(ValueError, "reviewed MISSING allowlist drifted"):
                validate(ROOT, path, CHECKPOINTS)

    def test_rejects_false_native_trace_claim(self) -> None:
        checkpoints = json.loads(CHECKPOINTS.read_text(encoding="utf-8"))
        checkpoints["native_trace_available"] = True
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write_json(Path(raw_directory), "checkpoints.json", checkpoints)
            with self.assertRaisesRegex(ValueError, "native_trace_available"):
                validate(ROOT, LEDGER, path)

    def test_rejects_checkpoint_drift(self) -> None:
        checkpoints = json.loads(CHECKPOINTS.read_text(encoding="utf-8"))
        checkpoints["runtime"]["world_contract"]["world"]["width"] = 3999
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write_json(Path(raw_directory), "checkpoints.json", checkpoints)
            with self.assertRaisesRegex(ValueError, "world/start drifted"):
                validate(ROOT, LEDGER, path)

    def test_rejects_native_intro_availability_drift(self) -> None:
        checkpoints = json.loads(CHECKPOINTS.read_text(encoding="utf-8"))
        checkpoints["render"]["intro"]["availability"] = "render-pending"
        with tempfile.TemporaryDirectory() as raw_directory:
            path = self.write_json(Path(raw_directory), "checkpoints.json", checkpoints)
            with self.assertRaisesRegex(ValueError, "render.intro availability drifted"):
                validate(ROOT, LEDGER, path)


if __name__ == "__main__":
    unittest.main()
