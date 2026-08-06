#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.build_native_trace_map import build_map
from tools.miel_vliegt import native_trace


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tools/miel_vliegt/fixtures"


class NativeTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = native_trace.load_manifest()
        cls.coverage_map = build_map(native_trace.DEFAULT_INDEX)

    def test_generated_coverage_map_has_stable_function_block_and_edge_ids(self):
        counts = self.coverage_map["counts"]
        self.assertEqual(counts["functions"], 1369)
        self.assertEqual(counts["basic_blocks"], 14925)
        self.assertGreater(counts["edges"], 14000)
        self.assertIn("fn_0040e610", {item["id"] for item in self.coverage_map["functions"]})
        self.assertIn("bb_0040e610", {item["id"] for item in self.coverage_map["basic_blocks"]})

    def test_checked_in_fixture_replays_without_native_executable(self):
        records = native_trace.read_trace(FIXTURES / "native_trace_protocol_fixture.ndjson")
        native_trace.validate_trace(records)
        self.assertEqual(records[0]["capture_kind"], "protocol_fixture")
        self.assertEqual(records[1]["values"]["dt_seconds"], 0.04)
        report = native_trace.coverage_report(records, self.coverage_map)
        self.assertEqual(report["coverage.function"]["observed"], 1)
        self.assertEqual(report["coverage.function"]["unknown_count"], 0)
        self.assertGreater(report["coverage.block"]["uncovered_count"], 10000)

    def test_import_canonicalizes_float_bits_and_removes_pointer_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "trace.ndjson"
            records = native_trace.import_windbg(
                FIXTURES / "native_trace_protocol_fixture.windbg.log",
                output,
                "fixture-level-flight",
                "Protocol-only deterministic fixture",
                "0" * 64,
                capture_kind="protocol_fixture",
            )
        self.assertEqual(records[1]["values"], {"dt_seconds": 0.04})
        self.assertNotIn("diagnostics", records[1])

    def test_footer_detects_tampering(self):
        records = native_trace.read_trace(FIXTURES / "native_trace_protocol_fixture.ndjson")
        records[1]["values"]["dt_seconds"] = 0.5
        with self.assertRaisesRegex(ValueError, "content hash mismatch"):
            native_trace.validate_trace(records)

    def test_web_probe_events_import_into_the_native_comparison_protocol(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary) / "web.ndjson"
            output = Path(temporary) / "canonical.ndjson"
            raw.write_text(json.dumps({
                "record": "behavior",
                "protocol": native_trace.PROTOCOL,
                "version": 1,
                "sequence": 0,
                "scenario": "hangar.interaction",
                "adapter": "flight_hangar",
                "contract_id": "airplane.complete_component_mask",
                "step": 1,
                "phase": "exit",
                "channel": "airplane.airworthiness",
                "values": {"airworthy": False},
            }) + "\n", encoding="utf-8")
            records = native_trace.import_web(
                raw, output, "hangar.interaction", "web probe fixture",
                "0" * 64, "1" * 64,
            )
        self.assertEqual(records[0]["capture_kind"], "web")
        self.assertEqual(records[0]["source"]["web_runtime_sha256"], "1" * 64)
        self.assertEqual(records[1]["contract_id"], "airplane.complete_component_mask")
        native_trace.validate_trace(records)

    def test_comparator_accepts_float_tolerance_and_rejects_behavior_drift(self):
        baseline = native_trace.read_trace(FIXTURES / "native_trace_protocol_fixture.ndjson")
        candidate = copy.deepcopy(baseline[:-1])
        candidate[1]["values"]["dt_seconds"] += 0.00000005
        candidate = native_trace.canonicalize_records(candidate, self.manifest)
        self.assertEqual(
            native_trace.compare_traces(baseline, candidate, self.manifest, self.coverage_map),
            [],
        )
        candidate = copy.deepcopy(baseline[:-1])
        candidate[1]["values"]["dt_seconds"] = 0.041
        candidate = native_trace.canonicalize_records(candidate, self.manifest)
        differences = native_trace.compare_traces(baseline, candidate, self.manifest, self.coverage_map)
        self.assertTrue(any("dt_seconds" in difference for difference in differences))

    def test_unknown_edge_is_reported(self):
        records = native_trace.read_trace(FIXTURES / "native_trace_protocol_fixture.ndjson")[:-1]
        records.append({
            "record": "coverage",
            "sequence": len(records) - 1,
            "channel": "coverage.edge",
            "id": "edge_deadbeef_cafebabe",
        })
        records = native_trace.canonicalize_records(records, self.manifest)
        report = native_trace.coverage_report(records, self.coverage_map)
        self.assertEqual(report["coverage.edge"]["unknown"], ["edge_deadbeef_cafebabe"])

    def test_probe_manifest_pins_executable_and_behavior_addresses(self):
        self.assertEqual(
            self.manifest["source"]["executable_sha256"],
            "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2",
        )
        hooks = {item["id"]: item for item in self.manifest["behavior_hooks"]}
        self.assertEqual(hooks["flight.step.enter"]["address"], "0x0040e610")
        self.assertEqual(hooks["flight.step.leave"]["address"], "0x0040f82f")


if __name__ == "__main__":
    unittest.main()
