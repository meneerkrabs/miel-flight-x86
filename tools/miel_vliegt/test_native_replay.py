#!/usr/bin/env python3
import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_replay


ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "tools/miel_vliegt/scenarios"
SCENARIO = SCENARIOS / "native_replay_controls_fixture.json"
RECEIPT = SCENARIOS / "native_replay_receipt_fixture.json"


class NativeReplayTests(unittest.TestCase):
    def setUp(self):
        self.scenario = native_replay.load_scenario(SCENARIO)

    def test_fixture_builds_fixed_monotonic_key_and_mouse_replay(self):
        plan = native_replay.build_replay(self.scenario)
        self.assertEqual(plan["scenario"]["sha256"], "d3fec5056205a1f1ee7052d73fdb3e54438d4ecfdc994bb8afabbe54f112492c")
        self.assertEqual(plan["plan_sha256"], "2ae7bdc711324c10607ce6d618a86b36de0771740cf718966bfdc0d259621bfa")
        self.assertEqual(
            [event["monotonic_ns"] for event in plan["events"]],
            [40_000_000, 80_000_000, 120_000_000, 160_000_000, 200_000_000, 280_000_000],
        )
        self.assertEqual([event["sequence"] for event in plan["events"]], list(range(6)))
        self.assertEqual({event["type"] for event in plan["events"]}, {"key", "mouse"})
        self.assertEqual(plan["checkpoints"][1]["monotonic_ns"], 320_000_000)
        self.assertEqual(plan["seed"], 1_592_639_710)

    def test_canonical_json_and_hash_ignore_object_insertion_order(self):
        reordered = {key: self.scenario[key] for key in reversed(self.scenario)}
        self.assertEqual(native_replay.canonical_json(self.scenario), native_replay.canonical_json(reordered))
        self.assertEqual(native_replay.scenario_sha256(self.scenario), native_replay.scenario_sha256(reordered))
        self.assertEqual(native_replay.canonical_json({"é": 1, "a": 2}), '{"a":2,"é":1}')

    def test_events_and_checkpoints_must_follow_fixed_tick_order(self):
        broken = copy.deepcopy(self.scenario)
        broken["events"][1]["tick"] = 0
        with self.assertRaisesRegex(ValueError, "non-decreasing tick"):
            native_replay.validate_scenario(broken)
        broken = copy.deepcopy(self.scenario)
        broken["timing"]["monotonic_origin_ns"] = 10
        with self.assertRaisesRegex(ValueError, "origins of zero"):
            native_replay.validate_scenario(broken)
        broken = copy.deepcopy(self.scenario)
        broken["checkpoints"][1]["tick"] = 3
        with self.assertRaisesRegex(ValueError, "non-decreasing tick"):
            native_replay.validate_scenario(broken)

    def test_source_hashes_fail_closed_for_drift_missing_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            source.write_bytes(b"known")
            hashes = {"source.bin": native_replay.sha256_file(source)}
            self.assertEqual(native_replay.validate_source_hashes(hashes, root), hashes)
            source.write_bytes(b"drift")
            with self.assertRaisesRegex(ValueError, "hash drifted"):
                native_replay.validate_source_hashes(hashes, root)
            with self.assertRaisesRegex(ValueError, "missing"):
                native_replay.validate_source_hashes({"absent.bin": "0" * 64}, root)
            with self.assertRaisesRegex(ValueError, "unsafe|escapes"):
                native_replay.validate_source_hashes({"../outside.bin": "0" * 64}, root)
            with self.assertRaisesRegex(ValueError, "at least one"):
                native_replay.validate_source_hashes({}, root)

    def test_shards_are_stable_across_discovery_order_and_set_growth(self):
        second = copy.deepcopy(self.scenario)
        second["id"] = "controls-second"
        second["description"] = "Second deterministic shard fixture."
        first_manifest = native_replay.build_shard_manifest([self.scenario, second], 7)
        reversed_manifest = native_replay.build_shard_manifest([second, self.scenario], 7)
        self.assertEqual(first_manifest, reversed_manifest)
        original_shard = native_replay.shard_for(self.scenario["id"], 7)
        third = copy.deepcopy(self.scenario)
        third["id"] = "controls-third"
        grown = native_replay.build_shard_manifest([third, self.scenario, second], 7)
        assignment = {row["id"]: row["shard"] for row in grown["assignments"]}
        self.assertEqual(assignment[self.scenario["id"]], original_shard)
        self.assertEqual(
            sorted(sum((native_replay.scenarios_for_shard(grown, index) for index in range(7)), [])),
            sorted(assignment),
        )

    def test_receipt_is_bound_to_plan_sources_seed_events_and_checkpoints(self):
        receipt = native_replay.validate_receipt(RECEIPT, SCENARIO)
        self.assertEqual(receipt["status"], "PASS")
        for field in ("plan_sha256", "source_hashes", "seed", "event_count", "completed_tick"):
            tampered = copy.deepcopy(receipt)
            tampered[field] = "0" * 64 if field == "plan_sha256" else None
            with self.assertRaisesRegex(ValueError, field):
                native_replay.validate_receipt(tampered, self.scenario)
        tampered = copy.deepcopy(receipt)
        tampered["checkpoints"][0]["tick"] += 1
        with self.assertRaisesRegex(ValueError, "checkpoint 0 drifted"):
            native_replay.validate_receipt(tampered, self.scenario)
        tampered = copy.deepcopy(receipt)
        tampered["checkpoints"][0]["state_sha256"] = "not-a-hash"
        with self.assertRaisesRegex(ValueError, "state hash"):
            native_replay.validate_receipt(tampered, self.scenario)

    def test_cli_plan_is_canonical_and_repeatable(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.json"
            second = Path(temporary) / "second.json"
            command = ["python3", str(ROOT / "tools/miel_vliegt/native_replay.py"), "plan", str(SCENARIO)]
            subprocess.run([*command, str(first)], check=True, cwd=ROOT)
            subprocess.run([*command, str(second)], check=True, cwd=ROOT)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertTrue(first.read_bytes().endswith(b"\n"))
            self.assertEqual(first.read_text(encoding="utf-8").rstrip("\n"), native_replay.canonical_json(json.loads(first.read_text())))


if __name__ == "__main__":
    unittest.main()
