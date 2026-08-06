#!/usr/bin/env python3
"""Integrity and honesty gate for the native flight runtime capture contract."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "content/miel_vliegt"
CONTRACT_PATH = CONTENT / "flight_runtime_trace_contract.json"


def load(name: str) -> dict:
    return json.loads((CONTENT / name).read_text(encoding="utf-8"))


class FlightRuntimeTraceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load("flight_runtime_trace_contract.json")
        cls.identity = load("source_identity.json")
        cls.help_contract = load("dutch_help_contract.json")
        cls.flight_contract = load("uds_flight_contracts.json")
        cls.step_closure = load("flight_step_closure.json")
        cls.state_layout = load("native_flight_state_layout.json")
        cls.trajectory = load("trajectory_contract.json")
        cls.materials = load("ccf_material_contract.json")
        cls.render_checkpoints = load("ccf_render_checkpoints.json")

    def test_source_and_native_units_are_hash_pinned(self) -> None:
        self.assertEqual(self.contract["schema"], 1)
        self.assertEqual(
            self.contract["source_identity"]["executable_sha256"],
            self.identity["executable"]["sha256"],
        )
        units = self.contract["native_units"]
        self.assertEqual(len(units), len({unit["id"] for unit in units}))
        self.assertEqual(
            {unit["domain"] for unit in units},
            {"controls", "physics", "camera", "collision", "rendering"},
        )
        for unit in units:
            self.assertRegex(unit["address"], r"^0x[0-9a-f]{8}$")
            self.assertRegex(unit["end"], r"^0x[0-9a-f]{8}$")
            self.assertRegex(unit["sha256"], r"^[0-9a-f]{64}$")

        # The private function inventory is regenerated on the trusted build
        # host. Validate every address and hash when it is locally available,
        # while keeping the tracked trace contract independently reviewable.
        index_path = CONTENT / "native_function_index.json"
        if index_path.is_file():
            indexed = {
                row["address"]: row
                for row in json.loads(index_path.read_text(encoding="utf-8"))["functions"]
            }
            for unit in units:
                self.assertIn(unit["address"], indexed)
                self.assertEqual(unit["end"], indexed[unit["address"]]["end"])
                self.assertEqual(unit["sha256"], indexed[unit["address"]]["sha256"])

    def test_static_claims_match_their_original_evidence(self) -> None:
        claims = {
            row["id"]: row for row in self.contract["proven_static_contracts"]
        }
        controls = {
            row["id"]: row
            for row in self.help_contract["categories"]["controls"]
        }
        expected_control_hashes = {
            "left": controls["turn_left"]["evidence"][0]["sha256"],
            "right": controls["turn_right"]["evidence"][0]["sha256"],
            "up": controls["descend"]["evidence"][0]["sha256"],
            "down": controls["ascend"]["evidence"][0]["sha256"],
            "shift": controls["accelerate"]["evidence"][0]["sha256"],
            "control": controls["decelerate"]["evidence"][0]["sha256"],
        }
        self.assertEqual(
            claims["controls.key_meaning"]["values"],
            self.flight_contract["runtime"]["controls"],
        )
        self.assertEqual(
            claims["controls.key_meaning"]["evidence_sha256"],
            expected_control_hashes,
        )

        start = self.flight_contract["native_proofs"]["start_position"]
        self.assertEqual(claims["physics.initial_position"]["value"], start["values"])
        self.assertEqual(
            claims["physics.initial_position"]["instruction_sha256"],
            start["bytes_sha256"],
        )
        fixed_step = self.step_closure["fixed_step"]
        self.assertEqual(claims["physics.maximum_step"]["value"], fixed_step["max_step_seconds"])
        self.assertEqual(claims["physics.maximum_step"]["f32_bits"], fixed_step["max_step_bits"])

        material_claim = claims["rendering.source_assets"]["values"]
        self.assertEqual(material_claim["parts"], self.materials["counts"]["parts"])
        self.assertEqual(
            material_claim["material_uses"], self.materials["counts"]["material_uses"]
        )
        self.assertEqual(
            material_claim["unique_textures"], self.materials["counts"]["unique_textures"]
        )
        self.assertEqual(
            material_claim["texture_formats"], self.materials["counts"]["formats"]
        )

    def test_absent_native_outputs_remain_explicit_blockers(self) -> None:
        self.assertEqual(
            self.contract["policy"]["current_status"], "BLOCKED_NATIVE_REFERENCE"
        )
        channels = self.contract["capture_channels"]
        self.assertEqual(
            {channel["domain"] for channel in channels},
            {"controls", "physics", "systems", "camera", "collision", "rendering"},
        )
        for channel in channels:
            self.assertEqual(channel["status"], "BLOCKED_NATIVE_REFERENCE")
            self.assertRegex(
                channel["native_layout"],
                r"^content/miel_vliegt/native_flight_state_layout\.json#/",
            )

        scenarios = self.contract["scenarios"]
        self.assertEqual(len(scenarios), len({scenario["id"] for scenario in scenarios}))
        self.assertEqual(
            set().union(*(set(scenario["domains"]) for scenario in scenarios)),
            {
                "controls", "physics", "systems",
                "camera", "collision", "rendering",
            },
        )
        for scenario in scenarios:
            self.assertEqual(scenario["status"], "BLOCKED_NATIVE_REFERENCE")
            self.assertIsNone(scenario["native_reference"])
            self.assertIsNone(scenario["native_output"])
            self.assertTrue(scenario["blockers"])

    def test_trajectory_and_pixel_backlogs_are_preserved_exactly(self) -> None:
        trajectory_ids = {
            row["id"] for row in self.trajectory["native_scenario_backlog"]
        }
        scenario_ids = {row["id"] for row in self.contract["scenarios"]}
        self.assertTrue(trajectory_ids <= scenario_ids)
        self.assertTrue(
            all(
                row["status"] == "MISSING"
                and row["input_script"] is None
                for row in self.trajectory["native_scenario_backlog"]
            )
        )
        self.assertEqual(
            self.contract["comparison"]["trajectory"]["absolute_tolerances"],
            self.trajectory["comparison"]["absolute_tolerances"],
        )
        self.assertEqual(
            {
                key: self.contract["comparison"]["pixels"][key]
                for key in (
                    "maximum_channel_delta",
                    "maximum_different_pixels",
                    "maximum_mean_absolute_channel_delta",
                )
            },
            self.render_checkpoints["policy"],
        )
        fixed_frame = next(
            row
            for row in self.contract["scenarios"]
            if row["id"] == "default-airplane-fixed-camera-frame"
        )
        self.assertIsNone(fixed_frame["camera_contract"])
        self.assertEqual(
            self.render_checkpoints["checkpoints"][0]["status"],
            "BLOCKED_NATIVE_REFERENCE",
        )

    def test_promotion_policy_cannot_confuse_static_and_dynamic_evidence(self) -> None:
        promotion = self.contract["policy"]["promotion"]
        self.assertIn("raw native artifact", promotion["CAPTURED_NATIVE_REFERENCE"])
        self.assertIn("native and web traces", promotion["TRACE_EQUIVALENT"])
        self.assertIn("framebuffer", promotion["PIXEL_EQUIVALENT"])
        self.assertIn("20 indirect calls", " ".join(self.contract["global_blockers"]))
        self.assertEqual(self.step_closure["status"], "BLOCKED_CLOSURE")
        self.assertEqual(
            self.step_closure["blockers"]["unresolved_step_indirect_calls"], 20
        )

    def test_reviewed_native_layout_uses_real_per_frame_boundaries(self) -> None:
        layout = self.state_layout
        self.assertEqual(layout["status"], "REVIEWED_STATIC_LAYOUT")
        self.assertTrue(layout["policy"]["layout_is_not_runtime_evidence"])
        self.assertEqual(layout["controls"]["sampler"], "0x0041d990")
        self.assertEqual(layout["controls"]["post_mapping_capture"], "0x0041db7d")
        self.assertEqual(layout["camera"]["mode_open"], "0x0042b9a0")
        self.assertEqual(layout["camera"]["per_frame_update"], "0x0042ca10")
        self.assertEqual(layout["camera"]["state_commit"], "0x0042d2d3")
        self.assertEqual(layout["camera"]["camera_offsets"]["render_snapshot"], "0x9a4")
        self.assertEqual(
            layout["camera"]["camera_offsets"]["render_scaled_rotation_matrix_3x3_f32"],
            ["0x9a4", "0x9a8", "0x9ac", "0x9b0", "0x9b4", "0x9b8", "0x9bc", "0x9c0", "0x9c4"],
        )
        self.assertEqual(
            layout["camera"]["camera_offsets"]["render_world_position_xyz_f32"],
            ["0x9d0", "0x9d4", "0x9d8"],
        )
        self.assertEqual(layout["rendering"]["mode_fly_post_render_site"], "0x0042db51")
        self.assertEqual(layout["rendering"]["manager_render_callback"], "0x0041dbc0")
        self.assertEqual(layout["rendering"]["manager_render_vtable_slot"], "0x0044cc10")
        self.assertEqual(layout["rendering"]["device_read_screen_vtable_offset"], "0xbc")
        self.assertEqual(layout["physics"]["minimum_flight_size"], 613)
        self.assertEqual(layout["systems"]["fuel_f32"], "0x198")
        self.assertEqual(layout["systems"]["integrity_current_f32"], "0x1a0")
        self.assertEqual(layout["systems"]["integrity_maximum_f32"], "0x1a4")
        self.assertEqual(layout["systems"]["terminal_crash_hook"], "0x0042e240")
        self.assertEqual(
            layout["systems"]["landing_classification"],
            "DERIVED_TEMPORAL_PREDICATE",
        )
        self.assertNotIn("fuel", layout["unresolved_system_fields"])
        self.assertNotIn("integrity", layout["unresolved_system_fields"])

        rendered = json.dumps(self.contract)
        self.assertNotIn("DirectInput sample location and edge semantics are unknown", rendered)
        self.assertNotIn("Flight and camera object layouts are unreviewed", rendered)
        self.assertNotIn("Damage and destroyed-state fields are unknown", rendered)

    def test_native_units_do_not_mislabel_mode_open_as_camera_update(self) -> None:
        units = {row["id"]: row for row in self.contract["native_units"]}
        self.assertEqual(units["controls.sampler"]["address"], "0x0041d990")
        self.assertEqual(
            units["controls.sampler"]["capture_abi"]["post_mapping"],
            "0x0041db7d",
        )
        self.assertEqual(units["flight.mode_activate"]["address"], "0x0042b9a0")
        self.assertEqual(units["flight.update"]["capture_abi"]["entry"], "0x0042ca10")
        self.assertEqual(
            units["flight.update"]["capture_abi"]["camera_commit"],
            "0x0042d2d3",
        )


if __name__ == "__main__":
    unittest.main()
