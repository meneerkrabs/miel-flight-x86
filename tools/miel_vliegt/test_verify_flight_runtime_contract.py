#!/usr/bin/env python3
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.verify_flight_runtime_contract import (
    ROOT,
    validate,
    validate_pixel_proof,
)


def documents():
    content = ROOT / "content/miel_vliegt"
    return (
        json.loads((content / "flight_runtime_parity_contract.json").read_text()),
        json.loads((content / "flight_runtime_trace_contract.json").read_text()),
    )


class FlightRuntimeContractVerifierTests(unittest.TestCase):
    def write_pixel_fixture(self, root: Path):
        native_bytes = bytes((0, 0, 255, 0, 0, 255, 0, 0))
        web_bytes = bytes((255, 0, 0, 255, 0, 255, 0, 255))
        (root / "native.raw").write_bytes(native_bytes)
        (root / "web.raw").write_bytes(web_bytes)

        def digest(path):
            return hashlib.sha256((root / path).read_bytes()).hexdigest()

        native = {
            "schema": 1,
            "protocol": "miel-vliegt-framebuffer",
            "width": 2,
            "height": 1,
            "row_stride": 8,
            "pixel_format": "bgrx8",
            "origin": "top-left",
            "alpha_mode": "opaque",
            "data": {"path": "native.raw", "sha256": digest("native.raw")},
        }
        web = {
            **native,
            "pixel_format": "rgba8",
            "alpha_mode": "straight",
            "data": {"path": "web.raw", "sha256": digest("web.raw")},
        }
        (root / "native-frame.json").write_text(json.dumps(native))
        (root / "web-frame.json").write_text(json.dumps(web))
        canonical_sha256 = hashlib.sha256(web_bytes).hexdigest()
        policy = {"canonical_format": "rgba8", "comparison": "EXACT_BYTES"}
        policy_sha256 = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        receipt = {
            "schema": 1,
            "status": "PASS",
            "scenario": "pixel-fixture",
            "native_frame_sha256": digest("native-frame.json"),
            "web_frame_sha256": digest("web-frame.json"),
            "canonical_rgba_sha256": canonical_sha256,
            "comparator": "canonical-rgba8-exact-v1",
            "comparison_policy": policy,
            "comparison_policy_sha256": policy_sha256,
        }
        (root / "pixel-receipt.json").write_text(json.dumps(receipt))
        return {
            "native_frame": "native-frame.json",
            "web_frame": "web-frame.json",
            "pixel_receipt": "pixel-receipt.json",
        }, receipt, web

    def test_repository_contract_is_valid(self):
        runtime, trace = documents()
        self.assertEqual(validate(runtime, trace), [])

    def test_every_dynamic_domain_requires_a_gate(self):
        runtime, trace = documents()
        runtime["checkpoints"] = [
            row for row in runtime["checkpoints"] if row["domain"] != "collision"
        ]
        self.assertTrue(any("collision" in error for error in validate(runtime, trace)))

    def test_systems_is_a_fail_closed_semantic_release_gate(self):
        runtime, trace = documents()
        gate = next(
            row for row in runtime["checkpoints"]
            if row["id"] == "systems.native_response"
        )
        self.assertEqual(gate["domain"], "systems")
        self.assertTrue(gate["release_gate"])
        self.assertEqual(gate["status"], "BLOCKED_NATIVE_REFERENCE")
        self.assertEqual(
            gate["evidence"],
            "content/miel_vliegt/native_flight_state_layout.json#/systems",
        )
        self.assertEqual(
            set(gate["native_functions"]),
            {"0x40e610", "0x410cb0", "0x42db70", "0x42e240"},
        )
        self.assertEqual(
            set(gate["native_observation_sites"]),
            {
                "0x0040e610", "0x0040ee14", "0x0040f5cb",
                "0x00410cdf", "0x0042db70", "0x0042e240",
            },
        )
        self.assertEqual(
            set(gate["trace_scenarios"]),
            {
                "taxi-straight", "takeoff-climb", "level-flight-turn",
                "approach-landing", "impact-crash",
            },
        )
        systems_channel = next(
            row for row in trace["capture_channels"]
            if row["domain"] == "systems"
        )
        self.assertEqual(systems_channel["id"], "systems.state")
        self.assertEqual(
            systems_channel["native_layout"],
            "content/miel_vliegt/native_flight_state_layout.json#/systems",
        )
        self.assertTrue(all(
            "systems" in next(
                row for row in trace["scenarios"]
                if row["id"] == scenario_id
            )["domains"]
            for scenario_id in gate["trace_scenarios"]
        ))
        collision_channel = next(
            row for row in trace["capture_channels"]
            if row["domain"] == "collision"
        )
        self.assertIn("observed", collision_channel["required_fields"])
        self.assertIn(
            "contacts[].contact_position",
            collision_channel["required_fields"],
        )

    def test_json_pointer_references_must_resolve(self):
        runtime, trace = documents()
        gate = next(
            row for row in runtime["checkpoints"]
            if row["id"] == "systems.native_response"
        )
        gate["evidence"] = (
            "content/miel_vliegt/native_flight_state_layout.json#/missing"
        )
        errors = validate(runtime, trace)
        self.assertTrue(any("JSON pointer does not exist" in error for error in errors))

    def test_systems_cannot_point_at_the_physics_layout(self):
        runtime, trace = documents()
        gate = next(
            row for row in runtime["checkpoints"]
            if row["id"] == "systems.native_response"
        )
        gate["evidence"] = (
            "content/miel_vliegt/native_flight_state_layout.json#/physics"
        )
        errors = validate(runtime, trace)
        self.assertTrue(any("canonical evidence drifted" in error for error in errors))

    def test_gate_must_reference_a_scenario_that_observes_its_domain(self):
        runtime, trace = documents()
        gate = next(row for row in runtime["checkpoints"] if row["id"] == "camera.native_response")
        gate["trace_scenarios"] = ["controls-press-hold-release"]
        self.assertTrue(any("does not observe camera" in error for error in validate(runtime, trace)))

    def test_claimed_equivalence_requires_real_artifact_references(self):
        runtime, trace = documents()
        gate = next(row for row in runtime["checkpoints"] if row["id"] == "physics.native_trajectories")
        gate["status"] = "TRACE_EQUIVALENT"
        scenario = next(
            row for row in trace["scenarios"]
            if row["id"] == "taxi-straight"
        )
        scenario["web_output"] = "content/miel_vliegt/unreviewed-web-output.json"
        errors = validate(runtime, trace)
        self.assertTrue(any("exact bijection" in error for error in errors))
        self.assertTrue(any(
            "immutable browser evidence registry output" in error
            for error in errors
        ))

    def test_blocked_scenario_cannot_smuggle_native_output(self):
        runtime, trace = documents()
        trace["scenarios"][0]["native_output"] = "fake-native.json"
        self.assertTrue(any("contains native_output" in error for error in validate(runtime, trace)))

    def test_blocked_web_candidate_must_come_from_the_fixed_registry(self):
        runtime, trace = documents()
        trace["scenarios"][0]["web_output"] = "fake-web.json"
        self.assertTrue(any(
            "immutable browser evidence registry output" in error
            for error in validate(runtime, trace)
        ))

    def test_the_seven_scenario_capture_matrix_cannot_shrink(self):
        runtime, trace = documents()
        trace["scenarios"].pop()
        self.assertTrue(any("exactly the canonical seven" in error for error in validate(runtime, trace)))

    def test_release_gate_scenario_sets_cannot_shrink(self):
        runtime, trace = documents()
        gate = next(row for row in runtime["checkpoints"] if row["id"] == "camera.native_response")
        gate["trace_scenarios"].pop()
        self.assertTrue(any("canonical trace_scenarios" in error for error in validate(runtime, trace)))

    def test_duplicate_proof_rows_are_not_a_bijection(self):
        runtime, trace = documents()
        gate = next(row for row in runtime["checkpoints"] if row["id"] == "rendering.native_pixels")
        gate["status"] = "PIXEL_EQUIVALENT"
        gate["proofs"] = [
            {"scenario": "default-airplane-fixed-camera-frame"},
            {"scenario": "default-airplane-fixed-camera-frame"},
        ]
        self.assertTrue(any("exact bijection" in error for error in validate(runtime, trace)))

    def test_promoted_gate_requires_promoted_scenario_transcripts_and_layout(self):
        runtime, trace = documents()
        gate = next(row for row in runtime["checkpoints"] if row["id"] == "controls.native_response")
        gate["status"] = "TRACE_EQUIVALENT"
        gate["proofs"] = [{"scenario": "controls-press-hold-release"}]
        errors = validate(runtime, trace)
        self.assertTrue(any("scenario is still BLOCKED_NATIVE_REFERENCE" in error for error in errors))
        self.assertTrue(any("reviewed native layout" in error for error in errors))

    def test_policy_cannot_claim_progress_while_release_gates_are_blocked(self):
        runtime, trace = documents()
        trace["policy"]["current_status"] = "TRACE_EQUIVALENT"
        self.assertTrue(any("policy.current_status" in error for error in validate(runtime, trace)))

    def test_pixel_pass_recomputes_canonical_rgba_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof, _receipt, _web = self.write_pixel_fixture(root)
            validate_pixel_proof(root, proof, "pixel-fixture")

    def test_one_pixel_byte_fails_even_after_all_receipt_hashes_are_refreshed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof, receipt, web = self.write_pixel_fixture(root)
            changed = bytearray((root / "web.raw").read_bytes())
            changed[0] ^= 1
            (root / "web.raw").write_bytes(changed)
            web["data"]["sha256"] = hashlib.sha256(changed).hexdigest()
            (root / "web-frame.json").write_text(json.dumps(web))
            receipt["web_frame_sha256"] = hashlib.sha256(
                (root / "web-frame.json").read_bytes()
            ).hexdigest()
            receipt["canonical_rgba_sha256"] = hashlib.sha256(changed).hexdigest()
            (root / "pixel-receipt.json").write_text(json.dumps(receipt))

            with self.assertRaisesRegex(ValueError, "canonical RGBA8 bytes differ"):
                validate_pixel_proof(root, proof, "pixel-fixture")


if __name__ == "__main__":
    unittest.main()
