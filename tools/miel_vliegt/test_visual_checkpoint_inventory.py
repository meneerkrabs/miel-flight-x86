#!/usr/bin/env python3
"""Regression tests for the source-generated flight visual inventory."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.visual_checkpoint_inventory import (
    ROOT,
    UNPROVEN_BLOCKER,
    build_inventory,
    validate_inventory,
)


class VisualCheckpointInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.generated = build_inventory(ROOT)

    def test_checked_in_inventory_is_source_generated_and_valid(self):
        checked_in = json.loads(
            (ROOT / "content/miel_vliegt/visual_checkpoint_inventory.json")
            .read_text(encoding="utf-8")
        )
        validate_inventory(checked_in, root=ROOT)
        self.assertEqual(checked_in, self.generated)

    def test_all_twenty_two_native_modes_have_a_render_checkpoint(self):
        mode_checkpoints = [
            row for row in self.generated["checkpoints"]
            if row["kind"] == "MODE_RENDER"
        ]
        self.assertEqual(len(mode_checkpoints), 22)
        self.assertEqual(
            {row["coordinates"]["mode"] for row in mode_checkpoints},
            set(self.generated["axes"]["mode.render"]),
        )

    def test_required_visual_state_axes_are_expanded_into_checkpoints(self):
        axes = self.generated["axes"]
        self.assertEqual([row["score"] for row in axes["judge.score"]], [0, 1, 2, 3, 4, 5])
        self.assertEqual(len(axes["diploma.award"]), 6)
        self.assertEqual(len(axes["diploma.phase"]), 2)
        self.assertGreater(len(axes["outro.visual_command"]), 20)
        self.assertEqual(
            [row["modifier"] for row in axes["animation.modifier"]],
            ["LOOP", "LOOP_RANDOMTIMES", "LOOP_TIMES", "WAIT"],
        )
        self.assertEqual(axes["animation.phase"], ["STARTED", "ACTIVE", "COMPLETED"])

    def test_missing_duplicate_or_foreign_checkpoint_fails_closed(self):
        missing = copy.deepcopy(self.generated)
        missing["checkpoints"].pop()
        with self.assertRaisesRegex(ValueError, "exact checkpoint inventory"):
            validate_inventory(missing, root=ROOT)

        duplicate = copy.deepcopy(self.generated)
        duplicate["checkpoints"].append(copy.deepcopy(duplicate["checkpoints"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate checkpoint"):
            validate_inventory(duplicate, root=ROOT)

        foreign = copy.deepcopy(self.generated)
        foreign["checkpoints"][0]["id"] = "mode:invented:render"
        with self.assertRaisesRegex(ValueError, "exact checkpoint inventory"):
            validate_inventory(foreign, root=ROOT)

    def test_source_hash_axis_or_subject_drift_fails_closed(self):
        source_drift = copy.deepcopy(self.generated)
        source_drift["sources"]["native_mode_bodies"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source-generated header"):
            validate_inventory(source_drift, root=ROOT)

        axis_drift = copy.deepcopy(self.generated)
        axis_drift["axes"]["judge.score"].pop()
        with self.assertRaisesRegex(ValueError, "source-generated header"):
            validate_inventory(axis_drift, root=ROOT)

        subject_drift = copy.deepcopy(self.generated)
        subject_drift["checkpoints"][0]["subject_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "structural identity"):
            validate_inventory(subject_drift, root=ROOT)

    def test_unproven_checkpoint_cannot_smuggle_or_lose_evidence_state(self):
        proof_on_unproven = copy.deepcopy(self.generated)
        proof_on_unproven["checkpoints"][0]["proof"] = {
            "native_frame": "native.json",
            "web_frame": "web.json",
            "pixel_receipt": "receipt.json",
        }
        with self.assertRaisesRegex(ValueError, "UNPROVEN checkpoint"):
            validate_inventory(proof_on_unproven, root=ROOT)

        missing_blocker = copy.deepcopy(self.generated)
        missing_blocker["checkpoints"][0]["blocker"] = None
        with self.assertRaisesRegex(ValueError, "UNPROVEN checkpoint"):
            validate_inventory(missing_blocker, root=ROOT)

        self.assertTrue(all(
            row["status"] == "UNPROVEN"
            and row["blocker"] == UNPROVEN_BLOCKER
            and row["proof"] is None
            for row in self.generated["checkpoints"]
        ))

    def test_pixel_promotion_requires_independent_native_and_web_rgba8_evidence(self):
        promoted = copy.deepcopy(self.generated)
        checkpoint = promoted["checkpoints"][0]
        checkpoint["status"] = "PIXEL_EQUIVALENT"
        checkpoint["blocker"] = None
        checkpoint["proof"] = {}
        with self.assertRaisesRegex(ValueError, "proof must contain exactly"):
            validate_inventory(promoted, root=ROOT)

    def test_exact_rgba8_proof_promotes_and_one_byte_mutation_still_fails(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            evidence_root = Path(directory)
            proof, receipt, web_manifest = self._write_pixel_fixture(
                evidence_root, self.generated["checkpoints"][0]["id"]
            )
            prefix = evidence_root.relative_to(ROOT).as_posix()
            proof = {key: f"{prefix}/{value}" for key, value in proof.items()}

            promoted = copy.deepcopy(self.generated)
            checkpoint = promoted["checkpoints"][0]
            checkpoint["status"] = "PIXEL_EQUIVALENT"
            checkpoint["blocker"] = None
            checkpoint["proof"] = proof
            promoted["counts"]["pixel_equivalent"] = 1
            promoted["counts"]["unproven"] -= 1
            validate_inventory(promoted, root=ROOT)

            changed = bytearray((evidence_root / "web.raw").read_bytes())
            changed[0] ^= 1
            (evidence_root / "web.raw").write_bytes(changed)
            web_manifest["data"]["sha256"] = hashlib.sha256(changed).hexdigest()
            (evidence_root / "web-frame.json").write_text(json.dumps(web_manifest))
            receipt["web_frame_sha256"] = hashlib.sha256(
                (evidence_root / "web-frame.json").read_bytes()
            ).hexdigest()
            receipt["canonical_rgba_sha256"] = hashlib.sha256(changed).hexdigest()
            (evidence_root / "pixel-receipt.json").write_text(json.dumps(receipt))

            with self.assertRaisesRegex(ValueError, "canonical RGBA8 bytes differ"):
                validate_inventory(promoted, root=ROOT)

    @staticmethod
    def _write_pixel_fixture(root: Path, scenario: str):
        native_bytes = bytes((0, 0, 255, 0, 0, 255, 0, 0))
        web_bytes = bytes((255, 0, 0, 255, 0, 255, 0, 255))
        (root / "native.raw").write_bytes(native_bytes)
        (root / "web.raw").write_bytes(web_bytes)

        def digest(name: str) -> str:
            return hashlib.sha256((root / name).read_bytes()).hexdigest()

        native = {
            "schema": 1,
            "protocol": "miel-vliegt-framebuffer",
            "width": 2,
            "height": 1,
            "row_stride": 8,
            "pixel_format": "bgrx8",
            "origin": "top-left",
            "alpha_mode": "opaque",
            "data": {"path": f"{root.relative_to(ROOT).as_posix()}/native.raw", "sha256": digest("native.raw")},
        }
        web = {
            **native,
            "pixel_format": "rgba8",
            "alpha_mode": "straight",
            "data": {"path": f"{root.relative_to(ROOT).as_posix()}/web.raw", "sha256": digest("web.raw")},
        }
        (root / "native-frame.json").write_text(json.dumps(native))
        (root / "web-frame.json").write_text(json.dumps(web))
        policy = {"canonical_format": "rgba8", "comparison": "EXACT_BYTES"}
        receipt = {
            "schema": 1,
            "status": "PASS",
            "scenario": scenario,
            "native_frame_sha256": digest("native-frame.json"),
            "web_frame_sha256": digest("web-frame.json"),
            "canonical_rgba_sha256": hashlib.sha256(web_bytes).hexdigest(),
            "comparator": "canonical-rgba8-exact-v1",
            "comparison_policy": policy,
            "comparison_policy_sha256": hashlib.sha256(
                json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        (root / "pixel-receipt.json").write_text(json.dumps(receipt))
        return {
            "native_frame": "native-frame.json",
            "web_frame": "web-frame.json",
            "pixel_receipt": "pixel-receipt.json",
        }, receipt, web


if __name__ == "__main__":
    unittest.main()
