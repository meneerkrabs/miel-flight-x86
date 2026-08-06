from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_observation_profile_contract as contract


class NativeObservationProfileContractTests(unittest.TestCase):
    def test_tracked_json_and_header_are_deterministic(self):
        self.assertEqual(contract.JSON_PATH.read_bytes(), contract.render_json())
        self.assertEqual(contract.HEADER_PATH.read_bytes(), contract.render_header())
        contract.check_generated()

    def test_profiles_bind_scenario_mask_framebuffer_and_sha(self):
        semantic = contract.profile_for_scenario("taxi-straight")
        visual = contract.profile_for_scenario(contract.VISUAL_SCENARIO)
        self.assertEqual(semantic["id"], "production-semantic-v1")
        self.assertEqual(semantic["omit_mask"], "0x1fff")
        self.assertFalse(semantic["framebuffer_required"])
        self.assertEqual(visual["id"], "full-visual-pixel-v1")
        self.assertEqual(visual["omit_mask"], "0x0000")
        self.assertTrue(visual["framebuffer_required"])
        self.assertNotEqual(
            semantic["profile_sha256"], visual["profile_sha256"],
        )

    def test_semantic_receipt_channels_exclude_optional_media_audio(self):
        # The parity receipt contract is exactly the first four channels.
        # Audio / media-semantics observations speak a separate protocol
        # (miel-vliegt-native-media-semantics-observation) and can NEVER
        # promote parity, so they are deliberately excluded from the
        # scenario-bounded receipt. This is the contract-level reason the
        # observer may bind the audio detours best-effort without weakening a
        # fail-closed gate: a media site that cannot be bound skips an
        # optional channel instead of aborting the observer load.
        self.assertEqual(
            contract.SEMANTIC_RECEIPT_CHANNELS, contract.RECEIPT_CHANNELS[:4],
        )
        for excluded in ("audio", "media", "particle", "presentation", "shadow"):
            self.assertNotIn(excluded, contract.SEMANTIC_RECEIPT_CHANNELS)
        semantic = next(
            profile for profile in contract.contract_value()["profiles"]
            if profile["id"] == "production-semantic-v1"
        )
        self.assertEqual(semantic["observer_profile"], "scenario-bounded")
        self.assertEqual(
            semantic["applicable_receipt_channels"],
            list(contract.SEMANTIC_RECEIPT_CHANNELS),
        )

    def test_json_profile_or_sha_drift_fails_closed(self):
        value = contract.contract_value()
        value["profiles"][0]["omit_mask"] = "0x0000"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profiles.json"
            path.write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                contract.ObservationProfileContractError, "drifted",
            ):
                contract.load_contract(path)


if __name__ == "__main__":
    unittest.main()
