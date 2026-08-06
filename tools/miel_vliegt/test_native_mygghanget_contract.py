#!/usr/bin/env python3
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.native_mygghanget_contract import (
    PeImage,
    extract_native_mygghanget_contract,
)


ROOT = Path(__file__).resolve().parents[2]
EXECUTABLE = ROOT / "tmp/miel-vliegt-native-local/MulleMeck.exe"
ASSET_CONTRACT = ROOT / "content/miel_vliegt/flight_scene_asset_contract.json"


@unittest.skipUnless(EXECUTABLE.is_file(), "pinned native executable unavailable")
class NativeMygghangetContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generated = extract_native_mygghanget_contract(EXECUTABLE)

    def test_escape_input_route_is_bound_to_native_dispatch(self):
        bootstrap = self.generated["bootstrapInputContract"]
        self.assertEqual(bootstrap["input"], {
            "api": "SendInput",
            "kind": "keyboard-scan-code",
            "scanCode": "0x01",
            "nativeKeyCode": 1,
            "name": "DIK_ESCAPE",
        })
        self.assertEqual(bootstrap["dispatch"], {
            "entry": "0x00417160",
            "entryReceipt": {
                "address": "0x00417160", "size": 35,
                "sha256": "bac6c3d1dd8bf4350fc41e0cfaec63e68b7ce57201bd9b6295314bd56f1714e1",
            },
            "lookupAddress": "0x004175b9",
            "lookupReceipt": {
                "address": "0x004175b9", "size": 30,
                "sha256": "cbea432f81c7e96a03ab9fd87325f2cd8c7f4a2e2df4fd4ca3731f0c7e414058",
            },
            "lookupTable": "0x004176fc",
            "lookupIndex": 0,
            "jumpTable": "0x004176e4",
            "action": "0x004175d7",
            "outsideViewBranch": "0x00417614",
            "handler": "0x00419100",
        })
        self.assertEqual(
            bootstrap["policy"],
            "REAL_INPUT_ONLY_NO_DIRECT_HANDLER_OR_STATE_MODE_WRITE",
        )

    def test_start_engine_input_reaches_the_native_state_five_gate(self):
        start_engine = self.generated["bootstrapInputContract"]["startEngine"]
        self.assertEqual(start_engine["input"], {
            "api": "SendInput",
            "kind": "keyboard-scan-code-held-until-departure",
            "scanCode": "0x2a",
            "nativeScanCodes": [42, 54, 78],
            "name": "DIK_LSHIFT_OR_EQUIVALENT_FASTER",
        })
        self.assertEqual(start_engine["sample"], {
            "entry": "0x0041da3c",
            "receipt": {
                "address": "0x0041da3c", "size": 59,
                "sha256": "42c03bf4ef82230bd6be8af6eb84632cd85c1ba1b0bb7d74400b234ca6a495a2",
            },
            "managerNodeField": "0x74",
            "throttleAdjust": "0x0040f8d0",
        })
        self.assertEqual(start_engine["gate"], {
            "entry": "0x0042611f",
            "receipt": {
                "address": "0x0042611f", "size": 48,
                "sha256": "755b6b83271259eb612c9848f70ec2bb908f5b8d7b56c8763034aae5b31bb664",
            },
            "sharedFlightField": "0x5c",
            "throttleField": "0x148",
            "latchField": "0x8b4",
            "thresholdAddress": "0x0044c748",
            "thresholdF32": 0.5,
        })
        self.assertEqual(start_engine["directDeparture"], {
            "offscreenTestEntry": "0x004262c9",
            "receipt": {
                "address": "0x004262c9", "size": 42,
                "sha256": "f03b16bfa2b1e300d2a7f484fd48bc670b2c2dbbbeb596850ceda4e27c2a7a23",
            },
            "modeSetCallsite": "0x004262ee",
            "targetMode": "mode_fly",
        })

    def test_presentation_handles_are_render_only(self):
        boundary = self.generated["assets"]["presentationBoundary"]
        self.assertEqual(boundary["renderer"]["entry"], "0x00405970")
        self.assertEqual(
            boundary["renderer"]["inputSemantics"],
            "NONE_STATIC_RENDER_ONLY",
        )
        self.assertEqual(
            boundary["renderer"]["selectorToHandleField"],
            {"1": "0x1d8", "2": "0x1dc", "3": "0x1e0",
             "4": "0x1e4", "5": "0x1e8"},
        )
        self.assertEqual(
            {resource["classification"] for resource in boundary["resources"]},
            {"PRESENTATION_OVERLAY_STATIC_RENDER_ONLY"},
        )

    def test_checked_asset_contract_embeds_exact_native_contract(self):
        checked = json.loads(ASSET_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(checked["sources"]["nativeMygghanget"], self.generated)

    def test_mutated_escape_lookup_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "MulleMeck.exe"
            shutil.copyfile(EXECUTABLE, mutated)
            image = PeImage(mutated)
            payload = bytearray(mutated.read_bytes())
            payload[image.address_to_offset(0x004175B9)] ^= 0x01
            mutated.write_bytes(payload)
            with self.assertRaisesRegex(ValueError, "barn escape lookup"):
                extract_native_mygghanget_contract(mutated)


if __name__ == "__main__":
    unittest.main()
