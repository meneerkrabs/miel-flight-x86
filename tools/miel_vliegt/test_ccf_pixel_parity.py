import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from tools.miel_vliegt.ccf_pixel_parity import compare_images, render_runtime_sha256, verify


class CcfPixelParityTest(unittest.TestCase):
    def setUp(self):
        self.identity = {"executable": {"sha256": "pinned-exe"}}
        self.policy = {
            "maximum_channel_delta": 0,
            "maximum_different_pixels": 0,
            "maximum_mean_absolute_channel_delta": 0.0,
        }

    def compared_checkpoint(self, root, status="EQUIVALENT"):
        camera = root / "camera.json"
        camera.write_text(json.dumps({
            "schema": 1, "viewport": [0, 0, 2, 1],
            "projection": [1, 0, 0, 1], "view": [1, 0, 0, 1]
        }))
        log = root / "native-capture.log"
        log.write_text("MulleMeck.exe image_base=0x00400000 checkpoint=hangar-part-6")
        receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-native-render-capture",
            "review_status": "REVIEWED",
            "checkpoint_id": "hangar-part-6",
            "executable_sha256": "pinned-exe",
            "target_module": {"filename": "MulleMeck.exe", "image_base": "0x00400000"},
            "image_sha256": hashlib.sha256((root / "native.png").read_bytes()).hexdigest(),
            "camera_contract_sha256": hashlib.sha256(camera.read_bytes()).hexdigest(),
            "capture_tool": "reviewed-native-capture",
            "capture_command": ["capture", "hangar-part-6"],
            "capture_host": {"kind": "windows-i386", "review_status": "REVIEWED"},
            "raw_capture_log": "native-capture.log",
            "raw_capture_log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        }
        (root / "native-receipt.json").write_text(json.dumps(receipt))
        return {
            "id": "hangar-part-6", "status": status,
            "camera_contract": "camera.json",
            "native_reference": {"path": "native.png", "capture_receipt": "native-receipt.json"},
            "web_capture": {
                "path": "web.png",
                "image_sha256": hashlib.sha256((root / "web.png").read_bytes()).hexdigest(),
                "runtime_sha256": render_runtime_sha256(root),
            },
            "metrics": compare_images(root / "native.png", root / "web.png"),
        }

    def test_blocked_checkpoint_cannot_contain_invented_native_evidence(self):
        manifest = {
            "schema": 1,
            "policy": self.policy,
            "checkpoints": [{
                "id": "hangar-part-6", "status": "BLOCKED_NATIVE_REFERENCE",
                "native_reference": {"path": "native.png"}, "web_capture": None, "metrics": None,
            }],
        }
        with self.assertRaisesRegex(ValueError, "must not invent native evidence"):
            verify(manifest, Path("."), self.identity)

    def test_equivalent_requires_pinned_native_provenance_and_recomputed_pixels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            Image.new("RGBA", (2, 1), (10, 20, 30, 255)).save(root / "native.png")
            Image.new("RGBA", (2, 1), (10, 20, 30, 255)).save(root / "web.png")
            checkpoint = self.compared_checkpoint(root)
            manifest = {"schema": 1, "policy": self.policy, "checkpoints": [checkpoint]}
            self.assertEqual(verify(manifest, root, self.identity)["EQUIVALENT"], 1)
            receipt_path = root / "native-receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["executable_sha256"] = "wrong"
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "another checkpoint or executable"):
                verify(manifest, root, self.identity)

    def test_partial_cannot_hide_a_now_exact_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            Image.new("RGBA", (1, 1), "white").save(root / "native.png")
            Image.new("RGBA", (1, 1), "white").save(root / "web.png")
            checkpoint = self.compared_checkpoint(root, status="PARTIAL")
            manifest = {
                "schema": 1, "policy": self.policy,
                "checkpoints": [checkpoint],
            }
            with self.assertRaisesRegex(ValueError, "PARTIAL is stale"):
                verify(manifest, root, self.identity)


if __name__ == "__main__":
    unittest.main()
