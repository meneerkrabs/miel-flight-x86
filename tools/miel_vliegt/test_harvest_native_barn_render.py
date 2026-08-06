import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.harvest_native_barn_render import CC_SHA256, EXE_SHA256, PeImage


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "content/miel_vliegt/native_barn_render_contract.json"


class NativeBarnRenderContractTests(unittest.TestCase):
    def test_committed_contract_is_fail_closed_and_source_exact(self):
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["source"]["executable_sha256"], EXE_SHA256)
        self.assertEqual(value["source"]["cc_dll_sha256"], CC_SHA256)
        self.assertEqual(value["camera"]["axis_rotation_order"], ["z", "x", "y"])
        self.assertEqual(value["camera"]["views"][0]["position"], [21.5, 15.0, 11.0])
        self.assertEqual(value["barn"]["record_size"], 20)
        self.assertEqual(value["barn"]["all_nan_position_sentinels"], [192])
        self.assertTrue(value["policy"]["promotion_requires_native_framebuffer_differential"])

    def test_pe_reader_rejects_unpinned_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-the-source.exe"
            path.write_bytes(b"MZ" + bytes(126))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                PeImage(path, EXE_SHA256)

    def test_full_iso_regeneration_enforces_the_native_contract(self):
        script = (ROOT / "tools/miel_vliegt/regenerate_flight_content.sh").read_text(
            encoding="utf-8"
        )
        command = 'python3 "$ROOT/tools/miel_vliegt/harvest_native_barn_render.py"'
        self.assertEqual(script.count(command), 1)
        self.assertIn('"$SYS/MulleMeck.exe" "$SYS/Cc.dll"', script)
        self.assertIn(
            '"$ROOT/content/miel_vliegt/native_barn_render_contract.json"', script
        )

    def test_pinned_local_sources_regenerate_when_available(self):
        executable = Path("/tmp/MulleMeck.exe")
        cc_dll = Path("/tmp/Cc.dll")
        if not executable.is_file() or not cc_dll.is_file():
            self.skipTest("separately supplied pinned native binaries are unavailable")
        subprocess.run([
            "python3", str(ROOT / "tools/miel_vliegt/harvest_native_barn_render.py"),
            str(executable), str(cc_dll), str(CONTRACT), "--check",
        ], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
