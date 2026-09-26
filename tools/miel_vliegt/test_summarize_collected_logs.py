import json
from pathlib import Path
import tempfile
import unittest

from tools.miel_vliegt.summarize_collected_logs import MAX_TAIL, summarize


class BoundedLogDiagnosticsTests(unittest.TestCase):
    def test_private_content_cannot_enter_public_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "PRIVATE_ISO_CONTENT_AND_USER_PATH"
            (root / "proxy.log").write_text(
                secret + "\nMVP_DllMain loaded\nMVP_EXC code=0x8007000E\n"
            )
            (root / "outside.log").symlink_to(root / "proxy.log")
            result = summarize(root)
            rendered = json.dumps(result)
            self.assertNotIn(secret, rendered)
            self.assertNotIn("proxy.log", rendered)
            self.assertNotIn("tail_sha256", rendered)
            self.assertEqual(result["status"], "DIAGNOSTIC_ONLY")
            self.assertEqual(len(result["logs"]), 1)
            self.assertEqual(result["logs"][0]["markers"]["MVP_EXC"], 1)
            self.assertEqual(result["logs"][0]["known_error_codes"], ["E_OUTOFMEMORY"])

    def test_large_log_samples_only_bounded_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "observer.log").write_bytes(b"private-data" * 10000 + b"\nMVO ready\n")
            row = summarize(root)["logs"][0]
            self.assertGreater(row["size_bytes"], MAX_TAIL)
            self.assertEqual(row["tail_bytes"], MAX_TAIL)
            self.assertEqual(row["markers"]["MVO"], 1)

    def test_too_many_files_fail_closed_before_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(13):
                (root / f"log-{index}.log").write_text("PRIVATE_CONTENT")
            with self.assertRaisesRegex(ValueError, "too many diagnostic files"):
                summarize(root)


if __name__ == "__main__":
    unittest.main()
