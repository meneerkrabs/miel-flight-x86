#!/usr/bin/env python3
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "tools/miel_vliegt/hangover/native_sha256.h"


class NativeSha256Test(unittest.TestCase):
    def test_header_hashes_block_boundaries_and_rejects_missing_file(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "sha256-harness.c"
            harness.write_text(
                '#include <stdio.h>\n'
                '#include "native_sha256.h"\n'
                'int main(int argc, char **argv) {\n'
                '    char digest[65];\n'
                '    if (argc != 2 || !miel_sha256_file(argv[1], digest)) return 2;\n'
                '    puts(digest);\n'
                '    return 0;\n'
                '}\n',
                encoding="ascii",
            )
            binary = root / "sha256-harness"
            subprocess.run(
                [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(HEADER.parent), str(harness), "-o", str(binary),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            for length in (0, 55, 56, 63, 64, 65, 16384, 16385):
                payload = bytes(index % 251 for index in range(length))
                fixture = root / f"fixture-{length}.bin"
                fixture.write_bytes(payload)
                result = subprocess.run(
                    [str(binary), str(fixture)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    result.stdout.strip(), hashlib.sha256(payload).hexdigest(),
                    f"length {length}",
                )
            missing = subprocess.run(
                [str(binary), str(root / "missing.bin")],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(missing.stdout, "")


if __name__ == "__main__":
    unittest.main()
