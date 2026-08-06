import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.extract_udsp import FileEntry, UdspArchive, normalize_archive_path


class ExtractUdspTests(unittest.TestCase):
    def test_archive_paths_are_relative_and_traversal_free(self):
        self.assertEqual(
            normalize_archive_path(r"Data\Graphics\Thing.CCF"),
            ("Data", "Graphics", "Thing.CCF"),
        )
        for unsafe in (
            r"..\escape.bin",
            r"Data\..\escape.bin",
            r"C:\escape.bin",
            r"\server\share\escape.bin",
        ):
            with self.subTest(path=unsafe):
                with self.assertRaisesRegex(ValueError, "unsafe archive path"):
                    normalize_archive_path(unsafe)

    def test_extraction_rejects_case_insensitive_output_collisions(self):
        archive = object.__new__(UdspArchive)
        archive._data = b"ab"
        archive.files = [
            FileEntry(r"Data\Thing.bin", 0, 0, 0, 1, 1, 0),
            FileEntry(r"data\thing.BIN", 0, 0, 0, 1, 1, 1),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "case-insensitive archive path collision"):
                archive.extract(Path(directory))


if __name__ == "__main__":
    unittest.main()
