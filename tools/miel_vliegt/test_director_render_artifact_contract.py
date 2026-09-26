import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.verify_director_render_oracle import _artifact


class DirectorRenderArtifactContractTests(unittest.TestCase):
    def test_absolute_references_inside_the_artifact_root_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = root / "manifest.json"
            manifest.write_bytes(b"{}")
            with self.assertRaisesRegex(
                ValueError, "non-empty relative artifact path"
            ):
                _artifact(root, str(manifest), "LibreShockwave manifest")


if __name__ == "__main__":
    unittest.main()
