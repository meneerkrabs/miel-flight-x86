import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/miel_vliegt/web_scene_semantic_evidence.py"


class WebSemanticArtifactContractTests(unittest.TestCase):
    def test_artifact_references_are_checked_for_absolute_paths_before_resolution(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        resolver = source[
            source.index("def _resolve_ref"):
            source.index("def validate_manifest")
        ]
        absolute_check = 'Path(reference.get("path")).is_absolute()'
        type_check = 'not isinstance(reference.get("path"), str)'
        empty_check = 'not reference["path"]'
        resolution = '(ROOT / reference["path"]).resolve()'
        resolution_index = resolver.index(resolution)
        for check in (type_check, empty_check, absolute_check):
            self.assertIn(check, resolver)
            self.assertLess(resolver.index(check), resolution_index)
        self.assertIn(resolution, resolver)


if __name__ == "__main__":
    unittest.main()
