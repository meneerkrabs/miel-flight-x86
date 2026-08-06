#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import web_transition_build as build


class WebTransitionBuildTest(unittest.TestCase):
    def test_checked_in_manifest_matches_every_producer_input(self):
        self.assertEqual(build.validate_manifest(), build.build_manifest())

    def test_input_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in build.INPUT_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((build.ROOT / relative).read_bytes())
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(build.build_manifest(root)), encoding="utf-8",
            )
            (root / build.INPUT_PATHS[-1]).write_text("drift", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inputs drifted"):
                build.validate_manifest(manifest, root)

    def test_build_hash_is_derived_instead_of_caller_supplied(self):
        value = build.build_manifest()
        self.assertRegex(value["build_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            [row["path"] for row in value["inputs"]], list(build.INPUT_PATHS),
        )

    def test_boolean_schema_does_not_equal_integer_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            value = build.build_manifest()
            value["schema"] = True
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "drifted"):
                build.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
