import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.verify_libreshockwave_pin import (
    DEFAULT_MANIFEST,
    validate_manifest,
)


class LibreShockwavePinTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))

    def validate_changed(self, change):
        document = json.loads(json.dumps(self.manifest))
        change(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return validate_manifest(path)

    def test_checked_in_renderer_pin_is_valid(self):
        document = validate_manifest()
        self.assertEqual(len(document["commit"]), 40)
        self.assertEqual(len(document["archive_sha256"]), 64)
        self.assertEqual(len(document["license_file_sha256"]), 64)
        exporter = DEFAULT_MANIFEST.parents[2] / document["exporter_path"]
        self.assertEqual(
            document["exporter_sha256"],
            hashlib.sha256(exporter.read_bytes()).hexdigest(),
        )
        probe = DEFAULT_MANIFEST.parents[2] / document["font_map_probe_path"]
        self.assertEqual(
            document["font_map_probe_sha256"],
            hashlib.sha256(probe.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            document["font_map_probe_build_target"],
            "miel_director_font_map_probe",
        )
        self.assertIn("cpp/apps/tools/RenderProbe.cpp", document["expected_paths"])

    def test_exporter_source_byte_drift_is_rejected_without_manifest_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for field in (
                "compatibility_patch",
                "exporter_path",
                "font_map_probe_path",
            ):
                source = DEFAULT_MANIFEST.parents[2] / self.manifest[field]
                destination = root / self.manifest[field]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            manifest = root / "libreshockwave.json"
            manifest.write_text(json.dumps(self.manifest), encoding="utf-8")
            validate_manifest(manifest, root=root)
            exporter = root / self.manifest["exporter_path"]
            exporter.write_bytes(exporter.read_bytes() + b"\n// adversarial drift\n")
            with self.assertRaisesRegex(ValueError, "exporter_sha256 drifted"):
                validate_manifest(manifest, root=root)

    def test_short_or_symbolic_revision_is_rejected(self):
        for revision in ("master", "f8efd3f", "F" * 40):
            with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "full 40-hex"):
                self.validate_changed(lambda document: document.__setitem__("commit", revision))

    def test_renderer_path_contract_is_exact_and_ordered(self):
        with self.assertRaisesRegex(ValueError, "source-path contract drifted"):
            self.validate_changed(lambda document: document["expected_paths"].pop())

    def test_bundling_renderer_code_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "external build tool"):
            self.validate_changed(
                lambda document: document.__setitem__("integration_mode", "bundled-runtime"))

    def test_license_or_repository_drift_is_rejected(self):
        for field, value, message in (
            ("license", "MIT", "license"),
            ("repository", "git://github.com/Quackster/LibreShockwave", "canonical HTTPS"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                self.validate_changed(lambda document, f=field, v=value: document.__setitem__(f, v))

    def test_source_identity_fields_are_format_checked_and_pinned(self):
        cases = (
            ("commit", "0" * 40, "reviewed renderer pin"),
            ("commit_date", "2026-07-06", "UTC timestamp"),
            ("commit_date", "2026-07-07T04:52:36Z", "commit date"),
            ("archive_sha256", "not-a-hash", "lowercase 64-hex"),
            ("archive_sha256", "0" * 64, "archive hash"),
            ("license_file_sha256", "A" * 64, "lowercase 64-hex"),
            ("license_file_sha256", "0" * 64, "license file hash"),
            ("exporter_sha256", "not-a-hash", "lowercase 64-hex"),
            ("exporter_sha256", "0" * 64, "exporter_sha256 drifted"),
            (
                "font_map_probe_sha256",
                "not-a-hash",
                "lowercase 64-hex",
            ),
            (
                "font_map_probe_sha256",
                "0" * 64,
                "font_map_probe_sha256 drifted",
            ),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, message):
                self.validate_changed(lambda document, f=field, v=value: document.__setitem__(f, v))

    def test_build_and_runtime_contract_fields_are_exact(self):
        for field in (
            "build_target",
            "font_map_probe_build_target",
            "minimum_cmake",
            "language_standard",
            "runtime_status",
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                self.validate_changed(
                    lambda document, f=field: document.__setitem__(f, "unexpected"))

    def test_exporter_path_cannot_be_repointed_to_another_source(self):
        with self.assertRaisesRegex(ValueError, "exporter path drifted"):
            self.validate_changed(
                lambda document: document.__setitem__("exporter_path", "README.md"))

    def test_unknown_or_missing_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "fields drifted"):
            self.validate_changed(lambda document: document.__setitem__("binary", "renderer"))
        with self.assertRaisesRegex(ValueError, "fields drifted"):
            self.validate_changed(lambda document: document.pop("runtime_status"))


if __name__ == "__main__":
    unittest.main()
