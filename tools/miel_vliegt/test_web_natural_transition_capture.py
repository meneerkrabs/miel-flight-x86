import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt import (
    natural_transition_trace,
    web_natural_transition_capture as capture,
)


class WebNaturalTransitionCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = capture._run_javascript_capture()

    def test_javascript_bundle_is_exact_and_deterministic(self):
        rows = capture._validate_bundle(self.bundle)
        self.assertEqual(len(rows), 48)
        self.assertEqual(
            [row["edge"] for row in rows],
            list(natural_transition_trace.EDGES),
        )
        self.assertEqual(self.bundle, capture._run_javascript_capture())

    def test_generator_writes_and_validates_all_raw_normalized_pairs(self):
        with tempfile.TemporaryDirectory(dir=capture.ROOT) as directory:
            root = Path(directory)
            output = root / "captures"
            manifest = root / "manifest.json"
            value = capture.generate(output, manifest)
            checked = capture.validate_manifest(manifest)
            self.assertEqual(value, checked)
            self.assertEqual(len(value["captures"]), 48)
            self.assertFalse(value["parityEligible"])
            self.assertEqual(
                value["status"],
                "SYNTHETIC_CONTRACT_MODEL_COMPLETE_REAL_GAMEPLAY_REQUIRED",
            )
            self.assertEqual(value["policy"], {
                "browserE2ERequired": False,
                "contractModelOnly": True,
                "debugEntryAllowed": False,
                "evidenceScope": "NATURAL_TRANSITION",
                "edgeCount": 48,
                "promotionAllowed": False,
                "realGameplayCaptureRequiredForPromotion": True,
            })
            self.assertEqual(len(list(output.glob("*.raw.ndjson"))), 48)
            self.assertEqual(
                len([
                    path for path in output.glob("*.ndjson")
                    if not path.name.endswith(".raw.ndjson")
                ]),
                48,
            )

    def test_committed_manifest_is_current(self):
        checked = capture.validate_manifest()
        self.assertEqual(len(checked["captures"]), 48)
        self.assertFalse(checked["parityEligible"])
        self.assertFalse(checked["policy"]["promotionAllowed"])

        first = checked["captures"][0]
        normalized = (
            capture.MANIFEST_PATH.parent /
            checked["captureDirectory"] /
            first["normalized"]["path"]
        )
        with self.assertRaisesRegex(ValueError, "wrong driver"):
            natural_transition_trace.load_capture(normalized, "web-gameplay")

        raw = (
            capture.MANIFEST_PATH.parent /
            checked["captureDirectory"] /
            first["raw"]["path"]
        )
        event = json.loads(raw.read_text(encoding="utf-8").splitlines()[1])
        self.assertEqual(
            event["classification"], "SYNTHETIC_CONTRACT_MODEL_EDGE",
        )
        self.assertFalse(event["parity_eligible"])

    def test_test_fixture_is_an_exact_projection_of_regenerated_model_output(self):
        checked = capture.validate_manifest()
        first = checked["captures"][0]
        capture_root = (
            capture.MANIFEST_PATH.parent / checked["captureDirectory"]
        )
        fixture_root = capture.ROOT / "tools/miel_vliegt/fixtures"
        canonical_raw = capture_root / first["raw"]["path"]
        fixture_raw = fixture_root / "web_natural_transition_raw_fixture.ndjson"
        self.assertEqual(fixture_raw.read_bytes(), canonical_raw.read_bytes())

        canonical = [
            json.loads(line)
            for line in (
                capture_root / first["normalized"]["path"]
            ).read_text(encoding="utf-8").splitlines()
        ]
        fixture = [
            json.loads(line)
            for line in (
                fixture_root / "web_natural_transition_fixture.ndjson"
            ).read_text(encoding="utf-8").splitlines()
        ]
        canonical[0]["raw_trace"]["path"] = fixture_raw.name
        self.assertEqual(fixture, canonical)

    def test_fails_closed_for_bundle_inventory_and_artifact_drift(self):
        broken = json.loads(json.dumps(self.bundle))
        broken["captures"].pop()
        with self.assertRaisesRegex(
            capture.WebNaturalTransitionCaptureError, "48-edge",
        ):
            capture._validate_bundle(broken)

        with tempfile.TemporaryDirectory(dir=capture.ROOT) as directory:
            root = Path(directory)
            output = root / "captures"
            manifest = root / "manifest.json"
            value = capture.generate(output, manifest)
            target = output / value["captures"][0]["raw"]["path"]
            target.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                capture.WebNaturalTransitionCaptureError, "artifact drifted",
            ):
                capture.validate_manifest(manifest)

    def test_fails_closed_if_javascript_producer_build_differs(self):
        broken = json.loads(json.dumps(self.bundle))
        broken["buildSha256"] = "0" * 64
        with self.assertRaisesRegex(
            capture.WebNaturalTransitionCaptureError, "bundle differs",
        ):
            capture._validate_bundle(broken)

    def test_check_does_not_regenerate_missing_or_drifted_evidence(self):
        with tempfile.TemporaryDirectory(dir=capture.ROOT) as directory:
            missing = Path(directory) / "missing.json"
            with mock.patch.object(capture, "_run_javascript_capture") as runner:
                with self.assertRaises(
                    capture.WebNaturalTransitionCaptureError,
                ):
                    capture.validate_manifest(missing)
                runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
