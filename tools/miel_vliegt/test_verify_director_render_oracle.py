"""Regression tests for Director render-oracle evidence promotion."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.verify_director_render_oracle import (
    expected_libreshockwave_renderer,
    validate,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((
    ROOT / "content/miel_vliegt/director_intro_render_oracle_contract.json"
).read_text(encoding="utf-8"))


class DirectorRenderOracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.artifacts = Path(self.temporary.name)
        self.contract = copy.deepcopy(CONTRACT)
        clock = self.artifacts / "clock.json"
        clock.write_text('[{"frame":1,"time_microseconds":0}]', encoding="utf-8")
        self.clock = {
            "id": "intro-score-frames",
            "path": clock.name,
            "sha256": hashlib.sha256(clock.read_bytes()).hexdigest(),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_json(self, name: str, value: object) -> Path:
        path = self.artifacts / name
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        return path

    def _manifest(self, kind: str, rgba: bytes) -> Path:
        expected = self.contract["canonical_frame"]["width"] \
            * self.contract["canonical_frame"]["height"] * 4
        rgba += bytes(expected - len(rgba))
        rgba_name = f"{kind}.rgba"
        (self.artifacts / rgba_name).write_bytes(rgba)
        if kind == "libreshockwave":
            renderer = {
                field: self.contract["renderers"]["libreshockwave"][field]
                for field in (
                    "commit", "tree", "archive_sha256", "compatibility_patch_sha256",
                    "exporter_sha256", "build_target", "surface",
                )
            }
            renderer.update({
                "binary_sha256": "b" * 64,
                "build_environment": "Linux x86_64 / C++20 release",
                "capture_tool": "reviewed frameSnapshot RGBA adapter",
                "capture_tool_sha256": "c" * 64,
            })
        else:
            renderer = dict(self.contract["renderers"]["native_oracle"])
            renderer["capture_tool"] = "Windows 2000 VM / lossless framebuffer hook"
            renderer["capture_tool_sha256"] = "d" * 64
            renderer["environment"] = "Windows 2000 SP4 / Director 8 projector"
        return self._write_json(f"{kind}.json", {
            "schema": 1,
            "renderer_kind": kind,
            "intro_movie_sha256": self.contract["source"]["intro_movie_sha256"],
            "canonical_frame": self.contract["canonical_frame"],
            "renderer": renderer,
            "clock_transcript": self.clock,
            "frames": [{
                "frame": 1,
                "time_microseconds": 0,
                "rgba": rgba_name,
                "rgba_sha256": hashlib.sha256(rgba).hexdigest(),
            }],
        })

    def _captured_contract(self, libre: bytes, native: bytes) -> tuple[Path, Path]:
        libre_path = self._manifest("libreshockwave", libre)
        native_path = self._manifest("native-oracle", native)
        self.contract["status"] = "CAPTURED_RENDERERS"
        self.contract["blockers"] = []
        self.contract["artifacts"].update({
            "libreshockwave_manifest": libre_path.name,
            "native_oracle_manifest": native_path.name,
        })
        return libre_path, native_path

    def _receipt(self, libre_path: Path, native_path: Path, status: str, different: int, delta: int) -> Path:
        return self._write_json("comparison.json", {
            "schema": 1,
            "status": status,
            "policy": self.contract["comparison"],
            "libreshockwave_manifest_sha256": hashlib.sha256(libre_path.read_bytes()).hexdigest(),
            "native_oracle_manifest_sha256": hashlib.sha256(native_path.read_bytes()).hexdigest(),
            "observed": {
                "frames": 1,
                "different_pixels": different,
                "maximum_channel_delta": delta,
            },
        })

    def test_tracked_blocked_contract_is_honest(self) -> None:
        validate(CONTRACT, ROOT, self.artifacts)

    def test_all_render_contracts_follow_the_pinned_libreshockwave_manifest(self) -> None:
        manifest = json.loads((
            ROOT / "tools/miel_vliegt/libreshockwave.json"
        ).read_text(encoding="utf-8"))
        expected_renderer = expected_libreshockwave_renderer(ROOT)
        flight_intro = json.loads((
            ROOT / "content/miel_vliegt/flight_intro_contract.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(
            CONTRACT["renderers"]["libreshockwave"],
            expected_renderer,
        )
        self.assertEqual(
            flight_intro["reconstruction"]["receipt"]["renderer"],
            manifest,
        )

    def test_false_capture_promotion_fails_closed(self) -> None:
        self.contract["status"] = "CAPTURED_RENDERERS"
        with self.assertRaisesRegex(ValueError, "manifest must be a non-empty"):
            validate(self.contract, ROOT, self.artifacts)

    def test_equivalence_recomputes_exact_rgba_from_gitignored_frames(self) -> None:
        rgba = bytes((10, 20, 30, 255, 40, 50, 60, 255))
        libre_path, native_path = self._captured_contract(rgba, rgba)
        receipt = self._receipt(libre_path, native_path, "PASS", 0, 0)
        self.contract["status"] = "ORACLE_EQUIVALENT"
        self.contract["artifacts"]["comparison_receipt"] = receipt.name
        validate(self.contract, ROOT, self.artifacts)

    def test_forged_pass_receipt_cannot_hide_native_pixel_difference(self) -> None:
        libre = bytes((10, 20, 30, 255, 40, 50, 60, 255))
        native = bytes((11, 20, 30, 255, 40, 50, 60, 255))
        libre_path, native_path = self._captured_contract(libre, native)
        receipt = self._receipt(libre_path, native_path, "PASS", 0, 0)
        self.contract["status"] = "ORACLE_EQUIVALENT"
        self.contract["artifacts"]["comparison_receipt"] = receipt.name
        with self.assertRaisesRegex(ValueError, "observations drifted|status is false"):
            validate(self.contract, ROOT, self.artifacts)

    def test_libreshockwave_commit_is_part_of_the_render_identity(self) -> None:
        rgba = bytes((10, 20, 30, 255, 40, 50, 60, 255))
        self._captured_contract(rgba, rgba)
        manifest_path = self.artifacts / "libreshockwave.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["renderer"]["commit"] = "0" * 40
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "renderer commit drifted"):
            validate(self.contract, ROOT, self.artifacts)

    def test_contract_cannot_silently_float_to_an_upstream_renderer_revision(self) -> None:
        self.contract["renderers"]["libreshockwave"]["commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "reviewed revision"):
            validate(self.contract, ROOT, self.artifacts)

    def test_original_render_payload_root_must_remain_gitignored(self) -> None:
        self.contract["artifact_policy"]["root"] = "content/miel_vliegt/tracked-frames"
        with self.assertRaisesRegex(ValueError, "gitignored projector root"):
            validate(self.contract, ROOT, self.artifacts)


if __name__ == "__main__":
    unittest.main()
