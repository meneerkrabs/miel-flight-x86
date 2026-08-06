import hashlib
import json
import multiprocessing
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt import browser_flight_capture_artifacts as capture
from tools.miel_vliegt import browser_flight_evidence_registry as registry
from tools.miel_vliegt import browser_flight_runtime_receipts as runtime_receipts
from tools.miel_vliegt import (
    browser_flight_runtime_source_manifest as runtime_source_manifest,
)
from tools.miel_vliegt import native_scenario_artifacts as scenarios


def _write_addressed(directory: Path, value: dict) -> tuple[Path, str]:
    payload = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(payload).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest}.json"
    path.write_bytes(payload)
    return path, digest


def _import_process(
    queue, manifest: str, suite: str, receipt: str, repository: str,
) -> None:
    try:
        value = registry.import_capture(
            Path(manifest), Path(suite), Path(receipt),
            root=Path(repository),
        )
        queue.put(("ok", value["capture"]["id"]))
    except Exception as error:  # pragma: no cover - asserted by parent process
        queue.put(("error", str(error)))


def _hold_registry_lock(
    repository: str, acquired, release,
) -> None:
    with registry._registry_lock(Path(repository)):
        acquired.set()
        release.wait(timeout=15)


def _initial_state(root: Path, payload: bytes = b"\x01") -> dict:
    fixture = root / "fixtures/user0.dat"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(payload)
    one_fields = {
        "flight.active", "flight.orientation_w", "flight.propulsion_scale",
        "flight.fuel_capacity", "flight.fuel", "flight.integrity",
        "flight.maximum_integrity", "flight.controls_enabled",
    }
    values = []
    for name, encoding in scenarios.RUNTIME_STATE_FIELDS:
        values.append({
            "name": name,
            "encoding": encoding,
            "value_hex": (
                "01" if encoding == "u8" and name in one_fields
                else "00" if encoding == "u8"
                else "3f800000" if name in one_fields
                else "00000000"
            ),
        })
    return {
        "files": [{
            "role": "user-profile",
            "path": "fixtures/user0.dat",
            "byte_length": len(payload),
            "sha256": scenarios.sha256_file(fixture),
        }],
        "values": values,
    }


def _input_schedule(scenario: dict) -> list[dict[str, bool]]:
    events_by_tick = {}
    for event in scenario["input_script"]["events"]:
        events_by_tick.setdefault(event["tick"], []).append(event)
    pressed = set()
    focus_active = True
    result = []
    for tick in range(scenario["input_script"]["tick_count"]):
        for event in events_by_tick.get(tick, []):
            if event["type"] == "focus":
                focus_active = event["active"]
            elif event["action"] == "down":
                pressed.add(event["key"])
            else:
                pressed.remove(event["key"])
        result.append({
            key: focus_active and key in pressed
            for key in scenarios.CONTROL_KEYS
        })
    return result


def _frame(index: int, elapsed: float, delta: float, inputs: dict) -> dict:
    return {
        "frame": index,
        "time_seconds": elapsed,
        "inputs": inputs,
        "events": [],
        "numeric": {
            "timing": {
                "deltaSeconds": delta,
                "fixedStepSeconds": 0.04,
                "stepIndex": index + 1,
            },
            "physics": {
                "position": [1289, 70, 1060 - index],
                "orientation": [0, 0, 0, 1],
                "velocity": [0, 0, -95],
                "angularVelocity": None,
            },
            "collisions": {"observed": False, "contacts": []},
        },
        "camera": {
            "projection_matrix": [1] * 16,
            "view_matrix": [1] * 16,
            "vertical_fov_radians": 1,
            "near_clip": 0.1,
            "far_clip": 6000,
            "viewport": {"x": 0, "y": 0, "width": 640, "height": 480},
            "control": {"owner": "common_location", "state": 5},
        },
        "render": {
            "diagnostics": {
                "webgl": {
                    "drawCalls": 16,
                    "triangles": 843,
                    "bufferUploads": 0,
                    "textureBinds": 16,
                },
            },
        },
    }


class BrowserFlightCaptureArtifactsTest(unittest.TestCase):
    def test_runtime_source_manifest_covers_all_committed_content_data(self):
        manifest = runtime_source_manifest.build_manifest()
        covered = {row["path"] for row in manifest["inputs"]}
        committed = subprocess.run(
            [
                "git", "-C", str(capture.REPO_ROOT), "ls-tree", "-r",
                "--name-only", "HEAD", "--", "content/data",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        self.assertTrue(committed)
        self.assertEqual(
            sorted(committed),
            sorted(path for path in covered if path.startswith("content/data/")),
        )
        self.assertIn(
            "content/data/director_member_identity.json",
            covered,
        )
        self.assertIn("content/data/sea_maps.hash.json", covered)

    def _capture(
        self, root: Path, *, initial_payload: bytes = b"\x01",
        bundle_payload: bytes = b"test production bundle\n",
    ) -> tuple[Path, Path]:
        suite_root = root / "suite"
        suite = scenarios.materialize_scenario_suite(
            suite_root, _initial_state(suite_root, initial_payload),
        )
        subject, texture_assets = capture._capture_subject_contract()
        runtime_root = root / "runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        (runtime_root / "bundle.js").write_bytes(bundle_payload)
        runtime = {
            "bundle": {
                "url": "https://example.test/bundle.js",
                "sha256": hashlib.sha256(bundle_payload).hexdigest(),
            },
            "parts": {
                "url": "https://example.test/uds_flight_parts.json",
                "sha256": scenarios.sha256_file(capture.PARTS_CONTRACT),
            },
            "subject": subject,
            "texture_assets": texture_assets,
            "texture_assets_sha256": scenarios.canonical_sha256(texture_assets),
            "browser": {
                "name": "chromium",
                "version": "1",
                "user_agent": "test",
            },
            "webgl": {
                "version": "WebGL 1",
                "shading_language_version": "WebGL GLSL ES 1",
                "vendor": "test",
                "renderer": "test",
            },
        }
        output = root / "capture"
        rows = []
        rgba = bytes([4]) * (640 * 480 * 4)
        rgba_sha256 = hashlib.sha256(rgba).hexdigest()
        for entry in suite["scenarios"]:
            scenario_path = suite_root / entry["scenario"]["path"]
            scenario = scenarios.load_scenario(scenario_path)
            elapsed = 0.0
            frames = []
            for index, (clock, inputs) in enumerate(zip(
                scenario["clock_transcript"]["samples"],
                _input_schedule(scenario),
                strict=True,
            )):
                delta = capture._f32_from_bits(clock["dt_f32_bits"])
                elapsed += delta
                frames.append(_frame(index, elapsed, delta, inputs))
            pixel_checkpoints = [
                checkpoint
                for checkpoint in scenario["checkpoints"]
                if "render.framebuffer" in checkpoint["required_channels"]
            ]
            framebuffer_artifacts = []
            for checkpoint in pixel_checkpoints:
                frames[checkpoint["tick"]]["render"]["pixel_checkpoint"] = {
                    "id": checkpoint["id"],
                    "width": 640,
                    "height": 480,
                    "pixel_format": "rgba8",
                    "origin": "top-left",
                    "alpha_mode": "straight",
                    "reference_sha256": rgba_sha256,
                }
                framebuffer = output / "framebuffers" / f"{rgba_sha256}.rgba"
                framebuffer.parent.mkdir(parents=True, exist_ok=True)
                framebuffer.write_bytes(rgba)
                framebuffer_artifacts.append({
                    "id": checkpoint["id"],
                    "tick": checkpoint["tick"],
                    "path": f"framebuffers/{rgba_sha256}.rgba",
                    "sha256": rgba_sha256,
                    "byte_length": len(rgba),
                    "width": 640,
                    "height": 480,
                    "pixel_format": "rgba8",
                    "origin": "top-left",
                    "alpha_mode": "straight",
                })
            trace = {
                "protocol": "miel-vliegt-flight-frame-trace",
                "version": 2,
                "capture_kind": "web",
                "source": {
                    "runtime_sha256": runtime["bundle"]["sha256"],
                    "parts_sha256": runtime["parts"]["sha256"],
                    **subject,
                    "texture_assets": texture_assets,
                    "texture_assets_sha256": runtime["texture_assets_sha256"],
                    "capture_boundary": capture.BOUNDARY,
                    "initial_state_applied": True,
                    "runtime_projection": capture.RUNTIME_PROJECTION,
                    "initial_state_readback": scenario["initial_state"]["values"],
                    "initial_state_readback_sha256": scenarios.canonical_sha256(
                        scenario["initial_state"]["values"],
                    ),
                },
                "scenario": scenario,
                "frames": frames,
            }
            _, digest = _write_addressed(output / "traces", trace)
            rows.append({
                "scenario": entry["id"],
                "path": f"traces/{digest}.json",
                "sha256": digest,
                "frame_count": len(frames),
                "pixel_checkpoint_count": len(pixel_checkpoints),
                "framebuffer_artifacts": framebuffer_artifacts,
            })
        manifest = {
            "schema": 1,
            "protocol": capture.PROTOCOL,
            "status": capture.STATUS,
            "promotion_allowed": False,
            "suite": {
                "spec_sha256": scenarios.sha256_file(
                    suite_root / "suite-spec.json",
                ),
                "scenario_order": list(scenarios.SCENARIO_ID_ORDER),
                "scenarios": [{
                    "id": entry["id"],
                    "scenario_sha256": entry["scenario"]["sha256"],
                    "scenario_semantic_sha256": entry["scenario"]["semantic_sha256"],
                } for entry in suite["scenarios"]],
            },
            "producer": {
                "entry_driver": "browser-parity-harness-source-default",
                "state": "flight_world",
                "boundary": capture.BOUNDARY,
                "initial_state_policy": capture.INITIAL_STATE_POLICY,
                "camera_policy": capture.CAMERA_POLICY,
                "native_camera_match": False,
                "renderer": {
                    "kind": "browser-webgl1-canonical-fbo",
                    "rasterized": True,
                    "framebuffer_evidence": True,
                    "width": 640,
                    "height": 480,
                },
            },
            "runtime_identity": runtime,
            "artifacts": rows,
        }
        manifest_path, _ = _write_addressed(output / "manifests", manifest)
        return manifest_path, suite_root / "suite-spec.json"

    def test_verifies_hash_bound_production_candidate_without_promoting_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            report = capture.verify_capture(manifest, suite)
            self.assertEqual(report["status"], "VERIFIED_WEB_CANDIDATE")
            self.assertIs(report["promotion_allowed"], False)
            self.assertEqual(len(report["verified"]), 7)
            self.assertEqual(
                report["domain_readiness"]["systems"],
                "WEB_OBSERVATION_CHANNEL_INCOMPLETE",
            )
            self.assertEqual(
                report["domain_readiness"]["camera"],
                "WEB_POLICY_CAPTURED_NATIVE_MATCH_REQUIRED",
            )
            report_path = capture.write_report(manifest, report)
            self.assertEqual(
                report_path.name,
                f"{hashlib.sha256(report_path.read_bytes()).hexdigest()}.json",
            )

    def test_rejects_non_rasterized_renderer_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            value = json.loads(manifest.read_text())
            value["producer"]["renderer"]["rasterized"] = False
            drifted, _ = _write_addressed(manifest.parent, value)
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "not canonical raster evidence",
            ):
                capture.verify_capture(drifted, suite)

    def test_rejects_trace_not_emitted_by_the_production_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            value = json.loads(manifest.read_text())
            row = value["artifacts"][0]
            root = manifest.parent.parent
            trace = json.loads((root / row["path"]).read_text())
            trace["source"]["capture_boundary"] = "FlightWorldReplay.runFlightWorldReplay"
            _, digest = _write_addressed(root / "traces", trace)
            row["path"] = f"traces/{digest}.json"
            row["sha256"] = digest
            drifted, _ = _write_addressed(manifest.parent, value)
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "source provenance differs",
            ):
                capture.verify_capture(drifted, suite)

    def test_rejects_the_retired_web_shell_initial_state_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            value = json.loads(manifest.read_text())
            value["producer"][
                "initial_state_policy"
            ] = "PRODUCTION_DEFAULT_NOT_NATIVE_SCENARIO"
            drifted, _ = _write_addressed(manifest.parent, value)
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "production scene boundary",
            ):
                capture.verify_capture(drifted, suite)

        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            value = json.loads(manifest.read_text())
            row = value["artifacts"][0]
            root = manifest.parent.parent
            trace = json.loads((root / row["path"]).read_text())
            trace["source"]["initial_state_applied"] = False
            trace["source"][
                "runtime_projection"
            ] = "interactive-production-web-shell"
            _, digest = _write_addressed(root / "traces", trace)
            row["path"] = f"traces/{digest}.json"
            row["sha256"] = digest
            drifted, _ = _write_addressed(manifest.parent, value)
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "source provenance differs",
            ):
                capture.verify_capture(drifted, suite)

    def test_rejects_hash_bound_runtime_readback_drift(self):
        for mutation in ("value", "hash"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                manifest, suite = self._capture(Path(temporary))
                value = json.loads(manifest.read_text())
                row = value["artifacts"][0]
                root = manifest.parent.parent
                trace = json.loads((root / row["path"]).read_text())
                if mutation == "value":
                    trace["source"]["initial_state_readback"][0]["value_hex"] = "00"
                    trace["source"][
                        "initial_state_readback_sha256"
                    ] = scenarios.canonical_sha256(
                        trace["source"]["initial_state_readback"],
                    )
                else:
                    trace["source"]["initial_state_readback_sha256"] = "0" * 64
                _, digest = _write_addressed(root / "traces", trace)
                row["path"] = f"traces/{digest}.json"
                row["sha256"] = digest
                drifted, _ = _write_addressed(manifest.parent, value)
                with self.assertRaisesRegex(
                    capture.BrowserCaptureError, "source provenance differs",
                ):
                    capture.verify_capture(drifted, suite)

    def test_rejects_invented_unobserved_domain_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            value = json.loads(manifest.read_text())
            row = value["artifacts"][0]
            root = manifest.parent.parent
            trace = json.loads((root / row["path"]).read_text())
            trace["frames"][0]["numeric"]["systems"] = {"fuel": 1}
            _, digest = _write_addressed(root / "traces", trace)
            row["path"] = f"traces/{digest}.json"
            row["sha256"] = digest
            drifted, _ = _write_addressed(manifest.parent, value)
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "invalid shape",
            ):
                capture.verify_capture(drifted, suite)

    def test_rejects_raw_framebuffer_byte_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            value = json.loads(manifest.read_text())
            raw = next(
                row["framebuffer_artifacts"][0]
                for row in value["artifacts"]
                if row["framebuffer_artifacts"]
            )
            (manifest.parent.parent / raw["path"]).write_bytes(b"\x00")
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "raw framebuffer bytes differ",
            ):
                capture.verify_capture(manifest, suite)

    def test_rejects_missing_or_extra_observation_domains(self):
        mutations = (
            ("numeric", lambda frame: frame.pop("numeric")),
            ("camera", lambda frame: frame.pop("camera")),
            ("render", lambda frame: frame.pop("render")),
            ("timing", lambda frame: frame["numeric"].pop("timing")),
            ("physics", lambda frame: frame["numeric"].pop("physics")),
            ("extra", lambda frame: frame["numeric"].update({"systems": {}})),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                manifest, suite = self._capture(Path(temporary))
                value = json.loads(manifest.read_text())
                row = value["artifacts"][0]
                root = manifest.parent.parent
                trace = json.loads((root / row["path"]).read_text())
                mutate(trace["frames"][0])
                _, digest = _write_addressed(root / "traces", trace)
                row["path"] = f"traces/{digest}.json"
                row["sha256"] = digest
                drifted, _ = _write_addressed(manifest.parent, value)
                with self.assertRaisesRegex(
                    capture.BrowserCaptureError, "invalid shape",
                ):
                    capture.verify_capture(drifted, suite)

    def test_rejects_forged_clock_and_effective_input_schedules(self):
        mutations = (
            ("elapsed", lambda frame: frame.update({
                "time_seconds": frame["time_seconds"] + 0.001,
            })),
            ("delta", lambda frame: frame["numeric"]["timing"].update({
                "deltaSeconds": 0.01,
            })),
            ("step", lambda frame: frame["numeric"]["timing"].update({
                "stepIndex": 99,
            })),
            ("input", lambda frame: frame["inputs"].update({
                "left": not frame["inputs"]["left"],
            })),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                manifest, suite = self._capture(Path(temporary))
                value = json.loads(manifest.read_text())
                row = value["artifacts"][0]
                root = manifest.parent.parent
                trace = json.loads((root / row["path"]).read_text())
                mutate(trace["frames"][0])
                _, digest = _write_addressed(root / "traces", trace)
                row["path"] = f"traces/{digest}.json"
                row["sha256"] = digest
                drifted, _ = _write_addressed(manifest.parent, value)
                with self.assertRaisesRegex(
                    capture.BrowserCaptureError, "canonical schedule",
                ):
                    capture.verify_capture(drifted, suite)

    def test_rejects_malformed_camera_physics_and_render_shapes(self):
        mutations = (
            ("physics-vector", lambda frame: frame["numeric"]["physics"].update({
                "position": [1, 2],
            })),
            ("camera-matrix", lambda frame: frame["camera"].update({
                "view_matrix": [1] * 15,
            })),
            ("camera-viewport", lambda frame: frame["camera"].update({
                "viewport": {"x": 0, "y": 0, "width": 320, "height": 240},
            })),
            ("render-stats", lambda frame: frame["render"]["diagnostics"]["webgl"].update({
                "drawCalls": 1.5,
            })),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                manifest, suite = self._capture(Path(temporary))
                value = json.loads(manifest.read_text())
                row = value["artifacts"][0]
                root = manifest.parent.parent
                trace = json.loads((root / row["path"]).read_text())
                mutate(trace["frames"][0])
                _, digest = _write_addressed(root / "traces", trace)
                row["path"] = f"traces/{digest}.json"
                row["sha256"] = digest
                drifted, _ = _write_addressed(manifest.parent, value)
                with self.assertRaises(capture.BrowserCaptureError):
                    capture.verify_capture(drifted, suite)

    def test_rejects_non_source_loadout_camera_or_texture_provenance(self):
        mutations = (
            ("loadout", lambda value: value["runtime_identity"]["subject"].update({
                "airplane_graph": [{"part_id": 99, "link_slot": 0, "linked_part_id": 0}],
            })),
            ("camera", lambda value: value["producer"].update({
                "camera_policy": "native-fixed-camera",
                "native_camera_match": True,
            })),
            ("texture", lambda value: value["runtime_identity"]["texture_assets"][0].update({
                "observed_sha256": "f" * 64,
            })),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                manifest, suite = self._capture(Path(temporary))
                value = json.loads(manifest.read_text())
                mutate(value)
                drifted, _ = _write_addressed(manifest.parent, value)
                with self.assertRaises(capture.BrowserCaptureError):
                    capture.verify_capture(drifted, suite)

    def test_rejects_extra_trace_source_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, suite = self._capture(Path(temporary))
            value = json.loads(manifest.read_text())
            row = value["artifacts"][0]
            root = manifest.parent.parent
            trace = json.loads((root / row["path"]).read_text())
            trace["source"]["unreviewed_claim"] = True
            _, digest = _write_addressed(root / "traces", trace)
            row["path"] = f"traces/{digest}.json"
            row["sha256"] = digest
            drifted, _ = _write_addressed(manifest.parent, value)
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "invalid shape",
            ):
                capture.verify_capture(drifted, suite)

    def _empty_registry(self, root: Path) -> Path:
        path = root / registry.REGISTRY_REFERENCE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schema": 1,
            "protocol": registry.PROTOCOL,
            "capture": None,
        }) + "\n")
        receipt_registry = root / runtime_receipts.REGISTRY_REFERENCE
        receipt_registry.write_text(json.dumps({
            "schema": 1,
            "protocol": runtime_receipts.REGISTRY_PROTOCOL,
            "receipts": [],
        }) + "\n")
        return path

    def _review_runtime_receipt(
        self, repository: Path, manifest: Path, *, commit: str | None = None,
        image_digest: str = "b" * 64, origin: str = "https://example.test",
    ) -> Path:
        manifest_value = json.loads(manifest.read_text())
        runtime = manifest_value["runtime_identity"]
        content = repository / "content/miel_vliegt/runtime-proof"
        content.mkdir(parents=True, exist_ok=True)

        bundle_source = manifest.parent.parent.parent / "runtime/bundle.js"
        bundle = content / "bundle.js"
        bundle.write_bytes(bundle_source.read_bytes())
        version = content / "version.txt"
        required_sources = (
            set(runtime_source_manifest.FIXED_INPUT_PATHS)
            | set(runtime_source_manifest.ESSENTIAL_INPUT_PATHS)
        )
        for reference in sorted(required_sources):
            source_path = repository / reference
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(
                "{}\n" if source_path.suffix == ".json"
                else f"// reviewed fixture: {reference}\n",
            )
        source_input = repository / runtime_source_manifest.ENTRYPOINT
        source_input.write_text("export const reviewed = true;\n")
        if commit is None:
            subprocess.run(
                ["git", "init", "-q", str(repository)], check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.email",
                 "parity@example.test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name",
                 "Parity Test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "add", "."],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m",
                 "fixture"],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
        version.write_text(f"Miel Monteur (nl, {commit[:12]})\n")
        resolved, committed_payloads = (
            runtime_source_manifest.committed_input_payloads(
                repository, commit,
            )
        )
        runtime_source = runtime_source_manifest.manifest_from_payloads(
            resolved, committed_payloads,
        )
        source_sha256 = hashlib.sha256(source_input.read_bytes()).hexdigest()
        transition_source_row = {
            "path": runtime_source_manifest.ENTRYPOINT,
            "sha256": source_sha256,
        }
        transition_identity = {
            "schema": 1,
            "protocol": "miel-web-scene-transition-build",
            "inputs": [transition_source_row],
        }
        transition_value = {
            **transition_identity,
            "build_sha256": runtime_receipts.canonical_sha256(
                transition_identity,
            ),
        }
        transition = content / "web_transition_build.json"
        transition.write_text(json.dumps(transition_value) + "\n")

        assets = []
        parts = content / "uds_flight_parts.json"
        parts.write_bytes(capture.PARTS_CONTRACT.read_bytes())
        assets.append({
            "url": runtime["parts"]["url"],
            "path": parts.relative_to(repository).as_posix(),
            "sha256": hashlib.sha256(parts.read_bytes()).hexdigest(),
        })
        for texture in runtime["texture_assets"]:
            source = (
                capture.REPO_ROOT / "content/miel_vliegt/ccf-textures"
                / Path(texture["asset_url"]).name
            )
            destination = repository / texture["asset_url"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            assets.append({
                "url": f"{origin}/{texture['asset_url']}",
                "path": destination.relative_to(repository).as_posix(),
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            })
        assets.sort(key=lambda row: row["url"])
        tracked_inputs = []
        for row in runtime_source["inputs"]:
            source_snapshot = (
                repository / runtime_receipts.SOURCE_STORE_REFERENCE
                / f"{row['sha256']}.blob"
            )
            source_snapshot.parent.mkdir(parents=True, exist_ok=True)
            source_snapshot.write_bytes(committed_payloads[row["path"]])
            tracked_inputs.append({
                **row,
                "snapshot_path": source_snapshot.relative_to(
                    repository,
                ).as_posix(),
            })
        source = {
            "commit": commit,
            "runtime_source_manifest": runtime_source,
            "tracked_inputs": tracked_inputs,
            "tracked_inputs_sha256": runtime_receipts.canonical_sha256(
                tracked_inputs,
            ),
        }
        artifacts = {
            "bundle": {
                "url": runtime["bundle"]["url"],
                "path": bundle.relative_to(repository).as_posix(),
                "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            },
            "version": {
                "url": f"{origin}/version.txt",
                "path": version.relative_to(repository).as_posix(),
                "sha256": hashlib.sha256(version.read_bytes()).hexdigest(),
            },
            "web_transition_build": {
                "url": f"{origin}/assets/web_transition_build.json",
                "path": transition.relative_to(repository).as_posix(),
                "sha256": hashlib.sha256(transition.read_bytes()).hexdigest(),
            },
            "assets": assets,
        }
        identity = {
            "schema": 1,
            "protocol": runtime_receipts.PROTOCOL,
            "origin": origin,
            "source": source,
            "image": {
                "reference": f"registry.example/miel@sha256:{image_digest}",
                "digest": f"sha256:{image_digest}",
                "platform": "linux/arm64",
            },
            "artifacts": artifacts,
        }
        receipt = {
            **identity,
            "identity_sha256": runtime_receipts.canonical_sha256(identity),
        }
        receipt_path, digest = _write_addressed(
            repository
            / "content/miel_vliegt/browser_flight_runtime_receipts",
            receipt,
        )
        receipt_registry = repository / runtime_receipts.REGISTRY_REFERENCE
        receipt_registry.write_text(json.dumps({
            "schema": 1,
            "protocol": runtime_receipts.REGISTRY_PROTOCOL,
            "receipts": [{
                "id": digest,
                "path": receipt_path.relative_to(repository).as_posix(),
            }],
        }) + "\n")
        return receipt_path

    def test_registry_vendors_complete_capture_and_survives_source_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)

            published = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            expected = published["capture"]["scenarios"]
            shutil.rmtree(base / "external")

            verified, outputs = registry.verify_registry(root=repository)
            self.assertEqual(verified, published)
            self.assertEqual(
                outputs,
                {row["id"]: row["web_output"] for row in expected},
            )
            self.assertEqual(
                len(published["capture"]["scenarios"]),
                len(scenarios.SCENARIO_ID_ORDER),
            )
            self.assertEqual(
                json.loads(registry_path.read_text()),
                published,
            )

    def test_registry_import_is_byte_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            first = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            before = registry_path.read_bytes()
            second = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            self.assertEqual(second, first)
            self.assertEqual(registry_path.read_bytes(), before)

    def test_registry_rejects_mixed_capture_and_suite_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, _suite = self._capture(base / "capture-a")
            _manifest, other_suite = self._capture(
                base / "capture-b", initial_payload=b"\x02",
            )
            receipt = self._review_runtime_receipt(repository, manifest)
            before = registry_path.read_bytes()
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "capture suite identity differs",
            ):
                registry.import_capture(
                    manifest, other_suite, receipt, root=repository,
                )
            self.assertEqual(registry_path.read_bytes(), before)
            self.assertFalse(
                (repository / registry.STORE_REFERENCE).exists(),
            )

    def test_registry_rejects_partial_source_and_partial_vendored_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            manifest_value = json.loads(manifest.read_text())
            missing = (
                manifest.parent.parent
                / manifest_value["artifacts"][0]["path"]
            )
            missing.unlink()
            with self.assertRaisesRegex(
                capture.BrowserCaptureError, "hash differs",
            ):
                registry.import_capture(
                    manifest, suite, receipt, root=repository,
                )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            published = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            closure_path = repository / published["capture"]["files"][-1]["path"]
            payload = closure_path.read_bytes()
            target = base / "closure-target"
            target.write_bytes(payload)
            closure_path.unlink()
            closure_path.symlink_to(target)
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "symlink",
            ):
                registry.verify_registry(root=repository)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            published = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            dependency = published["capture"]["files"][-1]["path"]
            (repository / dependency).unlink()
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "does not exist",
            ):
                registry.verify_registry(root=repository)

    def test_registry_rejects_duplicate_rows_and_nonidentical_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "capture-a")
            receipt = self._review_runtime_receipt(repository, manifest)
            registry.import_capture(
                manifest, suite, receipt, root=repository,
            )

            other_manifest, other_suite = self._capture(
                base / "capture-b", initial_payload=b"\x02",
            )
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError,
                "nonidentical browser evidence registry overwrite",
            ):
                registry.import_capture(
                    other_manifest, other_suite, receipt, root=repository,
                )

            value = json.loads(registry_path.read_text())
            value["capture"]["scenarios"][1]["id"] = (
                value["capture"]["scenarios"][0]["id"]
            )
            registry_path.write_text(json.dumps(value))
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError,
                "duplicate, out of order",
            ):
                registry.verify_registry(root=repository)

    def test_registry_serializes_same_capture_imports_across_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            context = multiprocessing.get_context("spawn")
            queue = context.Queue()
            processes = [
                context.Process(
                    target=_import_process,
                    args=(
                        queue, str(manifest), str(suite), str(receipt),
                        str(repository),
                    ),
                )
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            results = [queue.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(timeout=30)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual([status for status, _ in results], ["ok", "ok"])
            self.assertEqual(results[0][1], results[1][1])
            registry.verify_registry(root=repository)

    def test_registry_lock_uses_private_runtime_path_keyed_by_canonical_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            alias = base / "repository-alias"
            alias.symlink_to(repository, target_is_directory=True)
            other_repository = base / "other-repository"
            other_repository.mkdir()

            lock_path = registry._registry_lock_path(repository)
            self.assertEqual(
                lock_path,
                registry._registry_lock_path(alias),
            )
            self.assertNotEqual(
                lock_path,
                registry._registry_lock_path(other_repository),
            )
            with self.assertRaises(ValueError):
                lock_path.relative_to(repository.resolve())
            self.assertEqual(lock_path.parent.name, registry.LOCK_DIRECTORY_NAME)
            self.assertEqual(
                lock_path.parent.stat().st_mode & 0o777,
                0o700,
            )
            self.assertEqual(lock_path.parent.stat().st_uid, os.getuid())

    def test_registry_lock_prefers_valid_xdg_and_rejects_unsafe_xdg(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            xdg = base / "xdg"
            xdg.mkdir(mode=0o700)
            with mock.patch.dict(
                os.environ, {"XDG_RUNTIME_DIR": str(xdg)},
            ):
                self.assertEqual(
                    registry._registry_lock_path(repository).parent.parent,
                    xdg.resolve(),
                )

            unsafe_xdg = base / "unsafe-xdg"
            unsafe_xdg.mkdir(mode=0o755)
            temporary_root = base / "temporary"
            temporary_root.mkdir()
            with mock.patch.dict(
                os.environ, {"XDG_RUNTIME_DIR": str(unsafe_xdg)},
            ), mock.patch.object(
                registry.tempfile, "gettempdir",
                return_value=str(temporary_root),
            ):
                lock_path = registry._registry_lock_path(repository)
                self.assertEqual(
                    lock_path.parent.parent,
                    (
                        temporary_root
                        / (
                            f"{registry.FALLBACK_RUNTIME_DIRECTORY_PREFIX}-"
                            f"{os.getuid()}"
                        )
                    ).resolve(),
                )
                self.assertEqual(
                    lock_path.parent.parent.stat().st_mode & 0o777,
                    0o700,
                )

    def test_repository_replacement_cannot_replace_registry_lock_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            lock_path = registry._registry_lock_path(repository)
            with registry._registry_lock(repository):
                before = lock_path.stat()
                shutil.rmtree(repository)
                repository.mkdir()
                after_path = registry._registry_lock_path(repository)
                after = after_path.stat()
                self.assertEqual(after_path, lock_path)
                self.assertEqual(after.st_dev, before.st_dev)
                self.assertEqual(after.st_ino, before.st_ino)

    def test_registry_lock_serializes_canonical_repository_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            alias = base / "repository-alias"
            alias.symlink_to(repository, target_is_directory=True)
            context = multiprocessing.get_context("spawn")
            first_acquired = context.Event()
            first_release = context.Event()
            second_acquired = context.Event()
            second_release = context.Event()
            first = context.Process(
                target=_hold_registry_lock,
                args=(str(repository), first_acquired, first_release),
            )
            second = context.Process(
                target=_hold_registry_lock,
                args=(str(alias), second_acquired, second_release),
            )
            first.start()
            self.assertTrue(first_acquired.wait(timeout=10))
            second.start()
            self.assertFalse(second_acquired.wait(timeout=0.5))
            first_release.set()
            self.assertTrue(second_acquired.wait(timeout=10))
            second_release.set()
            for process in (first, second):
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)

    def test_registry_serializes_different_capture_imports_without_clobber(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            self._empty_registry(repository)
            first_manifest, first_suite = self._capture(base / "first")
            second_manifest, second_suite = self._capture(
                base / "second", initial_payload=b"\x02",
            )
            receipt = self._review_runtime_receipt(
                repository, first_manifest,
            )
            context = multiprocessing.get_context("spawn")
            queue = context.Queue()
            processes = [
                context.Process(
                    target=_import_process,
                    args=(
                        queue, str(manifest), str(suite), str(receipt),
                        str(repository),
                    ),
                )
                for manifest, suite in (
                    (first_manifest, first_suite),
                    (second_manifest, second_suite),
                )
            ]
            for process in processes:
                process.start()
            results = [queue.get(timeout=30) for _ in processes]
            for process in processes:
                process.join(timeout=30)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(
                sorted(status for status, _ in results), ["error", "ok"],
            )
            verified, _ = registry.verify_registry(root=repository)
            self.assertIn(
                verified["capture"]["id"],
                {
                    hashlib.sha256(first_manifest.read_bytes()).hexdigest(),
                    hashlib.sha256(second_manifest.read_bytes()).hexdigest(),
                },
            )

    def test_registry_recovers_only_an_exact_content_addressed_orphan(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            published = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            registry_path.write_bytes(registry._render(registry._empty_registry()))
            recovered = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            self.assertEqual(recovered, published)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            published = registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            registry_path.write_bytes(registry._render(registry._empty_registry()))
            (repository / published["capture"]["files"][-1]["path"]).write_bytes(
                b"partial orphan",
            )
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError,
                "partial or nonidentical",
            ):
                registry.import_capture(
                    manifest, suite, receipt, root=repository,
                )

    def test_registry_rolls_back_only_the_state_published_by_this_importer(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            before = registry_path.read_bytes()
            real_verify = registry.verify_registry
            calls = 0

            def fail_post_publish(*, root):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_verify(root=root)
                raise registry.BrowserEvidenceRegistryError("post verify failed")

            with mock.patch.object(
                registry, "verify_registry", side_effect=fail_post_publish,
            ), self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "post verify failed",
            ):
                registry.import_capture(
                    manifest, suite, receipt, root=repository,
                )
            self.assertEqual(registry_path.read_bytes(), before)
            capture_id = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self.assertFalse(
                (repository / registry.STORE_REFERENCE / capture_id).exists(),
            )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            foreign = b'{"foreign":"writer"}\n'
            real_verify = registry.verify_registry
            calls = 0

            def replace_post_publish(*, root):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_verify(root=root)
                registry_path.write_bytes(foreign)
                raise registry.BrowserEvidenceRegistryError("foreign writer")

            with mock.patch.object(
                registry, "verify_registry", side_effect=replace_post_publish,
            ), self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "foreign writer",
            ):
                registry.import_capture(
                    manifest, suite, receipt, root=repository,
                )
            self.assertEqual(registry_path.read_bytes(), foreign)
            capture_id = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self.assertTrue(
                (repository / registry.STORE_REFERENCE / capture_id).is_dir(),
            )

    def test_registry_rejects_symlinked_trust_and_evidence_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            target = registry_path.with_name("registry-target.json")
            registry_path.rename(target)
            registry_path.symlink_to(target)
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "symlink",
            ):
                registry.import_capture(
                    manifest, suite, receipt, root=repository,
                )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            outside = base / "outside"
            outside.mkdir()
            store = repository / registry.STORE_REFERENCE
            store.parent.mkdir(parents=True, exist_ok=True)
            store.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "symlink",
            ):
                registry.import_capture(
                    manifest, suite, receipt, root=repository,
                )

    def test_registry_rejects_noncanonical_entry_paths_and_file_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            registry_path = self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            registry.import_capture(
                manifest, suite, receipt, root=repository,
            )
            value = json.loads(registry_path.read_text())
            value["capture"]["manifest"]["path"] = value["capture"]["suite"]["path"]
            registry_path.write_text(json.dumps(value))
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "not canonical",
            ):
                registry.verify_registry(root=repository)

    def test_registry_strict_json_rejects_duplicate_and_nonfinite_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            path = self._empty_registry(repository)
            path.write_text(
                '{"schema":1,"schema":1,'
                f'"protocol":"{registry.PROTOCOL}","capture":null}}\n'
            )
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "duplicate JSON",
            ):
                registry.verify_registry(root=repository)
            path.write_text(
                '{"schema":NaN,'
                f'"protocol":"{registry.PROTOCOL}","capture":null}}\n'
            )
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "non-finite",
            ):
                registry.verify_registry(root=repository)

    def test_registry_rejects_unreviewed_or_forged_runtime_receipts(self):
        mutations = ("commit", "origin", "image", "bundle")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                repository = base / "repository"
                self._empty_registry(repository)
                manifest, suite = self._capture(base / "external")
                receipt = self._review_runtime_receipt(repository, manifest)
                value = json.loads(receipt.read_text())
                if mutation == "commit":
                    value["source"]["commit"] = "c" * 40
                elif mutation == "origin":
                    value["origin"] = "https://forged.example"
                elif mutation == "image":
                    value["image"]["digest"] = f"sha256:{'c' * 64}"
                else:
                    value["artifacts"]["bundle"]["sha256"] = "c" * 64
                identity = {key: value[key] for key in (
                    "schema", "protocol", "origin", "source", "image",
                    "artifacts",
                )}
                value["identity_sha256"] = (
                    runtime_receipts.canonical_sha256(identity)
                )
                receipt.write_text(json.dumps(value) + "\n")
                receipt_registry = (
                    repository / runtime_receipts.REGISTRY_REFERENCE
                )
                reviewed = json.loads(receipt_registry.read_text())
                reviewed["receipts"][0]["id"] = hashlib.sha256(
                    receipt.read_bytes(),
                ).hexdigest()
                receipt_registry.write_text(json.dumps(reviewed) + "\n")
                with self.assertRaises((
                    registry.BrowserEvidenceRegistryError,
                    runtime_receipts.BrowserFlightRuntimeReceiptError,
                )):
                    registry.import_capture(
                        manifest, suite, receipt, root=repository,
                    )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            self._empty_registry(repository)
            manifest, suite = self._capture(base / "external")
            receipt = self._review_runtime_receipt(repository, manifest)
            reviewed = repository / runtime_receipts.REGISTRY_REFERENCE
            value = json.loads(reviewed.read_text())
            value["receipts"] = []
            reviewed.write_text(json.dumps(value) + "\n")
            with self.assertRaisesRegex(
                registry.BrowserEvidenceRegistryError, "not present exactly once",
            ):
                registry.import_capture(
                    manifest, suite, receipt, root=repository,
                )

    def test_runtime_receipt_rejects_missing_essential_producer_inputs(self):
        essential_inputs = (
            "src/flight/runtime/FlightProductionTraceCapture.js",
            "src/scenes/flight_world.js",
            "webpack.prod.js",
        )
        for omitted in essential_inputs:
            with self.subTest(omitted=omitted), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                repository = base / "repository"
                self._empty_registry(repository)
                manifest, _suite = self._capture(base / "external")
                receipt = self._review_runtime_receipt(repository, manifest)
                value = json.loads(receipt.read_text())
                source = value["source"]
                runtime_source = source["runtime_source_manifest"]
                runtime_source["inputs"] = [
                    row for row in runtime_source["inputs"]
                    if row["path"] != omitted
                ]
                runtime_identity = {
                    key: runtime_source[key]
                    for key in (
                        "schema", "protocol", "source_commit", "entrypoint",
                        "input_policy", "inputs",
                    )
                }
                runtime_source["build_sha256"] = (
                    runtime_source_manifest.canonical_sha256(
                        runtime_identity,
                    )
                )
                source["tracked_inputs"] = [
                    row for row in source["tracked_inputs"]
                    if row["path"] != omitted
                ]
                source["tracked_inputs_sha256"] = (
                    runtime_receipts.canonical_sha256(
                        source["tracked_inputs"],
                    )
                )
                identity = {
                    key: value[key]
                    for key in (
                        "schema", "protocol", "origin", "source", "image",
                        "artifacts",
                    )
                }
                value["identity_sha256"] = (
                    runtime_receipts.canonical_sha256(identity)
                )
                receipt.write_text(json.dumps(value) + "\n")
                with self.assertRaisesRegex(
                    runtime_receipts.BrowserFlightRuntimeReceiptError,
                    "complete committed production graph",
                ):
                    runtime_receipts.validate_receipt(
                        receipt, root=repository,
                    )

    def test_rejects_invented_event_and_collision_observations(self):
        mutations = (
            ("event", lambda frame: frame["events"].append({"kind": "forged"})),
            (
                "collision",
                lambda frame: frame["numeric"]["collisions"]["contacts"].append({
                    "kind": "forged",
                }),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                manifest, suite = self._capture(Path(temporary))
                value = json.loads(manifest.read_text())
                row = value["artifacts"][0]
                root = manifest.parent.parent
                trace = json.loads((root / row["path"]).read_text())
                mutate(trace["frames"][0])
                _, digest = _write_addressed(root / "traces", trace)
                row["path"] = f"traces/{digest}.json"
                row["sha256"] = digest
                drifted, _ = _write_addressed(manifest.parent, value)
                with self.assertRaises(capture.BrowserCaptureError):
                    capture.verify_capture(drifted, suite)

    def test_collision_schema_distinguishes_observed_no_contact_from_unobserved(self):
        base = {
            "timing": {
                "deltaSeconds": 0.04,
                "fixedStepSeconds": 0.04,
                "stepIndex": 1,
            },
            "physics": {
                "position": [0, 0, 0],
                "orientation": [0, 0, 0, 1],
                "velocity": [0, 0, 0],
                "angularVelocity": None,
            },
            "collisions": {"observed": True, "contacts": []},
        }
        capture._validate_numeric(base, "frame.numeric")

        base["collisions"]["observed"] = False
        capture._validate_numeric(base, "frame.numeric")

        base["collisions"]["contacts"].append({
            "kind": "terrain",
            "contactPosition": [0, 0, 0],
            "contactNormal": [0, 1, 0],
            "relativeVelocity": [0, -1, 0],
            "damage": 0,
            "landingClassification": "safe",
        })
        with self.assertRaisesRegex(
            capture.BrowserCaptureError,
            "requires an observed collision channel",
        ):
            capture._validate_numeric(base, "frame.numeric")


if __name__ == "__main__":
    unittest.main()
