import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.miel_vliegt import flight_cleanroom_completion as completion
from tools.miel_vliegt import flight_scenario_completion_adapter as adapter
from tools.miel_vliegt import native_scenario_artifacts as artifacts


ROOT = Path(__file__).resolve().parents[2]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FlightScenarioCompletionAdapterTest(unittest.TestCase):
    def native_evidence_stub(self) -> dict:
        runtime_trace = json.loads(
            (
                ROOT / "content/miel_vliegt/flight_runtime_trace_contract.json"
            ).read_text(encoding="utf-8")
        )
        return {
            "path": "/tmp/calibrated-suite-run.json",
            "sha256": "a" * 64,
            "status": adapter.NATIVE_SUITE_STATUS,
            "production_claim": False,
            "executable_sha256":
                runtime_trace["source_identity"]["executable_sha256"],
            "scenarios": {
                identifier: {"run_1": {"native_trace": {}}}
                for identifier in artifacts.SCENARIO_ID_ORDER
            },
        }

    def test_projection_never_overrides_the_authoritative_completion_matrix(self):
        matrix = completion.build_from_root(ROOT)
        report = adapter.build_report(
            Path("/tmp/not-read.json"),
            native_evidence=self.native_evidence_stub(),
            completion_matrix=matrix,
        )
        adapter.validate_report(report)

        authoritative = {
            (dimension["id"], item["id"]): item["status"]
            for dimension in matrix["dimensions"]
            if dimension["id"] in {"gameplay_runtimes", "subsystems", "assets"}
            for item in dimension["items"]
        }
        projected = {
            (dimension["id"], item["id"]): item
            for dimension in report["dimensions"]
            for item in dimension["items"]
        }
        self.assertEqual(set(projected), set(authoritative))
        for identity, canonical_status in authoritative.items():
            self.assertEqual(
                projected[identity]["status"],
                "PASS" if canonical_status == "COMPLETE" else "BLOCKED",
            )

        gameplay = next(
            row for row in report["dimensions"]
            if row["id"] == "gameplay_runtimes"
        )
        self.assertTrue(all(
            any(
                blocker.startswith(
                    "NO_CANONICAL_SCENARIO_TO_COMPLETION_BOUNDARY:"
                )
                for blocker in item["blockers"]
            )
            for item in gameplay["items"] if item["status"] == "BLOCKED"
        ))
        physics = next(
            item
            for dimension in report["dimensions"]
            if dimension["id"] == "subsystems"
            for item in dimension["items"]
            if item["id"] == "physics_collision"
        )
        self.assertIn(
            "WEB_TRACE_MISSING:taxi-straight:physics",
            physics["blockers"],
        )
        self.assertIn(
            "WEB_TRACE_MISSING:taxi-straight:systems",
            physics["blockers"],
        )
        self.assertIn(
            "REVIEWED_PRODUCTION_NATIVE_OBSERVER_RECEIPT_MISSING",
            physics["blockers"],
        )

    def write_native_suite_fixture(self, root: Path) -> Path:
        suite_root = root / "suite"
        output_root = root / "output"
        suite_root.mkdir()
        output_root.mkdir()
        manifest_path = suite_root / "suite-spec.json"
        manifest_path.write_text('{"suite":"fixture"}\n', encoding="utf-8")
        activation_path = suite_root / "flight-activation-rng.json"
        activation_path.write_text('{"activation":"fixture"}\n', encoding="utf-8")
        raw = b"raw-frame"
        rgba = b"canonical-rgba"
        projection = {
            field: {
                "count": 0,
                "sha256": digest(field.encode("ascii")),
                "records": [],
            }
            for field in adapter.EXTRACTORS
        }
        projection["flight_activation_rng"] = {
            "count": 0,
            "sha256": digest(b"flight_activation_rng"),
            "draws": [],
        }
        projection["flight_activation_clock"] = {
            "count": 0,
            "sha256": digest(b"flight_activation_clock"),
            "ticks": [],
        }
        exact_rows = []
        for identifier in artifacts.SCENARIO_ID_ORDER:
            profile = artifacts.scenario_observation_profile(identifier)
            profile_receipt = {
                **profile,
                "sha256": artifacts.observation_profile_sha256(
                    profile, scenario_id=identifier,
                ),
            }
            not_applicable = lambda channel: {
                "status": "NOT_APPLICABLE",
                "profile_id": profile["id"],
                "channel": channel,
                "reason": "omitted_by_observation_profile",
            }
            scenario_projection = {
                field: copy.deepcopy(projection[field])
                if field in profile["applicable_receipt_channels"]
                else not_applicable(field)
                for field in adapter.EXTRACTORS
            }
            pair_paths = []
            for repeat in (1, 2):
                run_root = output_root / "exact" / identifier / f"run-{repeat}"
                run_root.mkdir(parents=True)
                observer = run_root / "native-observer-box64.log"
                observer.write_text(f"observer {identifier}\n", encoding="utf-8")
                if profile["framebuffer_required"]:
                    metadata = run_root / f"native-frame-{identifier}-box64.json"
                    metadata.write_text("{}\n", encoding="utf-8")
                    metadata.with_suffix(".raw").write_bytes(raw)
                    native_metadata = metadata.with_name(
                        f"{metadata.stem}.native.json"
                    )
                    native_metadata.write_text("{}\n", encoding="utf-8")
                    native_metadata.with_name(
                        native_metadata.name.removesuffix(".json") + ".raw"
                    ).write_bytes(raw)
                receipt = {
                    "status": "CANDIDATE_ONLY",
                    "production_claim": False,
                    "scenario": identifier,
                    "observation_profile": profile_receipt,
                    "hook_observation_profile": {
                        "profile": profile["observer_profile"],
                        "omit_mask": profile["omit_mask"],
                    },
                    "semantic_sha256": digest(f"semantic:{identifier}".encode()),
                    "observer_log_sha256": digest(observer.read_bytes()),
                    "framebuffer_raw_sha256": (
                        digest(raw)
                        if "framebuffer" in profile["applicable_receipt_channels"]
                        else not_applicable("framebuffer")
                    ),
                    "framebuffer_rgba_sha256": (
                        digest(rgba)
                        if "framebuffer" in profile["applicable_receipt_channels"]
                        else not_applicable("framebuffer")
                    ),
                    "runtime_initial_state": [{"name": "fixture"}],
                    **copy.deepcopy(scenario_projection),
                }
                exact = run_root / "exact-run.json"
                exact.write_text(json.dumps(receipt), encoding="utf-8")
                pair_paths.append(exact.relative_to(output_root).as_posix())
            first = json.loads(
                (output_root / pair_paths[0]).read_text(encoding="utf-8")
            )
            exact_rows.append({
                "id": identifier,
                "run_1": pair_paths[0],
                "run_2": pair_paths[1],
                "observation_profile": profile_receipt,
                "semantic_sha256": first["semantic_sha256"],
                "framebuffer_raw_sha256": first["framebuffer_raw_sha256"],
                "framebuffer_rgba_sha256": first["framebuffer_rgba_sha256"],
                **{
                    f"{field}_sha256": (
                        first[field]["sha256"]
                        if field in profile["applicable_receipt_channels"]
                        else first[field]
                    )
                    for field in adapter.EXTRACTORS
                },
            })
        suite = {
            "schema": adapter.NATIVE_SUITE_VERSION,
            "protocol": adapter.NATIVE_SUITE_PROTOCOL,
            "status": adapter.NATIVE_SUITE_STATUS,
            "production_claim": False,
            "scenario_order": list(artifacts.SCENARIO_ID_ORDER),
            "provenance": {
                "backend": {"id": "box64", "hodll": "wowbox64.dll"},
                "paths": {
                    "source_executable": {
                        "path": "/native/Miel.exe",
                        "sha256": "e" * 64,
                    },
                },
            },
            "prefix": {},
            "calibration": [],
            "calibrated_suite": {
                "path": suite_root.relative_to(root).as_posix(),
                "manifest_sha256": digest(manifest_path.read_bytes()),
                "scenario_order": list(artifacts.SCENARIO_ID_ORDER),
                "flight_activation_rng_sha256": digest(
                    activation_path.read_bytes()
                ),
            },
            "exact_runs": exact_rows,
            "blocker": None,
        }
        path = output_root / "calibrated-suite-run.json"
        path.write_text(json.dumps(suite), encoding="utf-8")
        self.fixture_projection = projection
        self.fixture_rgba = rgba
        self.fixture_raw = raw
        return path

    def test_native_suite_fixture_matches_producer_framebuffer_omission(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_native_suite_fixture(root)
            for identifier in artifacts.SCENARIO_ID_ORDER:
                profile = artifacts.scenario_observation_profile(identifier)
                run_root = root / "output" / "exact" / identifier / "run-1"
                frame_artifacts = list(run_root.glob("native-frame-*"))
                if profile["framebuffer_required"]:
                    self.assertEqual(len(frame_artifacts), 4, identifier)
                else:
                    self.assertEqual(frame_artifacts, [], identifier)

    def test_exact_suite_validator_binds_repeat_receipts_logs_and_framebuffers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt_path = self.write_native_suite_fixture(root)
            manifest = {
                "scenario_order": list(artifacts.SCENARIO_ID_ORDER),
                "scenarios": [
                    {
                        "id": identifier,
                        "observation_profile":
                            artifacts.scenario_observation_profile(identifier),
                        "scenario": {"path": f"{identifier}.json"},
                        "native_replay": {"path": f"{identifier}.mvo"},
                        "capture_tick": 0,
                    }
                    for identifier in artifacts.SCENARIO_ID_ORDER
                ],
            }
            for identifier in artifacts.SCENARIO_ID_ORDER:
                (root / "suite" / f"{identifier}.json").write_text("{}")
                (root / "suite" / f"{identifier}.mvo").write_bytes(b"replay")

            def entry(_manifest, identifier):
                return next(
                    row for row in manifest["scenarios"] if row["id"] == identifier
                )

            def scenario(path, **_kwargs):
                identifier = path.stem
                return {
                    "id": identifier,
                    "checkpoints": [{
                        "id": "frame",
                        "tick": 0,
                        "required_channels": ["render.framebuffer"],
                    }],
                }

            def completed(_observer, scenario_value, **_kwargs):
                return {
                    "semantic_sha256":
                        digest(f"semantic:{scenario_value['id']}".encode()),
                }

            def metadata(path, **_kwargs):
                identifier = path.name.removeprefix(
                    "native-frame-"
                ).removesuffix("-box64.json")
                return {
                    "scenario": identifier,
                    "scenario_sha256": digest(b"replay"),
                    "tick": 0,
                    "raw_sha256": digest(self.fixture_raw),
                }

            patches = [
                patch.object(
                    artifacts, "load_scenario_suite_manifest",
                    return_value=manifest,
                ),
                patch.object(artifacts, "scenario_suite_entry", side_effect=entry),
                patch.object(artifacts, "load_scenario", side_effect=scenario),
                patch.object(
                    artifacts, "validate_completed_scenario_trace",
                    side_effect=completed,
                ),
                patch.object(
                    adapter.hangover_probe,
                    "validate_scenario_observation_profile_receipt",
                    side_effect=lambda observer, _profile: json.loads(
                        (observer.parent / "exact-run.json").read_text()
                    )["hook_observation_profile"],
                ),
                patch.object(
                    artifacts, "load_framebuffer_metadata",
                    side_effect=metadata,
                ),
                patch.object(
                    artifacts, "canonicalize_native_framebuffer",
                    return_value=self.fixture_rgba,
                ),
                patch.object(
                    artifacts, "extract_bound_runtime_initial_state",
                    return_value=[{"name": "fixture"}],
                ),
                patch.object(
                    artifacts, "build_native_framebuffer_evidence",
                    return_value={
                        "tick": 0,
                        "raw_sha256": digest(self.fixture_raw),
                        "pixel_checkpoint": {
                            "id": "frame",
                            "width": 1,
                            "height": 1,
                            "pixel_format": "rgba8",
                            "origin": "top-left",
                            "alpha_mode": "straight",
                            "reference_sha256": digest(self.fixture_rgba),
                        },
                    },
                ),
                patch.object(
                    adapter.differential, "native_semantic_to_trace",
                    side_effect=lambda _semantic, _source, scenario_value, _frame: {
                        "scenario": {"id": scenario_value["id"]},
                        "capture_kind": "native",
                    },
                ),
                patch.dict(
                    adapter.EXTRACTORS,
                    {
                        field: (
                            lambda _path, value=copy.deepcopy(
                                self.fixture_projection[field]
                            ): copy.deepcopy(value)
                        )
                        for field in adapter.EXTRACTORS
                    },
                    clear=True,
                ),
            ]
            for active in patches:
                active.start()
                self.addCleanup(active.stop)

            evidence = adapter.validate_native_suite(receipt_path)
            self.assertEqual(
                set(evidence["scenarios"]),
                set(artifacts.SCENARIO_ID_ORDER),
            )
            self.assertFalse(evidence["production_claim"])

            unexpected_frame = (
                root / "output" / "exact" / artifacts.SCENARIO_ID_ORDER[0]
                / "run-1"
                / (
                    "native-frame-"
                    f"{artifacts.SCENARIO_ID_ORDER[0]}-box64.json"
                )
            )
            unexpected_frame.write_bytes(self.fixture_raw)
            with self.assertRaisesRegex(
                adapter.AdapterError, "omitted framebuffer artifacts exist",
            ):
                adapter.validate_native_suite(receipt_path)
            unexpected_frame.unlink()

            original_receipt = receipt_path.read_text(encoding="utf-8")
            for invalid_path in (
                "/absolute/calibrated-suite",
                "../calibrated-suite",
                "calibrated-suite/../calibrated-suite",
                r"calibrated-suite\windows",
            ):
                suite = json.loads(original_receipt)
                suite["calibrated_suite"]["path"] = invalid_path
                receipt_path.write_text(json.dumps(suite), encoding="utf-8")
                with self.assertRaisesRegex(
                    adapter.AdapterError, "canonical bundle-relative path",
                ):
                    adapter.validate_native_suite(receipt_path)
            receipt_path.write_text(original_receipt, encoding="utf-8")

            (root / "bundle-alias").symlink_to(root, target_is_directory=True)
            suite = json.loads(original_receipt)
            suite["calibrated_suite"]["path"] = "bundle-alias/suite"
            receipt_path.write_text(json.dumps(suite), encoding="utf-8")
            with self.assertRaisesRegex(
                adapter.AdapterError, "must not contain symlink components",
            ):
                adapter.validate_native_suite(receipt_path)
            (root / "bundle-alias").unlink()

            with tempfile.TemporaryDirectory() as outside_temporary:
                outside = Path(outside_temporary)
                (outside / "suite").mkdir()
                (root / "bundle-escape").symlink_to(
                    outside, target_is_directory=True,
                )
                suite["calibrated_suite"]["path"] = "bundle-escape/suite"
                receipt_path.write_text(json.dumps(suite), encoding="utf-8")
                with self.assertRaisesRegex(
                    adapter.AdapterError, "must not contain symlink components",
                ):
                    adapter.validate_native_suite(receipt_path)
                (root / "bundle-escape").unlink()
            receipt_path.write_text(original_receipt, encoding="utf-8")

            suite = json.loads(receipt_path.read_text())
            suite["exact_runs"][0]["semantic_sha256"] = "0" * 64
            receipt_path.write_text(json.dumps(suite))
            with self.assertRaisesRegex(adapter.AdapterError, "summary drifted"):
                adapter.validate_native_suite(receipt_path)
            receipt_path.write_text(original_receipt, encoding="utf-8")

            with tempfile.TemporaryDirectory() as relocated_temporary:
                relocated = Path(relocated_temporary) / "downloaded-bundle"
                shutil.copytree(root, relocated)
                shutil.rmtree(root)
                relocated_evidence = adapter.validate_native_suite(
                    relocated / "output" / "calibrated-suite-run.json"
                )
                self.assertEqual(
                    Path(relocated_evidence["suite_root"]),
                    (relocated / "suite").resolve(),
                )
                self.assertEqual(
                    set(relocated_evidence["scenarios"]),
                    set(artifacts.SCENARIO_ID_ORDER),
                )

    def test_report_hash_and_inventory_are_fail_closed(self):
        matrix = completion.build_from_root(ROOT)
        report = adapter.build_report(
            Path("/tmp/not-read.json"),
            native_evidence=self.native_evidence_stub(),
            completion_matrix=matrix,
        )
        changed = copy.deepcopy(report)
        changed["summary"]["pass"] += 1
        with self.assertRaisesRegex(adapter.AdapterError, "hash drifted"):
            adapter.validate_report(changed)

        wrong_edition = self.native_evidence_stub()
        wrong_edition["executable_sha256"] = "0" * 64
        with self.assertRaisesRegex(adapter.AdapterError, "executable identity"):
            adapter.build_report(
                Path("/tmp/not-read.json"),
                native_evidence=wrong_edition,
                completion_matrix=matrix,
            )

    def test_a_matching_web_trace_remains_candidate_only(self):
        canonical_trace = json.loads(
            (
                ROOT / "content/miel_vliegt/flight_runtime_trace_contract.json"
            ).read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for row in canonical_trace["scenarios"]:
                reference = f"web/{row['id']}.json"
                row["web_output"] = reference
                path = root / reference
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
            with patch.object(
                adapter.differential, "load_trace",
                return_value={"capture_kind": "web"},
            ), patch.object(
                adapter.differential, "compare_trace_domain",
                return_value=SimpleNamespace(
                    matches=True, frames_compared=3, divergence=None,
                ),
            ):
                rows = adapter._scenario_diagnostics(
                    self.native_evidence_stub(), canonical_trace, root,
                )
        self.assertTrue(all(
            domain["status"] == "MATCH_CANDIDATE_ONLY"
            for row in rows for domain in row["domains"].values()
        ))
        self.assertTrue(all(row["promotion_allowed"] is False for row in rows))
        self.assertTrue(all(
            row["promotion_blocker"] ==
            "REVIEWED_PRODUCTION_NATIVE_OBSERVER_RECEIPT_MISSING"
            for row in rows
        ))


if __name__ == "__main__":
    unittest.main()
