#!/usr/bin/env python3
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt import hangover_probe
from tools.miel_vliegt import native_body_suite
from tools.miel_vliegt import native_body_trace
from tools.miel_vliegt import native_mode_bodies


ROOT = Path(__file__).resolve().parents[2]


class NativeBodyCliEntrypointTest(unittest.TestCase):
    def test_documented_direct_entrypoints_bootstrap_repository_imports(self):
        for relative in (
            "tools/miel_vliegt/native_body_suite.py",
            "tools/miel_vliegt/native_body_trace.py",
        ):
            with self.subTest(entrypoint=relative):
                result = subprocess.run(
                    [sys.executable, relative, "--help"],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


def body_dispatch_receipt(
    executable: Path, mode: str, phase_ticks: dict[str, int],
) -> dict:
    flight = mode == "mode_fly"
    return_mode = "mode_login" if mode == "mode_barn" else "mode_barn"
    counts = {phase: int(phase in phase_ticks) for phase in native_body_trace.PHASES}
    return {
        "schema": 2,
        "protocol": "miel-vliegt-native-body-dispatch",
        "status": "INCOMPLETE" if flight else "PASS",
        "evidence_scope": "BODY_ONLY",
        "natural_transition_evidence": False,
        "debug_skip_used": False,
        "executable_sha256": hangover_probe.sha256(executable),
        "requested_mode": mode,
        "return_mode": return_mode,
        "command": {
            "name": "engine_mode",
            "id": 15,
            "dispatch": "registered-command-callback",
        },
        "callback_count": 2,
        "manager_thread": True,
        "dispatch_thread": 77,
        "ticks": {
            "entry_dispatch": 1,
            "target_activation": 3,
            "core_ready": 4,
            "return_dispatch": 4,
            "return_activation": 5,
        },
        "entry": {
            "pre": {
                "manager_canonical": True,
                "current_mode": "mode_barn",
                "pending_null": True,
                "target_resolved_before_mutation": True,
                "registry_record_resolved": True,
            },
            "post": {
                "current_mode": "mode_barn",
                "pending_mode": None if mode == "mode_barn" else mode,
                "dispatch_effect": (
                    "SAME_MODE_NOOP" if mode == "mode_barn"
                    else "PENDING_TARGET"
                ),
            },
            "activation": {
                "current_mode": mode,
                "pending_null": True,
                "loaded": True,
                "opened": True,
            },
        },
        "core": {
            "paired_counts": {
                phase: counts[phase] for phase in native_body_trace.CORE_PHASES
            },
            "last_leave_ticks": {
                phase: phase_ticks.get(phase)
                for phase in native_body_trace.CORE_PHASES
            },
            "fresh_after_activation": {"TICK": True, "RENDER": True},
            "complete": True,
        },
        "return": {
            "pre": {
                "current_mode": mode,
                "pending_null": True,
                "loaded": True,
                "opened": True,
            },
            "post": {
                "current_mode": mode,
                "pending_mode": return_mode,
                "dispatch_effect": "PENDING_RETURN",
            },
            "activation": {
                "current_mode": return_mode,
                "pending_null": True,
                "loaded": True,
                "opened": True,
            },
        },
        "teardown": {
            "close_pairs_delta": 1,
            "unload_pairs_delta": 0 if flight else 1,
            "close_observed": True,
            "unload_observed": not flight,
            "unload_policy": "SKIPPED_MODE_FLY" if flight else "MANAGER_COMMIT",
            "missing_phases": ["UNLOAD"] if flight else [],
            "complete": not flight,
        },
        "lifecycle_complete": not flight,
    }


class NativeBodySuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.executable = self.root / "MulleMeck.exe"
        self.observer = self.root / "observer.dll"
        self.launcher = self.root / "launcher.exe"
        self.debugger = self.root / "debugger.exe"
        for path, payload in (
            (self.executable, b"pinned-executable"),
            (self.observer, b"observer"),
            (self.launcher, b"launcher"),
            (self.debugger, b"debugger"),
        ):
            path.write_bytes(payload)
        self.contract = copy.deepcopy(native_mode_bodies.load_contract())
        self.contract["source"]["executable_sha256"] = hangover_probe.sha256(
            self.executable,
        )
        self.output = self.root / "suite"

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def host_path(wine_path: str) -> Path:
        if not wine_path.startswith("Z:\\"):
            raise AssertionError(wine_path)
        return Path("/" + wine_path[3:].replace("\\", "/"))

    def successful_navigation(
        self, *, mutate_after_first: Path | None = None,
        rewrite_runtime_config: bool = False,
        phases: tuple[str, ...] = native_body_trace.PHASES,
    ):
        calls = []

        def side_effect(
            environment, backend, executable, output, scene, scene_debugger,
            observer_dll, observer_launcher, **options,
        ):
            mode = options["observer_environment"]["MIEL_OBSERVER_BODY_MODE"]
            headless_config = hangover_probe.install_headless_config(
                executable.parent,
            )
            config_payload = (executable.parent / "config.ini").read_bytes()
            self.assertEqual(
                config_payload, hangover_probe.HEADLESS_CONFIG.read_bytes(),
            )
            log = output.parent / "native-observer-mock.log"
            mode_row = next(row for row in self.contract["modes"] if row["mode"] == mode)
            records = []
            actual_phases = tuple(
                phase for phase in phases
                if not (mode == "mode_fly" and phase == "UNLOAD")
            )
            phase_ticks = {
                "LOAD": 2, "OPEN": 2, "TICK": 3,
                "RENDER": 4, "CLOSE": 4, "UNLOAD": 4,
            }
            for phase in actual_phases:
                lifecycle = {
                    "schema": 1,
                    "protocol": "miel-vliegt-native-body-lifecycle",
                    "sequence": len(records),
                    "evidence_scope": "BODY_ONLY",
                    "natural_transition_evidence": False,
                    "mode_id": mode_row["id"],
                    "object": "0x12345678",
                    "vtable": mode_row["vtable"],
                    "phase": phase,
                    "entry": mode_row["lifecycle"][phase.lower()],
                    "edge": "ENTER",
                    "thread": 77,
                    "tick": phase_ticks[phase],
                    "depth": 0,
                }
                records.extend([
                    lifecycle,
                    {**lifecycle, "sequence": len(records) + 1, "edge": "LEAVE"},
                ])
            log.write_text(
                "".join(
                    "MVB " + json.dumps(record, sort_keys=True) + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )
            receipt_path = self.host_path(
                options["observer_environment"]["MIEL_OBSERVER_BODY_RECEIPT"],
            )
            receipt_path.write_text(
                json.dumps(body_dispatch_receipt(
                    executable, mode,
                    {phase: phase_ticks[phase] for phase in actual_phases},
                )),
                encoding="utf-8",
            )
            calls.append({
                "mode": mode,
                "root": output.parent,
                "scene": scene,
                "environment": options["observer_environment"],
                "config_payload": config_payload,
            })
            if mutate_after_first is not None and len(calls) == 1:
                mutate_after_first.write_bytes(b"drift")
            if rewrite_runtime_config:
                (executable.parent / "config.ini").write_text(
                    "gtdriver gtDirect3D\nsetupwindow true\nfullscreen true\n",
                    encoding="ascii",
                )
            return {
                "headless_config": headless_config,
                "route": "suspended-process-observer-launcher",
                "scene_bootstrap_confirmed": True,
                "observer_launcher_receipt": {"status": "PASS"},
                "observer_log": {
                    "path": log.name,
                    "sha256": hangover_probe.sha256(log),
                    "hook_loaded": True,
                },
            }

        return calls, side_effect

    def capture(self, side_effect):
        with mock.patch.object(
            native_mode_bodies, "load_contract", return_value=self.contract,
        ), mock.patch.object(
            hangover_probe, "run_scene_navigation", side_effect=side_effect,
        ):
            return native_body_suite.capture_body_suite(
                ["env", "WINEPREFIX=/tmp/prefix"],
                {"id": "box64", "hodll": "wowbox64.dll"},
                self.executable, self.output, self.debugger, self.observer,
                self.launcher,
            )

    def test_runs_exact_22_modes_in_isolated_roots_and_writes_candidate_receipt(self):
        calls, side_effect = self.successful_navigation()
        receipt = self.capture(side_effect)

        self.assertEqual([call["mode"] for call in calls], [
            row["mode"] for row in self.contract["modes"]
        ])
        self.assertEqual(len({call["root"] for call in calls}), 22)
        self.assertTrue(all(call["scene"] == "barn" for call in calls))
        self.assertEqual(receipt["status"], "INCOMPLETE")
        self.assertEqual(receipt["evidence_scope"], "BODY_ONLY")
        self.assertFalse(receipt["natural_transition_evidence"])
        self.assertEqual(receipt["runtime_equivalence"], "UNPROVEN")
        self.assertFalse(receipt["parity_eligible"])
        self.assertEqual(receipt["mode_count"], 22)
        self.assertTrue(all(
            capture["lifecycle_validation"]["observed"].get(capture["mode_id"])
            for capture in receipt["captures"]
        ))
        self.assertEqual(
            [capture["mode_id"] for capture in receipt["captures"]
             if capture["missing_phases"]],
            ["flight"],
        )
        flight = next(
            capture for capture in receipt["captures"]
            if capture["mode_id"] == "flight"
        )
        self.assertEqual(flight["missing_phases"], ["UNLOAD"])
        self.assertEqual(flight["status"], "INCOMPLETE")
        self.assertTrue((self.output / native_body_suite.SUITE_RECEIPT).is_file())
        for call, row in zip(calls, self.contract["modes"]):
            self.assertEqual(call["root"], self.output / row["id"])
            self.assertEqual(
                call["environment"]["MIEL_OBSERVER_BODY_MODE"], row["mode"],
            )

    def test_completed_suite_revalidates_all_artifacts(self):
        _, side_effect = self.successful_navigation()
        receipt = self.capture(side_effect)
        with mock.patch.object(
            native_mode_bodies, "load_contract", return_value=self.contract,
        ):
            loaded = native_body_suite.load_body_suite_receipt(
                self.output / native_body_suite.SUITE_RECEIPT,
                self.executable, self.observer, self.launcher, self.debugger,
            )
        self.assertEqual(loaded, receipt)

    def test_trace_missing_claimed_teardown_fails_closed(self):
        _, side_effect = self.successful_navigation(
            phases=("LOAD", "OPEN", "TICK", "RENDER"),
        )
        with self.assertRaisesRegex(ValueError, "teardown binding failed closed"):
            self.capture(side_effect)
        self.assertFalse((self.output / native_body_suite.SUITE_RECEIPT).exists())

    def test_missing_dispatch_receipt_fails_without_suite_receipt(self):
        def missing(*args, **kwargs):
            output = args[3]
            headless_config = hangover_probe.install_headless_config(
                args[2].parent,
            )
            log = output.parent / "native-observer-mock.log"
            log.write_text("loaded\n", encoding="utf-8")
            return {
                "headless_config": headless_config,
                "route": "suspended-process-observer-launcher",
                "scene_bootstrap_confirmed": True,
                "observer_launcher_receipt": {"status": "PASS"},
                "observer_log": {
                    "path": log.name,
                    "sha256": hangover_probe.sha256(log),
                    "hook_loaded": True,
                },
            }

        with self.assertRaisesRegex(ValueError, "no valid receipt"):
            self.capture(missing)
        self.assertFalse((self.output / native_body_suite.SUITE_RECEIPT).exists())

    def test_dirty_output_and_duplicate_mode_contract_fail_before_launch(self):
        self.output.mkdir()
        (self.output / "stale.json").write_text("{}", encoding="utf-8")
        calls, side_effect = self.successful_navigation()
        with self.assertRaisesRegex(ValueError, "absent or empty"):
            self.capture(side_effect)
        self.assertEqual(calls, [])

        self.output = self.root / "second-suite"
        self.contract["modes"][1]["mode"] = self.contract["modes"][0]["mode"]
        with self.assertRaisesRegex(ValueError, "duplicates"):
            self.capture(side_effect)
        self.assertEqual(calls, [])

    def test_input_hash_drift_aborts_before_second_mode(self):
        calls, side_effect = self.successful_navigation(mutate_after_first=self.observer)
        with self.assertRaisesRegex(ValueError, "hash drifted"):
            self.capture(side_effect)
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.output / native_body_suite.SUITE_RECEIPT).exists())

    def test_polluted_config_is_replaced_before_every_mode_launch(self):
        config = self.executable.parent / "config.ini"
        config.write_text(
            "gtdriver gtDirect3D\nsetupwindow true\nfullscreen true\n",
            encoding="ascii",
        )
        calls, side_effect = self.successful_navigation()
        original = hangover_probe.install_headless_config
        with mock.patch.object(
            hangover_probe, "install_headless_config", wraps=original,
        ) as install:
            receipt = self.capture(side_effect)
        self.assertEqual(install.call_count, 22)
        self.assertEqual(len(calls), 22)
        self.assertTrue(all(
            b"setupwindow false" in call["config_payload"] for call in calls
        ))
        self.assertEqual(config.read_bytes(), hangover_probe.HEADLESS_CONFIG.read_bytes())
        self.assertTrue(all(
            capture["headless_config"] == native_body_suite.HEADLESS_POLICY
            for capture in receipt["captures"]
        ))

    def test_native_runtime_rewrite_is_allowed_and_next_launch_reinstalls(self):
        calls, side_effect = self.successful_navigation(
            rewrite_runtime_config=True,
        )
        receipt = self.capture(side_effect)
        self.assertEqual(len(calls), 22)
        self.assertEqual(receipt["mode_count"], 22)
        self.assertTrue((self.output / native_body_suite.SUITE_RECEIPT).is_file())
        self.assertIn(
            "setupwindow true",
            (self.executable.parent / "config.ini").read_text(encoding="ascii"),
        )

    def test_artifact_hash_and_claim_promotion_edits_fail_closed(self):
        _, side_effect = self.successful_navigation()
        receipt = self.capture(side_effect)
        first_log = self.output / receipt["captures"][0]["observer_log"]["path"]
        first_log.write_text("tampered\n", encoding="utf-8")
        with mock.patch.object(
            native_mode_bodies, "load_contract", return_value=self.contract,
        ), self.assertRaisesRegex(ValueError, "artifact hash drifted"):
            native_body_suite.validate_body_suite_receipt(
                receipt, self.output, self.executable, self.observer,
                self.launcher, self.debugger,
            )

        receipt["captures"][0]["observer_log"]["sha256"] = hangover_probe.sha256(first_log)
        receipt["natural_transition_evidence"] = True
        with mock.patch.object(
            native_mode_bodies, "load_contract", return_value=self.contract,
        ), self.assertRaisesRegex(ValueError, "policy or input identity"):
            native_body_suite.validate_body_suite_receipt(
                receipt, self.output, self.executable, self.observer,
                self.launcher, self.debugger,
            )

    def test_duplicate_artifact_reference_fails_closed(self):
        _, side_effect = self.successful_navigation()
        receipt = self.capture(side_effect)
        receipt["captures"][1]["observer_log"] = copy.deepcopy(
            receipt["captures"][0]["observer_log"],
        )
        with mock.patch.object(
            native_mode_bodies, "load_contract", return_value=self.contract,
        ), self.assertRaisesRegex(ValueError, "artifact identity failed"):
            native_body_suite.validate_body_suite_receipt(
                receipt, self.output, self.executable, self.observer,
                self.launcher, self.debugger,
            )

    def test_environment_requires_unique_nonempty_pairs(self):
        self.assertEqual(
            native_body_suite._environment(["WINEPREFIX=/tmp/prefix"]),
            ["env", "WINEPREFIX=/tmp/prefix"],
        )
        for values in (["WINEPREFIX="], ["broken"], ["A=1", "A=2"]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                native_body_suite._environment(values)


if __name__ == "__main__":
    unittest.main()
