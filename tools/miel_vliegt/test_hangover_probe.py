#!/usr/bin/env python3
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.miel_vliegt.hangover_probe import (
    BODY_MODES,
    CONTRACT,
    DEBUG_PROFILES,
    HEADLESS_CONFIG_SHA256,
    NATIVE_XVFB_ARGUMENTS,
    OBSERVER_BOOTSTRAP_STRATEGY,
    OBSERVER_INPUT_IDLE_PROBE_TIMEOUT_MS,
    OBSERVER_HOST_DEADLINE_GRACE_SECONDS,
    OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS,
    SMOKE_SENTINEL,
    bootstrap_prefix,
    bind_native_proxy_dll_override,
    configure_gdi_renderer,
    FEX_CAPTURE_DLL_OVERRIDE,
    FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE,
    FEX_RPCSS_READINESS_TIMEOUT_MS,
    FEX_RUNTIME_READINESS_TIMEOUT_SECONDS,
    install_headless_config,
    native_wine_command,
    native_runtime_environment,
    native_persistent_wineserver_command,
    native_wineserver_command,
    observer_environment_arguments,
    observer_launcher_host_deadline,
    probe,
    probe_debug_capability,
    read_debug_capability_receipt,
    run,
    run_scene_navigation,
    run_native_semantic_scenario,
    run_native_semantic_suite,
    shutdown_private_wineserver,
    validate_contract,
    validate_body_only_receipt,
    validate_i386_pe,
    validate_observer_launcher_receipt,
    validate_observe_ms,
    validate_start_patch_receipt,
    validate_unmodified_start_receipt,
    verify_runtime_readiness,
    PERSISTENT_WINESERVER_ACK_SENTINEL,
    validate_capture_backend,
    validate_calibration_observation_profile,
    validate_scenario_observation_profile_receipt,
)


class HangoverProbeTests(unittest.TestCase):
    def setUp(self):
        # install_observer_proxy copies the built DINPUT proxy (only present in
        # the container image at /opt/hangover/DINPUT.dll) into the game dir.
        # Point it at a temp stand-in so the orchestration tests can exercise
        # the real staging without the image being present.
        self._proxy_dir = tempfile.TemporaryDirectory()
        proxy = Path(self._proxy_dir.name) / "DINPUT.dll"
        proxy.write_bytes(b"proxy")
        replay = Path(self._proxy_dir.name) / "observer-replay.mvo"
        replay.write_bytes(b"replay")
        for attr, value in (
            ("OBSERVER_PROXY_DLL", proxy),
            ("OBSERVER_REPLAY", replay),
        ):
            patcher = patch(f"tools.miel_vliegt.hangover_probe.{attr}", value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self._proxy_dir.cleanup)

    @staticmethod
    def completed_run(output="", exit_code=0):
        return {
            "command": ["fake"],
            "exit_code": exit_code,
            "timed_out": False,
            "output_sha256": "0" * 64,
            "output_tail": output.splitlines(),
        }

    @staticmethod
    def create_complete_prefix(prefix):
        (prefix / "drive_c/windows/system32").mkdir(parents=True)
        (prefix / "drive_c/windows/syswow64").mkdir(parents=True)
        (prefix / "dosdevices").mkdir()
        (prefix / "dosdevices/c:").symlink_to("../drive_c")
        (prefix / "dosdevices/z:").symlink_to("/")
        for relative in (
            "system.reg",
            "user.reg",
            "userdef.reg",
        ):
            (prefix / relative).touch()
        image = bytearray(70)
        image[:2] = b"MZ"
        image[0x3C:0x40] = (64).to_bytes(4, "little")
        image[64:68] = b"PE\0\0"
        image[68:70] = (0x014C).to_bytes(2, "little")
        (prefix / "drive_c/windows/system32/rundll32.exe").write_bytes(image)

    @staticmethod
    def debug_capability_receipt(capability, trap_strategy="int3"):
        supported = capability == "SUPPORTED"
        return {
            "schema": 1,
            "protocol": "miel-hangover-win32-debug-capability",
            "status": "PASS" if supported else "FAIL",
            "phase": "debug-api-capability",
            "debug_api_capability": capability,
            "controller_machine": "i386",
            "child_machine": "i386",
            "trap_strategy": trap_strategy,
            "checks": {
                "create_process_event_seen": supported,
                "ready_debug_string_seen": supported,
                "deliberate_trap_arm_ok": supported,
                "deliberate_breakpoint_seen": supported,
                "deliberate_second_breakpoint_seen": supported,
                "deliberate_trap_restore_ok": supported,
                "deliberate_second_trap_restore_ok": supported,
                "restored_execution_semantics_ok": supported,
                "deliberate_trap_location_matches": supported,
                "startup_breakpoint_context_ok": supported,
                "get_thread_context_ok": supported,
                "set_thread_context_ok": supported,
                "context_mutation_roundtrip_ok": supported,
                "trap_resume_context_ok": supported,
                "remote_memory_roundtrip_ok": supported,
                "code_memory_roundtrip_ok": supported,
                "continue_attempted": supported,
                "continue_debug_event_ok": supported,
                "exit_process_seen": supported,
            },
            "deliberate_breakpoint_hits": 2 if supported else 0,
            "deliberate_trap_address": 0x401000 if supported else 0,
            "deliberate_second_trap_address": 0x401010 if supported else 0,
        }

    def test_capture_host_is_pinned_but_never_counts_as_parity_evidence(self):
        contract = validate_contract()
        self.assertEqual(contract["source"]["release"], "hangover-11.9")
        self.assertEqual([item["id"] for item in contract["probe_backends"]], ["box64", "fex"])
        self.assertFalse(contract["parity_policy"]["probe_success_is_native_evidence"])
        self.assertFalse(contract["parity_policy"]["production_capture_enabled"])
        self.assertEqual(
            contract["observer_strategy"]["selected"],
            "dinput-post-loader-worker-or-call-bootstrap",
        )
        self.assertFalse(any("winedbg" in item for item in contract["acceptance"]))
        self.assertIn("never a selected-route precondition", contract["acceptance"][-1])
        self.assertEqual(OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS, 600000)

    def test_host_deadline_covers_proxy_then_scenario_budgets(self):
        self.assertEqual(
            observer_launcher_host_deadline(900_000),
            1_530,
        )
        self.assertEqual(
            observer_launcher_host_deadline(1_000),
            631,
        )
        with self.assertRaisesRegex(ValueError, "exceeds"):
            observer_launcher_host_deadline(1_000, 632)

    def test_backend_commands_are_fixed_by_the_checked_backend_identity(self):
        box64 = {"id": "box64", "hodll": "wowbox64.dll"}
        fex = {"id": "fex", "hodll": "libwow64fex.dll"}
        self.assertEqual(validate_capture_backend(box64), box64)
        self.assertEqual(validate_capture_backend(fex), fex)
        self.assertEqual(
            native_wine_command("cmd", "/c", "exit", backend=box64),
            [*NATIVE_XVFB_ARGUMENTS, "wine", "cmd", "/c", "exit"],
        )
        self.assertEqual(
            native_wine_command("cmd", "/c", "exit", backend=fex),
            [*NATIVE_XVFB_ARGUMENTS, "/opt/miel/fex-wine", "cmd", "/c", "exit"],
        )
        self.assertEqual(native_wineserver_command(box64, "-k"), ["wineserver", "-k"])
        self.assertEqual(native_wineserver_command(fex, "-w"), [
            "FEX", "/opt/fex/rootfs/usr/lib/wine/wineserver64", "-w",
        ])
        for invalid in (
            {"id": "fex", "hodll": "wowbox64.dll"},
            {"id": "box64", "hodll": "libwow64fex.dll"},
            {"id": "fex", "hodll": "libwow64fex.dll", "wine": "evil"},
        ):
            with self.assertRaisesRegex(ValueError, "backend"):
                validate_capture_backend(invalid)

    def test_scenario_observer_environment_is_allowlisted_and_single_line(self):
        self.assertEqual(observer_environment_arguments({
            "MIEL_OBSERVER_SCENARIO_SHA256": "a" * 64,
            "MIEL_OBSERVER_SCENARIO": r"Z:\capture\scenario.mvo",
        }), [
            r"MIEL_OBSERVER_SCENARIO=Z:\capture\scenario.mvo",
            "MIEL_OBSERVER_SCENARIO_SHA256=" + "a" * 64,
        ])
        self.assertEqual(observer_environment_arguments({
            "MIEL_OBSERVER_OBSERVATION_PROFILE": "scenario-bounded",
            "MIEL_OBSERVER_OBSERVATION_OMIT_MASK": "0x1fff",
        }), [
            "MIEL_OBSERVER_OBSERVATION_OMIT_MASK=0x1fff",
            "MIEL_OBSERVER_OBSERVATION_PROFILE=scenario-bounded",
        ])
        self.assertEqual(observer_environment_arguments({
            "MIEL_OBSERVER_SCENE_DISPATCH": "1",
            "MIEL_OBSERVER_OBSERVATION_PROFILE": "semantic-only",
            "MIEL_OBSERVER_OBSERVATION_OMIT_MASK": "0x1fff",
            "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE": "1",
        }), [
            "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE=1",
            "MIEL_OBSERVER_OBSERVATION_OMIT_MASK=0x1fff",
            "MIEL_OBSERVER_OBSERVATION_PROFILE=semantic-only",
            "MIEL_OBSERVER_SCENE_DISPATCH=1",
        ])
        self.assertEqual(observer_environment_arguments({
            "MIEL_OBSERVER_CALIBRATE_INITIAL_STATE": "1",
        }), ["MIEL_OBSERVER_CALIBRATE_INITIAL_STATE=1"])
        self.assertEqual(observer_environment_arguments({
            "MIEL_OBSERVER_CALIBRATE_INITIAL_STATE": "1",
            "MIEL_OBSERVER_OBSERVATION_PROFILE": "calibration-only",
        }), [
            "MIEL_OBSERVER_CALIBRATE_INITIAL_STATE=1",
            "MIEL_OBSERVER_OBSERVATION_PROFILE=calibration-only",
        ])
        self.assertEqual(observer_environment_arguments({
            "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS": "1",
            "MIEL_OBSERVER_DIAGNOSTIC_PROFILE": "session-only",
        }), [
            "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS=1",
            "MIEL_OBSERVER_DIAGNOSTIC_PROFILE=session-only",
        ])
        self.assertEqual(observer_environment_arguments({
            "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS": "1",
            "MIEL_OBSERVER_DIAGNOSTIC_PROFILE": "barn-session",
        }), [
            "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS=1",
            "MIEL_OBSERVER_DIAGNOSTIC_PROFILE=barn-session",
        ])
        for invalid in (
            {"MIEL_OBSERVER_OBSERVATION_PROFILE": "full"},
            {"MIEL_OBSERVER_OBSERVATION_PROFILE": "calibration-only"},
            {"MIEL_OBSERVER_OBSERVATION_PROFILE": "scenario-bounded"},
            {
                "MIEL_OBSERVER_SCENE_DISPATCH": "1",
                "MIEL_OBSERVER_OBSERVATION_PROFILE": "scenario-bounded",
                "MIEL_OBSERVER_OBSERVATION_OMIT_MASK": "0x1fff",
            },
            {
                "MIEL_OBSERVER_SCENE_DISPATCH": "1",
                "MIEL_OBSERVER_OBSERVATION_PROFILE": "semantic-only",
                "MIEL_OBSERVER_OBSERVATION_OMIT_MASK": "0x0fff",
                "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE": "1",
            },
            {"MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE": "0"},
            {"MIEL_OBSERVER_CALIBRATE_INITIAL_STATE": "0"},
            {"MIEL_OBSERVER_DIAGNOSTIC_PROFILE": "session-only"},
            {
                "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS": "1",
                "MIEL_OBSERVER_DIAGNOSTIC_PROFILE": "full",
            },
        ):
            with self.assertRaises(ValueError):
                observer_environment_arguments(invalid)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            observer_environment_arguments({"MIEL_OBSERVER_LOG": "override"})
        with self.assertRaisesRegex(ValueError, "single-line"):
            observer_environment_arguments({"MIEL_OBSERVER_FRAME": "bad\npath"})
        body_environment = observer_environment_arguments({
            "MIEL_OBSERVER_BODY_MODE": "mode_fly",
            "MIEL_OBSERVER_BODY_RECEIPT": r"Z:\capture\body.json",
        })
        self.assertEqual(body_environment, [
            "MIEL_OBSERVER_BODY_MODE=mode_fly",
            r"MIEL_OBSERVER_BODY_RECEIPT=Z:\capture\body.json",
        ])
        self.assertEqual(len(BODY_MODES), 22)
        self.assertEqual(len(set(BODY_MODES)), 22)
        with self.assertRaisesRegex(ValueError, "22-mode allowlist"):
            observer_environment_arguments({
                "MIEL_OBSERVER_BODY_MODE": "mode_unknown",
                "MIEL_OBSERVER_BODY_RECEIPT": r"Z:\capture\body.json",
            })
        with self.assertRaisesRegex(ValueError, "configured together"):
            observer_environment_arguments({"MIEL_OBSERVER_BODY_MODE": "mode_fly"})

    def test_body_only_receipt_is_hash_bound_and_cannot_claim_natural_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned-native")
            receipt_path = root / "body.json"
            receipt = {
                "schema": 1,
                "protocol": "miel-vliegt-native-body-dispatch",
                "status": "PASS",
                "evidence_scope": "BODY_ONLY",
                "natural_transition_evidence": False,
                "debug_skip_used": False,
                "executable_sha256": hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
                "requested_mode": "mode_fly",
                "command": {
                    "name": "engine_mode", "id": 15,
                    "dispatch": "registered-command-callback",
                },
                "callback_count": 1,
                "manager_thread": True,
                "pre": {
                    "manager_canonical": True,
                    "current_mode": "mode_barn",
                    "pending_null": True,
                    "target_resolved_before_mutation": True,
                    "registry_record_resolved": True,
                },
                "post": {
                    "current_unchanged": True,
                    "current_is_target": False,
                    "pending_is_target": True,
                    "pending_null": False,
                },
                "activation": {
                    "target_is_current": True,
                    "pending_null": True,
                    "loaded": True,
                    "opened": True,
                },
            }
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            self.assertEqual(
                validate_body_only_receipt(receipt_path, executable, "mode_fly"),
                receipt,
            )
            receipt["natural_transition_evidence"] = True
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "failed closed"):
                validate_body_only_receipt(receipt_path, executable, "mode_fly")

    def test_native_proxy_override_is_fixed_and_conflicts_fail_closed(self):
        self.assertEqual(
            bind_native_proxy_dll_override(["env", "HODLL=libwow64fex.dll"]),
            [
                "env", "HODLL=libwow64fex.dll",
                "WINEDLLOVERRIDES=dinput=n,b",
            ],
        )
        self.assertEqual(
            bind_native_proxy_dll_override([
                "env", "WINEDLLOVERRIDES=dinput=n,b",
            ]),
            ["env", "WINEDLLOVERRIDES=dinput=n,b"],
        )
        self.assertEqual(
            bind_native_proxy_dll_override([
                "env",
                f"WINEDLLOVERRIDES={FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE}",
            ]),
            ["env", f"WINEDLLOVERRIDES={FEX_CAPTURE_DLL_OVERRIDE}"],
        )
        with self.assertRaisesRegex(ValueError, "native DINPUT override"):
            bind_native_proxy_dll_override([
                "env", "WINEDLLOVERRIDES=dinput=b",
            ])

    def test_fex_runtime_environment_disables_optional_installers(self):
        self.assertEqual(
            native_runtime_environment(
                Path("/prefix"),
                {"id": "fex", "hodll": "libwow64fex.dll"},
            ),
            [
                "env", "WINEPREFIX=/prefix", "HODLL=libwow64fex.dll",
                "WINEARCH=win32", "WINEDEBUG=-all",
                f"WINEDLLOVERRIDES={FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE}",
            ],
        )
        self.assertEqual(
            native_runtime_environment(
                Path("/prefix"),
                {"id": "box64", "hodll": "wowbox64.dll"},
            ),
            ["env", "WINEPREFIX=/prefix", "HODLL=wowbox64.dll"],
        )
        expected_script = (
            '"$@" >/dev/null 2>&1 || exit $?; '
            "printf \"%s\\n\" MIEL_WINESERVER_PERSISTENCE_ACKNOWLEDGED"
        )
        self.assertEqual(
            native_persistent_wineserver_command(
                {"id": "fex", "hodll": "libwow64fex.dll"},
            ),
            [
                "sh", "-c", expected_script,
                "miel-persistent-wineserver",
                "FEX", "/opt/fex/rootfs/usr/lib/wine/wineserver64", "-p0",
            ],
        )
        self.assertEqual(
            native_persistent_wineserver_command(
                {"id": "box64", "hodll": "wowbox64.dll"},
            ),
            [
                "sh", "-c", expected_script,
                "miel-persistent-wineserver", "wineserver", "-p0",
            ],
        )

    def test_fex_runtime_readiness_requires_service_registry_and_activation(self):
        output = "\n".join((
            "MIEL_RPCSS_STATE=RUNNING",
            "MIEL_WINE_RENDERER=GDI",
            "MIEL_WINE_DECORATED=N",
            "MIEL_COM_REGISTRY clsid={47D4D946-62E8-11CF-93BC-444553540000}",
            "MIEL_COM_REGISTRY clsid={BCDE0395-E52F-467C-8E3D-C4579291692E}",
            "MIEL_COM_ACTIVATION clsid={47D4D946-62E8-11CF-93BC-444553540000} "
            "hresult=0x00000000",
            "MIEL_COM_ACTIVATION clsid={BCDE0395-E52F-467C-8E3D-C4579291692E} "
            "hresult=0x00000000",
            "MIEL_FEX_WINE_READINESS_OK",
        ))
        with patch(
            "tools.miel_vliegt.hangover_probe.run",
            return_value=self.completed_run(output),
        ) as runner:
            receipt = verify_runtime_readiness(
                ["env", "WINEPREFIX=/prefix"],
                Path("/game"),
                {"id": "fex", "hodll": "libwow64fex.dll"},
            )
        self.assertTrue(receipt["required"])
        self.assertTrue(receipt["verified"])
        self.assertIn(
            r"Z:\opt\miel\wine-readiness-canary.exe",
            runner.call_args.args[0],
        )
        self.assertIn("--rpcss-timeout-ms", runner.call_args.args[0])
        self.assertEqual(
            runner.call_args.args[0][-1],
            str(FEX_RPCSS_READINESS_TIMEOUT_MS),
        )
        self.assertEqual(
            runner.call_args.kwargs["timeout"],
            FEX_RUNTIME_READINESS_TIMEOUT_SECONDS,
        )
        self.assertEqual(receipt["budget"], {
            "guest_process_seconds": FEX_RUNTIME_READINESS_TIMEOUT_SECONDS,
            "rpcss_poll_milliseconds": FEX_RPCSS_READINESS_TIMEOUT_MS,
        })

        with patch(
            "tools.miel_vliegt.hangover_probe.run",
            return_value=self.completed_run(output),
        ) as custom_runner:
            custom = verify_runtime_readiness(
                ["env", "WINEPREFIX=/prefix"],
                Path("/game"),
                {"id": "fex", "hodll": "libwow64fex.dll"},
                runtime_timeout=120,
                rpcss_timeout_ms=45_000,
            )
        self.assertTrue(custom["verified"])
        self.assertEqual(custom_runner.call_args.kwargs["timeout"], 120)
        self.assertEqual(custom_runner.call_args.args[0][-1], "45000")

        with patch(
            "tools.miel_vliegt.hangover_probe.run",
            return_value=self.completed_run("MIEL_FEX_WINE_READINESS_OK"),
        ):
            receipt = verify_runtime_readiness(
                ["env", "WINEPREFIX=/prefix"],
                Path("/game"),
                {"id": "fex", "hodll": "libwow64fex.dll"},
            )
        self.assertFalse(receipt["verified"])

        with self.assertRaisesRegex(ValueError, "30..300"):
            verify_runtime_readiness(
                ["env", "WINEPREFIX=/prefix"],
                Path("/game"),
                {"id": "fex", "hodll": "libwow64fex.dll"},
                runtime_timeout=29,
            )
        with self.assertRaisesRegex(ValueError, "1000..120000"):
            verify_runtime_readiness(
                ["env", "WINEPREFIX=/prefix"],
                Path("/game"),
                {"id": "fex", "hodll": "libwow64fex.dll"},
                rpcss_timeout_ms=999,
            )

    def test_persistence_control_accepts_an_immediately_returning_server_command(self):
        command = native_persistent_wineserver_command(
            {"id": "box64", "hodll": "wowbox64.dll"},
        )
        success = subprocess.run(
            [*command[:4], "sh", "-c", "exit 0"],
            text=True,
            capture_output=True,
            check=False,
        )
        failure = subprocess.run(
            [*command[:4], "sh", "-c", "exit 7"],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(
            success.stdout.strip(),
            PERSISTENT_WINESERVER_ACK_SENTINEL,
        )
        self.assertEqual(failure.returncode, 7)
        self.assertNotIn(PERSISTENT_WINESERVER_ACK_SENTINEL, failure.stdout)

    def test_private_wineserver_shutdown_requires_stop_then_wait(self):
        calls = []

        def runner(command, **_kwargs):
            calls.append(command)
            return self.completed_run()

        receipt = shutdown_private_wineserver(
            ["env", "WINEPREFIX=/prefix"],
            Path("/game"),
            {"id": "fex", "hodll": "libwow64fex.dll"},
            runner=runner,
        )
        self.assertTrue(receipt["complete"])
        self.assertEqual(calls[0][-1], "-k")
        self.assertEqual(calls[1][-1], "-w")

        calls.clear()

        def failed_stop(command, **_kwargs):
            calls.append(command)
            return self.completed_run("stop diagnostic", exit_code=1)

        receipt = shutdown_private_wineserver(
            ["env", "WINEPREFIX=/prefix"],
            Path("/game"),
            {"id": "box64", "hodll": "wowbox64.dll"},
            runner=failed_stop,
        )
        self.assertFalse(receipt["complete"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(receipt["runs"]["wait"]["skipped"], "wineserver-stop-failed")

        duplicated_wrong_classes = "\n".join((
            "MIEL_RPCSS_STATE=RUNNING",
            "MIEL_WINE_RENDERER=GDI",
            "MIEL_WINE_DECORATED=N",
            "MIEL_COM_REGISTRY clsid={47D4D946-62E8-11CF-93BC-444553540000}",
            "MIEL_COM_REGISTRY clsid={47D4D946-62E8-11CF-93BC-444553540000}",
            "MIEL_COM_ACTIVATION clsid={47D4D946-62E8-11CF-93BC-444553540000} "
            "hresult=0x00000000",
            "MIEL_COM_ACTIVATION clsid={47D4D946-62E8-11CF-93BC-444553540000} "
            "hresult=0x00000000",
            "MIEL_FEX_WINE_READINESS_OK",
        ))
        with patch(
            "tools.miel_vliegt.hangover_probe.run",
            return_value=self.completed_run(duplicated_wrong_classes),
        ):
            receipt = verify_runtime_readiness(
                ["env", "WINEPREFIX=/prefix"],
                Path("/game"),
                {"id": "fex", "hodll": "libwow64fex.dll"},
            )
        self.assertFalse(receipt["verified"])

    def test_body_only_receipt_rejects_callback_or_activation_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned-native")
            receipt_path = root / "body.json"
            base = {
                "schema": 1,
                "protocol": "miel-vliegt-native-body-dispatch",
                "status": "PASS",
                "evidence_scope": "BODY_ONLY",
                "natural_transition_evidence": False,
                "debug_skip_used": False,
                "executable_sha256": hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
                "requested_mode": "mode_barn",
                "command": {
                    "name": "engine_mode", "id": 15,
                    "dispatch": "registered-command-callback",
                },
                "callback_count": 2,
                "manager_thread": True,
                "pre": {
                    "manager_canonical": True,
                    "current_mode": "mode_barn", "pending_null": True,
                    "target_resolved_before_mutation": True,
                    "registry_record_resolved": True,
                },
                "post": {
                    "current_unchanged": True, "current_is_target": True,
                    "pending_is_target": False, "pending_null": True,
                },
                "activation": {
                    "target_is_current": True, "pending_null": True,
                    "loaded": True, "opened": True,
                },
            }
            receipt_path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "failed closed"):
                validate_body_only_receipt(receipt_path, executable, "mode_barn")

    def test_native_scenario_runner_passes_reviewed_initial_values_to_observer(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["files"][0]["role"] = "user-profile"
            artifacts.materialize_scenario_suite(suite, initial_state)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"native")
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            proxy = root / "reviewed-DINPUT.dll"
            proxy.write_bytes(b"proxy")
            with patch(
                "tools.miel_vliegt.hangover_probe.run_scene_navigation",
                return_value={},
            ) as launch:
                with self.assertRaisesRegex(ValueError, "did not bootstrap cleanly"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"}, executable,
                        root / "out" / "capture.json", suite / "suite-spec.json",
                        "controls-press-hold-release", root,
                        {"user-profile": "Data/User/user0.dat"}, observer,
                        root / "game-proxy/MulleMeck.exe",
                        proxy_dll=proxy,
                    )
            launch.assert_called_once()
            self.assertEqual(launch.call_args.kwargs["proxy_dll"], proxy)
            observer_environment = launch.call_args.kwargs["observer_environment"]
            self.assertNotIn(
                "MIEL_OBSERVER_CALIBRATE_INITIAL_STATE", observer_environment,
            )

    def test_native_scenario_runner_can_request_low_cost_semantic_observation(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["files"][0]["role"] = "user-profile"
            artifacts.materialize_scenario_suite(suite, initial_state)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"native")
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            with patch(
                "tools.miel_vliegt.hangover_probe.run_scene_navigation",
                return_value={},
            ) as launch:
                with self.assertRaisesRegex(ValueError, "did not bootstrap cleanly"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                        executable, root / "out/capture.json",
                        suite / "suite-spec.json", "taxi-straight", root,
                        {"user-profile": "Data/User/user0.dat"}, observer,
                        root / "game-proxy/MulleMeck.exe",
                        observation_profile="semantic-only",
                    )
            observer_environment = launch.call_args.kwargs["observer_environment"]
            self.assertEqual(
                observer_environment["MIEL_OBSERVER_OBSERVATION_PROFILE"],
                "semantic-only",
            )
            self.assertEqual(
                observer_environment["MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE"], "1",
            )
            self.assertEqual(observer_environment["MIEL_OBSERVER_SCENE_DISPATCH"], "1")

    def test_native_scenario_runner_uses_production_bounded_profile_without_divergence(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["files"][0]["role"] = "user-profile"
            artifacts.materialize_scenario_suite(suite, initial_state)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"native")
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            profile = artifacts.scenario_observation_profile("taxi-straight")
            with patch(
                "tools.miel_vliegt.hangover_probe.run_scene_navigation",
                return_value={},
            ) as launch:
                with self.assertRaisesRegex(ValueError, "did not bootstrap cleanly"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                        executable, root / "out/capture.json",
                        suite / "suite-spec.json", "taxi-straight", root,
                        {"user-profile": "Data/User/user0.dat"}, observer,
                        root / "game-proxy/MulleMeck.exe",
                        observation_profile=profile,
                    )
            observer_environment = launch.call_args.kwargs["observer_environment"]
            self.assertEqual(
                observer_environment["MIEL_OBSERVER_OBSERVATION_PROFILE"],
                "scenario-bounded",
            )
            self.assertEqual(
                observer_environment["MIEL_OBSERVER_OBSERVATION_OMIT_MASK"],
                "0x1fff",
            )
            self.assertNotIn(
                "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE", observer_environment,
            )
            self.assertNotIn("MIEL_OBSERVER_SCENE_DISPATCH", observer_environment)

    def test_native_scenario_runner_can_request_calibration_only_observation(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["files"][0]["role"] = "user-profile"
            initial_state["values"] = []
            artifacts.materialize_scenario_suite(suite, initial_state)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"native")
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            with patch(
                "tools.miel_vliegt.hangover_probe.run_scene_navigation",
                return_value={},
            ) as launch:
                with self.assertRaisesRegex(ValueError, "did not bootstrap cleanly"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                        executable, root / "out/capture.json",
                        suite / "suite-spec.json", "taxi-straight", root,
                        {"user-profile": "Data/User/user0.dat"}, observer,
                        root / "game-proxy/MulleMeck.exe",
                        observation_profile="calibration-only",
                    )
            observer_environment = launch.call_args.kwargs["observer_environment"]
            self.assertEqual(observer_environment[
                "MIEL_OBSERVER_OBSERVATION_PROFILE"
            ], "calibration-only")
            self.assertEqual(
                observer_environment["MIEL_OBSERVER_CALIBRATE_INITIAL_STATE"], "1",
            )
            self.assertNotIn(
                "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE", observer_environment,
            )
            self.assertNotIn("MIEL_OBSERVER_SCENE_DISPATCH", observer_environment)

    def test_calibration_observation_profile_receipt_is_exact_and_fail_closed(self):
        from tools.miel_vliegt import native_observation_profile_contract

        retained = [
            "session", "input-proof", "clock.tick", "flight.tick", "rng",
            "runtime-initial-state", "flight-activation-rng",
            "flight-activation-clock", "render.framebuffer",
        ]
        omitted = [
            "controls-values", "physics", "collision", "camera-values",
            "render-values", "fuel", "contact", "damage", "terrain", "udsp",
            "position-character", "particle-lifecycle",
            "presentation-render", "shadow-render",
        ]
        receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-native-observation-profile",
            "sequence": 0,
            "profile": "calibration-only",
            "profile_id": "",
            "profile_sha256": "",
            "contract_sha256":
                native_observation_profile_contract.contract_value()[
                    "contract_sha256"
                ],
            "omit_mask": "0x1fff",
            "target_hook_mask": "0x00000000",
            "omitted_channels": omitted,
            "retained_channels": retained,
            "applicable_receipt_channels": [],
            "omitted_receipt_channels": [],
            "framebuffer_required": False,
            "evidence_eligible": False,
            "evidence_blocker": "calibration_only",
            "signature_preflight_complete": True,
            "profile_state_writes": False,
            "thread_id": 7,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observer.log"
            path.write_text("MVD " + json.dumps(receipt) + "\n", encoding="utf-8")
            self.assertEqual(
                validate_calibration_observation_profile(path)["profile"],
                "calibration-only",
            )
            receipt["evidence_eligible"] = True
            path.write_text("MVD " + json.dumps(receipt) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contract drifted"):
                validate_calibration_observation_profile(path)

    def test_scenario_observation_profile_receipt_binds_mask_and_channels(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt import native_observation_profile_contract

        profile = artifacts.scenario_observation_profile("taxi-straight")
        receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-native-observation-profile",
            "sequence": 0,
            "profile": "scenario-bounded",
            "profile_id": profile["id"],
            "profile_sha256": profile["profile_sha256"],
            "contract_sha256":
                native_observation_profile_contract.contract_value()[
                    "contract_sha256"
                ],
            "omit_mask": "0x1fff",
            "target_hook_mask": "0x00000000",
            "omitted_channels": [
                "particle-lifecycle", "presentation-render", "shadow-render",
            ],
            "retained_channels": [],
            "applicable_receipt_channels":
                profile["applicable_receipt_channels"],
            "omitted_receipt_channels":
                profile["omitted_receipt_channels"],
            "framebuffer_required": False,
            "evidence_eligible": True,
            "evidence_blocker": None,
            "signature_preflight_complete": True,
            "profile_state_writes": False,
            "thread_id": 7,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "observer.log"
            path.write_text("MVD " + json.dumps(receipt) + "\n", encoding="utf-8")
            self.assertEqual(
                validate_scenario_observation_profile_receipt(
                    path, profile,
                )["omit_mask"],
                "0x1fff",
            )
            receipt["omitted_channels"] = [
                "particle-lifecycle", "presentation-render",
            ]
            path.write_text("MVD " + json.dumps(receipt) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contract drifted"):
                validate_scenario_observation_profile_receipt(path, profile)

    def test_native_scenario_runner_can_request_session_only_diagnostics(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["files"][0]["role"] = "user-profile"
            artifacts.materialize_scenario_suite(suite, initial_state)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"native")
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            with patch(
                "tools.miel_vliegt.hangover_probe.run_scene_navigation",
                return_value={},
            ) as launch:
                with self.assertRaisesRegex(ValueError, "did not bootstrap cleanly"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                        executable, root / "out/capture.json",
                        suite / "suite-spec.json", "taxi-straight", root,
                        {"user-profile": "Data/User/user0.dat"}, observer,
                        root / "game-proxy/MulleMeck.exe",
                        diagnostic_profile="session-only",
                    )
            self.assertEqual(launch.call_args.kwargs["observer_environment"], {
                **launch.call_args.kwargs["observer_environment"],
                "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS": "1",
                "MIEL_OBSERVER_DIAGNOSTIC_PROFILE": "session-only",
            })

    def test_native_scenario_runner_can_request_barn_session_diagnostics(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["files"][0]["role"] = "user-profile"
            artifacts.materialize_scenario_suite(suite, initial_state)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"native")
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            with patch(
                "tools.miel_vliegt.hangover_probe.run_scene_navigation",
                return_value={},
            ) as launch:
                with self.assertRaisesRegex(ValueError, "did not bootstrap cleanly"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                        executable, root / "out/capture.json",
                        suite / "suite-spec.json", "taxi-straight", root,
                        {"user-profile": "Data/User/user0.dat"}, observer,
                        root / "game-proxy/MulleMeck.exe",
                        diagnostic_profile="barn-session",
                    )
            self.assertEqual(
                launch.call_args.kwargs["observer_environment"][
                    "MIEL_OBSERVER_DIAGNOSTIC_PROFILE"
                ],
                "barn-session",
            )

    def test_barn_session_profile_drives_login_without_manager_tick_hook(self):
        hook = (
            Path(__file__).resolve().parents[2]
            / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        configure = hook[
            hook.index("static BOOL configure_diagnostic_profile"):
            hook.index("static BOOL observation_omit_mask_is_coherent")
        ]
        self.assertIn('strcmp(profile, "barn-session")', configure)
        self.assertIn("diagnostic_direct_login_tick = TRUE", configure)
        self.assertIn("diagnostic_skip_manager_tick = TRUE", configure)
        manager_install = hook[
            hook.index("static BOOL install_manager_tick_interposition(void)\n{"):
            hook.index("static BOOL install_manager_render_interposition(void)\n{")
        ]
        self.assertIn("diagnostic_skip_manager_tick", manager_install)
        login_hook = hook[
            hook.index("static void __attribute__((naked)) login_tick_hook"):
            hook.index("static void __attribute__((naked)) mode_set_hook")
        ]
        self.assertIn("call _record_login_tick", login_hook)
        self.assertIn("jmp *_login_tick_trampoline", login_hook)
        self.assertIn("diagnostic_direct_login_tick &&", hook)
        self.assertEqual(
            hook.count("install_detour(LOGIN_TICK, LOGIN_TICK_SIGNATURE"), 1,
        )
        self.assertEqual(
            hook.count("rollback_detour(LOGIN_TICK, LOGIN_TICK_SIGNATURE"), 1,
        )

    def test_native_scenario_runner_requires_the_exact_user_fixture_target(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["values"] = []
            artifacts.materialize_scenario_suite(suite, initial_state)
            with patch("tools.miel_vliegt.hangover_probe.run_scene_navigation") as launch:
                with self.assertRaisesRegex(ValueError, "user-profile as its only"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"}, root / "MulleMeck.exe",
                        root / "out" / "capture.json", suite / "suite-spec.json",
                        "controls-press-hold-release", root / "state",
                        {"fixture": "Data/User/user0.dat"}, root / "observer.dll",
                        root / "game-proxy/MulleMeck.exe",
                    )
            launch.assert_not_called()

    def test_native_scenario_runner_rejects_a_user_profile_inside_the_repository(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts
        from tools.miel_vliegt.test_native_scenario_artifacts import scenario

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            suite = repository / "suite"
            suite.mkdir()
            initial_state = scenario(suite)["initial_state"]
            initial_state["files"][0]["role"] = "user-profile"
            initial_state["values"] = []
            artifacts.materialize_scenario_suite(suite, initial_state)
            executable = repository / "game/MulleMeck.exe"
            executable.parent.mkdir()
            executable.write_bytes(b"native")
            observer = repository / "observer.dll"
            observer.write_bytes(b"observer")

            with patch("tools.miel_vliegt.hangover_probe.ROOT", repository), \
                 patch("tools.miel_vliegt.hangover_probe.run_scene_navigation") as launch:
                with self.assertRaisesRegex(ValueError, "outside the repository"):
                    run_native_semantic_scenario(
                        ["env"], {"id": "box64", "hodll": "wowbox64.dll"}, executable,
                        repository / "out/capture.json", suite / "suite-spec.json",
                        "controls-press-hold-release", executable.parent,
                        {"user-profile": "Data/User/user0.dat"}, observer,
                        repository / "game-proxy/MulleMeck.exe",
                    )
            launch.assert_not_called()

    def test_native_scenario_never_deletes_preexisting_frame_artifacts(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "out" / "capture.json"
            output.parent.mkdir()
            preexisting = output.parent / (
                "native-frame-controls-press-hold-release-box64.native.raw"
            )
            preexisting.write_bytes(b"user-owned")
            with patch.object(
                artifacts, "load_scenario_suite_manifest",
            ) as load_manifest:
                with self.assertRaisesRegex(
                    ValueError, "framebuffer output already exists",
                ):
                    run_native_semantic_scenario(
                        ["env"],
                        {"id": "box64", "hodll": "wowbox64.dll"},
                        root / "MulleMeck.exe",
                        output,
                        root / "suite-spec.json",
                        "controls-press-hold-release",
                        root,
                        {"user-profile": "Data/User/user0.dat"},
                        root / "observer.dll",
                        root / "proxy/MulleMeck.exe",
                    )
            self.assertEqual(preexisting.read_bytes(), b"user-owned")
            load_manifest.assert_not_called()

    def test_native_scenario_runner_binds_restored_user_hash_to_observer(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite"
            suite.mkdir()
            scenario_path = suite / "scenario.json"
            replay_path = suite / "scenario.mvo"
            scenario_path.touch()
            replay_path.touch()
            output = root / "out" / "capture.json"
            output.parent.mkdir()
            observer_log = output.parent / "native-observer-box64.log"
            observer_log.write_bytes(b"observer log")
            replay_hash = "a" * 64
            user_hash = "b" * 64
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"native")
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            disposable = root / "game-proxy/MulleMeck.exe"
            disposable.parent.mkdir()
            disposable.write_bytes(b"native")
            executable_hash = __import__("hashlib").sha256(b"native").hexdigest()
            observer_hash = __import__("hashlib").sha256(b"observer").hexdigest()
            scenario_value = {
                "id": "controls-press-hold-release",
                "initial_state": {
                    "files": [{"role": "user-profile", "path": scenario_path.name}],
                    "values": [],
                },
            }

            def fake_hash(path):
                if path.name == replay_path.name:
                    return replay_hash
                if path.name == observer_log.name:
                    return "c" * 64
                if path == executable:
                    return executable_hash
                if path == observer:
                    return observer_hash
                return "d" * 64

            def fake_navigation(*_args, **_kwargs):
                frame_prefix = output.parent / (
                    "native-frame-controls-press-hold-release-box64"
                )
                frame_prefix.with_suffix(".raw").write_bytes(b"canonical")
                frame_prefix.with_suffix(".native.raw").write_bytes(b"native")
                return {
                    "route": "suspended-process-observer-launcher",
                    "scene_bootstrap_confirmed": True,
                    "start_executable_receipt": {
                        "schema": 1,
                        "protocol": "miel-vliegt-native-unmodified-start",
                        "status": "PREPARED",
                        "strategy": "byte-identical-disposable-copy",
                        "source_executable_sha256": executable_hash,
                        "launch_executable_sha256": executable_hash,
                        "scene": "flight",
                        "changes": [],
                    },
                    "observer_launcher_receipt": {
                        "original_executable_sha256": executable_hash,
                        "patched_executable_sha256": executable_hash,
                    },
                    "observer_log": {
                        "path": observer_log.name,
                        "sha256": "c" * 64,
                        "hook_loaded": True,
                    },
                }

            with patch.object(artifacts, "load_scenario_suite_manifest", return_value={}), \
                 patch.object(artifacts, "scenario_suite_entry", return_value={
                     "scenario": {"path": scenario_path.name,
                                  "semantic_sha256": "1" * 64},
                     "native_replay": {"path": replay_path.name},
                     "capture_tick": 12,
                 }), \
                 patch.object(artifacts, "load_scenario", return_value=scenario_value), \
                 patch.object(artifacts, "restore_scenario_initial_state_files", return_value={
                     "files": [{"role": "user-profile", "target_path": "Data/User/user0.dat",
                                "sha256": user_hash}],
                 }), \
                 patch.object(artifacts, "sha256_file", side_effect=fake_hash), \
                 patch.object(artifacts, "validate_completed_scenario_trace", return_value={
                     "semantic_sha256": "e" * 64, "record_count": 1,
                 }), \
                 patch.object(artifacts, "extract_focus_timeline_receipt", return_value={
                     "clock": "query_performance_counter",
                     "origin": "episode-focus-loss",
                     "scenario_sha256": "1" * 64,
                     "timeline_sha256": "2" * 64,
                     "event_count": 2,
                     "events": [],
                     "sha256": "3" * 64,
                 }), \
                 patch.object(artifacts, "load_framebuffer_metadata", return_value={
                     "scenario": "controls-press-hold-release",
                     "scenario_sha256": replay_hash,
                     "tick": 12,
                     "width": 640,
                     "height": 480,
                     "raw_sha256": "f" * 64,
                 }), \
                 patch.object(artifacts, "load_framebuffer_source_metadata", return_value={
                     "scenario": "controls-press-hold-release",
                     "scenario_sha256": replay_hash,
                     "tick": 12,
                     "width": 640,
                     "height": 480,
                     "raw_sha256": "a" * 64,
                     "gt_format_id": 5,
                     "gt_format_name": "RGB565",
                     "conversion": "rgb565-le-to-xrgb8888-le",
                 }), \
                 patch.object(artifacts, "validate_framebuffer_derivation", return_value={
                     "source_raw_sha256": "a" * 64,
                     "canonical_raw_sha256": "f" * 64,
                     "conversion": "rgb565-le-to-xrgb8888-le",
                     "byte_exact": True,
                     "origin": {
                         "protocol": "miel-vliegt-native-framebuffer-origin",
                         "contract_file_sha256": "1" * 64,
                         "contract_receipt_sha256": "2" * 64,
                         "lock_call_address": "0x1000825b",
                         "measured_pitch": 1280,
                         "resolved": "TOP_LEFT",
                     },
                     "pixel_parity_eligible": True,
                 }), \
                 patch.object(artifacts, "validate_framebuffer_trace_binding", return_value={
                     "tick": 12,
                     "raw_sha256": "f" * 64,
                     "capture": "native_read_screen",
                     "render_final_correlated": True,
                     "profile": "exact",
                 }), \
                 patch(
                     "tools.miel_vliegt.hangover_probe.run_scene_navigation",
                     side_effect=fake_navigation,
                 ) as launch:
                result = run_native_semantic_scenario(
                    ["env"], {"id": "box64", "hodll": "wowbox64.dll"}, executable, output,
                    suite / "suite-spec.json", "controls-press-hold-release",
                    root, {"user-profile": "Data/User/user0.dat"},
                    observer, disposable,
                )

            observer_environment = launch.call_args.kwargs["observer_environment"]
            self.assertEqual(
                observer_environment["MIEL_OBSERVER_INITIAL_USER_SHA256"],
                user_hash,
            )
            self.assertEqual(observer_environment["MIEL_OBSERVER_SCENARIO_SHA256"], replay_hash)
            self.assertTrue(launch.call_args.kwargs["unmodified_start"])
            self.assertEqual(result["inputs"]["executable_sha256"], executable_hash)
            self.assertEqual(result["status"], "CANDIDATE_ONLY")

    def test_native_suite_runs_exactly_seven_isolated_candidate_captures(self):
        from tools.miel_vliegt import native_scenario_artifacts as artifacts

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []

            def fake_scenario(*args, **_kwargs):
                identifier = args[5]
                calls.append((identifier, args[3].parent.name))
                return {
                    "status": "CANDIDATE_ONLY",
                    "production_claim": False,
                    "scenario": identifier,
                }

            with patch(
                "tools.miel_vliegt.native_scenario_artifacts.load_scenario_suite_manifest",
                return_value={"scenario_order": list(artifacts.SCENARIO_ID_ORDER)},
            ), patch(
                "tools.miel_vliegt.hangover_probe.run_native_semantic_scenario",
                side_effect=fake_scenario,
            ):
                receipt = run_native_semantic_suite(
                    ["env"], {"id": "box64", "hodll": "wowbox64.dll"}, root / "MulleMeck.exe",
                    root / "out", root / "suite-spec.json", root / "state",
                    {"fixture": "user0.dat"}, root / "observer.dll",
                    root / "game-proxy/MulleMeck.exe",
                )

            self.assertEqual(
                calls,
                [(identifier, identifier) for identifier in artifacts.SCENARIO_ID_ORDER],
            )
            self.assertEqual(receipt["status"], "CANDIDATE_ONLY")
            self.assertFalse(receipt["production_claim"])
            self.assertEqual(len(receipt["results"]), 7)
            self.assertTrue((root / "out" / "suite-run.json").is_file())

    def test_rejects_a_contract_that_promotes_probe_success(self):
        contract = json.loads(CONTRACT.read_text())
        contract["parity_policy"]["probe_success_is_native_evidence"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(contract))
            with self.assertRaisesRegex(ValueError, "must not be accepted"):
                validate_contract(path)

    def test_rejects_a_contract_that_changes_the_reviewed_observer_strategy(self):
        contract = json.loads(CONTRACT.read_text())
        contract["observer_strategy"]["ranking"][2]["disposition"] = "SELECTED"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(contract))
            with self.assertRaisesRegex(ValueError, "reviewed ranking"):
                validate_contract(path)

    def test_expensive_probe_is_manual_only_and_cannot_deploy(self):
        root = CONTRACT.parents[2]
        workflow = (root / ".github/workflows/probe-hangover-flight.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        trigger_block = workflow.split("concurrency:", 1)[0]
        self.assertNotIn("push:", trigger_block)
        self.assertNotIn("deploy-oracle", workflow)
        self.assertIn("--require-observer-bootstrap", workflow)
        self.assertIn("--require-all", workflow)
        self.assertNotIn("--require-debug-api", workflow)
        self.assertNotIn("--probe-debug-api", workflow)
        self.assertIn("900s docker run", workflow)
        self.assertIn("HANGOVER_CONTAINER: miel-vliegt-hangover-${{ github.run_id }}", workflow)
        self.assertIn("default: flight", workflow)
        self.assertIn("- flight", workflow)
        self.assertIn('docker rm --force "$HANGOVER_CONTAINER"', workflow)
        self.assertIn('docker image rm --force "$HANGOVER_IMAGE"', workflow)

        deploy = (root / ".github/workflows/deploy-oracle.yml").read_text()
        international = (root / ".github/workflows/international-compatibility.yml").read_text()
        self.assertIn('- ".github/workflows/deploy-oracle.yml"', deploy)
        # Workflow changes must exercise the workflow they alter. The native
        # probe remains isolated through the explicit negative path filters
        # below, not by suppressing this workflow's own path.
        self.assertIn('- ".github/workflows/international-compatibility.yml"', international)
        isolated_paths = (
            "tools/miel_vliegt/hangover/**",
            "tools/miel_vliegt/hangover_probe.py",
            "tools/miel_vliegt/native_discovery.py",
            "tools/miel_vliegt/native_scene_navigator.py",
        )
        for path in isolated_paths:
            self.assertIn(f'- "{path}"', deploy)
            self.assertIn(f'- "!{path}"', international)

    def test_timeout_is_not_held_open_by_an_emulated_grandchild_output_handle(self):
        script = (
            "import subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "time.sleep(60)"
        )
        started = time.monotonic()
        result = run([sys.executable, "-c", script], cwd=CONTRACT.parent, timeout=1)
        self.assertTrue(result["timed_out"])
        self.assertLess(time.monotonic() - started, 8)

    def test_rejects_non_i386_smoke_executable(self):
        image = bytearray(70)
        image[:2] = b"MZ"
        image[0x3C:0x40] = (64).to_bytes(4, "little")
        image[64:68] = b"PE\0\0"
        image[68:70] = (0x8664).to_bytes(2, "little")
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "smoke.exe"
            executable.write_bytes(image)
            with self.assertRaisesRegex(ValueError, "PE32 i386"):
                validate_i386_pe(executable)

    def test_sysarm32_c0000135_fails_closed_before_target_or_smoke(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "prefix"
            smoke = root / "smoke.exe"
            smoke.touch()

            def failed_wineboot(command, **_kwargs):
                if "wineboot" in command:
                    self.create_complete_prefix(prefix)
                    (prefix / "drive_c/windows/sysarm32").mkdir()
                    return self.completed_run(
                        'wine: failed to start L"C:\\windows\\sysarm32\\rundll32.exe": c0000135'
                    )
                return self.completed_run()

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=failed_wineboot) as mocked:
                result = bootstrap_prefix(
                    prefix,
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    smoke,
                )

            self.assertFalse(result["usable"])
            self.assertFalse(result["checks"]["wineboot_loader_clean"])
            self.assertFalse(result["checks"]["no_unserviceable_sysarm32"])
            self.assertFalse(result["checks"]["win32_smoke"])
            self.assertEqual(result["runs"]["win32_smoke"]["skipped"], "prefix-bootstrap-failed")
            self.assertEqual(mocked.call_count, 3)

    def test_clean_prefix_must_run_i386_smoke_sentinel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "prefix"
            smoke = root / "wine-readiness-canary.exe"
            smoke.touch()

            def successful_runs(command, **_kwargs):
                if "wineboot" in command:
                    self.create_complete_prefix(prefix)
                    return self.completed_run()
                if any("wineserver" in item for item in command):
                    if command[-1] == "-p0":
                        return self.completed_run(
                            PERSISTENT_WINESERVER_ACK_SENTINEL
                        )
                    return self.completed_run()
                if "query" in command:
                    if "Decorated" in command:
                        value = "Decorated    REG_SZ    N"
                    elif "Graphics" in command:
                        value = "Graphics    REG_SZ    x11"
                    else:
                        value = "renderer    REG_SZ    gdi"
                    return self.completed_run(value)
                if "reg" in command:
                    return self.completed_run()
                if "wine-readiness-canary.exe" in " ".join(command):
                    return self.completed_run("\n".join((
                        "MIEL_FEX_WINE_CANARY_OK",
                        "MIEL_RPCSS_STATE=RUNNING",
                        "MIEL_WINE_RENDERER=GDI",
                        "MIEL_WINE_DECORATED=N",
                        "MIEL_COM_REGISTRY "
                        "clsid={47D4D946-62E8-11CF-93BC-444553540000}",
                        "MIEL_COM_REGISTRY "
                        "clsid={BCDE0395-E52F-467C-8E3D-C4579291692E}",
                        "MIEL_COM_ACTIVATION "
                        "clsid={47D4D946-62E8-11CF-93BC-444553540000} "
                        "hresult=0x00000000",
                        "MIEL_COM_ACTIVATION "
                        "clsid={BCDE0395-E52F-467C-8E3D-C4579291692E} "
                        "hresult=0x00000000",
                        "MIEL_FEX_WINE_READINESS_OK",
                    )))
                return self.completed_run(SMOKE_SENTINEL)

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=successful_runs) as mocked:
                result = bootstrap_prefix(
                    prefix,
                    {"id": "fex", "hodll": "libwow64fex.dll"},
                    smoke,
                )

            self.assertTrue(result["usable"])
            self.assertTrue(all(result["checks"].values()))
            self.assertEqual(mocked.call_count, 6)
            self.assertEqual(mocked.call_args_list[0].kwargs["timeout"], 120)
            self.assertEqual(mocked.call_args_list[4].kwargs["timeout"], 120)
            for call_index in (4, 5):
                command = mocked.call_args_list[call_index].args[0]
                self.assertIn("--rpcss-timeout-ms", command)
                timeout_index = command.index("--rpcss-timeout-ms")
                self.assertEqual(command[timeout_index + 1], "30000")

    def test_clean_prefix_accepts_already_stopped_private_wineserver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "prefix"
            smoke = root / "smoke.exe"
            smoke.touch()

            def successful_runs(command, **_kwargs):
                if "wineboot" in command:
                    self.create_complete_prefix(prefix)
                    return self.completed_run()
                if any("wineserver" in item for item in command):
                    if command[-1] == "-p0":
                        return self.completed_run(
                            PERSISTENT_WINESERVER_ACK_SENTINEL
                        )
                    return {
                        **self.completed_run(),
                        "exit_code": 1,
                    }
                if "query" in command:
                    if "Decorated" in command:
                        value = "Decorated    REG_SZ    N"
                    elif "Graphics" in command:
                        value = "Graphics    REG_SZ    x11"
                    else:
                        value = "renderer    REG_SZ    gdi"
                    return self.completed_run(value)
                if "reg" in command:
                    return self.completed_run()
                return self.completed_run(SMOKE_SENTINEL)

            with patch(
                "tools.miel_vliegt.hangover_probe.run",
                side_effect=successful_runs,
            ):
                result = bootstrap_prefix(
                    prefix,
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    smoke,
                )

            self.assertTrue(result["usable"])
            self.assertTrue(result["checks"]["wineserver_stopped"])
            self.assertTrue(result["checks"]["wineserver_waited"])

    def test_zero_exit_without_smoke_sentinel_is_not_usable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "prefix"
            smoke = root / "smoke.exe"
            smoke.touch()

            def incomplete_runs(command, **_kwargs):
                if "wineboot" in command:
                    self.create_complete_prefix(prefix)
                return self.completed_run()

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=incomplete_runs):
                result = bootstrap_prefix(
                    prefix,
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    smoke,
                )

            self.assertFalse(result["usable"])
            self.assertFalse(result["checks"]["win32_smoke"])

    def test_container_blocks_false_arm32_detection_and_builds_smoke_out_of_tree(self):
        dockerfile = (CONTRACT.parents[2] / "tools/miel_vliegt/hangover/Dockerfile").read_text()
        self.assertIn("FROM ubuntu:24.04 AS win32-builder", dockerfile)
        self.assertIn("gcc-mingw-w64-i686", dockerfile)
        self.assertIn("LD_PRELOAD=/opt/hangover/libblock-aarch32-personality.so", dockerfile)
        self.assertIn("/opt/hangover/win32-smoke.exe", dockerfile)
        self.assertIn("win32_debug_capability.c", dockerfile)
        self.assertIn("/opt/hangover/win32-debug-capability.exe", dockerfile)
        self.assertIn("native_scene_navigator.py emit-header", dockerfile)
        self.assertIn("/opt/hangover/native-scene-debugger.exe", dockerfile)
        self.assertIn("/opt/hangover/native-observer-launcher.exe", dockerfile)
        self.assertIn("/opt/hangover/native-observer-hook.dll", dockerfile)
        self.assertIn("/opt/hangover/headless-config.ini", dockerfile)
        self.assertIn(
            "native_observation_profile_contract.py "
            "/opt/repo/tools/miel_vliegt/native_observation_profile_contract.py",
            dockerfile,
        )
        self.assertIn(
            "native_observation_profiles.json "
            "/opt/repo/content/miel_vliegt/native_observation_profiles.json",
            dockerfile,
        )
        self.assertIn(HEADLESS_CONFIG_SHA256, dockerfile)

    def test_container_layout_bootstraps_repository_module_before_help(self):
        repository = CONTRACT.parents[2]
        with tempfile.TemporaryDirectory() as directory:
            opt = Path(directory) / "opt"
            probe = opt / "hangover/hangover_probe.py"
            contract_module = (
                opt
                / "repo/tools/miel_vliegt/native_observation_profile_contract.py"
            )
            probe.parent.mkdir(parents=True)
            contract_module.parent.mkdir(parents=True)
            shutil.copy2(
                repository / "tools/miel_vliegt/hangover_probe.py",
                probe,
            )
            shutil.copy2(
                repository
                / "tools/miel_vliegt/native_observation_profile_contract.py",
                contract_module,
            )

            result = subprocess.run(
                [sys.executable, str(probe), "--help"],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Probe Hangover as an isolated native-capture host", result.stdout)

    def test_headless_config_is_byte_pinned_and_installed_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "headless.ini"
            source.write_bytes(
                b"gtdriver gtSoftware\nsetupwindow false\nfullscreen false\n"
            )
            receipt = install_headless_config(root, source)
            self.assertEqual(receipt["sha256"], HEADLESS_CONFIG_SHA256)
            self.assertEqual((root / "config.ini").read_bytes(), source.read_bytes())
            self.assertFalse((root / ".config.ini.miel-observer.tmp").exists())
            source.write_bytes(
                b"gtdriver gtDirect3D\nsetupwindow true\nfullscreen true\n"
            )
            with self.assertRaisesRegex(ValueError, "drifted"):
                install_headless_config(root, source)

    def test_renderer_config_removes_non_client_pixels_and_reads_both_values_back(self):
        outputs = iter((
            self.completed_run(),
            self.completed_run("renderer    REG_SZ    gdi"),
            self.completed_run(),
            self.completed_run("Decorated    REG_SZ    N"),
            self.completed_run(),
            self.completed_run("Graphics    REG_SZ    x11"),
        ))
        with patch(
            "tools.miel_vliegt.hangover_probe.run",
            side_effect=lambda *_args, **_kwargs: next(outputs),
        ) as runner:
            receipt = configure_gdi_renderer(["env", "WINEPREFIX=/prefix"], Path("/game"))
        self.assertTrue(receipt["written"])
        self.assertTrue(receipt["verified"])
        self.assertEqual(set(receipt["runs"]), {
            "renderer_add", "renderer_query", "decorated_add", "decorated_query",
            "graphics_add", "graphics_query",
        })
        commands = [call.args[0] for call in runner.call_args_list]
        self.assertIn(r"HKCU\Software\Wine\X11 Driver", commands[2])
        self.assertIn("Decorated", commands[2])
        self.assertIn("N", commands[2])
        self.assertEqual(
            NATIVE_XVFB_ARGUMENTS,
            ("xvfb-run", "-a", "-s", "-screen 0 646x512x16 -nolisten tcp"),
        )

    def test_observation_deadline_matches_the_native_launcher_contract(self):
        self.assertEqual(validate_observe_ms(120_000), 120_000)
        for value in (999, 3_600_001, True):
            with self.assertRaisesRegex(ValueError, "observe_ms"):
                validate_observe_ms(value)

    def test_win32_debug_capability_probe_is_bounded_self_contained_and_fail_closed(self):
        source = (
            CONTRACT.parents[2] / "tools/miel_vliegt/hangover/win32_debug_capability.c"
        ).read_text()
        required_calls = (
            "CreateProcessA",
            "DEBUG_ONLY_THIS_PROCESS",
            "WaitForDebugEvent",
            "CREATE_PROCESS_DEBUG_EVENT",
            "ContinueDebugEvent",
            "OutputDebugStringA",
            "GetThreadContext",
            "SetThreadContext",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "FlushInstructionCache",
            "GetTickCount",
            "TerminateProcess",
        )
        for call in required_calls:
            self.assertIn(call, source)
        self.assertIn('"--child"', source)
        self.assertIn('"--receipt"', source)
        self.assertIn("create-process-event-timeout", source)
        self.assertIn("miel-hangover-win32-debug-capability", source)
        self.assertIn('supported ? "PASS" : "FAIL"', source)
        self.assertIn('"ud2"', source)
        self.assertIn("EXCEPTION_ILLEGAL_INSTRUCTION", source)
        self.assertIn("trap_resume_context_ok", source)
        self.assertIn("deliberate_trap_site", source)
        self.assertIn("restore_deliberate_trap", source)
        self.assertIn("deliberate_second_breakpoint_seen", source)
        self.assertIn("deliberate_second_trap_restore_ok", source)
        self.assertIn("FIRST_EXECUTION_SENTINEL", source)
        self.assertIn("SECOND_EXECUTION_SENTINEL", source)
        self.assertIn("restored_execution_semantics_ok", source)
        self.assertIn("read_thread_eip", source)
        self.assertIn("deliberate_trap_location_matches", source)
        self.assertIn("DBG_EXCEPTION_NOT_HANDLED", source)
        self.assertIn("unhandled-second-chance-exception", source)
        self.assertIn("context.Eip = exception_address + 1", source)
        self.assertLess(
            source.rindex("write_receipt(receipt, &result"),
            source.rindex("TerminateProcess(process.hProcess"),
        )
        self.assertNotIn("MulleMeck", source)
        self.assertNotIn("native_scenes", source)

    def test_backend_profiles_use_a_proven_trap_adapter_before_slow_fallbacks(self):
        self.assertEqual(DEBUG_PROFILES["box64"][0]["id"], "default-int3")
        self.assertEqual(
            DEBUG_PROFILES["box64"][1]["trap_strategy"], "ud2",
        )
        self.assertEqual(
            DEBUG_PROFILES["fex"][1]["trap_strategy"], "ud2"
        )
        self.assertNotIn("FEX_SINGLESTEP=1", DEBUG_PROFILES["fex"][1]["environment"])

    def test_native_scene_debugger_restores_one_shot_traps_at_the_same_pc(self):
        source = (
            CONTRACT.parents[2] / "tools/miel_vliegt/hangover/native_scene_debugger.c"
        ).read_text()
        self.assertIn("breakpoint->stolen_size", source)
        self.assertIn("reported_exception_address", source)
        self.assertIn("breakpoint->action_pending", source)
        self.assertIn("write_exact(breakpoint->address, breakpoint->original", source)
        self.assertIn("context->Eip != breakpoint->address", source)
        self.assertIn("reported_exception_address != breakpoint->address", source)
        self.assertNotIn("context->Eip =", source)
        self.assertNotIn("--control", source)
        self.assertNotIn("poll_control", source)
        self.assertIn("loader_breakpoints[MIEL_SCENE_COUNT]", source)
        self.assertIn("continue_debug_event_checked", source)
        self.assertIn("unhandled-second-chance-exception", source)
        self.assertIn("CREATE_THREAD_DEBUG_EVENT", source)
        self.assertIn("event.u.ExitProcess.dwExitCode != ERROR_SUCCESS", source)

    def test_persistent_observation_runs_inside_the_original_game_thread(self):
        root = CONTRACT.parents[2]
        launcher = (root / "tools/miel_vliegt/hangover/native_observer_launcher.c").read_text()
        hook = (root / "tools/miel_vliegt/hangover/native_observer_hook.c").read_text()
        proxy = (root / "tools/miel_vliegt/x86_wine/native_observer_dinput_proxy.c").read_text()
        self.assertIn("CREATE_SUSPENDED", launcher)
        self.assertIn("WaitForInputIdle", launcher)
        self.assertIn("WaitForMultipleObjects", launcher)
        self.assertIn("remaining > 100u ? 100u : remaining", launcher)
        self.assertIn('create_observer_event(process_id, "Complete"', launcher)
        self.assertIn('create_observer_event(process_id, "Failure"', launcher)
        self.assertIn('create_observer_event(process_id, "Ready"', launcher)
        self.assertIn('values[0] = "1"', launcher)
        self.assertIn('"MIEL_OBSERVER_EVENTS_PREOWNED"', launcher)
        self.assertIn("scenario-completion-timeout", launcher)
        self.assertIn("observer-reported-failure", launcher)
        self.assertNotIn("primary_suspended_during_load", launcher)
        self.assertNotIn("primary_suspended_during_initialize", launcher)
        self.assertIn("proxy_observer_ready", launcher)
        self.assertIn("login_pending_observed", launcher)
        self.assertIn("ready_before_login_pending", launcher)
        self.assertIn("login_activation_observed", launcher)
        self.assertIn("ready_before_login_activation", launcher)
        bootstrap_wait = launcher[
            launcher.index("static DWORD wait_for_proxy_bootstrap"):
            launcher.index("static BOOL parse_options")
        ]
        self.assertIn("evidence->proxy_observer_ready", bootstrap_wait)
        self.assertIn("evidence->login_pending_observed", bootstrap_wait)
        self.assertIn("wake_process_message_loop(process)", bootstrap_wait)
        self.assertIn("INPUT_IDLE_PROBE_TIMEOUT_MS", bootstrap_wait)
        self.assertIn("evidence->projector_input_idle = TRUE", bootstrap_wait)
        self.assertNotIn("GetThreadContext", launcher)
        self.assertNotIn("SetThreadContext", launcher)
        self.assertNotIn("WaitForSingleObject(process.hProcess, options.observe_ms)", launcher)
        self.assertIn("fallback_timeout=60", (root / "tools/miel_vliegt/hangover_probe.py").read_text())
        self.assertEqual(
            (root / "tools/miel_vliegt/hangover_probe.py").read_text().count(
                '"start_executable_receipt": start_receipt'
            ),
            1,
        )
        self.assertNotIn("CreateRemoteThread", launcher)
        self.assertNotIn("WaitForSingleObject(load_thread", launcher)
        self.assertNotIn("WaitForSingleObject(initialize_thread", launcher)
        self.assertNotIn("WaitForDebugEvent", launcher)
        self.assertNotIn("SuspendThread", launcher)
        self.assertNotIn("MIEL_ENTRYPOINT_ADDRESS", launcher)
        main = launcher[launcher.index("int main(int argc"):]
        self.assertLess(
            main.index("create_observer_events(process.dwProcessId"),
            main.index("ResumeThread(process.hThread)"),
        )
        self.assertLess(
            main.index("if (ResumeThread(process.hThread)"),
            main.index("wait_for_proxy_bootstrap"),
        )
        self.assertNotIn("WaitForInputIdle", main)
        self.assertIn("PROXY_BOOTSTRAP_TIMEOUT_MS, &evidence", main)
        self.assertIn("#define PROXY_BOOTSTRAP_TIMEOUT_MS 600000u", launcher)
        probe_source = (
            root / "tools/miel_vliegt/hangover_probe.py"
        ).read_text()
        self.assertIn(
            "math.ceil(observe_ms / 1000)",
            probe_source,
        )
        self.assertIn(
            "OBSERVER_HOST_DEADLINE_GRACE_SECONDS",
            probe_source,
        )
        self.assertEqual(OBSERVER_HOST_DEADLINE_GRACE_SECONDS, 30)
        self.assertIn('"host_deadline_seconds": launcher_timeout', probe_source)
        self.assertIn('"deadline_clock": "host_monotonic"', probe_source)
        self.assertEqual(main.count("ResumeThread(process.hThread)"), 1)
        self.assertEqual(launcher.count("ResumeThread(process.hThread)"), 1)
        self.assertIn('GetModuleHandleA("Cc.dll")', proxy)
        self.assertIn("bootstrap_after_loader", proxy)
        self.assertIn("CreateThread", proxy)
        self.assertIn("BOOTSTRAP_TIMEOUT_MS", proxy)
        self.assertIn("#define BOOTSTRAP_TIMEOUT_MS 600000u", proxy)
        self.assertIn("if (!initialize_proxy())", proxy)
        self.assertNotIn("APPLICATION_POINTER", proxy)
        self.assertNotIn("MANAGER_CURRENT_MODE_OFFSET", proxy)
        self.assertNotIn("MANAGER_PENDING_MODE_OFFSET", proxy)
        self.assertIn('GetModuleHandleA("Cc.dll")', proxy)
        self.assertIn('proxy_diagnostic("cc_ready_initialize")', proxy)
        self.assertIn('GetProcAddress(observer_module, "MielObserverInitialize")', proxy)
        self.assertIn("observer_initialize(NULL) != 1u", proxy)
        self.assertIn("signal_observer_failure();", proxy)
        self.assertIn("MielObserverFailure-%lu", proxy)
        self.assertLess(
            proxy.index("observer_initialize(NULL) != 1u"),
            proxy.index("return real_direct_input_create"),
        )
        self.assertIn("terminate_failed_target", launcher)
        self.assertLess(
            launcher.index("TerminateProcess(process->hProcess", launcher.index("terminate_failed_target")),
            launcher.index("write_receipt(options, evidence", launcher.index("terminate_failed_target")),
        )
        self.assertIn("MANAGER_TICK_VTABLE_SLOT", hook)
        self.assertIn("MANAGER_RENDER_VTABLE_SLOT", hook)
        self.assertIn("InterlockedCompareExchangePointer", hook)
        self.assertIn("manager_tick_vtable_hook", hook)
        self.assertIn("manager_render_vtable_hook", hook)
        self.assertIn("manager_tick_prepare", hook)
        self.assertIn("engine_thread_id", hook)
        self.assertIn("MODE_SET ((BYTE *)(ULONG_PTR)0x0041e450u)", hook)
        self.assertIn("MODE_SET_SIGNATURE", hook)
        self.assertIn("0x56, 0x8b, 0xf1, 0x57, 0x8b, 0x7c, 0x24, 0x0c", hook)
        self.assertIn("memcmp(MODE_SET, MODE_SET_SIGNATURE", hook)
        self.assertIn("install_detour(MODE_SET, MODE_SET_SIGNATURE, 8u", hook)
        self.assertIn("mode_set_hook", hook)
        mode_hook = hook[
            hook.index("static void __attribute__((naked)) mode_set_hook"):
            hook.index("SEMANTIC_HOOK(controls_pre_hook")
        ]
        self.assertIn('"pushl 12(%esp)\\n\\tcall *_mode_set_trampoline', mode_hook)
        self.assertIn('"popal\\n\\tpopfl\\n\\taddl $8, %esp\\n\\tret $4', mode_hook)
        self.assertIn("miel-vliegt-native-mode-transition", hook)
        self.assertIn("BODY_MODE_COUNT 22u", hook)
        self.assertIn("BODY_MODE_ALLOWLIST[BODY_MODE_COUNT]", hook)
        body_allowlist = hook[
            hook.index("BODY_MODE_ALLOWLIST[BODY_MODE_COUNT]"):
            hook.index("static const BYTE TICK_SIGNATURE")
        ]
        self.assertEqual(tuple(re.findall(r'"(mode_[a-z0-9_]+)"', body_allowlist)),
                         BODY_MODES)
        self.assertIn("ENGINE_MODE_COMMAND_ID 15u", hook)
        self.assertIn('ENGINE_MODE_COMMAND_NAME "engine_mode"', hook)
        self.assertIn("resolve_registered_engine_mode_callback", hook)
        self.assertIn("callback_object != manager_address + 0x130u", hook)
        self.assertIn("callback_address != (DWORD)(ULONG_PTR)ENGINE_MODE_CALLBACK", hook)
        self.assertIn("callback(callback_object, ENGINE_MODE_COMMAND_ID, body_mode_name)", hook)
        self.assertIn("dispatch_body_mode_on_manager_tick(manager_address)", hook)
        self.assertIn("target_resolved_before_mutation", hook)
        self.assertIn("BODY_ONLY", hook)
        self.assertIn("natural_transition_evidence", hook)
        self.assertIn("*transition_id = INVALID_ID", hook)
        self.assertIn("body_callback_active", hook)
        self.assertNotIn("call *0x0041e22d", hook)
        self.assertIn("record_bootstrap_pending_login", hook)
        self.assertIn("calibration_observation_only", hook)
        self.assertIn('strcmp(profile, "calibration-only")', hook)
        self.assertIn("calibration_detour_required", hook)
        self.assertIn(
            "target == CONTROLS_PRE || target == CONTROLS_POST", hook,
        )
        self.assertIn(
            "if (!calibration_observation_only) record_camera_commit(current)",
            hook,
        )
        self.assertIn('\\"evidence_blocker\\":%s', hook)
        self.assertIn('\\"retained_channels\\":%s', hook)
        self.assertIn("OBSERVER_READY_WAIT_MS 60000u", hook)
        self.assertIn("LATE_BOOTSTRAP_COMPLETION_WAIT_MS 5000u", hook)
        initialization = hook[
            hook.index("__declspec(dllexport) DWORD WINAPI MielObserverInitialize"):
            hook.index("install_failed:", hook.index(
                "__declspec(dllexport) DWORD WINAPI MielObserverInitialize"
            ))
        ]
        self.assertLess(
            initialization.index("configure_natural_transition_capture()"),
            initialization.index("configure_observation_profile()"),
        )
        completion_start = hook.index(
            "static BOOL complete_observer_bootstrap("
            "DWORD expected_manager)\n{"
        )
        completion = hook[
            completion_start:
            hook.index(
                "static BOOL install_shadow_render_interposition(",
                completion_start,
            )
        ]
        self.assertLess(
            completion.index("install_manager_tick_interposition()"),
            completion.index("InterlockedExchange(&observer_ready, 1)"),
        )
        self.assertLess(
            completion.index("InterlockedExchange(&observer_ready, 1)"),
            completion.index("SetEvent(ready_event)"),
        )
        self.assertLess(
            completion.index("SetEvent(ready_event)"),
            completion.index('write_marker("LOADED")'),
        )
        self.assertIn(
            "calibration_observation_only &&\n"
            "        !calibration_bootstrap_manager_ready(0u)",
            initialization,
        )
        self.assertIn("late_bootstrap_retry_thread", initialization)
        retry = hook[
            hook.index("static DWORD WINAPI late_bootstrap_retry_thread"):
            hook.index("static BOOL application_identity_matches")
        ]
        self.assertIn("WaitForMultipleObjects(", retry)
        self.assertIn("LATE_BOOTSTRAP_RETRY_MS", retry)
        self.assertIn(
            "manager == 0u && calibration_bootstrap_manager_ready(0u)",
            retry,
        )
        self.assertIn("complete_observer_bootstrap(manager)", retry)
        self.assertNotIn("emit_scheduler_watchdog", retry)
        self.assertNotIn("emit_bootstrap_diagnostic", retry)
        mode_entry = hook[
            hook.index("static void __attribute__((used)) "
                       "record_mode_transition_entry"):
            hook.index("static void __attribute__((used)) "
                       "record_mode_transition_leave")
        ]
        self.assertIn("late_bootstrap_manager_address", mode_entry)
        self.assertIn("SetEvent(late_bootstrap_event)", mode_entry)
        self.assertNotIn("complete_observer_bootstrap", mode_entry)
        self.assertIn("else if (!calibration_observation_only &&", mode_entry)
        self.assertIn(
            "ready_event, OBSERVER_READY_WAIT_MS) != WAIT_OBJECT_0",
            mode_entry,
        )
        mode_leave = hook[
            hook.index("static void __attribute__((used)) "
                       "record_mode_transition_leave"):
            hook.index("static void correlate_mode_activation")
        ]
        self.assertLess(
            mode_leave.index("complete_observer_bootstrap(manager_address)"),
            mode_leave.index(
                "InterlockedCompareExchange(&observer_ready, 0, 0) != 1"
            ),
        )
        self.assertIn(
            'session_fail("late_bootstrap_mode_set_leave_contract")',
            mode_leave,
        )
        self.assertIn(
            "ensure_calibration_manager_tick_interposition()",
            mode_leave,
        )
        slot_guard_start = hook.index(
            "static BOOL ensure_calibration_manager_tick_interposition("
            "void)\n{"
        )
        slot_guard = hook[
            slot_guard_start:
            hook.index(
                "static BOOL install_manager_render_interposition(",
                slot_guard_start,
            )
        ]
        self.assertNotIn("InterlockedCompareExchangePointer(", slot_guard)
        self.assertIn(
            "read_pointer(\n"
            "            (DWORD)(ULONG_PTR)MANAGER_TICK_VTABLE_SLOT, 0u,",
            slot_guard,
        )
        self.assertIn("if (observed == hook)", slot_guard)
        self.assertIn("if (observed != manager_tick_original ||", slot_guard)
        self.assertIn("replace_dispatch_slot(", slot_guard)
        self.assertIn(
            "WaitForSingleObject(\n"
            "                   ready_event, LATE_BOOTSTRAP_COMPLETION_WAIT_MS)",
            completion,
        )
        bootstrap_identity = hook[
            hook.index("static BOOL calibration_bootstrap_manager_ready"):
            hook.index("static BOOL validate_calibration_manager_identity")
        ]
        self.assertLess(
            bootstrap_identity.index("if (expected_manager != 0u)"),
            bootstrap_identity.index(
                "application = (DWORD)(ULONG_PTR)"
            ),
        )
        self.assertIn(
            "return mode_set_manager == (LONG)expected_manager",
            bootstrap_identity,
        )
        self.assertIn("manager_application == application", bootstrap_identity)
        manager_tick = hook[
            hook.index("static DWORD __attribute__((used)) "
                       "manager_tick_prepare"):
            hook.index("static void __attribute__((naked)) "
                       "manager_render_vtable_hook")
        ]
        self.assertLess(
            manager_tick.index(
                "validate_calibration_manager_identity(manager_address)"
            ),
            manager_tick.index("record_mode_lifecycle(manager_address)"),
        )
        identity_validation = hook[
            hook.index("static BOOL validate_calibration_manager_identity"):
            hook.index("static DWORD WINAPI late_bootstrap_retry_thread")
        ]
        self.assertIn("expected_manager == 0", identity_validation)
        self.assertIn("rooted_manager != manager_address", identity_validation)
        self.assertIn("manager_application != application", identity_validation)
        self.assertIn('create_observer_event("LoginPending", preowned', hook)
        self.assertIn('create_observer_event("LoginActivated", preowned', hook)
        self.assertIn('"MIEL_OBSERVER_EVENTS_PREOWNED"', hook)
        self.assertIn("ERROR_ALREADY_EXISTS) != preowned", hook)
        self.assertIn("WaitForSingleObject(*event_out, 0u) != WAIT_TIMEOUT", hook)
        self.assertIn("bootstrap_login_pending_missed", hook)
        self.assertIn("bootstrap_login_activation_contract", hook)
        self.assertIn("bootstrap_login_activation_read_contract", hook)
        self.assertIn('strcmp(transition->requested_mode, "mode_barn")', hook)
        self.assertIn("first_called_mode_transition_not_barn", hook)
        self.assertIn("first_called_mode_transition_manager_mismatch", hook)
        self.assertIn('emit_mode_transition("bootstrap_pending"', hook)
        self.assertIn('emit_mode_activation(transition, "manager_tick_current_mode")', hook)
        transition_records = hook[
            hook.index("static void emit_mode_transition"):
            hook.index("static void emit_bootstrap_diagnostic")
        ]
        self.assertEqual(
            transition_records.count(
                "next_id(&mode_transition_sequence_number)"
            ),
            2,
        )
        self.assertNotIn("next_id(&sequence_number)", transition_records)
        self.assertNotIn("%p", transition_records)
        self.assertNotIn('\\"manager_address\\"', transition_records)
        self.assertNotIn("MIEL_OBSERVER_AUTOSTART", hook)
        self.assertNotIn("drive_semantic_session", hook)
        self.assertNotIn("pump_engine_messages", hook)
        self.assertNotIn("UpdateWindow(projector_window)", hook)
        self.assertNotIn("semantic_timer_callback", hook)
        self.assertNotIn("semantic_driver_call", hook)
        login_dispatch_start = hook.rindex("static BOOL dispatch_ci_session")
        login_dispatch = hook[
            login_dispatch_start:
            hook.index("static BOOL login_dispatch_ready", login_dispatch_start)
        ]
        self.assertIn("current + 0xd5u", login_dispatch)
        self.assertIn("current + 0xd4u", login_dispatch)
        self.assertIn("current + 0x1d8u", login_dispatch)
        self.assertNotIn("current + 0x210u", login_dispatch)
        self.assertIn("MemoryBarrier()", login_dispatch)
        self.assertNotIn("LOGIN_FIND_OR_CREATE)(", login_dispatch)
        self.assertNotIn("SESSION_LOAD)(", login_dispatch)
        self.assertNotIn("MODE_SET)(", login_dispatch)
        login_identity = hook[
            hook.index("static BOOL canonical_profile_state"):
            hook.index("static BOOL flight_native_preroll_pending")
        ]
        self.assertIn("id == -1", login_identity)
        self.assertIn("id == 0", login_identity)
        self.assertIn("read_byte(login_address, 0xd4u, &editing)", login_identity)
        self.assertIn("login_address + 0xd5u", login_identity)
        self.assertIn("login_address + 0x1d8u", login_identity)
        self.assertIn('memcmp(input, "MVO_CI", 6u)', login_identity)
        self.assertNotIn("USER_GET_NAME", login_identity)
        self.assertNotIn("id >=", login_identity)
        self.assertIn("canonical_profile_state(application, current)", login_dispatch)
        login_ready = hook[
            hook.index("static BOOL login_dispatch_ready"):
            hook.index("static void __attribute__((used)) record_mode_lifecycle")
        ]
        self.assertIn("canonical_profile_state(application, current)", login_ready)
        lifecycle = hook[
            hook.index("static void __attribute__((used)) record_mode_lifecycle"):
            hook.index("static void __attribute__((used)) record_login_tick")
        ]
        self.assertIn('exact_barn_ready(manager_address, &barn_view)', lifecycle)
        self.assertIn("send_projector_click(104, 164)", lifecycle)
        self.assertIn('native_barn_inside_door', lifecycle)
        self.assertIn("barn_airplane_is_complete(manager_address)", lifecycle)
        self.assertIn("send_barn_escape_input()", lifecycle)
        self.assertIn('native_barn_escape_input', lifecycle)
        self.assertNotIn('BARN_FLYAWAY)(barn_mode)', lifecycle)
        self.assertNotIn("send_projector_click(596, 322)", lifecycle)
        self.assertIn("observe_native_flight_bootstrap(manager_address)", lifecycle)
        self.assertIn(
            "InterlockedCompareExchange(\n                    &session_state, SESSION_ARMED, SESSION_DISPATCHED)",
            lifecycle,
        )
        self.assertIn(
            'emit_session("armed", "native_flight_preroll_pending")',
            lifecycle,
        )
        self.assertNotIn("original_srand", lifecycle)
        record_tick = hook[
            hook.index("static DWORD __attribute__((used)) record_tick"):
            hook.index("static void __attribute__((used)) record_controls_pre")
        ]
        self.assertIn("verify_replay_key_sample(manager_node, tick)", record_tick)
        self.assertIn("session_state == SESSION_ARMED", record_tick)
        self.assertIn("original_srand((unsigned int)replay_rng_seed)", record_tick)
        self.assertIn(
            'emit_session("ready", "seeded_before_first_native_flight_step")',
            record_tick,
        )
        self.assertLess(
            record_tick.index("original_srand((unsigned int)replay_rng_seed)"),
            record_tick.index("InterlockedExchange(&session_state, SESSION_READY)"),
        )
        readiness = hook[
            hook.index("static BOOL exact_session_ready"):
            hook.index("static BOOL exact_barn_ready")
        ]
        self.assertIn('"mode_fly"', readiness)
        self.assertNotIn("registered_flight", readiness)
        self.assertIn("registered_render_list != flight_render_list", readiness)
        self.assertIn("flight_manager != manager_address", readiness)
        self.assertIn("flight_physics != physics", readiness)
        self.assertIn("!flight_native_preroll_pending(physics)", readiness)
        self.assertNotIn('"mode_mygghanget"', readiness)
        self.assertIn("read_byte(flight_address, 0x124u", hook)
        preroll = hook[
            hook.index("static BOOL flight_native_preroll_pending"):
            hook.index("static BOOL canonical_session_root")
        ]
        self.assertIn("contact_sound_initialized == 0u", preroll)
        self.assertNotIn("copy_writable", preroll)
        self.assertIn('\\"native_preroll_pending\\":%s', hook)
        manager_tick = hook[
            hook.index("static DWORD __attribute__((used)) manager_tick_prepare"):
            hook.index("static void __attribute__((naked)) manager_tick_vtable_hook")
        ]
        self.assertIn("record_mode_lifecycle(manager_address)", manager_tick)
        self.assertIn("record_tick(manager_node, dt_f32_bits)", manager_tick)
        self.assertIn("session_state != SESSION_ARMED", manager_tick)
        self.assertNotIn("manager_tick_flight_mode", manager_tick)
        input_focus = hook[
            hook.index("static void emit_input_focus"):
            hook.index("static void emit_input_transition")
        ]
        self.assertNotIn('\\"process_id\\":%lu,\\"window_thread_id\\":%lu,',
                         input_focus.split('\\"diagnostics\\"')[0])
        self.assertIn('\\"diagnostics\\":{\\"thread_id\\":%lu,\\"process_id\\":%lu,',
                      input_focus)
        rng = hook[
            hook.index("static BOOL executable_caller_rva"):
            hook.index("typedef struct ProjectorWindowEvidence")
        ]
        self.assertIn("__builtin_return_address(0)", rng)
        self.assertIn('\\"caller_rva\\":%s', rng)
        self.assertIn("SizeOfImage", rng)
        controls_post = hook[
            hook.index("static void __attribute__((used)) record_controls_post"):
            hook.index("static void __attribute__((used)) record_physics_entry")
        ]
        render_final = hook[
            hook.index("static void __attribute__((used)) record_render_final"):
            hook.index("#define SEMANTIC_HOOK")
        ]
        self.assertIn("ReplayTick *next_tick = &replay_ticks[replay_next_tick]",
                      controls_post)
        self.assertIn("arm_replay_focus_timeline(next_tick->tick)",
                      controls_post)
        self.assertIn("send_replay_keys(", controls_post)
        self.assertNotIn("send_replay_keys", render_final)
        collision_commit = hook[
            hook.index("static void __attribute__((used)) record_collision_commit"):
            hook.index("static void emit_outcome_contact")
        ]
        self.assertNotIn("resolve_read_screen_device", collision_commit)
        self.assertNotIn("record_camera_commit", collision_commit)
        self.assertNotIn("record_render_final", collision_commit)
        manager_render = hook[
            hook.index("static void __attribute__((used)) record_manager_render"):
            hook.index("static DWORD __attribute__((used)) manager_tick_prepare")
        ]
        self.assertIn("read_pointer(manager_node, 0x84u, &current)", manager_render)
        self.assertIn("record_camera_commit(current)", manager_render)
        self.assertIn("record_render_final(current, device_address)", manager_render)
        self.assertIn("complete_session_after_render()", manager_render)
        self.assertLess(
            manager_render.index("record_camera_commit(current)"),
            manager_render.index("complete_session_after_render()"),
        )
        render_inner = hook[
            hook.index("static void __attribute__((used)) record_render_final"):
            hook.index("static void complete_session_after_render")
        ]
        render_completion = hook[
            hook.index("static void complete_session_after_render"):
            hook.index("static const BodyModeLifecycle *body_mode_for_vtable")
        ]
        self.assertNotIn("SetEvent(complete_event)", render_inner)
        self.assertIn("SetEvent(complete_event)", render_completion)
        camera_commit = hook[
            hook.index("static void __attribute__((used)) record_camera_commit"):
            hook.index("static BOOL range_readable")
        ]
        self.assertIn('strcmp(mode_name, "mode_fly") == 0', camera_commit)
        self.assertIn("camera_offset = 0x58u", camera_commit)
        self.assertIn("flight_offset = 0x64u", camera_commit)
        self.assertIn("camera_offset = 0x54u", camera_commit)
        self.assertIn("flight_offset = 0x5cu", camera_commit)
        self.assertIn("read_pointer(controller_address, camera_offset, &camera_address)", camera_commit)
        self.assertIn("camera_address + 0x928u", camera_commit)
        self.assertNotIn("controller_address + 0x928u", camera_commit)
        self.assertIn("controller_address + 0x8dcu", camera_commit)
        self.assertIn('\\"camera_control_owner\\":\\"%s\\"', camera_commit)
        self.assertIn("read_byte(controller_address, 0x494cu", camera_commit)
        self.assertIn("read_byte(controller_address, 0x494du", camera_commit)
        self.assertIn("read_byte(controller_address, 0x494eu", camera_commit)
        framebuffer = hook[
            hook.index("static BOOL capture_framebuffer"):
            hook.index("static void emit_framebuffer")
        ]
        self.assertIn("virtual_read((void *)(ULONG_PTR)device_address, NULL)", framebuffer)
        self.assertNotIn("read_screen_export((void *)(ULONG_PTR)device_address, NULL)", framebuffer)
        self.assertNotIn("virtual_read_screen != (DWORD)(ULONG_PTR)read_screen_export", framebuffer)
        self.assertIn("pixel_size = pixel_size_bits / 8", framebuffer)
        self.assertIn("(pixel_size_bits & 7) != 0", framebuffer)
        self.assertIn("inspect_projector_window(&window_evidence)", framebuffer)
        self.assertIn(
            "window_evidence.client_width != PROJECTOR_CLIENT_WIDTH",
            framebuffer,
        )
        self.assertIn(
            "window_evidence.client_height != PROJECTOR_CLIENT_HEIGHT",
            framebuffer,
        )
        self.assertIn("render_ordinal <= 0", framebuffer)
        self.assertIn("non_black_pixel_count == 0u", framebuffer)
        self.assertIn('"framebuffer_window_readiness"', framebuffer)
        self.assertIn('"framebuffer_paint_progress"', framebuffer)
        self.assertIn('"framebuffer_unpainted"', framebuffer)
        self.assertIn('\\"schema\\":2', framebuffer)
        self.assertIn('\\"window_role\\":\\"top-level-projector\\"', framebuffer)
        self.assertIn(
            '\\"paint_progress\\":\\"manager-render-and-non-black\\"',
            framebuffer,
        )
        self.assertIn('\\"non_black_pixel_count\\"', framebuffer)
        self.assertIn('\\"bits_per_pixel\\"', framebuffer)
        self.assertIn('\\"bytes_per_pixel\\"', framebuffer)
        self.assertIn('\\"origin\\":\\"top-left\\"', framebuffer)
        self.assertIn('\\"packed_format\\":\\"xrgb8888-le\\"', framebuffer)
        self.assertIn('\\"memory_byte_order\\":\\"bgrx\\"', framebuffer)
        self.assertIn('\\"surface_alpha\\":\\"unused\\"', framebuffer)
        self.assertIn('\\"device_config\\":\\"config.ini\\"', framebuffer)
        self.assertIn('\\"device_module\\":\\"gtSoftware.dll\\"', framebuffer)
        self.assertIn("EXPECTED_CONFIG_SHA256", framebuffer)
        self.assertIn("EXPECTED_GT_SOFTWARE_SHA256", framebuffer)
        self.assertIn("framebuffer_capture_error", framebuffer)
        self.assertIn("BOOL raw_created = FALSE", framebuffer)
        self.assertIn("BOOL metadata_created = FALSE", framebuffer)
        self.assertIn("BOOL native_raw_created = FALSE", framebuffer)
        self.assertIn("BOOL native_metadata_created = FALSE", framebuffer)
        self.assertIn("raw_created = TRUE", framebuffer)
        self.assertIn("metadata_created = TRUE", framebuffer)
        self.assertIn("native_raw_created = TRUE", framebuffer)
        self.assertIn("native_metadata_created = TRUE", framebuffer)
        self.assertIn("if (raw_created) DeleteFileA(raw_path)", framebuffer)
        self.assertIn(
            "if (metadata_created) DeleteFileA(metadata_path)", framebuffer,
        )
        self.assertIn(
            "if (native_raw_created) DeleteFileA(native_raw_path)", framebuffer,
        )
        self.assertIn(
            "if (native_metadata_created) DeleteFileA(native_metadata_path)",
            framebuffer,
        )
        self.assertNotIn("if (raw_path[0] != '\\0') DeleteFileA", framebuffer)
        self.assertIn("row * (DWORD)pitch + column * (DWORD)pixel_size", framebuffer)
        self.assertIn("row * canonical_pitch + column * 4u", framebuffer)
        guarded_recorders = (
            "record_physics_entry", "record_physics_leave",
            "record_collision_entry", "record_collision_commit",
            "record_fuel", "record_contact", "record_damage_effective",
            "record_damage_post", "record_damage_nonterminal",
            "record_terminal_crash", "record_terrain_result",
            "record_camera_commit", "record_render_final",
        )
        for recorder in guarded_recorders:
            start = hook.index(
                f"static void __attribute__((used)) {recorder}"
            )
            boundaries = (
                hook.find("\nstatic ", start + 1),
                hook.find("\n#define ", start + 1),
            )
            end = min(position for position in boundaries if position != -1)
            self.assertIn(
                "session_state != SESSION_READY",
                hook[start:end],
                recorder,
            )
        projector_click_start = hook.index("static BOOL send_projector_click")
        projector_click = hook[
            projector_click_start:
            hook.index("static void session_fail", projector_click_start)
        ]
        self.assertIn("PostMessageA(projector_window, WM_LBUTTONDOWN", projector_click)
        self.assertIn("PostMessageA(projector_window, WM_LBUTTONUP", projector_click)
        self.assertNotIn("SendInput", projector_click)
        escape_input = hook[
            hook.index("static BOOL send_barn_escape_input"):
            hook.index("static BOOL send_projector_click")
        ]
        self.assertIn("inputs[0].ki.wScan = 0x01u", escape_input)
        self.assertIn("KEYEVENTF_SCANCODE", escape_input)
        self.assertIn("KEYEVENTF_KEYUP", escape_input)
        self.assertIn("SendInput(2u, inputs", escape_input)
        start_engine_input = hook[
            hook.index("static BOOL send_bootstrap_faster_input"):
            hook.index("static BOOL send_projector_click")
        ]
        self.assertIn("input.ki.wScan = 0x2au", start_engine_input)
        self.assertIn("KEYEVENTF_SCANCODE", start_engine_input)
        self.assertIn("KEYEVENTF_KEYUP", start_engine_input)
        self.assertIn("SendInput(1u, &input", start_engine_input)
        bootstrap_start = hook.index(
            "static BOOL observe_native_flight_bootstrap"
        )
        bootstrap = hook[
            bootstrap_start:
            hook.index("static BOOL login_dispatch_ready", bootstrap_start)
        ]
        self.assertIn("state != 5u && state != 4u && state != 0u", bootstrap)
        self.assertIn("exact_mygghanget_departure_transition", bootstrap)
        self.assertIn("bootstrap_mygghanget_to_flight_contract", bootstrap)
        self.assertIn("bootstrap_faster_sample_observed", bootstrap)
        self.assertIn("manager_address + 0x108u, &sampled_keys_valid", bootstrap)
        self.assertIn("send_bootstrap_faster_input(TRUE)", bootstrap)
        self.assertIn("send_bootstrap_faster_input(FALSE)", bootstrap)
        exact_departure = hook[
            hook.index("static BOOL exact_mygghanget_departure_transition"):
            hook.index("static BOOL exact_session_ready")
        ]
        self.assertIn("transition->caller_site == 0x00425c2eu", exact_departure)
        self.assertIn("transition->caller_site == 0x004262eeu", exact_departure)
        self.assertIn("matches != 1u", exact_departure)
        self.assertIn(
            'strcmp(transition->source_mode, "mode_mygghanget")',
            exact_departure,
        )
        self.assertIn(
            'strcmp(transition->requested_mode, "mode_fly")',
            exact_departure,
        )
        self.assertIn("memcmp(BARN_FLYAWAY, BARN_FLYAWAY_SIGNATURE", hook)
        self.assertIn(
            "memcmp(BARN_INPUT_DISPATCH, BARN_INPUT_DISPATCH_SIGNATURE", hook
        )
        self.assertIn(
            "memcmp(BARN_ESCAPE_LOOKUP, BARN_ESCAPE_LOOKUP_SIGNATURE", hook
        )
        self.assertIn(
            "memcmp(BARN_ESCAPE_ACTION, BARN_ESCAPE_ACTION_SIGNATURE", hook
        )
        self.assertIn(
            "memcmp(MYGGHANGET_START_ENGINE_GATE,", hook
        )
        self.assertIn(
            "memcmp(MYGGHANGET_DIRECT_DEPARTURE,", hook
        )
        self.assertLess(
            lifecycle.index("exact_session_ready(manager_address)"),
            lifecycle.index("send_replay_keys(0u"),
        )
        controller = hook[
            hook.index("static DWORD WINAPI session_controller_thread"):
            hook.index("static BOOL application_identity_matches")
        ]
        self.assertNotIn("record_mode_lifecycle", controller)
        self.assertNotIn("MANAGER_TICK_VTABLE_SLOT", controller)
        self.assertNotIn("UpdateWindow", controller)
        self.assertIn("EXPECTED_EXE_SHA256", hook)
        self.assertIn("STARTUP_MODE_ARGUMENT_SIGNATURE", hook)
        self.assertIn("memcmp(STARTUP_MODE_ARGUMENT", hook)
        self.assertNotIn("install_detour(FLIGHT_TICK", hook)
        self.assertEqual(
            hook.count("install_detour(LOGIN_TICK, LOGIN_TICK_SIGNATURE"), 1,
        )
        self.assertIn("diagnostic_direct_login_tick &&", hook)
        self.assertNotIn("install_detour(MODE_LIFECYCLE_RETURN", hook)
        self.assertIn("EnumWindows(post_null_to_process_window", launcher)
        self.assertIn("FLIGHT_STEP_ENTRY", hook)
        self.assertIn("FLIGHT_STEP_LEAVE", hook)
        for boundary in (
            "COLLISION_ENTRY", "CONTROLS_SAMPLE", "CAMERA_ENTRY", "RENDER_ENTRY",
        ):
            self.assertIn(boundary, hook)
        for channel in (
            "controls.sample.raw", "physics.entry.raw", "physics.leave.raw",
            "collision.entry.raw", "camera.entry.raw", "render.entry.raw",
        ):
            self.assertIn(channel, hook)
        self.assertIn("flight_entry_trampoline", hook)
        self.assertIn("flight_leave_trampoline", hook)
        self.assertIn("rollback_detour", hook)
        self.assertIn("GET_MODULE_HANDLE_EX_FLAG_PIN", hook)
        self.assertIn("fxsave", hook)
        self.assertIn("fxrstor", hook)
        self.assertIn("SetLastError", hook)
        self.assertNotIn("SetThreadContext", hook)
        self.assertNotIn("dispatch_application_lifecycle", hook)
        self.assertNotIn("NATIVE_APPLICATION_INITIALIZE", hook)
        self.assertNotIn("NATIVE_DISPATCHER_RENDER", hook)
        self.assertNotIn("SESSION_PUMP_MESSAGE", hook)
        self.assertIn("session_controller_thread", hook)
        self.assertNotIn("drive_session_from_application_root", hook)
        self.assertNotIn("MANAGER_LIFECYCLE", hook)
        self.assertNotIn("run_pending_flight_lifecycle", hook)
        self.assertNotIn("MODE_COMMIT", hook)
        self.assertIn("0x0040f824u", hook)
        self.assertIn("0x00410cdfu", hook)
        self.assertIn("pushl 428(%eax)", hook)
        self.assertIn("flds 424(%esp)", hook)
        self.assertIn("collision_entry_resume", hook)
        collision_entry_hook = hook[
            hook.index("static void __attribute__((naked)) collision_entry_hook"):
            hook.index("SEMANTIC_HOOK(collision_commit_hook")
        ]
        self.assertIn('"flds 424(%esp)\\n\\tjmp *_collision_entry_resume',
                      collision_entry_hook)
        self.assertNotIn("collision_entry_trampoline", collision_entry_hook)
        self.assertIn(
            "collision_entry_resume __attribute__((used)) =\n"
            "    (void *)(ULONG_PTR)0x00410ce6u;",
            hook,
        )
        self.assertIn("_controls_post_resume", hook)
        self.assertIn("_render_final_resume", hook)
        self.assertIn("MIEL_OBSERVER_DIAGNOSTIC_SKIP_TARGET", hook)
        self.assertIn("MIEL_OBSERVER_DIAGNOSTIC_PROFILE", hook)
        self.assertIn('strcmp(profile, "session-only")', hook)
        self.assertIn("diagnostic_skip_target_allowed", hook)
        self.assertIn("target == diagnostic_skip_target", hook)
        self.assertIn("0x00411d52u", hook)
        self.assertIn("0x00411fa8u", hook)
        self.assertIn("0x0042db51u", hook)
        self.assertNotIn("SetWindowLongA", hook)
        self.assertNotIn("SetWindowsHookExA", hook)
        self.assertNotIn("commit_pending_login", hook)
        self.assertNotIn("MODE_TICK_RETURNED", hook)
        self.assertNotIn("LOGIN_DIAGNOSTIC", hook)
        self.assertIn("APPLICATION_GETTER", hook)
        self.assertIn("canonical_session_root", hook)
        self.assertIn("static BOOL install_manager_render_interposition(void);", hook)
        self.assertIn('session_fail("manager_render_interposition")', hook)
        render_install = hook[
            hook.index("static BOOL install_manager_render_interposition(void)\n{"):
            hook.index("static BOOL rollback_manager_tick_interposition")
        ]
        self.assertIn("if (manager_render_interposed) return TRUE", render_install)
        tick_install = hook[
            hook.index("static BOOL install_manager_tick_interposition(void)\n{"):
            hook.index("static BOOL install_manager_render_interposition(void)\n{")
        ]
        self.assertNotIn("MANAGER_RENDER_VTABLE_SLOT", tick_install)
        self.assertIn("read_pointer(application, 0x1acu, &rooted_manager)", hook)
        self.assertIn("manager_application != application", hook)
        self.assertNotIn("user_context", hook)
        self.assertNotIn("login_user", hook)
        self.assertIn("static LONG WINAPI record_bootstrap_exception", hook)
        exception_handler = hook[
            hook.index("static LONG WINAPI record_bootstrap_exception"):
            hook.index("static DWORD rotate_right")
        ]
        self.assertIn("bootstrap_diagnostics_enabled", exception_handler)
        self.assertIn("EXCEPTION_ACCESS_VIOLATION", exception_handler)
        self.assertIn("EXCEPTION_ILLEGAL_INSTRUCTION", exception_handler)
        self.assertIn('code_name = "ILLEGAL_INSTRUCTION"', exception_handler)
        self.assertIn('access_kind_json', exception_handler)
        self.assertIn('exception->ContextRecord->Esp', exception_handler)
        self.assertIn('stack_words', exception_handler)
        self.assertIn('miel-vliegt-native-exception', exception_handler)
        self.assertIn("EXCEPTION_CONTINUE_SEARCH", exception_handler)
        self.assertNotIn("EXCEPTION_CONTINUE_EXECUTION", exception_handler)
        self.assertIn("AddVectoredExceptionHandler", hook)
        self.assertIn("RemoveVectoredExceptionHandler", hook)

    def test_capability_matrix_rejects_int3_and_selects_proven_ud2_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "probe.json"
            capability_executable = root / "capability.exe"
            capability_executable.touch()

            def fake_run(command, **_kwargs):
                if "wineserver" in command:
                    return self.completed_run()
                profile = "ud2-exception" if "ud2" in command else "default-int3"
                receipt_path = root / f"win32-debug-capability-box64-{profile}.json"
                supported = profile == "ud2-exception"
                receipt_path.write_text(json.dumps(self.debug_capability_receipt(
                    "SUPPORTED" if supported else "UNSUPPORTED",
                    "ud2" if supported else "int3",
                )), encoding="utf-8")
                return self.completed_run(exit_code=0 if supported else 1)

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run):
                result = probe_debug_capability(
                    ["env", "WINEPREFIX=/tmp/prefix", "HODLL=wowbox64.dll"],
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    output,
                    capability_executable,
                )

            self.assertEqual(result["capability"], "SUPPORTED")
            self.assertEqual(result["selected_profile"]["id"], "ud2-exception")
            self.assertEqual(
                [attempt["capability"] for attempt in result["attempts"]],
                ["UNSUPPORTED", "SUPPORTED"],
            )

    def test_supported_capability_receipt_fails_closed_on_a_missing_check(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            receipt = self.debug_capability_receipt("SUPPORTED")
            del receipt["checks"]["set_thread_context_ok"]
            path.write_text(json.dumps(receipt), encoding="utf-8")
            self.assertIsNone(read_debug_capability_receipt(path))

    def test_supported_capability_receipt_requires_exact_unique_traps(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            receipt = self.debug_capability_receipt("SUPPORTED")
            for mutation in (
                lambda value: value.update(deliberate_breakpoint_hits=3),
                lambda value: value.update(deliberate_trap_address=True),
                lambda value: value.update(
                    deliberate_second_trap_address=value["deliberate_trap_address"]
                ),
            ):
                candidate = json.loads(json.dumps(receipt))
                mutation(candidate)
                path.write_text(json.dumps(candidate), encoding="utf-8")
                self.assertIsNone(read_debug_capability_receipt(path))

    def test_terminal_supported_receipt_survives_hung_backend_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "probe.json"
            capability_executable = root / "capability.exe"
            capability_executable.touch()

            def fake_run(_command, **_kwargs):
                if any("wineserver" in part for part in _command):
                    return self.completed_run()
                receipt_path = root / "win32-debug-capability-fex-default-int3.json"
                receipt_path.write_text(json.dumps(
                    self.debug_capability_receipt("SUPPORTED")
                ), encoding="utf-8")
                value = self.completed_run()
                value["timed_out"] = True
                value["exit_code"] = None
                return value

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run):
                result = probe_debug_capability(
                    ["env", "WINEPREFIX=/tmp/prefix", "HODLL=libwow64fex.dll"],
                    {"id": "fex", "hodll": "libwow64fex.dll"},
                    output,
                    capability_executable,
                )

            self.assertEqual(result["capability"], "SUPPORTED")
            self.assertFalse(result["attempts"][0]["controller_cleanup_completed"])

    def test_capability_matrix_fails_closed_when_wineserver_cannot_be_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "probe.json"
            capability_executable = root / "capability.exe"
            capability_executable.touch()

            def fake_run(command, **_kwargs):
                if any("wineserver" in part for part in command):
                    value = self.completed_run()
                    value["timed_out"] = True
                    value["exit_code"] = None
                    return value
                (root / "win32-debug-capability-box64-default-int3.json").write_text(
                    json.dumps(self.debug_capability_receipt("SUPPORTED")),
                    encoding="utf-8",
                )
                return self.completed_run()

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run):
                result = probe_debug_capability(
                    ["env", "WINEPREFIX=/tmp/prefix", "HODLL=wowbox64.dll"],
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    output,
                    capability_executable,
                )

            self.assertEqual(result["capability"], "INDETERMINATE")
            self.assertFalse(result["prefix_clean"])
            self.assertIsNone(result["selected_profile"])

    def test_scene_receipt_requires_the_target_loader_and_mode_manager(self):
        from tools.miel_vliegt.hangover_probe import validate_scene_receipt

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            receipt = root / "scene.json"
            value = {
                "schema": 1,
                "protocol": "miel-vliegt-native-scene-navigation",
                "status": "PASS",
                "phase": "scene-loader",
                "trap_strategy": "int3",
                "executable_sha256": __import__("hashlib").sha256(b"pinned").hexdigest(),
                "scene": {"id": "roy_mccoy"},
                "mode_manager_observed": True,
            }
            receipt.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(validate_scene_receipt(receipt, executable, "roy_mccoy"), value)
            value["phase"] = "mode-transition"
            receipt.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "failed closed"):
                validate_scene_receipt(receipt, executable, "roy_mccoy")

    def test_scene_navigation_falls_back_when_hangover_forwards_no_debug_events(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            output = root / "receipt" / "probe.json"
            output.parent.mkdir()
            scene_debugger = root / "debugger.exe"
            scene_debugger.touch()
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            launcher = root / "launcher.exe"
            launcher.write_bytes(b"launcher")
            real_dinput = root / "dinput-real.dll"
            real_dinput.write_bytes(b"real dinput")
            (root / "config.ini").write_text(
                "gtdriver gtDirect3D\nsetupwindow true\nfullscreen true\n",
                encoding="ascii",
            )

            def fake_run(_command, **_kwargs):
                self.assertEqual(
                    (root / "config.ini").read_bytes(),
                    b"gtdriver gtSoftware\n"
                    b"setupwindow false\n"
                    b"fullscreen false\n",
                )
                patch_path = output.parent / "native-scene-patch-box64.json"
                patched = executable.parent / "MulleMeck-scene-box64.exe"
                (output.parent / "native-observer-box64.log").write_text(
                    'MVO {"status":"LOADED"}\n', encoding="utf-8",
                )
                checks = {name: True for name in (
                    "created_suspended", "loader_initialization_completed",
                    "proxy_observer_ready",
                    "observer_loaded", "observer_initialized", "main_thread_resumed",
                    "login_pending_observed", "ready_before_login_pending",
                    "login_activation_observed",
                    "ready_before_login_activation",
                    "message_loop_wake_posted",
                    "projector_input_idle", "scenario_completion_event",
                    "observer_failure_event_clear", "observation_window_completed",
                    "target_terminated",
                )}
                checks["main_thread_resume_count"] = 1
                checks["native_dispatch_requested"] = False
                checks["native_dispatch_completion_event"] = False
                (output.parent / "native-observer-launch-box64.json").write_text(
                    json.dumps({
                        "schema": 1, "protocol": "miel-vliegt-native-observer-launch",
                        "bootstrap_strategy": OBSERVER_BOOTSTRAP_STRATEGY,
                        "input_idle_probe_timeout_ms": OBSERVER_INPUT_IDLE_PROBE_TIMEOUT_MS,
                        "proxy_bootstrap_timeout_ms": OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS,
                        "detail": "observer-bootstrap-complete",
                        "status": "PASS", "phase": "cleanup",
                        "scene": "roy_mccoy",
                        "original_executable_sha256": __import__("hashlib").sha256(b"pinned").hexdigest(),
                        "patched_executable_sha256": __import__("hashlib").sha256(b"patched").hexdigest(),
                        "observer_dll_sha256": __import__("hashlib").sha256(b"observer").hexdigest(),
                        "real_dinput_sha256": __import__("hashlib").sha256(
                            b"real dinput"
                        ).hexdigest(),
                        "patch_receipt_sha256": __import__("hashlib").sha256(patch_path.read_bytes()).hexdigest(),
                        "capture_process": None,
                        "checks": checks,
                    }), encoding="utf-8",
                )
                return self.completed_run()

            patched_paths = []

            def fake_patch(_source, patched, _manifest, _scene, **kwargs):
                patched_paths.append(patched)
                patched.write_bytes(b"patched")
                return {
                    "schema": 1,
                    "protocol": "miel-vliegt-native-scene-start-patch",
                    "status": "PREPARED", "strategy": "startup-mode-argument",
                    "marker_directory": None,
                    "source_executable_sha256": __import__("hashlib").sha256(b"pinned").hexdigest(),
                    "patched_executable_sha256": __import__("hashlib").sha256(b"patched").hexdigest(),
                    "scene": {"id": "roy_mccoy"},
                    "changes": [{"kind": "startup-mode-argument"}],
                }

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run), \
                 patch("tools.miel_vliegt.native_scene_navigator.load_manifest", return_value={}), \
                 patch("tools.miel_vliegt.native_scene_navigator.scene_by_id", return_value={"id": "roy_mccoy"}), \
                 patch("tools.miel_vliegt.native_scene_navigator.patch_executable", side_effect=fake_patch):
                result = run_scene_navigation(
                    ["env", "WINEPREFIX=/tmp/prefix"],
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    executable,
                    output,
                    "roy_mccoy",
                    scene_debugger,
                    observer,
                    launcher,
                    attempt_debug=False,
                    real_dinput=real_dinput,
                )

            self.assertEqual(result["route"], "suspended-process-observer-launcher")
            self.assertTrue(result["scene_bootstrap_confirmed"])
            self.assertFalse(result["scene_loader_confirmed"])
            self.assertFalse(result["debug_event_forwarding"])
            self.assertEqual(result["headless_config"], {
                "path": str(root / "config.ini"),
                "sha256": HEADLESS_CONFIG_SHA256,
                "driver": "gtSoftware",
            })
            self.assertEqual(patched_paths, [executable.parent / "MulleMeck-scene-box64.exe"])

    def test_semantic_navigation_launches_original_bytes_without_calling_patcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            output = root / "receipt/capture.json"
            output.parent.mkdir()
            observer = root / "observer.dll"
            observer.write_bytes(b"observer")
            launcher = root / "launcher.exe"
            launcher.write_bytes(b"launcher")
            real_dinput = root / "dinput-real.dll"
            real_dinput.write_bytes(b"real dinput")
            disposable = root / "game-proxy/MulleMeck.exe"
            disposable.parent.mkdir()
            (disposable.parent / "DINPUT.dll").write_bytes(b"proxy")
            executable_hash = __import__("hashlib").sha256(b"pinned").hexdigest()

            def fake_run(command, **_kwargs):
                self.assertEqual(
                    _kwargs["timeout"],
                    observer_launcher_host_deadline(120_000),
                )
                receipt_path = output.parent / "native-unmodified-start-box64.json"
                observer_log = output.parent / "native-observer-box64.log"
                observer_log.write_text('MVO {"status":"LOADED"}\n', encoding="utf-8")
                source = command[command.index("--source") + 1]
                target = command[command.index("--target") + 1]
                bound_real_dinput = command[command.index("--real-dinput") + 1]
                self.assertEqual(
                    bound_real_dinput,
                    r"Z:" + str(real_dinput.resolve()).replace("/", "\\"),
                )
                self.assertFalse(any(
                    item.startswith("MIEL_REAL_DINPUT=")
                    or item.startswith("MIEL_OBSERVER_DLL=")
                    for item in command
                ))
                self.assertNotEqual(source, target)
                self.assertTrue(
                    target.replace("\\", "/").endswith(
                        "/game-proxy/MulleMeck.exe"
                    )
                )
                checks = {name: True for name in (
                    "created_suspended", "loader_initialization_completed",
                    "proxy_observer_ready",
                    "observer_loaded", "observer_initialized", "main_thread_resumed",
                    "login_pending_observed", "ready_before_login_pending",
                    "login_activation_observed",
                    "ready_before_login_activation",
                    "message_loop_wake_posted", "projector_input_idle",
                    "scenario_completion_event", "observer_failure_event_clear",
                    "observation_window_completed", "target_terminated",
                )}
                checks["main_thread_resume_count"] = 1
                checks["native_dispatch_requested"] = False
                checks["native_dispatch_completion_event"] = False
                (output.parent / "native-observer-launch-box64.json").write_text(
                    json.dumps({
                        "schema": 1,
                        "protocol": "miel-vliegt-native-observer-launch",
                        "bootstrap_strategy": OBSERVER_BOOTSTRAP_STRATEGY,
                        "input_idle_probe_timeout_ms": OBSERVER_INPUT_IDLE_PROBE_TIMEOUT_MS,
                        "proxy_bootstrap_timeout_ms": OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS,
                        "detail": "observer-bootstrap-complete",
                        "status": "PASS",
                        "phase": "cleanup",
                        "scene": "flight",
                        "original_executable_sha256": executable_hash,
                        "patched_executable_sha256": executable_hash,
                        "observer_dll_sha256": __import__("hashlib").sha256(
                            b"observer"
                        ).hexdigest(),
                        "real_dinput_sha256": __import__("hashlib").sha256(
                            b"real dinput"
                        ).hexdigest(),
                        "patch_receipt_sha256": __import__("hashlib").sha256(
                            receipt_path.read_bytes()
                        ).hexdigest(),
                        "capture_process": None,
                        "checks": checks,
                    }),
                    encoding="utf-8",
                )
                return self.completed_run()

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run), \
                 patch("tools.miel_vliegt.native_scene_navigator.load_manifest", return_value={}), \
                 patch("tools.miel_vliegt.native_scene_navigator.scene_by_id", return_value={
                     "id": "flight", "kind": "runtime_mode",
                 }), \
                 patch("tools.miel_vliegt.native_scene_navigator.patch_executable") as patcher:
                result = run_scene_navigation(
                    ["env"], {"id": "box64", "hodll": "wowbox64.dll"}, executable, output, "flight",
                    root / "debugger.exe", observer, launcher,
                    attempt_debug=False, unmodified_start=True,
                    unmodified_target=disposable, real_dinput=real_dinput,
                )

            patcher.assert_not_called()
            self.assertEqual(result["route"], "suspended-process-observer-launcher")
            self.assertIsNone(result["start_patch_receipt"])
            self.assertEqual(
                validate_unmodified_start_receipt(
                    result["start_executable_receipt"], executable,
                    disposable, "flight",
                )["changes"],
                [],
            )
            self.assertEqual(executable.read_bytes(), b"pinned")

    def test_probe_selects_bootstrap_without_running_rejected_debug_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"game")
            files = [root / name for name in (
                "smoke.exe", "capability.exe", "debugger.exe", "launcher.exe", "observer.dll",
            )]
            for item in files:
                item.write_bytes(b"pe")
            output = root / "probe.json"
            order = []
            bootstrap = {"usable": True, "checks": {"ready": True}, "runs": {}}

            def fake_navigation(*_args, **_kwargs):
                order.append("observer")
                return {
                    "route": "suspended-process-observer-launcher",
                    "scene_loader_confirmed": False,
                    "scene_bootstrap_confirmed": True,
                    "debug_event_forwarding": False,
                    "debug_receipt": None,
                    "observer_log": {"hook_loaded": True},
                    "start_patch_receipt": {"status": "PREPARED"},
                    "observer_launcher_receipt": {"status": "PASS"},
                    "partial_debug_receipt": None,
                    "runs": {
                        "debug_launch": self.completed_run(),
                        "debug_cleanup": self.completed_run(),
                        "start_patch_launch": self.completed_run(),
                    },
                }

            def fake_capability(*_args, **_kwargs):
                order.append("debug-diagnostic")
                return {
                    "capability": "UNSUPPORTED", "prefix_clean": True,
                    "selected_profile": None, "attempts": [],
                }

            contract = json.loads(CONTRACT.read_text())
            contract["target"]["executable_sha256"] = __import__("hashlib").sha256(b"game").hexdigest()
            with patch("tools.miel_vliegt.hangover_probe.validate_contract", return_value=contract), \
                 patch("tools.miel_vliegt.hangover_probe.validate_i386_pe"), \
                 patch("tools.miel_vliegt.hangover_probe.shutil.which", return_value="/bin/tool"), \
                 patch("tools.miel_vliegt.hangover_probe.bootstrap_prefix", return_value=bootstrap), \
                 patch("tools.miel_vliegt.hangover_probe.run_scene_navigation", side_effect=fake_navigation), \
                 patch("tools.miel_vliegt.hangover_probe.probe_debug_capability", side_effect=fake_capability), \
                 patch("tools.miel_vliegt.hangover_probe.run", return_value=self.completed_run("wine-11.9")):
                result = probe(
                    executable, output, files[0], files[1], "roy_mccoy",
                    observer_launcher=files[3], observer_dll=files[4],
                    require_observer_bootstrap=True,
                )

            self.assertEqual(order, ["observer"])
            self.assertTrue(result["capture_host_usable"])
            self.assertEqual(result["selected_backend"], "box64")
            self.assertEqual(result["selected_scene_route"], "suspended-process-observer-launcher")
            self.assertFalse(result["checks"]["scene_loader_confirmed"])

    def test_launcher_receipt_rejects_forged_hashes_and_false_runtime_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, patched, observer_dll, real_dinput, patch_receipt = [
                root / name for name in (
                    "original.exe", "patched.exe", "observer.dll",
                    "dinput-real.dll", "patch.json",
                )
            ]
            original.write_bytes(b"original")
            patched.write_bytes(b"patched")
            observer_dll.write_bytes(b"observer")
            real_dinput.write_bytes(b"real dinput")
            patch_receipt.write_bytes(b"patch receipt")
            checks = {name: True for name in (
                "created_suspended", "loader_initialization_completed",
                "proxy_observer_ready",
                "observer_loaded", "observer_initialized", "main_thread_resumed",
                "login_pending_observed", "ready_before_login_pending",
                "login_activation_observed",
                "ready_before_login_activation",
                "message_loop_wake_posted",
                "projector_input_idle", "scenario_completion_event",
                "observer_failure_event_clear", "observation_window_completed",
                "target_terminated",
            )}
            checks["main_thread_resume_count"] = 1
            checks["native_dispatch_requested"] = False
            checks["native_dispatch_completion_event"] = False
            value = {
                "schema": 1, "protocol": "miel-vliegt-native-observer-launch",
                "bootstrap_strategy": OBSERVER_BOOTSTRAP_STRATEGY,
                "input_idle_probe_timeout_ms": OBSERVER_INPUT_IDLE_PROBE_TIMEOUT_MS,
                "proxy_bootstrap_timeout_ms": OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS,
                "detail": "observer-bootstrap-complete",
                "status": "PASS", "phase": "cleanup", "scene": "roy_mccoy",
                "original_executable_sha256": __import__("hashlib").sha256(b"original").hexdigest(),
                "patched_executable_sha256": __import__("hashlib").sha256(b"patched").hexdigest(),
                "observer_dll_sha256": __import__("hashlib").sha256(b"observer").hexdigest(),
                "real_dinput_sha256": __import__("hashlib").sha256(b"real dinput").hexdigest(),
                "patch_receipt_sha256": __import__("hashlib").sha256(b"patch receipt").hexdigest(),
                "capture_process": None,
                "checks": checks,
            }
            receipt = root / "launch.json"
            receipt.write_text(json.dumps(value), encoding="utf-8")
            validate_observer_launcher_receipt(
                receipt, original, patched, observer_dll, real_dinput,
                patch_receipt, "roy_mccoy",
            )
            launcher_source = (
                CONTRACT.parents[2] /
                "tools/miel_vliegt/hangover/native_observer_launcher.c"
            ).read_text(encoding="utf-8")
            self.assertIn(
                f'#define OBSERVER_BOOTSTRAP_STRATEGY "{OBSERVER_BOOTSTRAP_STRATEGY}"',
                launcher_source,
            )
            self.assertIn(
                '"\\\"bootstrap_strategy\\\":\\\"" '
                'OBSERVER_BOOTSTRAP_STRATEGY "\\\","',
                launcher_source,
            )
            self.assertIn('"--real-dinput"', launcher_source)
            self.assertIn('"MIEL_REAL_DINPUT"', launcher_source)
            self.assertIn('"MIEL_OBSERVER_DLL"', launcher_source)
            self.assertIn("restore_child_environment", launcher_source)
            self.assertLess(
                launcher_source.index("set_child_environment"),
                launcher_source.index("CreateProcessA"),
            )
            self.assertGreater(
                launcher_source.index(
                    "environment_restored = restore_child_environment"
                ),
                launcher_source.index("CreateProcessA"),
            )
            for mutation in ("old-strategy", "extra-field"):
                broken = json.loads(json.dumps(value))
                if mutation == "old-strategy":
                    broken["bootstrap_strategy"] = (
                        "dinput-first-call-hook-bootstrap"
                    )
                else:
                    broken["unreviewed"] = True
                receipt.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "failed closed"):
                    validate_observer_launcher_receipt(
                        receipt, original, patched, observer_dll, real_dinput,
                        patch_receipt, "roy_mccoy",
                    )
            for field in (
                "patched_executable_sha256", "patch_receipt_sha256",
                "observer_dll_sha256", "real_dinput_sha256",
                "original_executable_sha256",
            ):
                broken = json.loads(json.dumps(value))
                broken[field] = "0" * 64
                receipt.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "failed closed"):
                    validate_observer_launcher_receipt(
                        receipt, original, patched, observer_dll, real_dinput,
                        patch_receipt, "roy_mccoy",
                    )
            for check in (
                "proxy_observer_ready",
                "login_pending_observed", "ready_before_login_pending",
                "login_activation_observed",
                "ready_before_login_activation",
                "target_terminated",
            ):
                broken = json.loads(json.dumps(value))
                broken["checks"][check] = False
                receipt.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "failed closed"):
                    validate_observer_launcher_receipt(
                        receipt, original, patched, observer_dll, real_dinput,
                        patch_receipt, "roy_mccoy",
                    )
            diagnostic = json.loads(json.dumps(value))
            diagnostic["checks"]["projector_input_idle"] = False
            receipt.write_text(json.dumps(diagnostic), encoding="utf-8")
            validate_observer_launcher_receipt(
                receipt, original, patched, observer_dll, real_dinput,
                patch_receipt, "roy_mccoy",
            )
            for counter, invalid_count in (
                ("main_thread_resume_count", True),
                ("main_thread_resume_count", 2),
            ):
                broken = json.loads(json.dumps(value))
                broken["checks"][counter] = invalid_count
                receipt.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "failed closed"):
                    validate_observer_launcher_receipt(
                        receipt, original, patched, observer_dll, real_dinput,
                        patch_receipt, "roy_mccoy",
                    )

    def test_bootstrap_rejects_missing_loaded_marker_and_launcher_timeout(self):
        for failure in ("missing-log", "timeout"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                executable = root / "MulleMeck.exe"
                executable.write_bytes(b"original")
                observer = root / "observer.dll"
                observer.write_bytes(b"observer")
                launcher = root / "launcher.exe"
                launcher.write_bytes(b"launcher")
                output = root / "receipt" / "probe.json"
                output.parent.mkdir()

                def fake_patch(_source, patched, *_args, **_kwargs):
                    patched.write_bytes(b"patched")
                    return {"status": "PREPARED"}

                def fake_run(*_args, **_kwargs):
                    if failure == "timeout":
                        (output.parent / "native-observer-box64.log").write_text(
                            'MVO {"status":"LOADED"}\n', encoding="utf-8",
                        )
                        value = self.completed_run()
                        value["timed_out"] = True
                        value["exit_code"] = None
                        return value
                    return self.completed_run()

                with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run), \
                     patch("tools.miel_vliegt.native_scene_navigator.load_manifest", return_value={}), \
                     patch("tools.miel_vliegt.native_scene_navigator.scene_by_id", return_value={"id": "roy_mccoy"}), \
                     patch("tools.miel_vliegt.native_scene_navigator.patch_executable", side_effect=fake_patch), \
                     patch("tools.miel_vliegt.hangover_probe.validate_start_patch_receipt"), \
                     patch("tools.miel_vliegt.hangover_probe.validate_observer_launcher_receipt", return_value={"status": "PASS"}):
                    result = run_scene_navigation(
                        ["env", "WINEPREFIX=/tmp/fresh"],
                        {"id": "box64", "hodll": "wowbox64.dll"},
                        executable, output, "roy_mccoy", root / "debugger.exe",
                        observer, launcher, attempt_debug=False,
                    )

                self.assertIsNone(result["route"])
                self.assertFalse(result["scene_bootstrap_confirmed"])
                self.assertFalse(result["scene_loader_confirmed"])
    def test_scene_navigation_prefers_a_confirmed_debug_event_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            output = root / "receipt" / "probe.json"
            output.parent.mkdir()
            scene_debugger = root / "debugger.exe"
            scene_debugger.touch()

            def fake_run(_command, **_kwargs):
                receipt = output.parent / "native-scene-box64.json"
                receipt.write_text(json.dumps({
                    "schema": 1,
                    "protocol": "miel-vliegt-native-scene-navigation",
                    "status": "PASS",
                    "phase": "scene-loader",
                    "trap_strategy": "int3",
                    "executable_sha256": __import__("hashlib").sha256(b"pinned").hexdigest(),
                    "scene": {"id": "roy_mccoy"},
                    "mode_manager_observed": True,
                }), encoding="utf-8")
                return self.completed_run()

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run), \
                 patch("tools.miel_vliegt.native_scene_navigator.patch_executable") as patcher:
                result = run_scene_navigation(
                    ["env", "WINEPREFIX=/tmp/prefix"],
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    executable,
                    output,
                    "roy_mccoy",
                    scene_debugger,
                )

            self.assertEqual(result["route"], "win32-debug-api")
            self.assertTrue(result["debug_event_forwarding"])
            patcher.assert_not_called()

    def test_terminal_scene_receipt_survives_hung_controller_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            output = root / "receipt" / "probe.json"
            output.parent.mkdir()
            scene_debugger = root / "debugger.exe"
            scene_debugger.touch()
            calls = 0

            def fake_run(command, **_kwargs):
                nonlocal calls
                calls += 1
                if "wineserver" in command:
                    return self.completed_run()
                (output.parent / "native-scene-box64.json").write_text(json.dumps({
                    "schema": 1,
                    "protocol": "miel-vliegt-native-scene-navigation",
                    "status": "PASS",
                    "phase": "scene-loader",
                    "trap_strategy": "int3",
                    "executable_sha256": __import__("hashlib").sha256(b"pinned").hexdigest(),
                    "scene": {"id": "roy_mccoy"},
                    "mode_manager_observed": True,
                }), encoding="utf-8")
                value = self.completed_run()
                value["timed_out"] = True
                value["exit_code"] = None
                return value

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run), \
                 patch("tools.miel_vliegt.native_scene_navigator.patch_executable") as patcher:
                result = run_scene_navigation(
                    ["env", "WINEPREFIX=/tmp/prefix"],
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    executable,
                    output,
                    "roy_mccoy",
                    scene_debugger,
                )

            self.assertEqual(result["route"], "win32-debug-api")
            self.assertFalse(result["debug_controller_cleanup_completed"])
            self.assertEqual(calls, 3)
            patcher.assert_not_called()

    def test_ud2_profile_is_bound_to_the_scene_debugger_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            output = root / "receipt" / "probe.json"
            output.parent.mkdir()
            scene_debugger = root / "debugger.exe"
            scene_debugger.touch()
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                if "wineserver" not in command:
                    (output.parent / "native-scene-box64.json").write_text(json.dumps({
                        "schema": 1,
                        "protocol": "miel-vliegt-native-scene-navigation",
                        "status": "PASS",
                        "phase": "scene-loader",
                        "trap_strategy": "ud2",
                        "executable_sha256": __import__("hashlib").sha256(b"pinned").hexdigest(),
                        "scene": {"id": "roy_mccoy"},
                        "mode_manager_observed": True,
                    }), encoding="utf-8")
                return self.completed_run()

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run):
                result = run_scene_navigation(
                    ["env", "WINEPREFIX=/tmp/prefix"],
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    executable,
                    output,
                    "roy_mccoy",
                    scene_debugger,
                    trap_strategy="ud2",
                )

            self.assertEqual(result["route"], "win32-debug-api")
            self.assertIn("ud2", commands[0])

    def test_scene_navigation_does_not_patch_a_dirty_debug_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            output = root / "receipt" / "probe.json"
            output.parent.mkdir()
            scene_debugger = root / "debugger.exe"
            scene_debugger.touch()
            calls = 0

            def fake_run(command, **_kwargs):
                nonlocal calls
                calls += 1
                if "wineserver" in command:
                    value = self.completed_run()
                    value["timed_out"] = True
                    value["exit_code"] = None
                    return value
                return self.completed_run(exit_code=1)

            with patch("tools.miel_vliegt.hangover_probe.run", side_effect=fake_run), \
                 patch("tools.miel_vliegt.native_scene_navigator.patch_executable") as patcher:
                result = run_scene_navigation(
                    ["env", "WINEPREFIX=/tmp/prefix"],
                    {"id": "box64", "hodll": "wowbox64.dll"},
                    executable,
                    output,
                    "roy_mccoy",
                    scene_debugger,
                )

            self.assertIsNone(result["route"])
            self.assertEqual(result["runs"]["start_patch_launch"]["skipped"], "debug-cleanup-failed")
            self.assertEqual(calls, 2)
            patcher.assert_not_called()

    def test_required_debug_route_never_spends_budget_on_startup_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "MulleMeck.exe"
            executable.write_bytes(b"pinned")
            output = root / "receipt" / "probe.json"
            output.parent.mkdir()
            scene_debugger = root / "debugger.exe"
            scene_debugger.touch()

            with patch("tools.miel_vliegt.hangover_probe.run") as runner, \
                 patch("tools.miel_vliegt.native_scene_navigator.patch_executable") as patcher:
                result = run_scene_navigation(
                    ["env", "WINEPREFIX=/tmp/prefix"],
                    {"id": "fex", "hodll": "libwow64fex.dll"},
                    executable,
                    output,
                    "roy_mccoy",
                    scene_debugger,
                    attempt_debug=False,
                    allow_fallback=False,
                )

            self.assertIsNone(result["route"])
            self.assertEqual(result["runs"]["start_patch_launch"]["skipped"], "debug-api-required")
            runner.assert_not_called()
            patcher.assert_not_called()


if __name__ == "__main__":
    unittest.main()
