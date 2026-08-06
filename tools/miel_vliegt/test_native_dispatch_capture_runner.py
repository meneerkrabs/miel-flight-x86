import hashlib
import json
import shutil
import tempfile
import unittest
import inspect
from pathlib import Path
from unittest.mock import patch

from tools.miel_vliegt import hangover_probe
from tools.miel_vliegt import native_dispatch_capture_job as capture_job
from tools.miel_vliegt import native_dispatch_capture_runner as runner
from tools.miel_vliegt import native_scene_navigator
from tools.miel_vliegt import scene_semantic_coverage as coverage
from tools.miel_vliegt import scene_semantic_evidence_batches as batches
from tools.miel_vliegt.native_dispatch_hook_contract import producer_build_sha256
from tools.miel_vliegt import native_dispatch_semantic_wire as semantic_wire
from tools.miel_vliegt.native_dispatch_hook_contract import EXECUTABLE_SHA256
from tools.miel_vliegt.test_native_dispatch_semantic_wire import event_for, line


ROOT = Path(__file__).resolve().parents[2]


class NativeLaunchDiagnosticTest(unittest.TestCase):
    def test_normalizes_only_bounded_allowlisted_crash_signals(self):
        diagnostic = runner._bounded_launch_diagnostic({
            "runs": {"start_patch_launch": {
                "command": ["env", "SECRET_TOKEN=never-copy-this"],
                "exit_code": None,
                "timed_out": True,
                "output_sha256": "a" * 64,
                "output_tail": [
                    "0128:warn:seh:dispatch_exception "
                    "EXCEPTION_ACCESS_VIOLATION exception "
                    "(code=c0000005) raised",
                    "wine: Unhandled page fault on read access to 01FC0FFF "
                    "at address 01FC0FFF (thread 0128), starting debugger...",
                    "0128:trace:seh:start_debugger Starting debugger "
                    "L\"winedbg --auto 292 248\"",
                    "SECRET_TOKEN=never-copy-this",
                ],
            }},
        })

        self.assertEqual(diagnostic, {
            "schema": 1,
            "protocol": "miel-vliegt-native-launch-diagnostic",
            "status": "DIAGNOSTIC_ONLY",
            "productionClaim": False,
            "parityEligible": False,
            "exitCode": None,
            "timedOut": True,
            "outputSha256": "a" * 64,
            "signals": [
                {
                    "kind": "wine-seh-exception",
                    "name": "ACCESS_VIOLATION",
                    "exceptionCode": "0xc0000005",
                },
                {
                    "kind": "wine-page-fault",
                    "access": "read",
                    "accessAddress": "0x01fc0fff",
                    "instructionAddress": "0x01fc0fff",
                },
                {"kind": "winedbg-invoked"},
            ],
            "signalsTruncated": False,
        })
        serialized = json.dumps(diagnostic, sort_keys=True)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("command", serialized)

    def test_bounds_signal_count_and_rejects_malformed_metadata(self):
        lines = [
            "wine: Unhandled page fault on write access to "
            f"{index:08X} at address {index + 16:08X} "
            f"(thread {index:04x}), starting debugger..."
            for index in range(10)
        ]
        lines.append("S" * 100_000)
        diagnostic = runner._bounded_launch_diagnostic({
            "runs": {"start_patch_launch": {
                "exit_code": True,
                "timed_out": "yes",
                "output_sha256": "A" * 64,
                "output_tail": lines,
            }},
        })

        self.assertIsNone(diagnostic["exitCode"])
        self.assertIsNone(diagnostic["timedOut"])
        self.assertIsNone(diagnostic["outputSha256"])
        self.assertEqual(len(diagnostic["signals"]), 8)
        self.assertTrue(diagnostic["signalsTruncated"])
        self.assertLess(len(json.dumps(diagnostic)), 2_000)


class NativeDispatchCaptureRunnerTest(unittest.TestCase):
    def test_internal_unmodified_start_identity_resolves_and_preserves_native_login(self):
        manifest = native_scene_navigator.load_manifest()
        target = native_scene_navigator.startup_target_by_id(
            manifest, runner.CAPTURE_SCENE,
        )

        self.assertEqual(target["id"], "flight")
        self.assertEqual(target["kind"], "runtime_mode")
        self.assertEqual(
            manifest["engine"]["startup_mode_transition"]["original_mode"],
            "mode_login",
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "tmp")
        self.root = Path(self.temp.name)
        self.plan = batches.generate()
        self.plan_path = self.root / "capture-plan.json"
        self.plan_path.write_text(
            json.dumps(self.plan, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        self.compilation = capture_job.compile_targets(self.plan_path)
        self.records = {
            row["id"]: row for row in json.loads(
                coverage.DEFAULT_LEDGER.read_text(encoding="utf-8")
            )["records"]
        }
        self.game = self.root / "game"
        self.game.mkdir()
        self.executable = self.game / "MulleMeck.exe"
        (self.game / "config.ini").write_bytes(b"initial-config")
        (self.game / "data.up").write_bytes(b"immutable-archive")
        self.observer = self.root / "native-observer-hook.dll"
        self.proxy = self.root / "DINPUT.dll"
        self.real_dinput = self.root / "dinput-real.dll"
        self.launcher_binary = self.root / "native-observer-launcher.exe"
        self.debugger = self.root / "native-scene-debugger.exe"
        for path, data in (
            (self.executable, b"MZ-executable"),
            (self.observer, b"MZ-observer"),
            (self.proxy, b"MZ-proxy"),
            (self.real_dinput, b"MZ-real-dinput"),
            (self.launcher_binary, b"MZ-launcher"),
            (self.debugger, b"MZ-debugger"),
        ):
            path.write_bytes(data)
        self.executable_identity = patch.object(
            runner, "EXECUTABLE_SHA256", self.sha(self.executable),
        )
        self.executable_identity.start()
        self.receipts = {}
        observer_sha = self.sha(self.observer)
        for target in self.compilation["targets"]:
            receipt = {
                "schema": 1,
                "protocol": "miel-vliegt-native-dispatch-observer-build-receipt",
                "capturePlanJobId": target["jobId"],
                "nativeSliceSha256": target["nativeSliceSha256"],
                "observerBinarySha256": observer_sha,
                "producerBuildSha256": producer_build_sha256(),
            }
            driver = runner.capture_driver_for_target(target)
            if driver is not None:
                receipt["captureDriverFoundation"] = {
                    "profile": runner.DRIVER_BOOTSTRAP_PROFILE,
                    "profileSha256": runner.DRIVER_BOOTSTRAP_PROFILE_SHA256,
                    "scenarioSha256": runner.DRIVER_SCENARIO_SHA256,
                    "initialUserSha256": runner.DRIVER_INITIAL_USER_SHA256,
                }
            path = self.root / f"receipt-{target['jobSha256']}.json"
            path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            self.receipts[target["jobId"]] = path
        self.cleanup_calls = []
        self.prefix_calls = []
        self.launch_calls = []
        self.next_pid = 100

    def tearDown(self):
        self.temp.cleanup()
        self.executable_identity.stop()

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def complete_prefix(prefix):
        windows = prefix / "drive_c/windows"
        (windows / "system32").mkdir(parents=True)
        (windows / "syswow64").mkdir(parents=True)
        (prefix / "dosdevices").mkdir()
        (prefix / "dosdevices/c:").symlink_to("../drive_c")
        (prefix / "dosdevices/z:").symlink_to("/")
        for relative in (
            "system.reg", "user.reg", "userdef.reg",
        ):
            (prefix / relative).touch()
        image = bytearray(70)
        image[:2] = b"MZ"
        image[0x3C:0x40] = (64).to_bytes(4, "little")
        image[64:68] = b"PE\0\0"
        image[68:70] = (0x014C).to_bytes(2, "little")
        (prefix / "drive_c/windows/system32/rundll32.exe").write_bytes(image)

    def wineserver(self, environment, cwd, backend, argument):
        self.cleanup_calls.append((tuple(environment), Path(cwd), backend, argument))
        return {"command": ["wineserver", "-k"], "exit_code": 0,
                "timed_out": False, "output_tail": []}

    def fake_launch(self, **kwargs):
        self.assertTrue(self.prefix_calls)
        self.launch_calls.append(kwargs)
        environment = dict(
            item.split("=", 1) for item in kwargs["environment"] if "=" in item
        )
        target = next(
            row for row in self.compilation["targets"]
            if row["jobId"] == environment["MIEL_OBSERVER_NATIVE_DISPATCH_JOB_ID"]
        )
        binding = {
            "capturePlanJobId": target["jobId"],
            "nativeSliceSha256": target["nativeSliceSha256"],
            "observerBinarySha256": self.sha(self.observer),
            "observerBuildReceiptSha256": self.sha(self.receipts[target["jobId"]]),
        }
        output_dir = kwargs["output"].parent
        backend_id = kwargs["backend"]["id"]
        raw = output_dir / f"native-observer-{backend_id}.log"
        record = self.records[target["claimId"]]
        self.next_pid += 1
        native_process_id = self.next_pid
        capture_session_id = f"mvds-{native_process_id:032x}"
        driver_receipt = environment.get(
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_RECEIPT"
        )
        if driver_receipt is not None:
            isolated_user = kwargs["executable"].parent / "Data" / "User"
            self.assertEqual(
                {path.name for path in isolated_user.iterdir()}, {"user0.dat"},
            )
            self.assertEqual(
                self.sha(isolated_user / "user0.dat"),
                runner.DRIVER_INITIAL_USER_SHA256,
            )
            (isolated_user / "user0.dat").write_bytes(b"native-mutated-user")
            for index in range(1, 11):
                (isolated_user / f"user{index}.dat").write_bytes(
                    runner.NATIVE_EMPTY_USER_SLOT
                )
            self.assertTrue(driver_receipt.startswith("Z:\\"))
            driver_path = Path(
                "/" + driver_receipt[3:].replace("\\", "/")
            )
            driver_version = environment[
                "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER"
            ]
            driver_mode = runner.capture_driver_for_target(target)["mode"]
            if driver_version in (
                "BOOTSTRAP_TRAVERSAL_V1", "MISSION_BARN_TRAVERSAL_V1",
            ):
                traversal_shape = {
                    "BOOTSTRAP_TRAVERSAL_V1": (
                        "NATIVE_LOGIN_BARN_MYGGHANGET_TRAVERSAL", "mode_barn",
                    ),
                    "MISSION_BARN_TRAVERSAL_V1": (
                        "NATIVE_LOGIN_BARN_TRAVERSAL", "mode_login",
                    ),
                }[driver_version]
                driver_path.write_text(json.dumps({
                    "schema": 3,
                    "protocol": runner.DRIVER_PROTOCOL,
                    "status": "PASS",
                    "driver": driver_version,
                    "bootstrap": {
                        "profile": runner.DRIVER_BOOTSTRAP_PROFILE,
                        "profileSha256":
                            runner.DRIVER_BOOTSTRAP_PROFILE_SHA256,
                        "scenarioSha256": runner.DRIVER_SCENARIO_SHA256,
                        "initialUserSha256":
                            runner.DRIVER_INITIAL_USER_SHA256,
                    },
                    "targetSha256": target["targetSha256"],
                    "nativeProcessId": native_process_id,
                    "captureSessionId": capture_session_id,
                    "managerAddress": 0x1000,
                    "entryPath": traversal_shape[0],
                    "sourceMode": traversal_shape[1],
                    "targetMode": driver_mode,
                    "naturalTransitionEvidence": False,
                    "ticks": {"loginDispatched": 9, "capture": 12},
                    "semanticStateWritePolicy": {
                        "policy": "NO_DIRECT_SEMANTIC_STATE_WRITES",
                        "loginUiBootstrapException": True,
                        "mission": False, "selector": False,
                        "root": False, "projectedValues": False,
                    },
                }, sort_keys=True, separators=(",", ":")), encoding="ascii")
            else:
                driver_path.write_text(json.dumps({
                "schema": 2 if driver_version ==
                    "GENERIC_LOCATION_CLEAN_V2" else 4,
                "protocol": runner.DRIVER_PROTOCOL,
                "status": "PASS",
                "driver": driver_version,
                "bootstrap": {
                    "profile": runner.DRIVER_BOOTSTRAP_PROFILE,
                    "profileSha256": runner.DRIVER_BOOTSTRAP_PROFILE_SHA256,
                    "scenarioSha256": runner.DRIVER_SCENARIO_SHA256,
                    "initialUserSha256": runner.DRIVER_INITIAL_USER_SHA256,
                },
                "targetSha256": target["targetSha256"],
                "nativeProcessId": native_process_id,
                "captureSessionId": capture_session_id,
                "managerAddress": 0x1000,
                "entryPath":
                    "NATIVE_BARN_MYGGHANGET_FLIGHT_THEN_ENGINE_MODE",
                "sourceMode": "mode_fly",
                "sourceModeAddress": 0x1800,
                "targetMode": driver_mode,
                "targetModeAddress": 0x2000,
                "callback": {
                    "name": "engine_mode", "id": 15,
                    "address": 0x0041E1B0,
                },
                "naturalTransitionEvidence": False,
                "flightPrerequisite": {
                    "departureCallerSite": "0x00425c2e",
                    "flightReady": True,
                },
                "ticks": {
                    "flightReady": 9, "dispatch": 10,
                    "activation": 11, "capture": 12,
                },
                "missionReadback": {
                    phase: {
                        "state": -1, "missionPresent": False,
                        "missionAddress": 0,
                        "functions": {
                            "applicationGetter": 0x00405A20,
                            "missionLookup": 0x004375E0,
                            "missionComplete": 0x00436090,
                        },
                    }
                    for phase in ("before", "hook")
                },
                "semanticStateWritePolicy": {
                    "policy": "NO_DIRECT_SEMANTIC_STATE_WRITES",
                    "loginUiBootstrapException": True,
                    "mission": False, "selector": False,
                    "root": False, "projectedValues": False,
                },
            }, sort_keys=True, separators=(",", ":")), encoding="ascii")
        installed_hooks = semantic_wire.required_semantic_hooks(target)
        forwarded_routes = semantic_wire.forwarded_route_hooks_for_target(target)
        route_forwarding = bool(forwarded_routes)
        target_capability = {
            "schema": 1,
            "protocol": semantic_wire.WIRE_PROTOCOL,
            "record": "CAPABILITY",
            "executableSha256": EXECUTABLE_SHA256,
            "producerBuildSha256": producer_build_sha256(),
            "runtimeCapture": True,
            "routeForwarding": route_forwarding,
            "engineThread": 37,
            "nativeProcessId": native_process_id,
            "captureSessionId": capture_session_id,
            "installedHookCount": len(installed_hooks),
            "installedHookMask": semantic_wire.semantic_hook_mask(installed_hooks),
            "installedHooks": list(installed_hooks),
            "forwardedRouteHooks": list(forwarded_routes),
            "capabilities": {
                name: route_forwarding if name == "route" else True
                for name in semantic_wire.DISPATCH_CAPABILITIES
            },
            **binding,
            **{
                field: target[field]
                for field in semantic_wire.TARGET_CAPABILITY_FIELDS
            },
        }
        native_event = event_for(record, 1)
        native_event.update({
            "nativeProcessId": native_process_id,
            "captureSessionId": capture_session_id,
        })
        raw.write_text(
            "observer noise\n" + line(target_capability) + "\n"
            + line(native_event) + "\nobserver shutdown\n",
            encoding="ascii",
        )
        disposable = kwargs["unmodified_target"]
        shutil.copy2(kwargs["executable"], disposable)
        start_receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-native-unmodified-start",
            "status": "PREPARED",
            "strategy": "byte-identical-disposable-copy",
            "source_executable_sha256": self.sha(kwargs["executable"]),
            "launch_executable_sha256": self.sha(kwargs["executable"]),
            "scene": kwargs["scene"],
            "changes": [],
        }
        start_path = output_dir / f"native-unmodified-start-{backend_id}.json"
        start_path.write_text(
            json.dumps(start_receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        checks = {
            "created_suspended": True,
            "loader_initialization_completed": True,
            "proxy_observer_ready": True,
            "observer_loaded": True,
            "observer_initialized": True,
            "login_pending_observed": True,
            "ready_before_login_pending": True,
            "login_activation_observed": True,
            "ready_before_login_activation": True,
            "message_loop_wake_posted": True,
            "main_thread_resumed": True,
            "main_thread_resume_count": 1,
            "projector_input_idle": True,
            "scenario_completion_event": True,
            "observer_failure_event_clear": True,
            "native_dispatch_requested": True,
            "native_dispatch_completion_event": True,
            "observation_window_completed": True,
            "target_terminated": True,
        }
        launcher_receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-native-observer-launch",
            "status": "PASS",
            "phase": "cleanup",
            "detail": "observer-bootstrap-complete",
            "bootstrap_strategy": hangover_probe.OBSERVER_BOOTSTRAP_STRATEGY,
            "input_idle_probe_timeout_ms": hangover_probe.OBSERVER_INPUT_IDLE_PROBE_TIMEOUT_MS,
            "proxy_bootstrap_timeout_ms": hangover_probe.OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS,
            "scene": kwargs["scene"],
            "original_executable_sha256": self.sha(kwargs["executable"]),
            "patched_executable_sha256": self.sha(disposable),
            "observer_dll_sha256": self.sha(kwargs["observer_dll"]),
            "real_dinput_sha256": self.sha(kwargs["real_dinput"]),
            "patch_receipt_sha256": self.sha(start_path),
            "capture_process": {
                "native_process_id": native_process_id,
                "capture_session_id": capture_session_id,
            },
            "checks": checks,
        }
        launcher_path = output_dir / f"native-observer-launch-{backend_id}.json"
        launcher_path.write_text(json.dumps(launcher_receipt), encoding="utf-8")
        return {
            "route": "suspended-process-observer-launcher",
            "scene_bootstrap_confirmed": True,
            "observer_log": {
                "path": raw.name, "sha256": self.sha(raw), "hook_loaded": True,
            },
            "start_executable_receipt": start_receipt,
            "observer_launcher_receipt": launcher_receipt,
            "captureProcess": {
                "nativeProcessId": native_process_id,
                "captureSessionId": capture_session_id,
            },
            "runs": {
                "start_patch_launch": {
                    "command": ["wine", "launcher"], "exit_code": 0,
                    "timed_out": False, "output_tail": [],
                },
            },
        }

    def prepare_prefix(self, **kwargs):
        self.prefix_calls.append(kwargs)
        return {
            "prefixBootstrap": {
                "winebootCompleted": True,
                "wineserverFlushed": True,
            },
        }

    def run_one(self, target=None, *, private_launch=None, private_wineserver=None,
                **changes):
        target = target or self.compilation["targets"][0]
        arguments = dict(
            compilation=self.compilation,
            target=target,
            plan_path=self.plan_path,
            environment=["BOX64_NORCFILES=1"],
            backend={"id": "box64", "hodll": "wowbox64.dll"},
            executable=self.executable,
            evidence_root=self.root,
            observer_dll=self.observer,
            observer_build_receipt=self.receipts[target["jobId"]],
            proxy_dll=self.proxy,
            real_dinput_dll=self.real_dinput,
            observer_launcher=self.launcher_binary,
            expected_launcher_sha256=self.sha(self.launcher_binary),
        )
        arguments.update(changes)
        with patch.object(
            runner, "_native_launch", side_effect=private_launch or self.fake_launch,
        ), patch.object(
            runner, "_prepare_wine_prefix", side_effect=self.prepare_prefix,
        ), patch.object(
            runner, "_run_wineserver",
            side_effect=private_wineserver or self.wineserver,
        ):
            return runner.run_capture_target(**arguments)

    def run_suite(self, targets, *, private_launch=None, private_wineserver=None):
        receipt_map = {
            target["jobId"]: self.receipts[target["jobId"]]
            for target in targets
        }
        with patch.object(
            runner, "_native_launch", side_effect=private_launch or self.fake_launch,
        ), patch.object(
            runner, "_prepare_wine_prefix", side_effect=self.prepare_prefix,
        ), patch.object(
            runner, "_run_wineserver",
            side_effect=private_wineserver or self.wineserver,
        ):
            return runner.run_capture_suite(
                compilation=self.compilation, targets=targets,
                plan_path=self.plan_path, environment=["BOX64_NORCFILES=1"],
                backend={"id": "box64", "hodll": "wowbox64.dll"},
                executable=self.executable, evidence_root=self.root,
                observer_dll=self.observer,
                observer_build_receipts=receipt_map,
                proxy_dll=self.proxy, real_dinput_dll=self.real_dinput,
                observer_launcher=self.launcher_binary,
                expected_launcher_sha256=self.sha(self.launcher_binary),
            )

    def test_runs_exact_unmodified_target_and_validates_real_wire(self):
        target = self.compilation["targets"][0]
        result = self.run_one(target)
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")
        self.assertFalse(result["productionClaim"])
        self.assertFalse(result["parityEligible"])
        self.assertEqual(result["claimId"], target["claimId"])
        self.assertEqual(result["semanticCandidate"]["claimId"], target["claimId"])
        self.assertEqual([row[3] for row in self.cleanup_calls], ["-k", "-w"])
        self.assertEqual(len(self.prefix_calls), 1)
        self.assertTrue(result["isolation"]["prefixBootstrap"]["wineserverFlushed"])
        call = self.launch_calls[0]
        self.assertTrue(call["unmodified_start"])
        self.assertFalse(call["attempt_debug"])
        self.assertNotEqual(call["unmodified_target"].parent, self.executable.parent)
        self.assertTrue((call["unmodified_target"].parent / "DINPUT.dll").is_file())
        env = dict(item.split("=", 1) for item in call["environment"] if "=" in item)
        self.assertEqual(env["WINEDLLOVERRIDES"], "dinput=n,b")
        self.assertEqual(
            set(env) - {
                "BOX64_NORCFILES", "WINEPREFIX", "WINEARCH",
                "WINEDLLOVERRIDES",
            },
            runner.OBSERVER_ENV_KEYS,
        )
        self.assertEqual(env["MIEL_OBSERVER_NATIVE_DISPATCH_TARGET_SHA256"], target["targetSha256"])
        self.assertEqual(env["MIEL_OBSERVER_NATIVE_DISPATCH_CLAIM_SHA256"], target["claimSha256"])
        staged = Path(result["isolation"]["runDirectory"]) / "evidence"
        self.assertTrue((staged / "capture-plan.json").is_file())
        self.assertTrue((staged / "native-observer-hook.dll").is_file())
        self.assertTrue((staged / "dinput-real.dll").is_file())
        self.assertEqual(call["real_dinput"], staged / "dinput-real.dll")
        self.assertTrue(result["isolation"]["winePrefixRemoved"])
        self.assertTrue(result["isolation"]["processDirectoryRemoved"])
        self.assertFalse(Path(result["isolation"]["processDirectory"]).exists())

    def test_prefix_is_bootstrapped_flushed_and_validated_before_launch(self):
        prefix = self.root / "prepared-prefix"
        environment = [
            "env", "HODLL=libwow64fex.dll", f"WINEPREFIX={prefix}",
            "WINEARCH=win32", "WINEDLLOVERRIDES=dinput=n,b",
            "MIEL_OBSERVER_NATIVE_DISPATCH=1",
        ]

        def wineboot(actual_environment, cwd, backend):
            self.complete_prefix(prefix)
            self.assertNotIn("WINEDLLOVERRIDES=dinput=n,b", actual_environment)
            self.assertFalse(any(
                item.startswith("MIEL_OBSERVER_") for item in actual_environment
            ))
            self.assertEqual(cwd, self.game)
            self.assertEqual(backend["id"], "fex")
            return {
                "exit_code": 0, "timed_out": False, "output_tail": [],
            }

        with patch.object(runner, "_run_wineboot", side_effect=wineboot), \
                patch.object(runner, "_cleanup_wineserver") as cleanup:
            value = runner._prepare_wine_prefix(
                environment=environment, cwd=self.game,
                backend={"id": "fex", "hodll": "libwow64fex.dll"},
                prefix=prefix,
            )
        cleanup.assert_called_once()
        self.assertTrue(all(value["prefixBootstrap"].values()))

    def test_fex_prefix_lifecycle_uses_emulation_aware_timeouts(self):
        calls = []

        def capture(command, *, cwd, timeout):
            calls.append((command, cwd, timeout))
            return {"exit_code": 0, "timed_out": False, "output_tail": []}

        environment = ["env", "WINEPREFIX=/tmp/prefix", "WINEARCH=win32"]
        backend = {"id": "fex", "hodll": "libwow64fex.dll"}
        with patch.object(hangover_probe, "run", side_effect=capture):
            runner._run_wineboot(environment, self.game, backend)
            runner._run_wineserver(environment, self.game, backend, "-w")
        self.assertEqual(
            [call[2] for call in calls],
            [runner.WINEBOOT_TIMEOUT_SECONDS["fex"],
             runner.WINESERVER_TIMEOUT_SECONDS["fex"]],
        )
        self.assertGreater(calls[0][2], runner.WINEBOOT_TIMEOUT_SECONDS["box64"])
        self.assertGreater(
            calls[1][2], runner.WINESERVER_TIMEOUT_SECONDS["box64"],
        )

    def test_prefix_bootstrap_rejects_missing_persisted_hive(self):
        prefix = self.root / "incomplete-prefix"
        self.complete_prefix(prefix)
        (prefix / "userdef.reg").unlink()
        environment = [
            "env", f"WINEPREFIX={prefix}", "WINEARCH=win32",
        ]
        completed = {"exit_code": 0, "timed_out": False, "output_tail": []}
        with patch.object(runner, "_run_wineboot", return_value=completed), \
                patch.object(runner, "_cleanup_wineserver"):
            with self.assertRaisesRegex(
                runner.NativeDispatchCaptureRunnerError,
                "incomplete after wineserver flush",
            ):
                runner._prepare_wine_prefix(
                    environment=environment, cwd=self.game,
                    backend={"id": "box64", "hodll": "wowbox64.dll"},
                    prefix=prefix,
                )

    def test_driver_selection_is_exactly_the_declared_cohorts(self):
        version_counts = {}
        for target in self.compilation["targets"]:
            selected = runner.capture_driver_for_target(target)
            if (
                target["evidenceClass"] == "LOCATION_POLICY"
                and target["trigger"].get("selector") ==
                    "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3"
                and target["trigger"].get("selectorHookFamily") ==
                    "GENERIC_LOCATION_ENTER"
            ):
                self.assertEqual(selected, {
                    "version": "GENERIC_LOCATION_CLEAN_V2",
                    "mode": target["trigger"]["mode"],
                })
            elif (
                target["evidenceClass"] == "LOCATION_POLICY"
                and target["trigger"].get("selector") ==
                    "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE"
                and target["trigger"].get("selectorHookFamily") ==
                    "MYGGHANGET_ENTER"
            ):
                self.assertEqual(selected, {
                    "version": "BOOTSTRAP_TRAVERSAL_V1",
                    "mode": "mode_mygghanget",
                })
            elif selected is not None:
                self.assertEqual(target["evidenceClass"], "MISSION_DISPATCH")
                self.assertEqual(
                    target["trigger"]["missionPhase"], "activate",
                )
                self.assertIn(selected["version"], (
                    "MISSION_LOCATION_ENTER_V1", "MISSION_BARN_TRAVERSAL_V1",
                ))
                self.assertTrue(selected["mode"].startswith("mode_"))
            if selected is not None:
                version_counts[selected["version"]] = \
                    version_counts.get(selected["version"], 0) + 1
        self.assertEqual(version_counts, {
            "GENERIC_LOCATION_CLEAN_V2": 15,
            "BOOTSTRAP_TRAVERSAL_V1": 1,
            "MISSION_LOCATION_ENTER_V1": 14,
            "MISSION_BARN_TRAVERSAL_V1": 2,
        })

    def test_driven_capture_removes_the_complete_transient_process_directory(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is not None
        )
        original = self.fake_launch

        def materialize_wine_prefix(**kwargs):
            environment = dict(
                item.split("=", 1) for item in kwargs["environment"] if "=" in item
            )
            prefix = Path(environment["WINEPREFIX"])
            prefix.mkdir()
            (prefix / "system.reg").write_bytes(b"transient-prefix")
            return original(**kwargs)

        result = self.run_one(target, private_launch=materialize_wine_prefix)
        process_directory = Path(result["isolation"]["processDirectory"])
        self.assertTrue(result["isolation"]["transientGameRootRemoved"])
        self.assertTrue(result["isolation"]["winePrefixRemoved"])
        self.assertTrue(result["isolation"]["processDirectoryRemoved"])
        self.assertFalse(process_directory.exists())
        run_directory = Path(result["isolation"]["runDirectory"])
        self.assertTrue((run_directory / "output").is_dir())
        self.assertTrue((run_directory / "proxy" / "DINPUT.dll").is_file())
        self.assertTrue((run_directory / "evidence" / "capture-plan.json").is_file())

    def test_driven_capture_rejects_noncanonical_native_empty_user_slot(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is not None
        )
        original = self.fake_launch

        def corrupt_empty_slot(**kwargs):
            result = original(**kwargs)
            user = kwargs["executable"].parent / "Data" / "User" / "user5.dat"
            user.write_bytes(b"not-a-native-empty-slot")
            return result

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "native empty user slot differs",
        ):
            self.run_one(target, private_launch=corrupt_empty_slot)

    def test_launch_failure_still_removes_wine_prefix_and_process_directory(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is not None
        )
        process_directory = (
            self.root / "runs" / target["targetSha256"] / "process"
        )

        def fail_after_prefix_creation(**kwargs):
            environment = dict(
                item.split("=", 1) for item in kwargs["environment"] if "=" in item
            )
            prefix = Path(environment["WINEPREFIX"])
            prefix.mkdir()
            (prefix / "system.reg").write_bytes(b"transient-prefix")
            raise RuntimeError("synthetic native launch failure")

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "native target launcher or isolation failed",
        ):
            self.run_one(target, private_launch=fail_after_prefix_creation)
        self.assertFalse(process_directory.exists())
        run_directory = process_directory.parent
        self.assertTrue((run_directory / "output").is_dir())
        self.assertTrue((run_directory / "proxy" / "DINPUT.dll").is_file())
        self.assertTrue((run_directory / "evidence" / "capture-plan.json").is_file())

    def test_replaced_process_symlink_is_unlinked_without_touching_output(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is None
        )
        process_directory = (
            self.root / "runs" / target["targetSha256"] / "process"
        )
        output_directory = process_directory.parent / "output"
        sentinel = output_directory / "protected-sentinel"
        original = self.fake_launch

        def replace_process_root(**kwargs):
            result = original(**kwargs)
            sentinel.write_bytes(b"protected")
            shutil.rmtree(process_directory)
            process_directory.symlink_to(output_directory, target_is_directory=True)
            return result

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "transient process cleanup target is not a physical directory",
        ):
            self.run_one(target, private_launch=replace_process_root)
        self.assertFalse(process_directory.exists())
        self.assertEqual(sentinel.read_bytes(), b"protected")

    def test_child_symlink_is_removed_without_following_its_target(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is None
        )
        original = self.fake_launch

        def add_child_symlink(**kwargs):
            result = original(**kwargs)
            environment = dict(
                item.split("=", 1) for item in kwargs["environment"] if "=" in item
            )
            process_directory = Path(environment["WINEPREFIX"]).parent
            output_directory = kwargs["output"].parent
            (output_directory / "protected-sentinel").write_bytes(b"protected")
            (process_directory / "output-link").symlink_to(
                output_directory, target_is_directory=True,
            )
            return result

        result = self.run_one(target, private_launch=add_child_symlink)
        run_directory = Path(result["isolation"]["runDirectory"])
        self.assertFalse(Path(result["isolation"]["processDirectory"]).exists())
        self.assertEqual(
            (run_directory / "output" / "protected-sentinel").read_bytes(),
            b"protected",
        )

    def test_eq3_and_non_cohort_targets_never_receive_a_driver(self):
        excluded = [
            target for target in self.compilation["targets"]
            if target["trigger"].get("selector") ==
                "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3"
            or (target["evidenceClass"] == "MISSION_DISPATCH"
                and target["trigger"]["missionPhase"] != "activate")
            or target["trigger"].get("selectorHookFamily") in (
                "GROTTE_STATE_SETTER", "RAYMOND_LOCATION_LOAD",
                "RAYMOND_STATE_SETTER", "EXHIBITION_STATE_SETTER",
            )
        ]
        self.assertEqual(len(excluded), 91)
        self.assertTrue(all(
            runner.capture_driver_for_target(target) is None
            for target in excluded
        ))
        driven = sum(
            runner.capture_driver_for_target(target) is not None
            for target in self.compilation["targets"]
        )
        self.assertEqual(driven, 32)

    def test_matching_target_gets_only_bound_driver_version_and_receipt(self):
        target = next(
            target for target in self.compilation["targets"]
            if (runner.capture_driver_for_target(target) or {}).get("version")
            == runner.DRIVER_VERSION
        )
        result = self.run_one(target)
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")
        environment = dict(
            item.split("=", 1)
            for item in self.launch_calls[0]["environment"] if "=" in item
        )
        self.assertEqual(
            environment["MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER"],
            runner.DRIVER_VERSION,
        )
        self.assertIn(
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_RECEIPT", environment,
        )
        self.assertNotIn("MIEL_OBSERVER_NATIVE_DISPATCH_MODE", environment)
        self.assertEqual(
            result["driverReceipt"]["receipt"]["targetMode"],
            target["trigger"]["mode"],
        )
        self.assertEqual(
            self.launch_calls[0]["observe_ms"], runner.DRIVER_MIN_OBSERVE_MS,
        )

    def traversal_target(self):
        return next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) == {
                "version": "BOOTSTRAP_TRAVERSAL_V1",
                "mode": "mode_mygghanget",
            }
        )

    def test_traversal_target_runs_with_bound_v3_receipt(self):
        result = self.run_one(self.traversal_target())
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")
        environment = dict(
            item.split("=", 1)
            for item in self.launch_calls[0]["environment"] if "=" in item
        )
        self.assertEqual(
            environment["MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER"],
            "BOOTSTRAP_TRAVERSAL_V1",
        )
        self.assertNotIn("MIEL_OBSERVER_NATIVE_DISPATCH_MODE", environment)
        receipt = result["driverReceipt"]["receipt"]
        self.assertEqual(receipt["schema"], 3)
        self.assertEqual(
            receipt["entryPath"], "NATIVE_LOGIN_BARN_MYGGHANGET_TRAVERSAL",
        )
        self.assertEqual(receipt["sourceMode"], "mode_barn")
        self.assertEqual(receipt["targetMode"], "mode_mygghanget")
        self.assertEqual(receipt["naturalTransitionEvidence"], False)
        self.assertNotIn("callback", receipt)
        self.assertNotIn("missionReadback", receipt)

    def test_traversal_receipt_rejects_dispatch_shaped_payload(self):
        original = self.fake_launch

        def dispatch_shaped(**kwargs):
            result = original(**kwargs)
            environment = dict(
                item.split("=", 1) for item in kwargs["environment"]
                if "=" in item
            )
            receipt = Path(
                "/" + environment[
                    "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_RECEIPT"
                ][3:].replace("\\", "/")
            )
            value = json.loads(receipt.read_text(encoding="ascii"))
            value["entryPath"] = "NATIVE_BARN_MYGGHANGET_FLIGHT_THEN_ENGINE_MODE"
            receipt.write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            return result

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "driver receipt differs",
        ):
            self.run_one(
                self.traversal_target(), private_launch=dispatch_shaped,
            )

    def test_mission_ground_target_runs_with_bound_v4_receipt(self):
        target = next(
            row for row in self.compilation["targets"]
            if (runner.capture_driver_for_target(row) or {}).get("version")
            == "MISSION_LOCATION_ENTER_V1"
        )
        result = self.run_one(target)
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")
        environment = dict(
            item.split("=", 1)
            for item in self.launch_calls[0]["environment"] if "=" in item
        )
        self.assertEqual(
            environment["MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER"],
            "MISSION_LOCATION_ENTER_V1",
        )
        receipt = result["driverReceipt"]["receipt"]
        self.assertEqual(receipt["schema"], 4)
        self.assertEqual(receipt["sourceMode"], "mode_fly")
        self.assertEqual(
            receipt["targetMode"],
            runner.capture_driver_for_target(target)["mode"],
        )
        self.assertEqual(
            receipt["callback"],
            {"name": "engine_mode", "id": 15, "address": 0x0041E1B0},
        )

    def test_mission_barn_target_runs_with_bound_v3_receipt(self):
        target = next(
            row for row in self.compilation["targets"]
            if (runner.capture_driver_for_target(row) or {}).get("version")
            == "MISSION_BARN_TRAVERSAL_V1"
        )
        result = self.run_one(target)
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")
        receipt = result["driverReceipt"]["receipt"]
        self.assertEqual(receipt["schema"], 3)
        self.assertEqual(receipt["entryPath"], "NATIVE_LOGIN_BARN_TRAVERSAL")
        self.assertEqual(receipt["sourceMode"], "mode_login")
        self.assertEqual(receipt["targetMode"], "mode_barn")

    def test_mission_receipt_with_wrong_schema_fails_closed(self):
        target = next(
            row for row in self.compilation["targets"]
            if (runner.capture_driver_for_target(row) or {}).get("version")
            == "MISSION_LOCATION_ENTER_V1"
        )
        original = self.fake_launch

        def clean_v2_schema(**kwargs):
            result = original(**kwargs)
            environment = dict(
                item.split("=", 1) for item in kwargs["environment"]
                if "=" in item
            )
            receipt = Path(
                "/" + environment[
                    "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_RECEIPT"
                ][3:].replace("\\", "/")
            )
            value = json.loads(receipt.read_text(encoding="ascii"))
            value["schema"] = 2
            receipt.write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            return result

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "driver receipt differs",
        ):
            self.run_one(target, private_launch=clean_v2_schema)

    def test_driver_receipt_requires_identical_mission_readbacks(self):
        target = next(
            target for target in self.compilation["targets"]
            if runner.capture_driver_for_target(target) is not None
        )
        original = self.fake_launch

        def drift_readback(**kwargs):
            result = original(**kwargs)
            environment = dict(
                item.split("=", 1) for item in kwargs["environment"]
                if "=" in item
            )
            receipt = Path(
                "/" + environment[
                    "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_RECEIPT"
                ][3:].replace("\\", "/")
            )
            value = json.loads(receipt.read_text(encoding="ascii"))
            value["missionReadback"]["hook"]["state"] = 0
            receipt.write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            return result

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "mission readbacks differ",
        ):
            self.run_one(target, private_launch=drift_readback)

    def test_incomplete_driver_may_leave_only_the_initial_user_slot(self):
        target = next(
            target for target in self.compilation["targets"]
            if runner.capture_driver_for_target(target) is not None
        )
        original = self.fake_launch

        def stop_before_profile_slot_initialization(**kwargs):
            result = original(**kwargs)
            user = kwargs["executable"].parent / "Data" / "User"
            for index in range(1, 11):
                (user / f"user{index}.dat").unlink()
            result["runs"]["start_patch_launch"].update({
                "exit_code": None, "timed_out": True,
            })
            return result

        result = self.run_one(
            target, private_launch=stop_before_profile_slot_initialization,
        )
        self.assertEqual(result["status"], runner.INCOMPLETE)
        self.assertEqual(
            result["isolation"]["nativeEmptyUserSlotsValidated"], "0",
        )

    def test_driver_uses_only_internal_proven_hash_bound_bootstrap(self):
        target = next(
            target for target in self.compilation["targets"]
            if runner.capture_driver_for_target(target) is not None
        )
        result = self.run_one(target)
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")
        environment = dict(
            item.split("=", 1)
            for item in self.launch_calls[0]["environment"] if "=" in item
        )
        self.assertTrue(runner.DRIVER_BOOTSTRAP_ENV_KEYS <= set(environment))
        self.assertEqual(set(environment) & runner.FOUNDATION_ENV_KEYS,
                         runner.FOUNDATION_ENV_KEYS)
        self.assertEqual(environment[
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_BOOTSTRAP_PROFILE"
        ], runner.DRIVER_BOOTSTRAP_PROFILE)
        self.assertEqual(environment[
            "MIEL_OBSERVER_NATIVE_DISPATCH_DRIVER_BOOTSTRAP_PROFILE_SHA256"
        ], runner.DRIVER_BOOTSTRAP_PROFILE_SHA256)
        self.assertEqual(environment[
            "MIEL_OBSERVER_INITIAL_USER_SHA256"
        ], runner.DRIVER_INITIAL_USER_SHA256)
        self.assertEqual(environment[
            "MIEL_OBSERVER_SCENARIO_SHA256"
        ], runner.DRIVER_SCENARIO_SHA256)
        self.assertFalse((self.game / "Data" / "User").exists())

    def test_public_api_has_no_callable_injection_surface(self):
        for boundary in (runner.run_capture_target, runner.run_capture_suite):
            parameters = inspect.signature(boundary).parameters
            self.assertNotIn("launch", parameters)
            self.assertNotIn("cleanup", parameters)
            self.assertNotIn("scenario_replay", parameters)
            self.assertNotIn("foundation", parameters)
            self.assertNotIn("scene", parameters)
            self.assertNotIn("scene_debugger", parameters)
        with self.assertRaises(TypeError):
            self.run_one(launch=self.fake_launch)

    def test_two_driven_targets_get_distinct_pristine_game_roots(self):
        targets = [
            target for target in self.compilation["targets"]
            if runner.capture_driver_for_target(target) is not None
        ][:2]
        result = self.run_suite(targets)
        self.assertEqual(result["status"], "PARTIAL_CANDIDATE")
        roots = [call["executable"].parent for call in self.launch_calls]
        self.assertEqual(len(roots), 2)
        self.assertNotEqual(roots[0], roots[1])
        self.assertTrue(all(root != self.game for root in roots))
        self.assertFalse((self.game / "Data" / "User").exists())
        self.assertEqual((self.game / "config.ini").read_bytes(), b"initial-config")
        self.assertEqual((self.game / "data.up").read_bytes(), b"immutable-archive")

    def test_launcher_and_wire_process_identity_must_match(self):
        original = self.fake_launch

        def drifted_identity(**kwargs):
            result = original(**kwargs)
            result["captureProcess"]["nativeProcessId"] += 1
            return result

        result = self.run_one(private_launch=drifted_identity)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reason"], "PROCESS_IDENTITY_NOT_OBSERVED")

    def test_incomplete_native_process_preserves_safe_launch_diagnostic(self):
        original = self.fake_launch

        def crashed(**kwargs):
            result = original(**kwargs)
            result["runs"]["start_patch_launch"] = {
                "command": ["env", "SECRET_TOKEN=never-copy-this"],
                "exit_code": None,
                "timed_out": True,
                "output_sha256": "b" * 64,
                "output_tail": [
                    "wine: Unhandled page fault on read access to 01FC0FFF "
                    "at address 01FC0FFF (thread 0128), starting debugger...",
                    "SECRET_TOKEN=never-copy-this",
                ],
            }
            return result

        result = self.run_one(private_launch=crashed)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reason"], "NATIVE_PROCESS_DID_NOT_COMPLETE")
        self.assertFalse(result["productionClaim"])
        self.assertFalse(result["parityEligible"])
        self.assertEqual(
            result["launchDiagnostic"]["signals"],
            [{
                "kind": "wine-page-fault",
                "access": "read",
                "accessAddress": "0x01fc0fff",
                "instructionAddress": "0x01fc0fff",
            }],
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("command", serialized)

    def test_zero_event_is_incomplete_and_suite_does_not_start_next(self):
        original = self.fake_launch

        def no_event(**kwargs):
            result = original(**kwargs)
            raw = kwargs["output"].parent / f"native-observer-{kwargs['backend']['id']}.log"
            raw.write_text("observer loaded but no target occurrence\n", encoding="ascii")
            result["observer_log"]["sha256"] = self.sha(raw)
            return result

        result = self.run_one(private_launch=no_event)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reason"], "EXACT_NATIVE_TARGET_NOT_OBSERVED")
        self.assertTrue(result["isolation"]["winePrefixRemoved"])
        self.assertTrue(result["isolation"]["processDirectoryRemoved"])
        self.assertEqual([row[3] for row in self.cleanup_calls], ["-k", "-w"])

    def test_two_events_fail_closed_after_cleanup(self):
        original = self.fake_launch

        def duplicate(**kwargs):
            result = original(**kwargs)
            raw = kwargs["output"].parent / f"native-observer-{kwargs['backend']['id']}.log"
            raw.write_bytes(raw.read_bytes() + next(
                line(event_for(self.records[row["claimId"]], 1)).encode("ascii") + b"\n"
                for row in self.compilation["targets"]
                if row["jobId"] == dict(
                    item.split("=", 1) for item in kwargs["environment"]
                    if "=" in item
                )["MIEL_OBSERVER_NATIVE_DISPATCH_JOB_ID"]
            ))
            result["observer_log"]["sha256"] = self.sha(raw)
            return result

        with self.assertRaisesRegex(runner.NativeDispatchCaptureRunnerError, "exactly one CAPABILITY and EVENT"):
            self.run_one(private_launch=duplicate)
        self.assertEqual([row[3] for row in self.cleanup_calls], ["-k", "-w"])

    def test_rejects_loose_observer_environment_before_launch(self):
        with self.assertRaisesRegex(runner.NativeDispatchCaptureRunnerError, "observer environment"):
            self.run_one(environment=["MIEL_OBSERVER_SCENARIO=invented"])
        self.assertEqual(self.launch_calls, [])

    def test_rejects_loose_real_dinput_environment_before_launch(self):
        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError, "observer environment",
        ):
            self.run_one(environment=["MIEL_REAL_DINPUT=Z:\\loose\\dinput.dll"])

    def test_rejects_loose_wine_dll_override_before_launch(self):
        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError, "observer environment",
        ):
            self.run_one(environment=["WINEDLLOVERRIDES=dinput=b"])
        self.assertEqual(self.launch_calls, [])

    def test_cleanup_failure_aborts_before_another_target(self):
        calls = 0

        def failing_cleanup(environment, cwd, backend, argument):
            nonlocal calls
            calls += 1
            return {"command": ["wineserver", "-k"], "exit_code": 1,
                    "timed_out": False, "output_tail": []}

        with self.assertRaisesRegex(runner.NativeDispatchCaptureRunnerError, "wineserver -k/-w cleanup"):
            self.run_one(private_wineserver=failing_cleanup)
        self.assertEqual(calls, 1)
        self.assertEqual(list((self.root / "runs").glob("*/process")), [])

    def test_wineserver_wait_failure_is_fatal(self):
        calls = []

        def wait_failure(environment, cwd, backend, argument):
            calls.append(argument)
            return {"command": ["wineserver", argument],
                    "exit_code": 1 if argument == "-w" else 0,
                    "timed_out": False, "output_tail": []}

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError, "wineserver -k/-w cleanup",
        ):
            self.run_one(private_wineserver=wait_failure)
        self.assertEqual(calls, ["-k", "-w"])
        self.assertEqual(list((self.root / "runs").glob("*/process")), [])

    def test_subset_suite_is_explicitly_partial(self):
        target = self.compilation["targets"][0]
        with patch.object(runner, "_native_launch", side_effect=self.fake_launch), \
                patch.object(
                    runner, "_prepare_wine_prefix", side_effect=self.prepare_prefix,
                ), \
                patch.object(runner, "_run_wineserver", side_effect=self.wineserver):
            result = runner.run_capture_suite(
                compilation=self.compilation, targets=[target],
                plan_path=self.plan_path, environment=[],
                backend={"id": "box64", "hodll": "wowbox64.dll"},
                executable=self.executable, evidence_root=self.root,
                observer_dll=self.observer,
                observer_build_receipts={target["jobId"]: self.receipts[target["jobId"]]},
                proxy_dll=self.proxy, real_dinput_dll=self.real_dinput,
                observer_launcher=self.launcher_binary,
                expected_launcher_sha256=self.sha(self.launcher_binary),
            )
        self.assertEqual(result["status"], "PARTIAL_CANDIDATE")
        self.assertFalse(result["parityEligible"])

    def test_exact_155_inventory_is_required_for_suite_captured(self):
        counter = 0

        def captured(**kwargs):
            nonlocal counter
            counter += 1
            target = kwargs["target"]
            output = self.root / f"synthetic-output-{counter}"
            log = output / "raw.log"
            return {
                "status": "CAPTURED_CANDIDATE",
                "processIdentity": {
                    "nativeProcessId": counter,
                    "sessionId": f"mvds-{counter:032x}",
                },
                "isolation": {"outputDirectory": str(output)},
                "rawLog": {"path": str(log)},
                "targetSha256": target["targetSha256"],
            }

        with patch.object(runner, "_run_capture_target", side_effect=captured):
            result = runner.run_capture_suite(
                compilation=self.compilation,
                targets=list(self.compilation["targets"]),
                plan_path=self.plan_path, environment=[],
                backend={"id": "box64", "hodll": "wowbox64.dll"},
                executable=self.executable, evidence_root=self.root,
                observer_dll=self.observer,
                observer_build_receipts=dict(self.receipts), proxy_dll=self.proxy,
                real_dinput_dll=self.real_dinput,
                observer_launcher=self.launcher_binary,
                expected_launcher_sha256=self.sha(self.launcher_binary),
            )
        self.assertEqual(counter, 155)
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")

    def test_symlink_evidence_root_is_rejected_before_launch(self):
        link = self.root.parent / f"{self.root.name}-link"
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError, "evidence root",
        ):
            self.run_one(evidence_root=link)
        self.assertEqual(self.launch_calls, [])

    def test_nested_runs_symlink_is_rejected_without_outside_write_or_launch(self):
        outside = self.root.parent / f"{self.root.name}-outside"
        outside.mkdir()
        self.addCleanup(shutil.rmtree, outside, True)
        (self.root / "runs").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError, "symlink|escapes",
        ):
            self.run_one()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.launch_calls, [])
        self.assertEqual(self.cleanup_calls, [])

    def test_suite_rejects_reused_process_identity(self):
        targets = self.compilation["targets"][:2]
        original = self.fake_launch

        def reused(**kwargs):
            result = original(**kwargs)
            process_id = 77
            session_id = "mvds-" + "77" * 16
            result["observer_launcher_receipt"]["capture_process"] = {
                "native_process_id": process_id,
                "capture_session_id": session_id,
            }
            result["captureProcess"] = {
                "nativeProcessId": process_id,
                "captureSessionId": session_id,
            }
            output_dir = kwargs["output"].parent
            backend_id = kwargs["backend"]["id"]
            raw = output_dir / f"native-observer-{backend_id}.log"
            rewritten = []
            for text in raw.read_text(encoding="ascii").splitlines():
                if text.startswith("MVDS "):
                    record = json.loads(text[5:])
                    record["nativeProcessId"] = process_id
                    record["captureSessionId"] = session_id
                    text = line(record)
                rewritten.append(text)
            raw.write_text("\n".join(rewritten) + "\n", encoding="ascii")
            result["observer_log"]["sha256"] = self.sha(raw)
            launcher_path = output_dir / f"native-observer-launch-{backend_id}.json"
            launcher_path.write_text(
                json.dumps(result["observer_launcher_receipt"]), encoding="utf-8",
            )
            return result

        receipt_map = {row["jobId"]: self.receipts[row["jobId"]] for row in targets}
        with patch.object(runner, "_native_launch", side_effect=reused), \
                patch.object(
                    runner, "_prepare_wine_prefix", side_effect=self.prepare_prefix,
                ), \
                patch.object(runner, "_run_wineserver", side_effect=self.wineserver), \
                self.assertRaisesRegex(
                    runner.NativeDispatchCaptureRunnerError,
                    "process/session identity is reused",
                ):
            runner.run_capture_suite(
                compilation=self.compilation,
                targets=targets,
                plan_path=self.plan_path,
                environment=[],
                backend={"id": "box64", "hodll": "wowbox64.dll"},
                executable=self.executable, evidence_root=self.root,
                observer_dll=self.observer,
                observer_build_receipts=receipt_map,
                proxy_dll=self.proxy, real_dinput_dll=self.real_dinput,
                observer_launcher=self.launcher_binary,
                expected_launcher_sha256=self.sha(self.launcher_binary),
            )
        self.assertEqual(len(self.cleanup_calls), 4)

    def test_target_mutation_during_launch_fails_closed(self):
        target = self.compilation["targets"][0]
        original = self.fake_launch

        def drifting(**kwargs):
            result = original(**kwargs)
            target["trigger"][next(iter(target["trigger"]))] = "DRIFTED"
            return result

        with self.assertRaisesRegex(runner.NativeDispatchCaptureRunnerError, "target drifted"):
            self.run_one(target, private_launch=drifting)
        self.assertEqual(len(self.cleanup_calls), 2)

    def test_post_copy_identity_failure_removes_transient_game_root(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is not None
        )
        original_copy = runner._copy_isolated_game

        def corrupt_after_copy(source, destination, initial_user):
            result = original_copy(source, destination, initial_user)
            (result[0] / self.executable.name).write_bytes(b"MZ-drifted")
            return result

        with patch.object(
            runner, "_copy_isolated_game", side_effect=corrupt_after_copy,
        ), self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "isolated native executable identity differs",
        ):
            self.run_one(target)
        self.assertEqual(
            list((self.root / "runs").glob("*/process/game")),
            [],
        )
        self.assertEqual(list((self.root / "runs").glob("*/process")), [])
        self.assertEqual(
            list((self.root / "runs").glob("*/process")),
            [],
        )
        self.assertEqual(self.launch_calls, [])

    def test_partial_isolated_copy_failure_removes_process_directory(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is not None
        )
        process_directory = (
            self.root / "runs" / target["targetSha256"] / "process"
        )

        def fail_with_partial_copy(source, destination, initial_user):
            destination.mkdir()
            (destination / "partial-copy").write_bytes(b"partial")
            raise runner.NativeDispatchCaptureRunnerError(
                "synthetic partial isolated copy failure"
            )

        with patch.object(
            runner, "_copy_isolated_game", side_effect=fail_with_partial_copy,
        ), self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            "synthetic partial isolated copy failure",
        ):
            self.run_one(target)
        self.assertFalse(process_directory.exists())
        self.assertEqual(self.launch_calls, [])

    def test_runtime_immutable_drift_reports_exact_path_before_cleanup(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is not None
        )
        original = self.fake_launch

        def mutate_game(**kwargs):
            result = original(**kwargs)
            (kwargs["executable"].parent / "Miel.ini").write_bytes(
                b"native-runtime-drift"
            )
            return result

        with self.assertRaisesRegex(
            runner.NativeDispatchCaptureRunnerError,
            r"isolated immutable game closure changed.*Miel\.ini",
        ):
            self.run_one(target, private_launch=mutate_game)
        self.assertEqual(
            list((self.root / "runs").glob("*/process/game")),
            [],
        )

    def test_native_renderer_log_is_the_only_mutable_log_shape(self):
        target = next(
            row for row in self.compilation["targets"]
            if runner.capture_driver_for_target(row) is not None
        )
        original = self.fake_launch

        def write_renderer_log(**kwargs):
            result = original(**kwargs)
            log = kwargs["executable"].parent / "Log"
            log.mkdir()
            (log / "gtSoftware-0123456789AB.log").write_bytes(b"renderer")
            return result

        result = self.run_one(target, private_launch=write_renderer_log)
        self.assertEqual(result["status"], "CAPTURED_CANDIDATE")
        self.assertEqual(
            list((self.root / "runs").glob("*/process/game")),
            [],
        )


if __name__ == "__main__":
    unittest.main()
