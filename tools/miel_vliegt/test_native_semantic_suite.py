import inspect
import json
import os
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.miel_vliegt import native_scenario_artifacts as artifacts
from tools.miel_vliegt import native_semantic_suite as semantic_suite
from tools.miel_vliegt.fex_wine import native_runner
from tools.miel_vliegt.hangover_probe import wineserver_shutdown_completed
from tools.miel_vliegt.native_semantic_suite import (
    DockerExecAdapter,
    SuiteRunConfig,
    SuiteRunError,
    _adapter_directory_receipt,
    _atomic_write,
    _calibration_capture,
    _exact_capture,
    _exclusive_capture_lock,
    _mirror_game_state,
    run_calibrated_suite,
    validate_run_config,
)


class NativeSemanticSuiteTests(unittest.TestCase):
    class FakeAdapter:
        def validate(self, config):
            return {
                "kind": "test-exact-bind",
                "container_id": config.container_id,
                "image_id": "sha256:" + config.container_image_sha256,
                "exec_uid": config.expected_uid,
            }

        def activate(self, _config):
            return nullcontext()

    def test_canonical_capture_inputs_match_tracked_edition_contracts(self):
        root = semantic_suite.REPOSITORY_ROOT
        identity = json.loads(
            (root / "content/miel_vliegt/source_identity.json").read_text()
        )
        package_io = json.loads(
            (root / "content/miel_vliegt/substitutions/package_io.json").read_text()
        )
        canonical = semantic_suite.CANONICAL_EDITION_INPUT_SHA256
        self.assertEqual(identity["edition"], semantic_suite.CANONICAL_EDITION)
        self.assertEqual(
            canonical["source_executable"],
            identity["executable"]["sha256"],
        )
        self.assertEqual(
            canonical["disposable_target"],
            identity["executable"]["sha256"],
        )
        archives = {
            row["filename"]: row["sha256"]
            for row in package_io["source"]["archives"]
        }
        self.assertEqual(canonical["data_archive"], archives["data.up"])
        self.assertEqual(canonical["map_archive"], archives["map.up"])
        self.assertEqual(canonical["sounds_archive"], archives["sounds.up"])

    def make_config(self, root: Path) -> SuiteRunConfig:
        root.mkdir(parents=True, exist_ok=True)
        game = root / "game"
        proxy = root / "game-proxy"
        tools = root / "native-tools"
        for directory in (game, proxy, tools):
            directory.mkdir()
        payloads = {
            "source_executable": (game / "MulleMeck.exe", b"game"),
            "disposable_target": (proxy / "MulleMeck.exe", b"game"),
            "user_profile": (root / "user0.dat", b"profile"),
            "observer_dll": (tools / "observer.dll", b"observer"),
            "observer_launcher": (tools / "launcher.exe", b"launcher"),
            "proxy_dinput": (proxy / "DINPUT.dll", b"proxy"),
            "real_dinput": (tools / "dinput-real.dll", b"real"),
            "smoke_executable": (tools / "smoke.exe", b"smoke"),
            "data_archive": (game / "data.up", b"data archive"),
            "map_archive": (game / "map.up", b"map archive"),
            "sounds_archive": (game / "sounds.up", b"sounds archive"),
            "miel_ini": (game / "Miel.ini", b"edition config"),
        }
        for path, payload in payloads.values():
            path.write_bytes(payload)
        hashes = {
            label: artifacts.sha256_file(path)
            for label, (path, _payload) in payloads.items()
        }
        canonical_patch = patch.dict(
            semantic_suite.CANONICAL_EDITION_INPUT_SHA256,
            {
                label: hashes[label]
                for label in semantic_suite.CANONICAL_EDITION_INPUT_SHA256
            },
            clear=True,
        )
        canonical_patch.start()
        self.addCleanup(canonical_patch.stop)
        return SuiteRunConfig(
            source_executable=payloads["source_executable"][0],
            disposable_target=payloads["disposable_target"][0],
            game_root=game,
            state_root=game,
            user_profile=payloads["user_profile"][0],
            observer_dll=payloads["observer_dll"][0],
            observer_launcher=payloads["observer_launcher"][0],
            proxy_dinput=payloads["proxy_dinput"][0],
            real_dinput=payloads["real_dinput"][0],
            smoke_executable=payloads["smoke_executable"][0],
            wine_prefix=root / "prefix",
            suite_root=root / "calibrated-suite",
            output_root=root / "captures",
            backend_id="box64",
            backend_hodll="wowbox64.dll",
            container_image="miel-flight-x86-wine:truthful-v5",
            container_image_sha256="a" * 64,
            container_id="container-for-test",
            container_mount_root=root,
            expected_uid=os.geteuid(),
            expected_sha256=hashes,
            observe_ms=1_000,
        )

    def test_preflight_binds_exact_topology_uid_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            receipt = validate_run_config(config)
            self.assertEqual(
                receipt["edition"],
                semantic_suite.CANONICAL_EDITION,
            )
            self.assertEqual(receipt["effective_uid"], os.geteuid())
            self.assertEqual(receipt["backend"], {
                "id": "box64", "hodll": "wowbox64.dll",
            })
            self.assertEqual(
                receipt["paths"]["source_executable"]["sha256"],
                config.expected_sha256["source_executable"],
            )
            self.assertEqual(
                receipt["paths"]["data_archive"]["path"],
                str((config.game_root / "data.up").resolve()),
            )
            self.assertEqual(
                receipt["paths"]["miel_ini"]["sha256"],
                config.expected_sha256["miel_ini"],
            )
            self.assertEqual(receipt["runtime_readiness_budget"], {
                "guest_process_seconds": 90,
                "rpcss_poll_milliseconds": 30000,
            })

    def test_preflight_rejects_target_proxy_and_clean_root_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            config.disposable_target.write_bytes(b"changed")
            with self.assertRaisesRegex(SuiteRunError, "disposable_target hash drifted"):
                validate_run_config(config)

    def test_preflight_requires_one_relocatable_evidence_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            isolated_bundle = root / "isolated-bundle"
            isolated_bundle.mkdir()
            outside = SuiteRunConfig(**{
                **config.__dict__,
                "output_root": isolated_bundle / "captures",
            })
            with self.assertRaisesRegex(
                SuiteRunError, "suite_root must live below the output bundle root",
            ):
                validate_run_config(outside)

    def test_preflight_rejects_incomplete_native_game_root_before_wine(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            (config.game_root / "map.up").unlink()
            with self.assertRaisesRegex(SuiteRunError, "map_archive is unavailable"):
                validate_run_config(config)

    def test_preflight_rejects_invalid_readiness_phase_budgets(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            invalid_runtime = SuiteRunConfig(**{
                **config.__dict__, "runtime_readiness_timeout": 29,
            })
            with self.assertRaisesRegex(
                SuiteRunError, "runtime_readiness_timeout",
            ):
                validate_run_config(invalid_runtime)

    def test_fex_preflight_requires_the_proven_full_observation_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            fex = SuiteRunConfig(**{
                **config.__dict__,
                "backend_id": "fex",
                "backend_hodll": "libwow64fex.dll",
                "observe_ms": semantic_suite.hangover_probe.DEFAULT_OBSERVE_MS,
            })
            with self.assertRaisesRegex(
                SuiteRunError,
                "FEX calibrated suite observe_ms must equal 3600000",
            ):
                validate_run_config(fex)

            accepted = SuiteRunConfig(**{
                **fex.__dict__,
                "observe_ms":
                    semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
            })
            receipt = validate_run_config(accepted)
            self.assertEqual(
                receipt["observation_budget"]["milliseconds"],
                semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
            )

    def test_sealed_roots_must_be_visible_below_exact_container_bind(self):
        with tempfile.TemporaryDirectory() as temporary, \
             tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            config = self.make_config(root)
            tmpfs = root / "tmpfs"
            tmpfs.mkdir()
            sealed = Path(outside) / "sealed"
            sealed.mkdir(mode=0o700)
            sealed_config = SuiteRunConfig(**{
                **config.__dict__,
                "backend_id": "fex",
                "backend_hodll": "libwow64fex.dll",
                "observe_ms": semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
                "backend_hodll_sha256": "b" * 64,
                "expected_gid": os.getegid(),
                "prefix_mode": "sealed",
                "wine_prefix": tmpfs / "prefix",
                "tmpfs_staging_root": tmpfs,
                "sealed_prefix_root": sealed,
            })
            with self.assertRaisesRegex(
                SuiteRunError,
                "sealed_prefix_root must live below container_mount_root",
            ):
                validate_run_config(sealed_config)
            invalid_rpcss = SuiteRunConfig(**{
                **config.__dict__, "rpcss_readiness_timeout_ms": 999,
            })
            with self.assertRaisesRegex(
                SuiteRunError, "rpcss_readiness_timeout_ms",
            ):
                validate_run_config(invalid_rpcss)

    def test_preflight_rejects_native_archive_hash_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            (config.game_root / "sounds.up").write_bytes(b"wrong edition")
            with self.assertRaisesRegex(SuiteRunError, "sounds_archive hash drifted"):
                validate_run_config(config)

    def test_preflight_rejects_caller_pinned_noncanonical_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            config = SuiteRunConfig(**{
                **config.__dict__,
                "expected_sha256": {
                    **config.expected_sha256,
                    "data_archive":
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
            })
            with self.assertRaisesRegex(
                SuiteRunError,
                "data_archive is not the canonical",
            ):
                validate_run_config(config)

    def test_exclusive_capture_lock_rejects_concurrent_mutable_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            lock = semantic_suite._exclusive_lock_path(config)
            with _exclusive_capture_lock(config) as receipt:
                self.assertTrue(lock.is_dir())
                self.assertEqual(receipt["wine_prefix"], str(config.wine_prefix.resolve()))
                self.assertEqual(
                    receipt["lock_scope"],
                    "one-suite-per-exact-container-bind-root",
                )
                self.assertRegex(
                    receipt["mutable_boundary"]["sha256"], r"^[0-9a-f]{64}$"
                )
                with self.assertRaisesRegex(SuiteRunError, "already locked"):
                    with _exclusive_capture_lock(config):
                        self.fail("concurrent capture acquired the same mutable boundary")
            self.assertFalse(lock.exists())

    def test_exclusive_capture_lock_is_released_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.make_config(Path(temporary))
            lock = semantic_suite._exclusive_lock_path(config)
            with self.assertRaisesRegex(RuntimeError, "capture failed"):
                with _exclusive_capture_lock(config):
                    raise RuntimeError("capture failed")
            self.assertFalse(lock.exists())

    def test_exclusive_lock_is_stable_across_pid_unique_prefixes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self.make_config(root)
            second = SuiteRunConfig(**{
                **first.__dict__,
                "wine_prefix": root / "tmpfs" / "wine-prefix-99999",
                "output_root": root / "captures-second",
            })
            self.assertEqual(
                semantic_suite._exclusive_lock_path(first),
                semantic_suite._exclusive_lock_path(second),
            )
            with _exclusive_capture_lock(first):
                with self.assertRaisesRegex(SuiteRunError, "already locked"):
                    with _exclusive_capture_lock(second):
                        self.fail("PID-unique prefix bypassed shared-state lock")

    def test_docker_adapter_binds_image_mount_uid_and_prefixes_every_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                return {
                    "command": command, "exit_code": 0, "timed_out": False,
                    "output_sha256": "0" * 64, "output_tail": [],
                }

            with _exclusive_capture_lock(config):
                with patch.object(adapter, "_inspect", return_value=inspect):
                    receipt = adapter.validate(config)
                environment_root = Path(
                    receipt["user_environment"]["directories"]["root"]["path"]
                )
                runtime_directory = Path(
                    receipt["user_environment"]["directories"]["runtime"]["path"]
                )
                self.assertTrue(environment_root.is_dir())
                self.assertTrue(runtime_directory.is_dir())
                self.assertNotEqual(runtime_directory.parent, environment_root)
                self.assertEqual(
                    receipt["user_environment"]["directories"]["runtime"]["mode"],
                    "0700",
                )
                with patch(
                    "tools.miel_vliegt.hangover_probe.run", side_effect=fake_run,
                ):
                    with adapter.activate(config):
                        from tools.miel_vliegt import hangover_probe
                        hangover_probe.run(
                            ["env", "WINEPREFIX=/prefix", "wine", "game.exe"],
                            cwd=config.game_root,
                        )
                self.assertFalse(environment_root.exists())
                self.assertFalse(runtime_directory.exists())
            self.assertEqual(receipt["exec_uid"], os.geteuid())
            self.assertEqual(commands[0][:5], [
                "docker", "exec", "--user", str(os.geteuid()), "--workdir",
            ])
            expected_environment = receipt["user_environment"]["variables"]
            for command in commands:
                actual_environment = {}
                for index, item in enumerate(command):
                    if item == "--env":
                        key, value = command[index + 1].split("=", 1)
                        actual_environment[key] = value
                self.assertEqual(actual_environment, expected_environment)
                self.assertEqual(command[command.index("f" * 64)], "f" * 64)
            self.assertEqual(commands[-1][-2:], ["wineserver", "-w"])
            self.assertEqual(commands[-2][-2:], ["wineserver", "-k"])

    def test_docker_adapter_requires_active_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            with patch.object(adapter, "_inspect", return_value=inspect):
                with self.assertRaisesRegex(SuiteRunError, "exclusive capture lock"):
                    adapter.validate(config)

    def test_sealed_adapter_verifies_hodll_bytes_inside_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            (root / "tmpfs").mkdir()
            (root / "sealed-prefixes").mkdir(mode=0o700)
            config = SuiteRunConfig(**{
                **config.__dict__,
                "backend_id": "fex",
                "backend_hodll": "libwow64fex.dll",
                "observe_ms": semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
                "backend_hodll_sha256": "b" * 64,
                "expected_gid": os.getegid(),
                "prefix_mode": "sealed",
                "tmpfs_staging_root": root / "tmpfs",
                "sealed_prefix_root": root / "sealed-prefixes",
            })
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            hodll_result = SimpleNamespace(
                returncode=0,
                stdout=(
                    "b" * 64 + "  "
                    + semantic_suite.BACKEND_HODLL_PATHS["fex"] + "\n"
                ),
                stderr="",
            )
            tmpfs_result = SimpleNamespace(
                returncode=0, stdout="tmpfs\n", stderr="",
            )
            with _exclusive_capture_lock(config), \
                 patch.object(adapter, "_inspect", return_value=inspect), \
                 patch(
                     "tools.miel_vliegt.native_semantic_suite.subprocess.run",
                     side_effect=(hodll_result, tmpfs_result),
                 ) as run:
                receipt = adapter.validate(config)
            self.assertEqual(receipt["hodll"], {
                "path": semantic_suite.BACKEND_HODLL_PATHS["fex"],
                "sha256": "b" * 64,
            })
            self.assertEqual(receipt["container_tmpfs"], {
                "path": str(config.tmpfs_staging_root.resolve()),
                "filesystem": "tmpfs",
            })
            self.assertIn("sha256sum", run.call_args_list[0].args[0])
            self.assertIn("stat", run.call_args_list[1].args[0])

    def test_sealed_adapter_rejects_store_outside_exact_bind(self):
        with tempfile.TemporaryDirectory() as temporary, \
             tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            config = self.make_config(root)
            tmpfs = root / "tmpfs"
            tmpfs.mkdir()
            config = SuiteRunConfig(**{
                **config.__dict__,
                "backend_id": "fex",
                "backend_hodll": "libwow64fex.dll",
                "observe_ms": semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
                "backend_hodll_sha256": "b" * 64,
                "expected_gid": os.getegid(),
                "prefix_mode": "sealed",
                "tmpfs_staging_root": tmpfs,
                "sealed_prefix_root": Path(outside),
            })
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            subprocess_receipts = (
                SimpleNamespace(
                    returncode=0,
                    stdout="b" * 64 + "  hodll\n",
                    stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="tmpfs\n", stderr=""),
            )
            with _exclusive_capture_lock(config), \
                 patch.object(adapter, "_inspect", return_value=inspect), \
                 patch(
                     "tools.miel_vliegt.native_semantic_suite.subprocess.run",
                     side_effect=subprocess_receipts,
                 ):
                with self.assertRaisesRegex(
                    SuiteRunError, "escape the exact bind mount",
                ):
                    adapter.validate(config)

    def test_docker_adapter_bounds_fex_socket_independently_of_prefix_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            config = SuiteRunConfig(**{
                **config.__dict__,
                "backend_id": "fex",
                "backend_hodll": "libwow64fex.dll",
                "observe_ms": semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
                "wine_prefix": root / ("prefix-" + "x" * 120),
            })
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                return {
                    "command": command, "exit_code": 0, "timed_out": False,
                    "output_sha256": "0" * 64, "output_tail": [],
                }

            with _exclusive_capture_lock(config), \
                 patch.object(adapter, "_inspect", return_value=inspect):
                receipt = adapter.validate(config)
                runtime_directory = Path(
                    receipt["user_environment"]["variables"]["XDG_RUNTIME_DIR"]
                )
                environment_root = Path(
                    receipt["user_environment"]["directories"]["root"]["path"]
                )
                socket_receipt = \
                    receipt["user_environment"]["directories"]["fex_socket"]
                self.assertLessEqual(
                    socket_receipt["byte_length"],
                    socket_receipt["max_byte_length"],
                )
                self.assertEqual(runtime_directory.parent, root.resolve())
                self.assertNotEqual(runtime_directory.parent, environment_root)
                with patch(
                    "tools.miel_vliegt.hangover_probe.run",
                    side_effect=fake_run,
                ):
                    with adapter.activate(config):
                        pass
                self.assertFalse(runtime_directory.exists())

    def test_docker_adapter_rejects_overlong_exact_bind_socket_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            config = SuiteRunConfig(**{
                **config.__dict__,
                "backend_id": "fex",
                "backend_hodll": "libwow64fex.dll",
                "observe_ms": semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
            })
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            original_fsencode = os.fsencode

            def overlong_socket(path):
                if str(path).endswith(".FEXServer.Socket"):
                    return b"x" * 108
                return original_fsencode(path)

            with _exclusive_capture_lock(config), \
                 patch.object(adapter, "_inspect", return_value=inspect), \
                 patch(
                     "tools.miel_vliegt.native_semantic_suite.os.fsencode",
                     side_effect=overlong_socket,
                 ):
                with self.assertRaisesRegex(SuiteRunError, "FEX Unix socket path"):
                    adapter.validate(config)

    def test_docker_adapter_uses_the_fixed_fex_wineserver_for_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            config = SuiteRunConfig(**{
                **config.__dict__,
                "backend_id": "fex",
                "backend_hodll": "libwow64fex.dll",
                "observe_ms": semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
            })
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                return {
                    "command": command, "exit_code": 0, "timed_out": False,
                    "output_sha256": "0" * 64, "output_tail": [],
                }

            with _exclusive_capture_lock(config):
                with patch.object(adapter, "_inspect", return_value=inspect):
                    adapter.validate(config)
                with patch(
                    "tools.miel_vliegt.hangover_probe.run", side_effect=fake_run,
                ):
                    with adapter.activate(config):
                        pass
            self.assertEqual(commands[-1][-3:], [
                "FEX", "/opt/fex/rootfs/usr/lib/wine/wineserver64", "-w",
            ])
            self.assertEqual(commands[-2][-3:], [
                "FEX", "/opt/fex/rootfs/usr/lib/wine/wineserver64", "-k",
            ])

    def test_docker_adapter_accepts_already_stopped_private_wineserver(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }

            def fake_run(command, **_kwargs):
                return {
                    "command": command,
                    "exit_code": 1,
                    "timed_out": False,
                    "output_sha256": "0" * 64,
                    "output_tail": [],
                }

            with _exclusive_capture_lock(config):
                with patch.object(adapter, "_inspect", return_value=inspect):
                    adapter.validate(config)
                with patch(
                    "tools.miel_vliegt.hangover_probe.run",
                    side_effect=fake_run,
                ):
                    with adapter.activate(config):
                        pass

    def test_docker_adapter_retains_isolated_state_until_wineserver_waits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }

            def fake_run(command, **_kwargs):
                failed = command[-1] == "-k"
                return {
                    "command": command,
                    "exit_code": 1 if failed else 0,
                    "timed_out": False,
                    "output_sha256": "0" * 64,
                    "output_tail": ["cannot stop"] if failed else [],
                }

            with _exclusive_capture_lock(config):
                with patch.object(adapter, "_inspect", return_value=inspect):
                    receipt = adapter.validate(config)
                environment_root = Path(
                    receipt["user_environment"]["directories"]["root"]["path"]
                )
                with patch(
                    "tools.miel_vliegt.hangover_probe.run",
                    side_effect=fake_run,
                ):
                    with self.assertRaisesRegex(
                        SuiteRunError, "could not stop",
                    ):
                        with adapter.activate(config):
                            pass
                self.assertTrue(environment_root.is_dir())

    def test_docker_adapter_environment_rejects_symlink_mode_owner_and_mount_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            directory = root / "checked"
            directory.mkdir(mode=0o700)
            receipt = _adapter_directory_receipt(
                directory,
                expected_uid=os.geteuid(),
                mount_root=root.resolve(),
                label="checked directory",
            )
            self.assertEqual(receipt["mode"], "0700")

            directory.chmod(0o755)
            with self.assertRaisesRegex(SuiteRunError, "mode 0700"):
                _adapter_directory_receipt(
                    directory,
                    expected_uid=os.geteuid(),
                    mount_root=root.resolve(),
                    label="checked directory",
                )
            directory.chmod(0o700)

            with self.assertRaisesRegex(SuiteRunError, "owned by uid"):
                _adapter_directory_receipt(
                    directory,
                    expected_uid=os.geteuid() + 1,
                    mount_root=root.resolve(),
                    label="checked directory",
                )

            outside = root.parent / f"{root.name}-outside"
            outside.mkdir(mode=0o700)
            try:
                with self.assertRaisesRegex(SuiteRunError, "escapes"):
                    _adapter_directory_receipt(
                        outside,
                        expected_uid=os.geteuid(),
                        mount_root=root.resolve(),
                        label="checked directory",
                    )
            finally:
                outside.rmdir()

            directory.rmdir()
            directory.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(SuiteRunError, "symlink"):
                _adapter_directory_receipt(
                    directory,
                    expected_uid=os.geteuid(),
                    mount_root=root.resolve(),
                    label="checked directory",
                )

    def test_docker_adapter_timeout_cleanup_uses_identical_isolated_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            adapter = DockerExecAdapter()
            inspect = {
                "Id": "f" * 64,
                "Name": "/miel-capture",
                "Image": "sha256:" + config.container_image_sha256,
                "Config": {"Image": config.container_image},
                "State": {"Running": True},
                "Mounts": [{
                    "Type": "bind",
                    "Source": str(root.resolve()),
                    "Destination": str(root.resolve()),
                    "RW": True,
                }],
            }
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                timed_out = command[-1] == "game.exe"
                return {
                    "command": command,
                    "exit_code": 1 if timed_out else 0,
                    "timed_out": timed_out,
                    "output_sha256": "0" * 64,
                    "output_tail": [],
                }

            with _exclusive_capture_lock(config):
                with patch.object(adapter, "_inspect", return_value=inspect):
                    receipt = adapter.validate(config)
                with patch(
                    "tools.miel_vliegt.hangover_probe.run", side_effect=fake_run,
                ):
                    with adapter.activate(config):
                        from tools.miel_vliegt import hangover_probe
                        with self.assertRaisesRegex(
                            SuiteRunError, "cannot override",
                        ):
                            hangover_probe.run(
                                ["env", "HOME=/root", "wine", "game.exe"],
                                cwd=config.game_root,
                            )
                        hangover_probe.run(
                            ["wine", "game.exe"], cwd=config.game_root,
                        )
            self.assertEqual(len(commands), 5)
            expected = receipt["user_environment"]["variables"]
            for command in commands:
                actual = {
                    command[index + 1].split("=", 1)[0]:
                    command[index + 1].split("=", 1)[1]
                    for index, item in enumerate(command)
                    if item == "--env"
                }
                self.assertEqual(actual, expected)

            config = self.make_config(root / "second")
            config.output_root.mkdir()
            with self.assertRaisesRegex(SuiteRunError, "output_root must not already exist"):
                validate_run_config(config)

    def test_calibration_tolerates_only_exact_rng_discovery_gap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            output = root / "calibration"
            manifest_path = root / "suite/suite-spec.json"
            manifest_path.parent.mkdir()
            manifest_path.write_text("{}", encoding="utf-8")
            observer = output / "native-observer-box64.log"
            frame = output / "native-frame-controls-press-hold-release-box64.json"
            replay = root / "suite/replay.mvo"
            replay.write_bytes(b"replay")
            profile = artifacts.scenario_observation_profile(
                "controls-press-hold-release"
            )

            def runner(*_args, **_kwargs):
                self.assertEqual(_kwargs["observation_profile"], profile)
                self.assertEqual(
                    _kwargs["proxy_dll"], config.proxy_dinput.resolve(),
                )
                observer.write_bytes(b"trace")
                frame.write_text("{}", encoding="utf-8")
                raise artifacts.ArtifactError(
                    "production rng.draw transcript drifted"
                )

            trace = {
                "scenario_id": "controls-press-hold-release",
                "semantic_sha256": "b" * 64,
                "record_count": 4,
                "profile": "production-session",
                "channel_counts": {"flight.tick": 1},
            }
            with patch.object(artifacts, "parse_semantic_log", return_value=trace), \
                 patch.object(artifacts, "load_scenario_suite_manifest", return_value={}), \
                 patch.object(artifacts, "scenario_suite_entry", return_value={
                     "observation_profile": profile,
                     "scenario": {"path": "scenario.json"},
                     "native_replay": {"path": "replay.mvo"}, "capture_tick": 58,
                 }), patch.object(artifacts, "load_framebuffer_metadata", return_value={
                     "scenario": "controls-press-hold-release",
                     "scenario_sha256": artifacts.sha256_file(replay),
                     "tick": 58,
                     "raw_sha256": "c" * 64,
                 }) as load_framebuffer, patch.object(
                     artifacts, "extract_calibrated_runtime_initial_state",
                     return_value=[],
                 ), patch.object(
                     artifacts, "extract_flight_activation_rng",
                     return_value={"count": 0, "sha256": "d" * 64, "draws": []},
                 ), patch.object(
                     artifacts, "extract_flight_activation_clock",
                     return_value={"count": 0, "sha256": "e" * 64, "ticks": []},
                 ), patch.object(
                     artifacts, "load_scenario",
                     return_value={"id": "controls-press-hold-release"},
                 ), patch.object(
                     artifacts, "extract_focus_timeline_receipt",
                     return_value={
                         "clock": "query_performance_counter",
                         "origin": "episode-focus-loss",
                         "scenario_sha256": "1" * 64,
                         "timeline_sha256": "2" * 64,
                         "event_count": 2,
                         "events": [],
                         "sha256": "3" * 64,
                     },
                 ), patch.object(
                     semantic_suite.hangover_probe,
                     "validate_scenario_observation_profile_receipt",
                     return_value={"profile": "scenario-bounded"},
                 ):
                captured, receipt = _calibration_capture(
                    config, ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                    manifest_path, "controls-press-hold-release", output, runner,
                )
            self.assertIs(captured, trace)
            self.assertEqual(receipt["status"], "CALIBRATION_ONLY")
            self.assertFalse(receipt["production_claim"])
            load_framebuffer.assert_not_called()
            self.assertEqual(receipt["framebuffer"], {
                "status": "NOT_APPLICABLE",
                "profile_id": "production-semantic-v1",
                "channel": "framebuffer",
                "reason": "omitted_by_observation_profile",
            })
            self.assertEqual(receipt["observation_cost"], {
                "profile": "production-session",
                "scenario_profile_id": "production-semantic-v1",
                "scenario_profile_sha256":
                    artifacts.observation_profile_sha256(
                        profile, scenario_id="controls-press-hold-release",
                    ),
                "omit_mask": "0x1fff",
                "record_count": 4,
                "channel_count": 1,
                "ticks": 1,
                "bytes_per_tick": len(b"trace"),
            })

            with patch.object(artifacts, "parse_semantic_log", return_value={
                **trace, "profile": "calibration-only",
            }), patch.object(
                artifacts, "load_scenario_suite_manifest", return_value={},
            ), patch.object(artifacts, "scenario_suite_entry", return_value={
                "observation_profile": profile,
                "native_replay": {"path": "replay.mvo"}, "capture_tick": 58,
            }), patch.object(
                semantic_suite.hangover_probe,
                "validate_scenario_observation_profile_receipt",
                return_value={"profile": "scenario-bounded"},
            ):
                with self.assertRaisesRegex(
                    SuiteRunError, "exact production observer profile",
                ):
                    _calibration_capture(
                        config, ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                        manifest_path, "controls-press-hold-release",
                        root / "profile-drift", runner,
                    )

            def wrong_failure(*_args, **_kwargs):
                raise artifacts.ArtifactError("production clock transcript drifted at tick 2")

            with patch.object(
                artifacts, "load_scenario_suite_manifest", return_value={},
            ), patch.object(artifacts, "scenario_suite_entry", return_value={
                "observation_profile": profile,
            }):
                with self.assertRaisesRegex(artifacts.ArtifactError, "clock transcript"):
                    _calibration_capture(
                        config, ["env"], {"id": "box64", "hodll": "wowbox64.dll"},
                        manifest_path, "controls-press-hold-release", root / "wrong",
                        wrong_failure,
                    )

    def test_calibration_and_exact_runs_share_the_production_observer_profile(self):
        calibration_source = inspect.getsource(_calibration_capture)
        exact_source = inspect.getsource(_exact_capture)
        self.assertIn("observation_profile=profile", calibration_source)
        self.assertIn("observation_profile=profile", exact_source)
        self.assertIn("proxy_dll=_resolved(config.proxy_dinput)", calibration_source)
        self.assertIn("proxy_dll=_resolved(config.proxy_dinput)", exact_source)
        self.assertIn('entry["observation_profile"]', calibration_source)
        self.assertIn('entry["observation_profile"]', exact_source)

    def test_omitted_channels_are_lazy_and_explicitly_not_applicable(self):
        profile = artifacts.scenario_observation_profile("taxi-straight")
        producer_called = False

        def producer():
            nonlocal producer_called
            producer_called = True
            return {"sha256": "a" * 64}

        value = semantic_suite._channel_value(
            profile, "shadow_polygon_render", producer,
        )
        self.assertFalse(producer_called)
        self.assertEqual(value, {
            "status": "NOT_APPLICABLE",
            "profile_id": "production-semantic-v1",
            "channel": "shadow_polygon_render",
            "reason": "omitted_by_observation_profile",
        })

    def test_media_semantics_receipt_is_explicit_when_not_observed(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "native.log"
            trace.write_text("MVT {\"channel\":\"flight.tick\"}\n")
            self.assertEqual(semantic_suite._media_semantics_receipt(trace), {
                "status": "NOT_OBSERVED",
                "production_claim": False,
                "reason":
                    "scenario_trace_contains_no_native_media_semantics_observations",
            })

    def test_media_semantics_receipt_remains_candidate_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "native.log"
            observation_set = {
                "schema": 1,
                "protocol":
                    semantic_suite.native_media_semantics_trace.SET_PROTOCOL,
                "promotionEligible": False,
                "promotionReceipt": None,
            }
            with patch.object(
                semantic_suite.native_media_semantics_trace,
                "consume_trace",
                return_value=observation_set,
            ):
                self.assertEqual(
                    semantic_suite._media_semantics_receipt(trace),
                    {
                        "status": "CANDIDATE_ONLY",
                        "production_claim": False,
                        "observation_set": observation_set,
                    },
                )

    def test_media_semantics_receipt_rejects_invalid_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "native.log"
            error_type = semantic_suite.native_media_semantics_trace \
                .NativeMediaSemanticsTraceError
            with patch.object(
                semantic_suite.native_media_semantics_trace,
                "consume_trace",
                side_effect=error_type("bad sequence"),
            ), self.assertRaisesRegex(error_type, "bad sequence"):
                semantic_suite._media_semantics_receipt(trace)
            with patch.object(
                semantic_suite.native_media_semantics_trace,
                "consume_trace",
                return_value={
                    "promotionEligible": True,
                    "promotionReceipt": {"status": "promoted"},
                },
            ), self.assertRaisesRegex(
                SuiteRunError, "unexpectedly allowed promotion",
            ):
                semantic_suite._media_semantics_receipt(trace)

    def test_orchestrator_persists_failed_prefix_bootstrap_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            bootstrap = {
                "usable": False,
                "checks": {
                    "wineboot_completed": True,
                    "runtime_readiness": False,
                },
                "runs": {"runtime_readiness": {"exit_code": 1}},
            }

            with self.assertRaisesRegex(
                SuiteRunError, "runtime_readiness",
            ), patch(
                "tools.miel_vliegt.hangover_probe.run",
                return_value={"exit_code": 0, "timed_out": False},
            ):
                run_calibrated_suite(
                    config,
                    execution_adapter=self.FakeAdapter(),
                    prefix_bootstrap=lambda *_args, **_kwargs: bootstrap,
                    scenario_runner=lambda *_args, **_kwargs: {},
                )

            persisted = json.loads(
                (config.output_root / "prefix-bootstrap.json").read_text()
            )
            self.assertEqual(persisted, bootstrap)

    def test_orchestrator_publishes_calibration_and_two_exact_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            calibration_ids = []
            prefix_bootstrap_calls = []

            def bootstrap_prefix(*args, **kwargs):
                prefix_bootstrap_calls.append((args, kwargs))
                return {"usable": True, "checks": {"fresh": True}}

            def fake_capture(
                _config, _environment, _backend, _manifest, scenario_id,
                output, _runner,
            ):
                calibration_ids.append(scenario_id)
                output.mkdir(parents=True)
                receipt = {
                    "status": "CALIBRATION_ONLY", "production_claim": False,
                    "scenario": scenario_id,
                    "observation_profile": {
                        **artifacts.scenario_observation_profile(scenario_id),
                        "sha256": artifacts.observation_profile_sha256(
                            artifacts.scenario_observation_profile(scenario_id),
                            scenario_id=scenario_id,
                        ),
                    },
                    "runtime_initial_state": [
                        {"name": name, "encoding": encoding,
                         "value_hex": "00" if encoding == "u8" else "00000000"}
                        for name, encoding in artifacts.RUNTIME_STATE_FIELDS
                    ],
                    "flight_activation_rng": {
                        "count": 0, "sha256": "d" * 64, "draws": [],
                    },
                    "flight_activation_clock": {
                        "count": 0, "sha256": "e" * 64, "ticks": [],
                    },
                }
                _atomic_write(output / "calibration-run.json", receipt)
                return {"scenario_id": scenario_id}, receipt

            exact_template = {
                "semantic_sha256": "a" * 64,
                "framebuffer_raw_sha256": "b" * 64,
                "framebuffer_rgba_sha256": "c" * 64,
                "runtime_initial_state": [],
                "flight_activation_rng": {
                    "count": 0, "sha256": "d" * 64, "draws": [],
                },
                "flight_activation_clock": {
                    "count": 0, "sha256": "e" * 64, "ticks": [],
                },
                "media_semantics": {
                    "status": "NOT_OBSERVED",
                    "production_claim": False,
                    "reason":
                        "scenario_trace_contains_no_native_media_semantics_observations",
                },
                "particle_lifecycle": {
                    "count": 0, "sha256": "f" * 64, "records": [],
                },
                "particle_activation": {
                    "count": 0, "sha256": "1" * 64, "records": [],
                },
                "render_presentation": {
                    "count": 0, "sha256": "2" * 64, "records": [],
                },
                "shadow_render": {
                    "count": 0, "sha256": "3" * 64, "records": [],
                },
                "shadow_camera_render": {
                    "count": 0, "sha256": "4" * 64, "records": [],
                },
                "shadow_render_room": {
                    "count": 0, "sha256": "5" * 64, "records": [],
                },
                "shadow_visible_objects": {
                    "count": 0, "sha256": "6" * 64, "records": [],
                },
                "shadow_visible_polygons": {
                    "count": 0, "sha256": "7" * 64, "records": [],
                },
                "shadow_polygon_render": {
                    "count": 0, "sha256": "8" * 64, "records": [],
                },
                "shadow_world_relation": {
                    "count": 0, "sha256": "9" * 64, "records": [],
                },
                "shadow_rotation_setter": {
                    "count": 0, "sha256": "0" * 64, "records": [],
                },
            }

            def fake_exact(*args, **_kwargs):
                scenario_id = args[4]
                output = args[5]
                output.mkdir(parents=True)
                receipt = {
                    **exact_template,
                    "observation_profile": {
                        **artifacts.scenario_observation_profile(scenario_id),
                        "sha256": artifacts.observation_profile_sha256(
                            artifacts.scenario_observation_profile(scenario_id),
                            scenario_id=scenario_id,
                        ),
                    },
                }
                _atomic_write(output / "exact-run.json", receipt)
                return receipt

            with patch(
                "tools.miel_vliegt.native_semantic_suite._calibration_capture",
                side_effect=fake_capture,
            ), patch.object(
                artifacts, "calibrate_scenario_rng_transcript",
                side_effect=lambda scenario, _trace, root: scenario,
            ), patch(
                "tools.miel_vliegt.native_semantic_suite._exact_capture",
                side_effect=fake_exact,
            ), patch(
                "tools.miel_vliegt.hangover_probe.run",
                return_value={"exit_code": 0, "timed_out": False},
            ):
                result = run_calibrated_suite(
                    config,
                    execution_adapter=self.FakeAdapter(),
                    prefix_bootstrap=bootstrap_prefix,
                    scenario_runner=lambda *_args, **_kwargs: {},
                )

            self.assertEqual(calibration_ids, list(artifacts.SCENARIO_ID_ORDER))
            self.assertTrue((config.suite_root / "suite-spec.json").is_file())
            persisted = json.loads(
                (config.output_root / "calibrated-suite-run.json").read_text()
            )
            self.assertEqual(result["status"], "REPRODUCIBLE_CANDIDATE_ONLY")
            self.assertEqual(persisted["status"], "REPRODUCIBLE_CANDIDATE_ONLY")
            self.assertEqual(persisted["schema"], semantic_suite.VERSION)
            self.assertEqual(
                persisted["calibrated_suite"]["path"],
                config.suite_root.relative_to(root).as_posix(),
            )
            self.assertFalse(persisted["production_claim"])
            self.assertEqual(len(persisted["exact_runs"]), 7)
            self.assertIsNone(persisted["blocker"])
            self.assertEqual(len(prefix_bootstrap_calls), 21)
            prefix_lifecycle = persisted["cold_audit_lane"]["prefix_lifecycle"]
            self.assertEqual(len(prefix_lifecycle), 20)
            for lifecycle in prefix_lifecycle:
                lifecycle_path = config.output_root / lifecycle["evidence"]["path"]
                self.assertTrue(lifecycle_path.is_file())
                self.assertEqual(
                    native_runner.sha256_file(lifecycle_path),
                    lifecycle["evidence"]["sha256"],
                )
            calibration_lifecycle = [
                lifecycle for lifecycle in prefix_lifecycle
                if lifecycle["reason"].startswith("calibration:")
            ]
            self.assertEqual(
                [lifecycle["reason"] for lifecycle in calibration_lifecycle],
                [
                    f"calibration:{scenario_id}:fresh-prefix"
                    for scenario_id in artifacts.SCENARIO_ID_ORDER[1:]
                ],
            )
            self.assertTrue(all(
                lifecycle["status"] == "COMPLETE"
                for lifecycle in calibration_lifecycle
            ))


class MirrorGameStateTests(unittest.TestCase):
    """Verify the clean-state mirror that prevents cross-scenario game-dir drift."""

    def test_mirror_restores_modified_files_and_removes_extras(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            clean = tmp / "clean"
            live = tmp / "live"
            (clean / "Data" / "User").mkdir(parents=True)
            (clean / "Data" / "User" / "user0.dat").write_bytes(b"CLEAN-USER")
            (clean / "Miel.ini").write_text("clean-config\n")
            (clean / "big.dat").write_bytes(b"x" * 1000)
            shutil.copytree(clean, live)
            # Simulate game writes: dirty two files, add a temp file + temp dir
            (live / "Data" / "User" / "user0.dat").write_bytes(b"DIRTY-USER")
            (live / "Miel.ini").write_text("dirty-config\n")
            (live / "game-cache.bin").write_bytes(b"temporary")
            (live / "Data" / "tmp").mkdir()
            (live / "Data" / "tmp" / "junk").write_bytes(b"junk")
            result = _mirror_game_state(clean, live)
            self.assertEqual(
                (live / "Data" / "User" / "user0.dat").read_bytes(), b"CLEAN-USER",
            )
            self.assertEqual((live / "Miel.ini").read_text(), "clean-config\n")
            self.assertFalse((live / "game-cache.bin").exists())
            self.assertFalse((live / "Data" / "tmp").exists())
            self.assertEqual((live / "big.dat").read_bytes(), b"x" * 1000)
            self.assertIn("Data/User/user0.dat", result["copied"])
            self.assertIn("Miel.ini", result["copied"])
            self.assertEqual(result["copied_count"], 2)
            self.assertIn("game-cache.bin", result["removed"])

    def test_mirror_is_idempotent_on_clean_directory(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            clean = tmp / "clean"
            live = tmp / "live"
            (clean / "Data" / "User").mkdir(parents=True)
            (clean / "Data" / "User" / "user0.dat").write_bytes(b"CLEAN")
            shutil.copytree(clean, live)
            result = _mirror_game_state(clean, live)
            self.assertEqual(result["copied_count"], 0)
            self.assertEqual(result["removed_count"], 0)


class WineserverShutdownCompletedTests(unittest.TestCase):
    """Wineserver -k/-w exit-code semantics for native Wine vs FEX."""

    def _result(self, exit_code, output_tail=None, timed_out=False):
        return {
            "exit_code": exit_code,
            "output_tail": output_tail or [],
            "timed_out": timed_out,
        }

    def test_exit_zero_passes(self):
        self.assertTrue(wineserver_shutdown_completed(
            self._result(0, ["some output"])
        ))

    def test_exit_one_empty_output_passes(self):
        self.assertTrue(wineserver_shutdown_completed(
            self._result(1, [])
        ))

    def test_exit_one_fex_connection_reset_passes(self):
        self.assertTrue(wineserver_shutdown_completed(
            self._result(1, ["read: Connection reset by peer"])
        ))

    def test_exit_one_fex_connection_reset_lowercase_passes(self):
        self.assertTrue(wineserver_shutdown_completed(
            self._result(1, ["READ: CONNECTION RESET BY PEER"])
        ))

    def test_exit_one_unexpected_output_fails(self):
        self.assertFalse(wineserver_shutdown_completed(
            self._result(1, ["some real error"])
        ))

    def test_exit_one_connection_reset_plus_other_output_fails(self):
        self.assertFalse(wineserver_shutdown_completed(
            self._result(1, ["read: Connection reset by peer", "real error"])
        ))

    def test_timeout_fails(self):
        self.assertFalse(wineserver_shutdown_completed(
            self._result(0, [], timed_out=True)
        ))

    def test_exit_two_fails(self):
        self.assertFalse(wineserver_shutdown_completed(
            self._result(2, [])
        ))


if __name__ == "__main__":
    unittest.main()
