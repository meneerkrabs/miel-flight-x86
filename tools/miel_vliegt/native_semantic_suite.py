#!/usr/bin/env python3
"""One-command, fail-closed native semantic suite calibration and capture.

This module orchestrates the existing reviewed scenario runner.  It creates a
fresh Wine prefix, records one native RNG calibration pass for every canonical
scenario, and atomically publishes the calibrated suite.  It deliberately
blocks before a second run until native runtime state has a reviewed apply and
read-back adapter.  None of its receipts are parity evidence.

The Python process is intentionally a capture-host process.  The selected x86
Wine image is provenance, not a place where this module assumes Python exists.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.miel_vliegt import native_scenario_artifacts as artifacts
from tools.miel_vliegt import hangover_probe
from tools.miel_vliegt import native_media_semantics_trace
from tools.miel_vliegt.fex_wine import native_runner


PROTOCOL = "miel-vliegt-native-semantic-calibrated-suite-run"
VERSION = 2
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BACKENDS = {
    "box64": "wowbox64.dll",
    "fex": "libwow64fex.dll",
    "wine": "i386",
    "native": "windows",
}
FEX_CALIBRATED_SUITE_OBSERVE_MS = 3_600_000
BACKEND_HODLL_PATHS = {
    "fex":
        "/opt/fex/rootfs/usr/lib/i386-linux-gnu/wine/i386-windows/"
        "libwow64fex.dll",
}
INPUT_LABELS = (
    "source_executable", "disposable_target", "user_profile", "observer_dll",
    "observer_launcher", "proxy_dinput", "real_dinput", "smoke_executable",
    "data_archive", "map_archive", "sounds_archive", "miel_ini",
)
RNG_CALIBRATION_ERRORS = frozenset({
    "production rng.seed reseed transcript drifted",
    "production rng.draw transcript drifted",
})
CANONICAL_EDITION = "miel-vliegt-de-wereld-rond-nl"
CANONICAL_EDITION_INPUT_SHA256 = {
    "source_executable":
        "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2",
    "disposable_target":
        "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2",
    "data_archive":
        "e5c8c1c7b5f8eb871692ffcf6812050999c9bf2c2fd2799ef6066498c7a9300a",
    "map_archive":
        "9f8d52a0df861ff947c2c9bf4f3e738f1c569a8b9c74feda93c24bd96d066c75",
    "sounds_archive":
        "7d1fe9a6adcfee26fd91fbf98d78110e5df42f5ddce52568d27548983decf676",
    "miel_ini":
        "e3059947a7e8050aa66958079e220b768a2e4a41195fba97382b96f2dfc44bed",
}
DOCKER_USER_ENVIRONMENT = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "USER",
    "LOGNAME",
)
LINUX_UNIX_SOCKET_PATH_MAX_BYTES = 107


class SuiteRunError(ValueError):
    """The suite cannot run without weakening provenance or isolation."""


@dataclass(frozen=True)
class SuiteRunConfig:
    source_executable: Path
    disposable_target: Path
    game_root: Path
    state_root: Path
    user_profile: Path
    observer_dll: Path
    observer_launcher: Path
    proxy_dinput: Path
    real_dinput: Path
    smoke_executable: Path
    wine_prefix: Path
    suite_root: Path
    output_root: Path
    backend_id: str
    backend_hodll: str
    container_image: str
    container_image_sha256: str
    container_id: str
    container_mount_root: Path
    expected_uid: int
    expected_sha256: Mapping[str, str]
    expected_gid: int | None = None
    backend_hodll_sha256: str | None = None
    observe_ms: int = FEX_CALIBRATED_SUITE_OBSERVE_MS
    max_records: int = 100_000
    runtime_readiness_timeout: int = \
        hangover_probe.FEX_RUNTIME_READINESS_TIMEOUT_SECONDS
    rpcss_readiness_timeout_ms: int = \
        hangover_probe.FEX_RPCSS_READINESS_TIMEOUT_MS
    prefix_mode: str = "cold-audit"
    sealed_prefix_root: Path | None = None
    tmpfs_staging_root: Path | None = None
    tmpfs_bytes_per_job: int = native_runner.DEFAULT_TMPFS_BYTES
    tmpfs_max_jobs: int = native_runner.DEFAULT_MAX_JOBS
    tmpfs_headroom_bytes: int = native_runner.DEFAULT_NO_SWAP_HEADROOM_BYTES
    clean_state_root: Path | None = None


class ExecutionAdapter(Protocol):
    """Run the existing Wine subprocess boundary in a proven environment."""

    def validate(self, config: SuiteRunConfig) -> dict[str, Any]: ...

    def activate(self, config: SuiteRunConfig) -> contextlib.AbstractContextManager[None]: ...


class DockerExecAdapter:
    """Route all Wine commands through one already-running exact-bind container."""

    def __init__(self, docker: str = "docker") -> None:
        self.docker = docker
        self._container_id: str | None = None
        self._user_environment: dict[str, str] | None = None
        self._user_environment_root: Path | None = None
        self._user_runtime_directory: Path | None = None

    def _inspect(self, container_id: str) -> dict[str, Any]:
        result = subprocess.run(
            [self.docker, "inspect", container_id],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise SuiteRunError(
                "docker inspect failed: " + result.stderr.strip()[-500:]
            )
        try:
            rows = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SuiteRunError("docker inspect did not return JSON") from error
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise SuiteRunError("docker inspect did not identify exactly one container")
        return rows[0]

    def validate(self, config: SuiteRunConfig) -> dict[str, Any]:
        if not isinstance(config.container_id, str) or not config.container_id.strip():
            raise SuiteRunError("container_id must be non-empty")
        record = self._inspect(config.container_id)
        state = record.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            raise SuiteRunError("native capture container is not running")
        image_id = record.get("Image")
        expected_image_id = "sha256:" + config.container_image_sha256
        if image_id != expected_image_id:
            raise SuiteRunError(
                f"capture container image drifted: expected {expected_image_id}, got {image_id}"
            )
        container_config = record.get("Config")
        configured_image = (
            container_config.get("Image") if isinstance(container_config, dict) else None
        )
        if configured_image != config.container_image:
            raise SuiteRunError(
                "capture container image reference drifted: "
                f"expected {config.container_image}, got {configured_image}"
            )
        hodll_receipt = None
        container_tmpfs_receipt = None
        if config.prefix_mode == "sealed":
            hodll_path = BACKEND_HODLL_PATHS.get(config.backend_id)
            if hodll_path is None or config.backend_hodll_sha256 is None:
                raise SuiteRunError("sealed backend HoDLL identity is incomplete")
            hodll_result = subprocess.run(
                [
                    self.docker, "exec", config.container_id,
                    "sha256sum", "--", hodll_path,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            actual_hodll_sha256 = hodll_result.stdout.split(maxsplit=1)[0] \
                if hodll_result.returncode == 0 else ""
            if actual_hodll_sha256 != config.backend_hodll_sha256:
                raise SuiteRunError(
                    "capture container HoDLL content drifted: "
                    f"expected {config.backend_hodll_sha256}, "
                    f"got {actual_hodll_sha256 or 'unavailable'}"
                )
            hodll_receipt = {
                "path": hodll_path,
                "sha256": actual_hodll_sha256,
            }
            if config.tmpfs_staging_root is None:
                raise SuiteRunError("sealed container tmpfs identity is incomplete")
            tmpfs_path = str(_resolved(config.tmpfs_staging_root))
            tmpfs_result = subprocess.run(
                [
                    self.docker, "exec", config.container_id,
                    "stat", "--file-system", "--format=%T", "--", tmpfs_path,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            container_filesystem = tmpfs_result.stdout.strip() \
                if tmpfs_result.returncode == 0 else ""
            if container_filesystem != "tmpfs":
                raise SuiteRunError(
                    "sealed staging is not tmpfs inside the live container"
                )
            container_tmpfs_receipt = {
                "path": tmpfs_path,
                "filesystem": container_filesystem,
            }
        mount_root = _resolved(config.container_mount_root)
        mounts = record.get("Mounts")
        exact_mounts = [
            row for row in mounts if isinstance(row, dict)
            and row.get("Type") == "bind"
            and Path(row.get("Source", "")).resolve() == mount_root
            and Path(row.get("Destination", "")).resolve() == mount_root
            and row.get("RW") is True
        ] if isinstance(mounts, list) else []
        if len(exact_mounts) != 1:
            raise SuiteRunError(
                "capture container needs one read-write bind with identical absolute "
                "source and destination mount root"
            )
        all_paths = [
            *_input_paths(config).values(),
            _resolved(config.game_root), _resolved(config.state_root),
            _resolved(config.wine_prefix), _resolved(config.suite_root),
            _resolved(config.output_root),
        ]
        if config.prefix_mode == "sealed":
            assert config.sealed_prefix_root is not None
            assert config.tmpfs_staging_root is not None
            all_paths.extend([
                _resolved(config.sealed_prefix_root),
                _resolved(config.tmpfs_staging_root),
            ])
        outside = []
        for path in all_paths:
            try:
                path.relative_to(mount_root)
            except ValueError:
                outside.append(str(path))
        if outside:
            raise SuiteRunError(
                "native capture paths escape the exact bind mount: " + ", ".join(outside)
            )
        full_id = record.get("Id")
        if not isinstance(full_id, str) or not full_id:
            raise SuiteRunError("docker inspect omitted the immutable container id")
        environment_root, runtime_directory, user_environment, \
            environment_directories = _create_docker_user_environment(
                config, mount_root,
            )
        self._container_id = full_id
        self._user_environment = user_environment
        self._user_environment_root = environment_root
        self._user_runtime_directory = runtime_directory
        return {
            "kind": "docker-exec-exact-bind-v1",
            "container_id": full_id,
            "container_name": record.get("Name"),
            "image_id": image_id,
            "mount": {
                "source": str(mount_root),
                "destination": str(mount_root),
                "read_write": True,
            },
            "exec_uid": config.expected_uid,
            "exec_gid": config.expected_gid,
            "hodll": hodll_receipt,
            "container_tmpfs": container_tmpfs_receipt,
            "user_environment": {
                "variables": dict(user_environment),
                "directories": environment_directories,
                "cleanup": "adapter-activation-finally",
            },
        }

    @contextlib.contextmanager
    def activate(self, config: SuiteRunConfig) -> Iterator[None]:
        if self._container_id is None or self._user_environment is None \
                or self._user_environment_root is None \
                or self._user_runtime_directory is None:
            raise SuiteRunError("Docker execution adapter was not validated")
        original_run = hangover_probe.run
        container_id = self._container_id
        docker = self.docker
        backend = hangover_probe.validate_capture_backend({
            "id": config.backend_id, "hodll": config.backend_hodll,
        })
        user_environment = dict(self._user_environment)
        environment_root = self._user_environment_root
        runtime_directory = self._user_runtime_directory

        def wrap(command: list[str], cwd: Path, interactive: bool = False) -> list[str]:
            if command and command[0] == "env":
                for assignment in command[1:]:
                    if "=" not in assignment:
                        break
                    if assignment.split("=", 1)[0] in DOCKER_USER_ENVIRONMENT:
                        raise SuiteRunError(
                            "Wine command cannot override the isolated Docker user environment"
                        )
            wrapped = [
                docker, "exec", "--user",
                (
                    str(config.expected_uid)
                    if config.expected_gid is None
                    else f"{config.expected_uid}:{config.expected_gid}"
                ),
                "--workdir", str(cwd),
            ]
            for key in DOCKER_USER_ENVIRONMENT:
                wrapped.extend(["--env", f"{key}={user_environment[key]}"])
            if interactive:
                wrapped.append("--interactive")
            wrapped.extend([container_id, *command])
            return wrapped

        def docker_run(
            command: list[str], *, cwd: Path, stdin: str | None = None,
            timeout: int = 45,
            watchdog: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
            resolved_cwd = _resolved(cwd)
            wrapped = wrap(command, resolved_cwd, stdin is not None)
            run_options: dict[str, Any] = {
                "cwd": resolved_cwd,
                "stdin": stdin,
                "timeout": timeout,
            }
            if watchdog is not None:
                run_options["watchdog"] = watchdog
            result = original_run(wrapped, **run_options)
            if result.get("timed_out") is True:
                stop_private_wineserver(resolved_cwd)
            return result

        def stop_private_wineserver(cwd: Path) -> bool:
            prefix = _resolved(config.wine_prefix)

            def container_runner(
                command: list[str], *, cwd: Path, timeout: int,
            ) -> dict[str, Any]:
                return original_run(
                    wrap(command, cwd), cwd=cwd, timeout=timeout,
                )

            shutdown = hangover_probe.shutdown_private_wineserver(
                ["env", f"WINEPREFIX={prefix}"],
                cwd,
                backend,
                timeout=15,
                runner=container_runner,
            )
            return shutdown["complete"]

        hangover_probe.run = docker_run
        primary_error: BaseException | None = None
        try:
            yield
        except BaseException as error:
            primary_error = error
            raise
        finally:
            hangover_probe.run = original_run
            game_root = _resolved(config.game_root)
            cleanup_error: BaseException | None = None
            try:
                cleanup_ok = stop_private_wineserver(game_root)
            except BaseException as error:
                cleanup_error = error
                cleanup_ok = False
            environment_cleanup_ok = False
            if cleanup_ok:
                try:
                    _remove_docker_user_environment(
                        config, environment_root, runtime_directory,
                    )
                    environment_cleanup_ok = True
                except (OSError, SuiteRunError) as error:
                    if primary_error is not None and hasattr(primary_error, "add_note"):
                        primary_error.add_note(
                            "docker execution adapter user environment cleanup failed: "
                            f"{error}"
                        )
            self._container_id = None
            self._user_environment = None
            self._user_environment_root = None
            self._user_runtime_directory = None
            if not cleanup_ok:
                if primary_error is not None and hasattr(primary_error, "add_note"):
                    detail = (
                        f": {cleanup_error}" if cleanup_error is not None else ""
                    )
                    primary_error.add_note(
                        "docker execution adapter prefix cleanup failed" + detail
                    )
                else:
                    raise SuiteRunError(
                        "docker execution adapter could not stop the private Wine server"
                    ) from cleanup_error
            if not environment_cleanup_ok and primary_error is None:
                raise SuiteRunError(
                    "docker execution adapter user environment cleanup failed"
                )


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve()


def _bundle_relative_directory(
    output_root: Path, directory: Path, label: str,
) -> str:
    """Bind a suite directory to the relocatable run bundle."""

    output_root = _resolved(output_root)
    directory = _resolved(directory)
    bundle_root = output_root.parent
    try:
        relative = directory.relative_to(bundle_root)
    except ValueError as error:
        raise SuiteRunError(
            f"{label} must live below the output bundle root"
        ) from error
    if not relative.parts:
        raise SuiteRunError(f"{label} cannot equal the output bundle root")
    return relative.as_posix()


def _exclusive_lock_path(config: SuiteRunConfig) -> Path:
    mount_root = _resolved(config.container_mount_root)
    return mount_root / ".miel-native-suite-exclusive-lock"


def _mutable_boundary(config: SuiteRunConfig) -> dict[str, Any]:
    boundary = {
        "container_id": config.container_id,
        "container_mount_root": str(_resolved(config.container_mount_root)),
        "game_root": str(_resolved(config.game_root)),
        "state_root": str(_resolved(config.state_root)),
        "disposable_target": str(_resolved(config.disposable_target)),
        "user_profile": str(_resolved(config.user_profile)),
        "wine_prefix": str(_resolved(config.wine_prefix)),
        "output_root": str(_resolved(config.output_root)),
        "sealed_prefix_root": (
            None if config.sealed_prefix_root is None
            else str(_resolved(config.sealed_prefix_root))
        ),
    }
    boundary["sha256"] = hashlib.sha256(
        json.dumps(
            boundary, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    return boundary


def _docker_runtime_directory(
    config: SuiteRunConfig, mount_root: Path,
) -> Path:
    lock = _exclusive_lock_path(config)
    namespace = hashlib.sha256(os.fsencode(lock)).hexdigest()[:12]
    return mount_root.resolve() / f".r{namespace}"


def _adapter_directory_receipt(
    path: Path, *, expected_uid: int, mount_root: Path, label: str,
) -> dict[str, Any]:
    path = path.parent.resolve() / path.name
    mount_root = mount_root.resolve()
    try:
        relative = path.relative_to(mount_root)
    except ValueError as error:
        raise SuiteRunError(
            f"{label} escapes the exact capture bind mount: {path}"
        ) from error
    information = path.lstat()
    if stat.S_ISLNK(information.st_mode):
        raise SuiteRunError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISDIR(information.st_mode):
        raise SuiteRunError(f"{label} is not a directory: {path}")
    mode = stat.S_IMODE(information.st_mode)
    if information.st_uid != expected_uid:
        raise SuiteRunError(
            f"{label} must be owned by uid {expected_uid}, "
            f"got {information.st_uid}: {path}"
        )
    if mode != 0o700:
        raise SuiteRunError(f"{label} must have mode 0700, got {mode:04o}: {path}")
    _owned_directory(path, expected_uid, label)
    return {
        "path": str(path),
        "relative_to_mount": relative.as_posix(),
        "uid": information.st_uid,
        "mode": "0700",
        "symlink": False,
        "writable": True,
    }


def _create_docker_user_environment(
    config: SuiteRunConfig, mount_root: Path,
) -> tuple[Path, Path, dict[str, str], dict[str, dict[str, Any]]]:
    lock = _exclusive_lock_path(config)
    if not lock.exists():
        raise SuiteRunError(
            "Docker execution adapter requires the active exclusive capture lock"
        )
    lock_receipt = _adapter_directory_receipt(
        lock,
        expected_uid=config.expected_uid,
        mount_root=mount_root,
        label="exclusive capture lock",
    )
    environment_root = lock / "container-user"
    if environment_root.exists() or environment_root.is_symlink():
        raise SuiteRunError(
            f"docker user environment already exists: {environment_root}"
        )
    runtime_directory = _docker_runtime_directory(config, mount_root)
    if runtime_directory.exists() or runtime_directory.is_symlink():
        raise SuiteRunError(
            f"docker user runtime already exists: {runtime_directory}"
        )
    fex_socket = runtime_directory / f"{config.expected_uid}.FEXServer.Socket"
    fex_socket_length = len(os.fsencode(fex_socket))
    if config.backend_id == "fex" \
            and fex_socket_length > LINUX_UNIX_SOCKET_PATH_MAX_BYTES:
        raise SuiteRunError(
            "FEX Unix socket path exceeds the Linux sockaddr_un limit "
            f"({fex_socket_length}>{LINUX_UNIX_SOCKET_PATH_MAX_BYTES}); "
            "use a shorter exact bind mount root"
        )
    directories = {
        "root": environment_root,
        "home": environment_root / "home",
        "config": environment_root / "config",
        "cache": environment_root / "cache",
        "data": environment_root / "data",
        "runtime": runtime_directory,
    }
    try:
        environment_root.mkdir(mode=0o700)
        for key in ("home", "config", "cache", "data"):
            directories[key].mkdir(mode=0o700)
        runtime_directory.mkdir(mode=0o700)
    except BaseException:
        if environment_root.exists() and not environment_root.is_symlink():
            shutil.rmtree(environment_root, ignore_errors=True)
        if runtime_directory.exists() and not runtime_directory.is_symlink():
            shutil.rmtree(runtime_directory, ignore_errors=True)
        raise
    receipts = {"lock": lock_receipt}
    for key, path in directories.items():
        receipts[key] = _adapter_directory_receipt(
            path,
            expected_uid=config.expected_uid,
            mount_root=mount_root,
            label=f"docker user {key} directory",
        )
    if config.backend_id == "fex":
        receipts["fex_socket"] = {
            "path": str(fex_socket),
            "byte_length": fex_socket_length,
            "max_byte_length": LINUX_UNIX_SOCKET_PATH_MAX_BYTES,
        }
    identity = f"miel-capture-{config.expected_uid}"
    environment = {
        "HOME": str(directories["home"]),
        "XDG_CONFIG_HOME": str(directories["config"]),
        "XDG_CACHE_HOME": str(directories["cache"]),
        "XDG_DATA_HOME": str(directories["data"]),
        "XDG_RUNTIME_DIR": str(directories["runtime"]),
        "USER": identity,
        "LOGNAME": identity,
    }
    if tuple(environment) != DOCKER_USER_ENVIRONMENT:
        raise SuiteRunError("docker user environment ordering drifted")
    return environment_root, runtime_directory, environment, receipts


def _remove_docker_user_environment(
    config: SuiteRunConfig, environment_root: Path, runtime_directory: Path,
) -> None:
    lock = _exclusive_lock_path(config)
    if environment_root.parent != lock \
            or environment_root.name != "container-user":
        raise SuiteRunError("docker user environment cleanup target drifted")
    expected_runtime = _docker_runtime_directory(
        config, _resolved(config.container_mount_root),
    )
    if runtime_directory != expected_runtime:
        raise SuiteRunError("docker user runtime cleanup target drifted")
    cleanup_targets = (
        ("environment", environment_root),
        ("runtime", runtime_directory),
    )
    for label, target in cleanup_targets:
        if target.is_symlink():
            raise SuiteRunError(
                f"docker user {label} cleanup target became a symlink"
            )
        if not target.exists():
            continue
        information = target.lstat()
        if not stat.S_ISDIR(information.st_mode) \
                or information.st_uid != config.expected_uid:
            raise SuiteRunError(
                f"docker user {label} cleanup ownership drifted"
            )
    for _label, target in cleanup_targets:
        if target.exists():
            shutil.rmtree(target, ignore_errors=False)


@contextlib.contextmanager
def _exclusive_capture_lock(config: SuiteRunConfig) -> Iterator[dict[str, Any]]:
    """Own the mutable Wine/target boundary for exactly one suite process.

    Output-directory checks alone are racy: two host processes can both pass
    preflight before either creates its output tree.  The fixed lock at the
    exact container bind root intentionally serializes suites that could share
    any game, proxy, profile, prefix, FEX socket, or sealed-store state.  The
    tmpfs max_jobs value is capacity only, never concurrency permission.
    """

    prefix = _resolved(config.wine_prefix)
    lock = _exclusive_lock_path(config)
    mount_root = _resolved(config.container_mount_root)
    if not mount_root.is_dir() or mount_root.is_symlink():
        raise SuiteRunError(
            "native suite container mount root is not a real directory"
        )
    mutable_boundary = _mutable_boundary(config)
    receipt = {
        "schema": 1,
        "protocol": "miel-vliegt-native-suite-exclusive-lock",
        "pid": os.getpid(),
        "uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "wine_prefix": str(prefix),
        "output_root": str(_resolved(config.output_root)),
        "lock_scope": "one-suite-per-exact-container-bind-root",
        "mutable_boundary": mutable_boundary,
    }
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as error:
        raise SuiteRunError(
            f"native suite mutable boundary is already locked: {lock}"
        ) from error
    try:
        _atomic_write(lock / "owner.json", receipt)
        yield receipt
    finally:
        shutil.rmtree(lock, ignore_errors=False)


def _require_hash(value: str, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise SuiteRunError(f"{label} must be a lowercase SHA-256")
    return value


def _owned_directory(path: Path, expected_uid: int, label: str) -> None:
    if not path.is_dir():
        raise SuiteRunError(f"{label} is not a directory: {path}")
    owner = path.stat().st_uid
    if owner != expected_uid:
        raise SuiteRunError(
            f"{label} must be owned by uid {expected_uid}, got {owner}: {path}"
        )
    probe = path / f".miel-suite-write-probe-{os.getpid()}"
    try:
        descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        probe.unlink()
    except OSError as error:
        probe.unlink(missing_ok=True)
        raise SuiteRunError(f"{label} is not writable: {path}") from error


def _input_paths(config: SuiteRunConfig) -> dict[str, Path]:
    game_root = _resolved(config.game_root)
    return {
        "source_executable": _resolved(config.source_executable),
        "disposable_target": _resolved(config.disposable_target),
        "user_profile": _resolved(config.user_profile),
        "observer_dll": _resolved(config.observer_dll),
        "observer_launcher": _resolved(config.observer_launcher),
        "proxy_dinput": _resolved(config.proxy_dinput),
        "real_dinput": _resolved(config.real_dinput),
        "smoke_executable": _resolved(config.smoke_executable),
        "data_archive": game_root / "data.up",
        "map_archive": game_root / "map.up",
        "sounds_archive": game_root / "sounds.up",
        "miel_ini": game_root / "Miel.ini",
    }


def _launcher_retry_identity(config: SuiteRunConfig) -> dict[str, str]:
    executable_sha256 = config.expected_sha256["source_executable"]
    return {
        "original_executable_sha256": executable_sha256,
        "patched_executable_sha256": executable_sha256,
        "observer_dll_sha256": config.expected_sha256["observer_dll"],
        "real_dinput_sha256": config.expected_sha256["real_dinput"],
    }


def validate_run_config(config: SuiteRunConfig) -> dict[str, Any]:
    """Validate topology, uid ownership, clean roots, and every hash pin."""

    if not isinstance(config.expected_uid, int) or isinstance(config.expected_uid, bool) \
            or config.expected_uid < 1:
        raise SuiteRunError("expected_uid must be a positive integer")
    effective_uid = os.geteuid() if hasattr(os, "geteuid") else None
    if effective_uid is not None and effective_uid != config.expected_uid:
        raise SuiteRunError(
            f"capture host effective uid is {effective_uid}, expected {config.expected_uid}"
        )
    effective_gid = os.getegid() if hasattr(os, "getegid") else None
    if config.backend_id not in BACKENDS \
            or config.backend_hodll != BACKENDS[config.backend_id]:
        raise SuiteRunError("backend id and HODLL do not match the reviewed pair")
    if not isinstance(config.container_image, str) or not config.container_image.strip():
        raise SuiteRunError("container_image must be non-empty")
    _require_hash(config.container_image_sha256, "container_image_sha256")
    if not isinstance(config.container_id, str) or not config.container_id.strip():
        raise SuiteRunError("container_id must be non-empty")
    hangover_probe.validate_observe_ms(config.observe_ms)
    if config.backend_id == "fex" \
            and config.observe_ms != FEX_CALIBRATED_SUITE_OBSERVE_MS:
        raise SuiteRunError(
            "FEX calibrated suite observe_ms must equal "
            f"{FEX_CALIBRATED_SUITE_OBSERVE_MS}; a shorter deadline can "
            "misclassify a slow native bootstrap as a startup hang"
        )
    if isinstance(config.runtime_readiness_timeout, bool) \
            or not 30 <= config.runtime_readiness_timeout <= 300:
        raise SuiteRunError(
            "runtime_readiness_timeout must be in 30..300 seconds"
        )
    if isinstance(config.rpcss_readiness_timeout_ms, bool) \
            or not 1_000 <= config.rpcss_readiness_timeout_ms <= 120_000:
        raise SuiteRunError(
            "rpcss_readiness_timeout_ms must be in 1000..120000"
        )
    if isinstance(config.max_records, bool) \
            or not 1 <= config.max_records <= 1_000_000:
        raise SuiteRunError("max_records must be in 1..1000000")
    if config.prefix_mode not in {"sealed", "cold-audit"}:
        raise SuiteRunError("prefix_mode must be sealed or cold-audit")
    performance_receipt = None
    if config.prefix_mode == "sealed":
        if config.backend_id != "fex":
            raise SuiteRunError("sealed prefix performance mode is FEX-only")
        if not isinstance(config.expected_gid, int) \
                or isinstance(config.expected_gid, bool) \
                or config.expected_gid < 0:
            raise SuiteRunError(
                "sealed mode requires a non-negative expected_gid"
            )
        if effective_gid is not None and effective_gid != config.expected_gid:
            raise SuiteRunError(
                f"capture host effective gid is {effective_gid}, "
                f"expected {config.expected_gid}"
            )
        _require_hash(
            config.backend_hodll_sha256, "backend_hodll_sha256",
        )
        if config.sealed_prefix_root is None or config.tmpfs_staging_root is None:
            raise SuiteRunError(
                "sealed mode requires sealed_prefix_root and tmpfs_staging_root"
            )
        sealed_root = _resolved(config.sealed_prefix_root)
        staging_root = _resolved(config.tmpfs_staging_root)
        mount_root = _resolved(config.container_mount_root)
        repository = hangover_probe.ROOT.resolve()
        for label, path in (
            ("sealed_prefix_root", sealed_root),
            ("tmpfs_staging_root", staging_root),
        ):
            if path == repository or repository in path.parents:
                raise SuiteRunError(f"{label} must remain outside the repository")
            try:
                path.relative_to(mount_root)
            except ValueError as error:
                raise SuiteRunError(
                    f"{label} must live below container_mount_root"
                ) from error
        if not sealed_root.is_dir() or sealed_root.is_symlink():
            raise SuiteRunError(
                "sealed_prefix_root must be a pre-provisioned real directory"
            )
        _owned_directory(
            sealed_root, config.expected_uid, "sealed_prefix_root",
        )
        if config.expected_gid is not None \
                and sealed_root.stat().st_gid != config.expected_gid:
            raise SuiteRunError("sealed_prefix_root gid drifted")
        try:
            performance_receipt = native_runner.validate_tmpfs_staging(
                staging_root,
                bytes_per_job=config.tmpfs_bytes_per_job,
                max_jobs=config.tmpfs_max_jobs,
                headroom_bytes=config.tmpfs_headroom_bytes,
            )
        except native_runner.NativeRunnerError as error:
            raise SuiteRunError(str(error)) from error
        _owned_directory(
            staging_root, config.expected_uid, "tmpfs_staging_root",
        )
        try:
            _resolved(config.wine_prefix).relative_to(staging_root)
        except ValueError as error:
            raise SuiteRunError(
                "sealed mode wine_prefix must live below tmpfs_staging_root"
            ) from error
        if sealed_root == staging_root or sealed_root in staging_root.parents \
                or staging_root in sealed_root.parents:
            raise SuiteRunError(
                "sealed_prefix_root and tmpfs_staging_root must not overlap"
            )
    elif config.sealed_prefix_root is not None \
            or config.tmpfs_staging_root is not None:
        raise SuiteRunError(
            "cold-audit mode must not configure sealed/tmpfs roots"
        )

    paths = _input_paths(config)
    expected_names = set(paths)
    if set(config.expected_sha256) != expected_names:
        raise SuiteRunError(
            "expected hashes differ: "
            f"missing={sorted(expected_names - set(config.expected_sha256))}, "
            f"unknown={sorted(set(config.expected_sha256) - expected_names)}"
        )
    for label, canonical_sha256 in CANONICAL_EDITION_INPUT_SHA256.items():
        expected = _require_hash(
            config.expected_sha256[label], f"{label}_sha256",
        )
        if expected != canonical_sha256:
            raise SuiteRunError(
                f"{label} is not the canonical {CANONICAL_EDITION} source: "
                f"expected {canonical_sha256}, got {expected}"
            )
    for label, path in paths.items():
        if not path.is_file():
            raise SuiteRunError(f"{label} is unavailable: {path}")
        expected = _require_hash(config.expected_sha256[label], f"{label}_sha256")
        actual = artifacts.sha256_file(path)
        if actual != expected:
            raise SuiteRunError(f"{label} hash drifted: expected {expected}, got {actual}")

    game_root = _resolved(config.game_root)
    state_root = _resolved(config.state_root)
    source = paths["source_executable"]
    target = paths["disposable_target"]
    proxy = paths["proxy_dinput"]
    if source.parent != game_root or state_root != game_root:
        raise SuiteRunError("source cwd and native state root must be the exact game root")
    if target == source or target.parent == game_root:
        raise SuiteRunError("disposable target must be in a separate proxy directory")
    if proxy != target.parent / "DINPUT.dll":
        raise SuiteRunError("proxy DINPUT must be DINPUT.dll beside the disposable target")
    if artifacts.sha256_file(target) != artifacts.sha256_file(source):
        raise SuiteRunError("disposable target is not byte-identical to the source executable")

    clean_roots = {
        "wine_prefix": _resolved(config.wine_prefix),
        "suite_root": _resolved(config.suite_root),
        "output_root": _resolved(config.output_root),
    }
    if len(set(clean_roots.values())) != len(clean_roots):
        raise SuiteRunError("wine prefix, suite root, and output root must be distinct")
    repository = hangover_probe.ROOT.resolve()
    for label, path in clean_roots.items():
        if path.exists():
            raise SuiteRunError(f"{label} must not already exist: {path}")
        if path == repository or repository in path.parents:
            raise SuiteRunError(f"{label} must remain outside the repository: {path}")
        _owned_directory(path.parent, config.expected_uid, f"{label} parent")
    _bundle_relative_directory(
        clean_roots["output_root"], clean_roots["suite_root"], "suite_root",
    )
    if clean_roots["suite_root"] in clean_roots["output_root"].parents \
            or clean_roots["output_root"] in clean_roots["suite_root"].parents:
        raise SuiteRunError("suite_root and output_root must not overlap")
    _owned_directory(game_root, config.expected_uid, "game root")
    _owned_directory(target.parent, config.expected_uid, "proxy target directory")

    return {
        "edition": CANONICAL_EDITION,
        "backend": {"id": config.backend_id, "hodll": config.backend_hodll},
        "container": {
            "image": config.container_image,
            "sha256": config.container_image_sha256,
        },
        "runtime_readiness_budget": {
            "guest_process_seconds": config.runtime_readiness_timeout,
            "rpcss_poll_milliseconds": config.rpcss_readiness_timeout_ms,
        },
        "observation_budget": {
            "milliseconds": config.observe_ms,
            "max_records": config.max_records,
        },
        "prefix_mode": config.prefix_mode,
        "performance_lane": performance_receipt,
        "effective_uid": effective_uid,
        "effective_gid": effective_gid,
        "paths": {
            label: {"path": str(path), "sha256": config.expected_sha256[label]}
            for label, path in paths.items()
        },
    }


def _assert_inputs_unchanged(config: SuiteRunConfig) -> None:
    changed = []
    for label, path in _input_paths(config).items():
        if not path.is_file() \
                or artifacts.sha256_file(path) != config.expected_sha256[label]:
            changed.append(label)
    if changed:
        raise SuiteRunError("native suite input drifted: " + ", ".join(changed))
    source = _resolved(config.source_executable)
    target = _resolved(config.disposable_target)
    if artifacts.sha256_file(source) != artifacts.sha256_file(target):
        raise SuiteRunError("source and disposable target identity diverged")


def _copy_fixture(root: Path, user_profile: Path) -> dict[str, Any]:
    fixture = root / "fixtures/user0.dat"
    fixture.parent.mkdir(parents=True)
    shutil.copy2(user_profile, fixture)
    return {
        "files": [{
            "role": "user-profile",
            "path": "fixtures/user0.dat",
            "byte_length": fixture.stat().st_size,
            "sha256": artifacts.sha256_file(fixture),
        }],
        "values": [],
    }


def _atomic_write(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    artifacts.write_canonical_json(temporary, value)
    os.replace(temporary, path)


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _regular_file_bytes(root: Path) -> int:
    if not root.is_dir() or root.is_symlink():
        return 0
    return sum(
        path.stat().st_size for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def _reject_stale_staging_references(value: Any, staging_root: Path) -> None:
    marker = str(staging_root.resolve())

    def visit(item: Any) -> bool:
        if isinstance(item, Path):
            return marker in str(item)
        if isinstance(item, str):
            return marker in item
        if isinstance(item, Mapping):
            return any(visit(key) or visit(nested) for key, nested in item.items())
        if isinstance(item, (list, tuple, set, frozenset)):
            return any(visit(nested) for nested in item)
        return False

    if visit(value):
        raise SuiteRunError(
            "producer result embeds an absolute tmpfs staging path"
        )


def _reject_stale_staging_references_in_files(staging_root: Path) -> None:
    marker = os.fsencode(str(staging_root.resolve()))
    for path in staging_root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        overlap = b""
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                if marker in overlap + block:
                    raise SuiteRunError(
                        "producer evidence embeds an absolute tmpfs staging "
                        f"path: {path.name}"
                    )
                overlap = block[-max(0, len(marker) - 1):]


class _SealedPrefixLane:
    """Own two immutable cold histories and disposable per-capture clones."""

    def __init__(
        self, config: SuiteRunConfig, backend: Mapping[str, str],
        prefix_bootstrap: Callable[..., dict[str, Any]],
    ) -> None:
        self.config = config
        self.backend = dict(backend)
        self.prefix_bootstrap = prefix_bootstrap
        contract_path = (
            REPOSITORY_ROOT / "tools/miel_vliegt/fex_wine/contract.json"
        )
        try:
            fex_contract = json.loads(contract_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SuiteRunError("FEX runner contract is unavailable") from error
        bootstrap_contract_sha256 = hashlib.sha256(
            json.dumps({
                "hangover_probe_sha256": artifacts.sha256_file(
                    Path(hangover_probe.__file__).resolve()
                ),
                "native_runner_sha256": artifacts.sha256_file(
                    Path(native_runner.__file__).resolve()
                ),
                "native_semantic_suite_sha256": artifacts.sha256_file(
                    Path(__file__).resolve()
                ),
                "fex_contract_sha256": artifacts.sha256_file(contract_path),
                "bootstrap": "wineboot-stop-wait-smoke-readiness-v1",
            }, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        startup_contract_sha256 = hashlib.sha256(
            json.dumps({
                "xvfb_arguments": list(hangover_probe.NATIVE_XVFB_ARGUMENTS),
                "observer_bootstrap_strategy":
                    hangover_probe.OBSERVER_BOOTSTRAP_STRATEGY,
                "observer_proxy_bootstrap_timeout_ms":
                    hangover_probe.OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS,
                "fex_capture_dll_override":
                    hangover_probe.FEX_CAPTURE_DLL_OVERRIDE,
                "startup": "sealed-clone-persist-smoke-readiness-v1",
            }, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        if config.expected_gid is None or config.backend_hodll_sha256 is None:
            raise SuiteRunError("sealed prefix identity is incomplete")
        try:
            self.identity = native_runner.contract_identity(
                backend=self.backend,
                container_image=config.container_image,
                container_image_sha256=config.container_image_sha256,
                smoke_sha256=config.expected_sha256["smoke_executable"],
                hodll_sha256=config.backend_hodll_sha256,
                bootstrap_contract_sha256=bootstrap_contract_sha256,
                startup_contract_sha256=startup_contract_sha256,
                expected_uid=config.expected_uid,
                expected_gid=config.expected_gid,
                fex_contract=fex_contract,
            )
        except native_runner.NativeRunnerError as error:
            raise SuiteRunError(str(error)) from error
        assert config.sealed_prefix_root is not None
        try:
            self.store_lease = native_runner.acquire_managed_store(
                _resolved(config.sealed_prefix_root),
                self.identity["sha256"],
                expected_uid=config.expected_uid,
                expected_gid=config.expected_gid,
            )
            self.store_receipt = {
                "root": str(self.store_lease.store),
                "identity_sha256": self.store_lease.identity_sha256,
                "lock": "shared-for-suite-lifetime",
                "inactive_ttl_seconds": self.store_lease.ttl_seconds,
                "prune": dict(self.store_lease.prune_receipt),
            }
            self.pair = self._ensure_pair()
        except native_runner.NativeRunnerError as error:
            lease = getattr(self, "store_lease", None)
            if lease is not None:
                lease.close()
            raise SuiteRunError(str(error)) from error
        except BaseException:
            lease = getattr(self, "store_lease", None)
            if lease is not None:
                lease.close()
            raise
        self.capture_receipts: list[dict[str, Any]] = []

    def _bootstrap_seal(self, prefix: Path) -> Mapping[str, Any]:
        receipt = self.prefix_bootstrap(
            prefix, self.backend, _resolved(self.config.smoke_executable),
            runtime_readiness_timeout=self.config.runtime_readiness_timeout,
            rpcss_readiness_timeout_ms=self.config.rpcss_readiness_timeout_ms,
        )
        if receipt.get("usable") is not True:
            return receipt
        shutdown = hangover_probe.shutdown_private_wineserver(
            hangover_probe.native_runtime_environment(prefix, self.backend),
            _resolved(self.config.game_root),
            self.backend,
            timeout=15,
        )
        if shutdown["complete"] is not True:
            raise SuiteRunError(
                "sealed prefix bootstrap did not stop and wait for Wine"
            )
        return {**receipt, "sealed_shutdown": shutdown, "usable": True}

    def _ensure_pair(self) -> dict[str, Any]:
        assert self.config.sealed_prefix_root is not None
        try:
            return native_runner.ensure_sealed_pair(
                _resolved(self.config.sealed_prefix_root),
                self.identity,
                self._bootstrap_seal,
            )
        except native_runner.NativeRunnerError as error:
            raise SuiteRunError(str(error)) from error

    def _remove_clone(self) -> None:
        prefix = _resolved(self.config.wine_prefix)
        if not prefix.exists():
            return
        shutdown = hangover_probe.shutdown_private_wineserver(
            ["env", f"WINEPREFIX={prefix}"],
            _resolved(self.config.game_root),
            self.backend,
            timeout=15,
        )
        if shutdown["complete"] is not True:
            raise SuiteRunError("could not stop disposable sealed-prefix clone")
        shutil.rmtree(prefix)

    def _prepare(self, slot: str) -> dict[str, Any]:
        self._remove_clone()
        try:
            clone = native_runner.clone_sealed_prefix(
                self.pair, slot, _resolved(self.config.wine_prefix),
            )
        except native_runner.NativeRunnerError as error:
            raise SuiteRunError(str(error)) from error
        activation = hangover_probe.activate_sealed_prefix(
            _resolved(self.config.wine_prefix),
            self.backend,
            _resolved(self.config.smoke_executable),
            runtime_readiness_timeout=self.config.runtime_readiness_timeout,
            rpcss_readiness_timeout_ms=self.config.rpcss_readiness_timeout_ms,
        )
        if activation.get("usable") is not True:
            raise SuiteRunError(f"sealed prefix {slot} activation failed")
        runs = activation.get("runs", {})
        activation_receipt = {
            "schema": activation.get("schema"),
            "protocol": activation.get("protocol"),
            "layout": activation.get("layout"),
            "checks": activation.get("checks"),
            "runtime_readiness_budget":
                activation.get("runtime_readiness_budget"),
            "usable": activation.get("usable"),
            "runs": {
                name: {
                    "exit_code": run.get("exit_code"),
                    "timed_out": run.get("timed_out"),
                    "output_sha256": run.get("output_sha256"),
                    "phase_timestamps": run.get("phase_timestamps"),
                }
                for name, run in runs.items() if isinstance(run, Mapping)
            } if isinstance(runs, Mapping) else {},
        }
        return {"clone": clone, "activation": activation_receipt}

    def _verify_slot(self, slot: str) -> dict[str, Any]:
        try:
            return native_runner.verify_seal(
                Path(self.pair["root"]) / slot / "template",
                self.identity["sha256"],
                slot,
            )
        except native_runner.NativeRunnerError as error:
            raise SuiteRunError(str(error)) from error

    def capture(
        self, slot: str, scenario_id: str, kind: str, destination: Path,
        producer: Callable[[Path], Any],
    ) -> Any:
        if destination.exists() or destination.is_symlink():
            raise SuiteRunError(f"managed capture destination exists: {destination}")
        assert self.config.tmpfs_staging_root is not None
        staging_root = _resolved(self.config.tmpfs_staging_root)
        attempt_identity = hashlib.sha256(json.dumps({
            "seal_identity_sha256": self.identity["sha256"],
            "slot": slot,
            "scenario": scenario_id,
            "kind": kind,
            "observer_dll_sha256": self.config.expected_sha256["observer_dll"],
            "observer_launcher_sha256":
                self.config.expected_sha256["observer_launcher"],
        }, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        attempts: list[dict[str, Any]] = []
        for attempt in (1, 2):
            attempt_root = staging_root / (
                f"{kind}-{scenario_id}-{slot.lower()}-{attempt}-{os.getpid()}"
            )
            if attempt_root.exists() or attempt_root.is_symlink():
                raise SuiteRunError("managed capture staging already exists")
            attempt_root.mkdir(mode=0o700)
            started = time.monotonic_ns()
            prepared: dict[str, Any] | None = None
            result: Any = None
            copyout: dict[str, Any] | None = None
            diagnostic_copyout: dict[str, Any] | None = None
            seal_after: dict[str, Any] | None = None
            primary_error: BaseException | None = None
            primary_traceback = None
            classification: dict[str, Any] = {
                "classification": "completed",
                "retryable": False,
            }
            integrity_ok = True
            try:
                prepared = self._prepare(slot)
                result = producer(attempt_root)
                _reject_stale_staging_references(result, attempt_root)
                _reject_stale_staging_references_in_files(attempt_root)
                prefix_size = _regular_file_bytes(
                    _resolved(self.config.wine_prefix)
                )
                evidence_size = _regular_file_bytes(attempt_root)
                if prefix_size + evidence_size > self.config.tmpfs_bytes_per_job:
                    raise SuiteRunError(
                        "managed capture exceeded its per-job tmpfs byte bound"
                    )
                copyout = native_runner.atomic_copyout_tree(
                    attempt_root, destination,
                )
            except BaseException as error:
                primary_error = error
                primary_traceback = error.__traceback__
                classification = native_runner.classify_pre_scenario_startup_hang(
                    error,
                    attempt_root,
                    _launcher_retry_identity(self.config),
                )
                if copyout is None and attempt_root.is_dir():
                    diagnostic_destination = (
                        _resolved(self.config.output_root)
                        / "failed-attempts" / kind / scenario_id
                        / f"{slot.lower()}-{attempt}"
                    )
                    try:
                        diagnostic_copyout = native_runner.atomic_copyout_tree(
                            attempt_root, diagnostic_destination,
                        )
                    except BaseException as diagnostic_error:
                        integrity_ok = False
                        if hasattr(primary_error, "add_note"):
                            primary_error.add_note(
                                "failed to preserve managed-capture diagnostics: "
                                f"{diagnostic_error}"
                            )
            try:
                seal_after = self._verify_slot(slot)
            except BaseException as seal_error:
                integrity_ok = False
                if primary_error is None:
                    primary_error = seal_error
                    primary_traceback = seal_error.__traceback__
                    classification = {
                        "classification": "seal-verification-failed",
                        "retryable": False,
                    }
                elif hasattr(primary_error, "add_note"):
                    primary_error.add_note(
                        f"sealed prefix post-verification failed: {seal_error}"
                    )
            try:
                self._remove_clone()
            except BaseException as cleanup_error:
                integrity_ok = False
                if primary_error is None:
                    primary_error = cleanup_error
                    primary_traceback = cleanup_error.__traceback__
                    classification = {
                        "classification": "clone-cleanup-failed",
                        "retryable": False,
                    }
                elif hasattr(primary_error, "add_note"):
                    primary_error.add_note(
                        f"disposable prefix cleanup failed: {cleanup_error}"
                    )
            try:
                shutil.rmtree(attempt_root)
            except BaseException as staging_error:
                integrity_ok = False
                if primary_error is None:
                    primary_error = staging_error
                    primary_traceback = staging_error.__traceback__
                    classification = {
                        "classification": "staging-cleanup-failed",
                        "retryable": False,
                    }
                elif hasattr(primary_error, "add_note"):
                    primary_error.add_note(
                        f"tmpfs attempt cleanup failed: {staging_error}"
                    )
            completed = time.monotonic_ns()
            attempt_receipt = {
                "attempt": attempt,
                "attempt_identity_sha256": attempt_identity,
                "started_monotonic_ns": started,
                "completed_monotonic_ns": completed,
                "duration_ns": completed - started,
                "classification": classification,
                "copyout": copyout,
                "diagnostic_copyout": diagnostic_copyout,
                "seal_after": seal_after,
                "prepared": prepared,
            }
            attempts.append(attempt_receipt)
            if primary_error is not None:
                if diagnostic_copyout is not None:
                    diagnostic_receipt = (
                        Path(diagnostic_copyout["destination"]).parent
                        / f"{slot.lower()}-{attempt}-receipt.json"
                    )
                    _atomic_write(diagnostic_receipt, attempt_receipt)
                if attempt == 1 and classification["retryable"] is True \
                        and integrity_ok:
                    continue
                raise primary_error.with_traceback(primary_traceback)
            receipt = {
                "slot": slot,
                "scenario": scenario_id,
                "kind": kind,
                "attempt_identity_sha256": attempt_identity,
                "attempts": attempts,
            }
            self.capture_receipts.append(receipt)
            return result
        raise AssertionError("managed capture retry loop did not terminate")

    def close(self) -> None:
        primary_error: BaseException | None = None
        try:
            self._remove_clone()
            for slot in native_runner.SLOTS:
                self._verify_slot(slot)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            lease = getattr(self, "store_lease", None)
            if lease is not None and not lease.closed:
                try:
                    lease.close()
                except BaseException as lease_error:
                    if primary_error is not None and hasattr(primary_error, "add_note"):
                        primary_error.add_note(
                            f"sealed store lease release failed: {lease_error}"
                        )
                    else:
                        raise


def _mirror_game_state(
    clean_root: Path, game_root: Path,
) -> dict[str, Any]:
    """Mirror a clean game-state snapshot into the live game root.

    Sequential scenario captures share one game directory.  Without a reset
    the game accumulates writes (config, cache, save side-channels) across
    captures and that residual state destabilises later cold boots: the game
    hangs before its stage manager takes its first tick.  This mirror restores
    every file to its verified clean-snapshot content and removes any file the
    game created, so each capture boots from a byte-identical directory.
    """
    clean = _resolved(clean_root)
    live = _resolved(game_root)
    if not clean.is_dir():
        raise SuiteRunError(
            f"clean-state snapshot is not a directory: {clean}"
        )
    if clean == live:
        raise SuiteRunError(
            "clean-state snapshot must differ from the live game root"
        )
    copied: list[str] = []
    removed: list[str] = []
    for src in sorted(clean.rglob("*")):
        rel = src.relative_to(clean)
        dst = live / rel
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue
        if not src.is_file() and not src.is_symlink():
            continue
        src_stat = src.stat()
        need_copy = True
        if dst.is_file():
            dst_stat = dst.stat()
            need_copy = (
                dst_stat.st_size != src_stat.st_size
                or dst_stat.st_mtime_ns != src_stat.st_mtime_ns
            )
        if need_copy:
            shutil.copy2(src, dst)
            copied.append(rel.as_posix())
    for dst in sorted(live.rglob("*"), reverse=True):
        rel = dst.relative_to(live)
        if (clean / rel).exists():
            continue
        if dst.is_file() or dst.is_symlink():
            dst.unlink()
            removed.append(rel.as_posix())
        elif dst.is_dir():
            try:
                dst.rmdir()
                removed.append(rel.as_posix() + "/")
            except OSError:
                pass
    return {
        "clean_state_root": str(clean),
        "game_root": str(live),
        "copied": copied,
        "removed": removed,
        "copied_count": len(copied),
        "removed_count": len(removed),
    }


class _ColdAuditCaptureLane:
    """Preserve cold-run failures and retry one proven pre-runtime hang."""

    def __init__(
        self,
        config: SuiteRunConfig,
        backend: Mapping[str, Any],
        prefix_bootstrap: Callable[..., dict[str, Any]],
    ) -> None:
        self.config = config
        self.backend = backend
        self.prefix_bootstrap = prefix_bootstrap
        self.capture_receipts: list[dict[str, Any]] = []
        self.prefix_receipts: list[dict[str, Any]] = []

    def rebootstrap(self, reason: str) -> dict[str, Any]:
        started = time.monotonic_ns()
        prefix = _resolved(self.config.wine_prefix)
        sequence = len(self.prefix_receipts) + 1
        receipt: dict[str, Any] = {
            "sequence": sequence,
            "reason": reason,
            "started_monotonic_ns": started,
            "shutdown": None,
            "bootstrap": None,
            "status": "FAILED",
        }
        primary_error: BaseException | None = None
        try:
            if prefix.is_symlink():
                raise SuiteRunError("cold Wine prefix must not be a symlink")
            if prefix.exists():
                if not prefix.is_dir():
                    raise SuiteRunError("cold Wine prefix is not a directory")
                shutdown = hangover_probe.shutdown_private_wineserver(
                    ["env", f"WINEPREFIX={prefix}"],
                    _resolved(self.config.game_root),
                    self.backend,
                    timeout=15,
                )
                receipt["shutdown"] = shutdown
                if shutdown.get("stopped") is not True:
                    raise SuiteRunError("could not stop cold-prefix Wine server")
                if shutdown.get("waited") is not True:
                    raise SuiteRunError("could not wait for cold-prefix Wine server")
                shutil.rmtree(prefix)
            # FEXServer kill DISABLED (was added in aa1167fb to fix "poisoned
            # JIT cache" stalls, but that diagnosis was wrong — the real cause
            # was the observe_ms reduction in c3c984c8). Killing FEXServer
            # destroys the JIT cache compiled by prior scenarios (controls,
            # taxi), which contains code paths that takeoff-climb depends on.
            # Without the pre-compiled cache, takeoff-climb deadlocks
            # deterministically under FEX-2607 JIT compilation.
            if False:  # FEXServer kill disabled — see comment above
                # Clear ALL FEX on-disk state to ensure the new FEXServer
                # starts with a completely clean compilation state.  Killing
                # FEXServer clears the in-memory JIT cache, but FEX-2607
                # persists AOT/JIT cache, configuration, and app data on disk.
                # FEX uses XDG_DATA_HOME/FEX-Emu/ for its primary data/AOT
                # cache (not XDG_CACHE_HOME as initially assumed).  We clear
                # every possible location to be thorough.
                lock_root = _exclusive_lock_path(self.config) / "container-user"
                fex_cache_paths = [
                    lock_root / "data" / "FEX-Emu",
                    lock_root / "cache" / "FEX-Emu",
                    lock_root / "config" / "FEX-Emu",
                    lock_root / "home" / ".fex-emu",
                ]
                fex_cache_clears: list[dict[str, Any]] = []
                for fex_cache_dir in fex_cache_paths:
                    entry: dict[str, Any] = {"path": str(fex_cache_dir)}
                    if fex_cache_dir.exists():
                        entry["existed"] = True
                        try:
                            shutil.rmtree(fex_cache_dir)
                            entry["cleared"] = True
                        except BaseException as cache_error:
                            entry["cleared"] = False
                            entry["error"] = str(cache_error)
                    else:
                        entry["existed"] = False
                    fex_cache_clears.append(entry)
                fex_kill["on_disk_cache"] = fex_cache_clears
                receipt["fex_server_kill"] = fex_kill
            bootstrap = self.prefix_bootstrap(
                prefix,
                self.backend,
                _resolved(self.config.smoke_executable),
                runtime_readiness_timeout=self.config.runtime_readiness_timeout,
                rpcss_readiness_timeout_ms=self.config.rpcss_readiness_timeout_ms,
            )
            receipt["bootstrap"] = bootstrap
            if bootstrap.get("usable") is not True:
                raise SuiteRunError("cold-prefix bootstrap failed")
            receipt["status"] = "COMPLETE"
            return receipt
        except BaseException as error:
            primary_error = error
            receipt["error_type"] = type(error).__name__
            receipt["error"] = str(error)
            raise
        finally:
            completed = time.monotonic_ns()
            receipt["completed_monotonic_ns"] = completed
            receipt["duration_ns"] = completed - started
            lifecycle_root = _resolved(self.config.output_root) / "prefix-lifecycle"
            lifecycle_path = lifecycle_root / f"{sequence:03d}.json"
            evidence_error: BaseException | None = None
            try:
                lifecycle_root.mkdir(exist_ok=True)
                _atomic_write(lifecycle_path, receipt)
                receipt["evidence"] = {
                    "path": lifecycle_path.relative_to(
                        _resolved(self.config.output_root)
                    ).as_posix(),
                    "sha256": artifacts.sha256_file(lifecycle_path),
                }
            except BaseException as error:
                evidence_error = error
                receipt["status"] = "FAILED"
                receipt["evidence_error_type"] = type(error).__name__
                receipt["evidence_error"] = str(error)
                if primary_error is None:
                    primary_error = error
                elif hasattr(primary_error, "add_note"):
                    primary_error.add_note(
                        "failed to preserve prefix lifecycle evidence: "
                        f"{error}"
                    )
            self.prefix_receipts.append(receipt)
            if evidence_error is not None and primary_error is evidence_error:
                raise evidence_error

    def capture(
        self,
        scenario_id: str,
        kind: str,
        destination: Path,
        producer: Callable[[Path], Any],
    ) -> Any:
        if destination.exists() or destination.is_symlink():
            raise SuiteRunError(f"cold capture destination exists: {destination}")
        output_root = _resolved(self.config.output_root)
        staging_parent = output_root / ".cold-capture-staging"
        staging_parent.mkdir(exist_ok=True)
        attempt_identity = hashlib.sha256(json.dumps({
            "mode": "cold-audit",
            "scenario": scenario_id,
            "kind": kind,
            "observer_dll_sha256": self.config.expected_sha256["observer_dll"],
            "observer_launcher_sha256":
                self.config.expected_sha256["observer_launcher"],
        }, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        attempts: list[dict[str, Any]] = []
        for attempt in (1, 2, 3):
            attempt_root = staging_parent / (
                f"{kind}-{scenario_id}-{attempt}-{os.getpid()}"
            )
            if attempt_root.exists() or attempt_root.is_symlink():
                raise SuiteRunError("cold capture staging already exists")
            game_state_reset: dict[str, Any] | None = None
            if self.config.clean_state_root is not None:
                game_state_reset = _mirror_game_state(
                    _resolved(self.config.clean_state_root),
                    _resolved(self.config.game_root),
                )
            started = time.monotonic_ns()
            result: Any = None
            copyout: dict[str, Any] | None = None
            diagnostic_copyout: dict[str, Any] | None = None
            reset_receipt: dict[str, Any] | None = None
            primary_error: BaseException | None = None
            primary_traceback = None
            classification: dict[str, Any] = {
                "classification": "completed",
                "retryable": False,
            }
            integrity_ok = True
            try:
                result = producer(attempt_root)
                _reject_stale_staging_references(result, attempt_root)
                _reject_stale_staging_references_in_files(attempt_root)
                copyout = native_runner.atomic_copyout_tree(
                    attempt_root, destination,
                )
            except BaseException as error:
                primary_error = error
                primary_traceback = error.__traceback__
                if not attempt_root.exists():
                    attempt_root.mkdir(mode=0o700)
                classification = native_runner.classify_pre_scenario_startup_hang(
                    error,
                    attempt_root,
                    _launcher_retry_identity(self.config),
                )
                diagnostic_destination = (
                    output_root / "failed-attempts" / kind / scenario_id
                    / f"cold-{attempt}"
                )
                try:
                    diagnostic_copyout = native_runner.atomic_copyout_tree(
                        attempt_root, diagnostic_destination,
                    )
                except BaseException as diagnostic_error:
                    integrity_ok = False
                    if hasattr(primary_error, "add_note"):
                        primary_error.add_note(
                            "failed to preserve cold-capture diagnostics: "
                            f"{diagnostic_error}"
                        )
            try:
                shutil.rmtree(attempt_root)
            except BaseException as staging_error:
                integrity_ok = False
                if primary_error is None:
                    primary_error = staging_error
                    primary_traceback = staging_error.__traceback__
                    classification = {
                        "classification": "staging-cleanup-failed",
                        "retryable": False,
                    }
                elif hasattr(primary_error, "add_note"):
                    primary_error.add_note(
                        f"cold attempt cleanup failed: {staging_error}"
                    )
            should_retry = (
                primary_error is not None
                and attempt in (1, 2)
                and classification["retryable"] is True
                and integrity_ok
            )
            if should_retry:
                reset_index = len(self.prefix_receipts)
                try:
                    reset_receipt = self.rebootstrap(
                        f"{kind}:{scenario_id}:pre-scenario-retry"
                    )
                except BaseException as reset_error:
                    integrity_ok = False
                    if len(self.prefix_receipts) != reset_index + 1:
                        raise AssertionError(
                            "prefix lifecycle failure was not preserved"
                        ) from reset_error
                    reset_receipt = self.prefix_receipts[reset_index]
                    if hasattr(primary_error, "add_note"):
                        primary_error.add_note(
                            f"cold-prefix reset blocked retry: {reset_error}"
                        )
            completed = time.monotonic_ns()
            attempt_receipt = {
                "attempt": attempt,
                "attempt_identity_sha256": attempt_identity,
                "started_monotonic_ns": started,
                "completed_monotonic_ns": completed,
                "duration_ns": completed - started,
                "classification": classification,
                "copyout": copyout,
                "diagnostic_copyout": diagnostic_copyout,
                "prefix_reset": reset_receipt,
                "game_state_reset": game_state_reset,
            }
            attempts.append(attempt_receipt)
            if primary_error is not None:
                if diagnostic_copyout is not None:
                    diagnostic_receipt = (
                        Path(diagnostic_copyout["destination"]).parent
                        / f"cold-{attempt}-receipt.json"
                    )
                    _atomic_write(diagnostic_receipt, attempt_receipt)
                if should_retry and integrity_ok:
                    continue
                raise primary_error.with_traceback(primary_traceback)
            receipt = {
                "scenario": scenario_id,
                "kind": kind,
                "attempt_identity_sha256": attempt_identity,
                "attempts": attempts,
            }
            self.capture_receipts.append(receipt)
            return result
        raise AssertionError("cold capture retry loop did not terminate")


@contextlib.contextmanager
def _performance_lane_lifecycle(
    lane: _SealedPrefixLane,
) -> Iterator[None]:
    primary_error: BaseException | None = None
    try:
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            lane.close()
        except BaseException as cleanup_error:
            if primary_error is not None and hasattr(primary_error, "add_note"):
                primary_error.add_note(
                    f"performance lane final cleanup failed: {cleanup_error}"
                )
            else:
                raise


def _profile_receipt(
    profile: Mapping[str, Any], *, scenario_id: str,
) -> dict[str, Any]:
    validated = artifacts.validate_scenario_observation_profile(
        profile, scenario_id=scenario_id,
    )
    return {
        **validated,
        "sha256": artifacts.observation_profile_sha256(
            validated, scenario_id=scenario_id,
        ),
    }


def _not_applicable(
    profile: Mapping[str, Any], channel: str,
) -> dict[str, str]:
    return {
        "status": "NOT_APPLICABLE",
        "profile_id": str(profile["id"]),
        "channel": channel,
        "reason": "omitted_by_observation_profile",
    }


def _channel_value(
    profile: Mapping[str, Any], channel: str, producer: Callable[[], Any],
) -> Any:
    if channel not in profile["applicable_receipt_channels"]:
        return _not_applicable(profile, channel)
    return producer()


def _channel_sha256(value: Any, profile: Mapping[str, Any], channel: str) -> Any:
    if channel not in profile["applicable_receipt_channels"]:
        return _not_applicable(profile, channel)
    if isinstance(value, str) and SHA256.fullmatch(value):
        return value
    if isinstance(value, Mapping):
        digest = value.get("sha256")
        if isinstance(digest, str) and SHA256.fullmatch(digest):
            return digest
    raise SuiteRunError(f"applicable channel has no SHA-256: {channel}")


def _media_semantics_receipt(trace_path: Path) -> dict[str, Any]:
    """Bind optional native media observations without implying promotion."""

    try:
        observation_set = native_media_semantics_trace.consume_trace(trace_path)
    except native_media_semantics_trace.NativeMediaSemanticsTraceError as error:
        if str(error) != "native media-semantics observations are absent":
            raise
        return {
            "status": "NOT_OBSERVED",
            "production_claim": False,
            "reason":
                "scenario_trace_contains_no_native_media_semantics_observations",
        }
    if observation_set.get("promotionEligible") is not False \
            or observation_set.get("promotionReceipt") is not None:
        raise SuiteRunError(
            "native media observation consumer unexpectedly allowed promotion"
        )
    return {
        "status": "CANDIDATE_ONLY",
        "production_claim": False,
        "observation_set": observation_set,
    }


def _calibration_capture(
    config: SuiteRunConfig,
    environment: list[str],
    backend: dict[str, str],
    manifest_path: Path,
    scenario_id: str,
    output_directory: Path,
    scenario_runner: Callable[..., dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture with the exact-run observer cost, tolerating only unknown RNG."""

    output_directory.mkdir(parents=True, exist_ok=True)
    output = output_directory / "capture.json"
    manifest = artifacts.load_scenario_suite_manifest(manifest_path)
    entry = artifacts.scenario_suite_entry(manifest, scenario_id)
    profile = artifacts.validate_scenario_observation_profile(
        entry["observation_profile"], scenario_id=scenario_id,
    )
    try:
        result = scenario_runner(
            environment,
            backend,
            _resolved(config.source_executable),
            output,
            manifest_path,
            scenario_id,
            _resolved(config.state_root),
            {"user-profile": "Data/User/user0.dat"},
            _resolved(config.observer_dll),
            _resolved(config.disposable_target),
            _resolved(config.observer_launcher),
            real_dinput=_resolved(config.real_dinput),
            proxy_dll=_resolved(config.proxy_dinput),
            observe_ms=config.observe_ms,
            max_records=config.max_records,
            observation_profile=profile,
        )
        trace_path = output_directory / result["observer_trace"]["path"]
        status = "EMPTY_RNG_TRANSCRIPT_MATCHED"
    except artifacts.ArtifactError as error:
        if str(error) not in RNG_CALIBRATION_ERRORS:
            raise
        trace_path = output_directory / f"native-observer-{backend['id']}.log"
        status = "RNG_TRANSCRIPT_RECORDED"
    trace = artifacts.parse_semantic_log(trace_path, require_complete=True)
    hook_profile = hangover_probe.validate_scenario_observation_profile_receipt(
        trace_path, profile,
    )
    if trace.get("profile") != "production-session":
        raise SuiteRunError(
            f"calibration must use the exact production observer profile: {scenario_id}"
        )
    captured_ticks = trace.get("channel_counts", {}).get("flight.tick")
    if type(captured_ticks) is not int or captured_ticks <= 0:
        raise SuiteRunError(
            f"calibration trace has no completed flight ticks: {scenario_id}"
        )
    if trace.get("scenario_id") != scenario_id:
        raise SuiteRunError(f"calibration trace targets another scenario: {scenario_id}")

    replay = manifest_path.parent / entry["native_replay"]["path"]
    scenario = artifacts.load_scenario(
        manifest_path.parent / entry["scenario"]["path"],
        root=manifest_path.parent,
    )
    focus_timeline = artifacts.extract_focus_timeline_receipt(
        trace_path, scenario, root=manifest_path.parent,
    )
    metadata_path = output_directory / f"native-frame-{scenario_id}-{backend['id']}.json"

    def calibration_framebuffer() -> dict[str, Any]:
        metadata = artifacts.load_framebuffer_metadata(metadata_path)
        if metadata["scenario"] != scenario_id \
                or metadata["scenario_sha256"] != artifacts.sha256_file(replay) \
                or metadata["tick"] != entry["capture_tick"]:
            raise SuiteRunError(
                f"calibration framebuffer binding drifted: {scenario_id}"
            )
        return {
            "path": metadata_path.name,
            "sha256": artifacts.sha256_file(metadata_path),
            "raw_sha256": metadata["raw_sha256"],
        }

    runtime_initial_state = artifacts.extract_calibrated_runtime_initial_state(
        trace_path,
    )
    flight_activation_rng = artifacts.extract_flight_activation_rng(trace_path)
    flight_activation_clock = artifacts.extract_flight_activation_clock(trace_path)
    receipt = {
        "status": "CALIBRATION_ONLY",
        "production_claim": False,
        "scenario": scenario_id,
        "rng_status": status,
        "observation_profile": _profile_receipt(
            profile, scenario_id=scenario_id,
        ),
        "hook_observation_profile": hook_profile,
        "runtime_initial_state": runtime_initial_state,
        "flight_activation_rng": flight_activation_rng,
        "flight_activation_clock": flight_activation_clock,
        "focus_timeline": focus_timeline,
        "media_semantics": _media_semantics_receipt(trace_path),
        "observer_log": {
            "path": trace_path.name,
            "sha256": artifacts.sha256_file(trace_path),
            "semantic_sha256": trace["semantic_sha256"],
            "byte_length": trace_path.stat().st_size,
            "record_count": trace["record_count"],
        },
        "observation_cost": {
            "profile": trace["profile"],
            "scenario_profile_id": profile["id"],
            "scenario_profile_sha256": artifacts.observation_profile_sha256(
                profile, scenario_id=scenario_id,
            ),
            "omit_mask": profile["omit_mask"],
            "record_count": trace["record_count"],
            "channel_count": len(trace.get("channel_counts", {})),
            "ticks": captured_ticks,
            "bytes_per_tick": (
                trace_path.stat().st_size + captured_ticks - 1
            ) // captured_ticks,
        },
        "framebuffer": _channel_value(
            profile, "framebuffer", calibration_framebuffer,
        ),
    }
    _atomic_write(output_directory / "calibration-run.json", receipt)
    return trace, receipt


def _publish_calibrated_suite(
    suite_root: Path,
    user_profile: Path,
    calibrated: Mapping[str, Mapping[str, Any]],
    activation_rng: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    staging = suite_root.with_name(f".{suite_root.name}.building-{os.getpid()}")
    if staging.exists():
        raise SuiteRunError(f"stale calibrated-suite staging directory: {staging}")
    staging.mkdir()
    try:
        initial_state = _copy_fixture(staging, user_profile)
        manifest = artifacts.materialize_scenario_suite(staging, initial_state)
        for entry in manifest["scenarios"]:
            scenario_id = entry["id"]
            scenario = artifacts.validate_scenario(calibrated[scenario_id], root=staging)
            scenario_path = staging / entry["scenario"]["path"]
            replay_path = staging / entry["native_replay"]["path"]
            _atomic_write(scenario_path, scenario)
            _atomic_write_bytes(
                replay_path,
                artifacts.build_native_replay_script(scenario, root=staging),
            )
            entry["scenario"]["sha256"] = artifacts.sha256_file(scenario_path)
            entry["scenario"]["semantic_sha256"] = artifacts.scenario_sha256(
                scenario, root=staging,
            )
            entry["native_replay"]["sha256"] = artifacts.sha256_file(replay_path)
        artifacts.validate_scenario_suite_manifest(manifest, root=staging)
        _atomic_write(staging / "suite-spec.json", manifest)
        _atomic_write(staging / "flight-activation-rng.json", {
            "schema": 1,
            "protocol": "miel-vliegt-native-flight-activation-rng-suite",
            "production_claim": False,
            "scenario_order": list(artifacts.SCENARIO_ID_ORDER),
            "scenarios": {
                scenario_id: activation_rng[scenario_id]
                for scenario_id in artifacts.SCENARIO_ID_ORDER
            },
        })
        os.replace(staging, suite_root)
        return artifacts.load_scenario_suite_manifest(suite_root / "suite-spec.json")
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _exact_capture(
    config: SuiteRunConfig,
    environment: list[str],
    backend: dict[str, str],
    manifest_path: Path,
    scenario_id: str,
    output_directory: Path,
    scenario_runner: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    output_directory.mkdir(parents=True, exist_ok=True)
    manifest = artifacts.load_scenario_suite_manifest(manifest_path)
    entry = artifacts.scenario_suite_entry(manifest, scenario_id)
    profile = artifacts.validate_scenario_observation_profile(
        entry["observation_profile"], scenario_id=scenario_id,
    )
    result = scenario_runner(
        environment,
        backend,
        _resolved(config.source_executable),
        output_directory / "capture.json",
        manifest_path,
        scenario_id,
        _resolved(config.state_root),
        {"user-profile": "Data/User/user0.dat"},
        _resolved(config.observer_dll),
        _resolved(config.disposable_target),
        _resolved(config.observer_launcher),
        real_dinput=_resolved(config.real_dinput),
        proxy_dll=_resolved(config.proxy_dinput),
        observe_ms=config.observe_ms,
        max_records=config.max_records,
        observation_profile=profile,
    )
    observer_log = output_directory / result["observer_trace"]["path"]
    result_profile = result.get("observation_profile")
    expected_profile_sha256 = artifacts.observation_profile_sha256(
        profile, scenario_id=scenario_id,
    )
    if not isinstance(result_profile, Mapping) \
            or result_profile.get("sha256") != expected_profile_sha256:
        raise SuiteRunError(f"scenario runner observation profile drifted: {scenario_id}")
    readback = artifacts.extract_bound_runtime_initial_state(observer_log)
    activation_rng = artifacts.extract_flight_activation_rng(observer_log)
    activation_clock = artifacts.extract_flight_activation_clock(observer_log)
    particle_activation = _channel_value(
        profile, "particle_activation",
        lambda: artifacts.extract_particle_activation_lifecycle(observer_log),
    )
    particle_lifecycle = _channel_value(
        profile, "particle_lifecycle",
        lambda: artifacts.extract_particle_lifecycle(observer_log),
    )
    render_presentation = _channel_value(
        profile, "render_presentation",
        lambda: artifacts.extract_render_presentation(observer_log),
    )
    shadow_render = _channel_value(
        profile, "shadow_render",
        lambda: artifacts.extract_shadow_render(observer_log),
    )
    shadow_camera_render = _channel_value(
        profile, "shadow_camera_render",
        lambda: artifacts.extract_shadow_camera_render(observer_log),
    )
    shadow_render_room = _channel_value(
        profile, "shadow_render_room",
        lambda: artifacts.extract_shadow_render_room(observer_log),
    )
    shadow_visible_objects = _channel_value(
        profile, "shadow_visible_objects",
        lambda: artifacts.extract_shadow_visible_objects(observer_log),
    )
    shadow_visible_polygons = _channel_value(
        profile, "shadow_visible_polygons",
        lambda: artifacts.extract_shadow_visible_polygons(observer_log),
    )
    shadow_polygon_render = _channel_value(
        profile, "shadow_polygon_render",
        lambda: artifacts.extract_shadow_polygon_render(observer_log),
    )
    shadow_world_relation = _channel_value(
        profile, "shadow_world_relation",
        lambda: artifacts.extract_shadow_world_relation(observer_log),
    )
    shadow_rotation_setter = _channel_value(
        profile, "shadow_rotation_setter",
        lambda: artifacts.extract_shadow_rotation_setter(observer_log),
    )
    framebuffer_metadata = None
    framebuffer_raw = None
    if profile["framebuffer_required"]:
        framebuffer_result = result.get("framebuffer")
        if not isinstance(framebuffer_result, Mapping):
            raise SuiteRunError(
                f"applicable framebuffer result is absent: {scenario_id}"
            )
        framebuffer_metadata = artifacts.load_framebuffer_metadata(
            output_directory / framebuffer_result["metadata_path"]
        )
        framebuffer_raw = (
            output_directory / framebuffer_result["raw_path"]
        ).read_bytes()
    framebuffer_raw_sha256 = _channel_value(
        profile, "framebuffer",
        lambda: result["framebuffer"]["raw_sha256"],
    )
    framebuffer_rgba_sha256 = _channel_value(
        profile, "framebuffer",
        lambda: hashlib.sha256(
            artifacts.canonicalize_native_framebuffer(
                framebuffer_metadata, framebuffer_raw,
            )
        ).hexdigest(),
    )
    scenario = artifacts.load_scenario(
        manifest_path.parent / entry["scenario"]["path"], root=manifest_path.parent,
    )
    focus_timeline = artifacts.extract_focus_timeline_receipt(
        observer_log, scenario, root=manifest_path.parent,
    )
    if result.get("focus_timeline") != focus_timeline:
        raise SuiteRunError(
            f"scenario runner focus timeline receipt drifted: {scenario_id}"
        )
    if readback != scenario["initial_state"]["values"]:
        raise SuiteRunError(f"bound runtime readback drifted: {scenario_id}")
    activation_suite = artifacts.load_json(
        manifest_path.parent / "flight-activation-rng.json"
    )
    expected_activation_rng = activation_suite.get("scenarios", {}).get(scenario_id) \
        if isinstance(activation_suite, dict) else None
    if {"rng": activation_rng, "clock": activation_clock} != expected_activation_rng:
        raise SuiteRunError(f"flight activation transcript drifted: {scenario_id}")
    receipt = {
        "status": "CANDIDATE_ONLY",
        "production_claim": False,
        "scenario": scenario_id,
        "observation_profile": _profile_receipt(
            profile, scenario_id=scenario_id,
        ),
        "hook_observation_profile": result_profile["hook_receipt"],
        "semantic_sha256": result["observer_trace"]["semantic_sha256"],
        "observer_log_sha256": result["observer_trace"]["sha256"],
        "framebuffer_raw_sha256": framebuffer_raw_sha256,
        "framebuffer_rgba_sha256": framebuffer_rgba_sha256,
        "runtime_initial_state": readback,
        "flight_activation_rng": activation_rng,
        "flight_activation_clock": activation_clock,
        "focus_timeline": focus_timeline,
        "media_semantics": _media_semantics_receipt(observer_log),
        "particle_activation": particle_activation,
        "particle_lifecycle": particle_lifecycle,
        "render_presentation": render_presentation,
        "shadow_render": shadow_render,
        "shadow_camera_render": shadow_camera_render,
        "shadow_render_room": shadow_render_room,
        "shadow_visible_objects": shadow_visible_objects,
        "shadow_visible_polygons": shadow_visible_polygons,
        "shadow_polygon_render": shadow_polygon_render,
        "shadow_world_relation": shadow_world_relation,
        "shadow_rotation_setter": shadow_rotation_setter,
    }
    _atomic_write(output_directory / "exact-run.json", receipt)
    return receipt


def _assert_exact_repeat_pair(
    scenario_id: str, first: Mapping[str, Any], second: Mapping[str, Any],
) -> None:
    compared = (
        "semantic_sha256", "framebuffer_rgba_sha256", "runtime_initial_state",
        "flight_activation_rng",
        "flight_activation_clock",
        "media_semantics",
        "particle_activation",
        "particle_lifecycle",
        "render_presentation",
        "shadow_render",
        "shadow_camera_render",
        "shadow_render_room",
        "shadow_visible_objects",
        "shadow_visible_polygons",
        "shadow_polygon_render",
        "shadow_world_relation",
        "shadow_rotation_setter",
        "observation_profile",
    )
    mismatches = [field for field in compared if first[field] != second[field]]
    if mismatches:
        raise SuiteRunError(
            f"cold exact native repeats drifted for {scenario_id}: "
            + ", ".join(mismatches)
        )


def _run_calibrated_suite_locked(
    config: SuiteRunConfig,
    *,
    lock_receipt: Mapping[str, Any],
    execution_adapter: ExecutionAdapter | None = None,
    prefix_bootstrap: Callable[..., dict[str, Any]] = hangover_probe.bootstrap_prefix,
    scenario_runner: Callable[..., dict[str, Any]] = hangover_probe.run_native_semantic_scenario,
) -> dict[str, Any]:
    """Calibrate, bind, and prove two cold exact native runs per scenario."""

    provenance = validate_run_config(config)
    provenance["exclusive_lock"] = dict(lock_receipt)
    adapter = execution_adapter if execution_adapter is not None else DockerExecAdapter()
    provenance["execution_adapter"] = adapter.validate(config)
    backend = provenance["backend"]
    output_root = _resolved(config.output_root)
    output_root.mkdir()
    baseline_root = output_root / "calibration-spec"
    baseline_root.mkdir()
    initial_state = _copy_fixture(baseline_root, _resolved(config.user_profile))
    manifest = artifacts.materialize_scenario_suite(baseline_root, initial_state)
    manifest_path = baseline_root / "suite-spec.json"

    performance_lane: _SealedPrefixLane | None = None
    cold_audit_lane: _ColdAuditCaptureLane | None = None
    with adapter.activate(config), contextlib.ExitStack() as cleanup_stack:
        if config.prefix_mode == "sealed":
            performance_lane = _SealedPrefixLane(
                config, backend, prefix_bootstrap,
            )
            cleanup_stack.enter_context(
                _performance_lane_lifecycle(performance_lane)
            )
            prefix = {
                "usable": True,
                "strategy": "independent-content-addressed-sealed-pair",
                "pair": performance_lane.pair,
            }
        else:
            prefix = prefix_bootstrap(
                _resolved(config.wine_prefix), backend,
                _resolved(config.smoke_executable),
                runtime_readiness_timeout=config.runtime_readiness_timeout,
                rpcss_readiness_timeout_ms=config.rpcss_readiness_timeout_ms,
            )
        _atomic_write(output_root / "prefix-bootstrap.json", prefix)
        if prefix.get("usable") is not True:
            checks = prefix.get("checks")
            failed = sorted(
                name for name, passed in checks.items() if passed is not True
            ) if isinstance(checks, dict) else ["receipt-shape"]
            raise SuiteRunError(
                "fresh native Wine prefix failed reviewed bootstrap checks: "
                + ", ".join(failed)
            )
        environment = hangover_probe.native_runtime_environment(
            _resolved(config.wine_prefix), backend,
        )
        if performance_lane is None:
            cold_audit_lane = _ColdAuditCaptureLane(
                config, backend, prefix_bootstrap,
            )

        calibrated: dict[str, Mapping[str, Any]] = {}
        calibrated_activation_rng: dict[str, Mapping[str, Any]] = {}
        calibration_profile_sha256: dict[str, str] = {}
        calibration_receipts = []
        # Diagnostic override: run takeoff-climb FIRST to test whether it
        # crashes due to state accumulation from prior scenarios or due to a
        # fundamental FEX/Wine issue. When set, the calibration and exact
        # replay loops use this order instead of the canonical one.
        calibration_order = list(artifacts.SCENARIO_ID_ORDER)
        if os.environ.get("NATIVE_SUITE_TAKEOFF_FIRST"):
            calibration_order = [
                "takeoff-climb",
                *[s for s in artifacts.SCENARIO_ID_ORDER if s != "takeoff-climb"],
            ]
        for calibration_index, scenario_id in enumerate(
            calibration_order
        ):
            _assert_inputs_unchanged(config)
            calibration_destination = output_root / "calibration" / scenario_id
            if performance_lane is None:
                assert cold_audit_lane is not None
                if calibration_index > 0:
                    cold_audit_lane.rebootstrap(
                        f"calibration:{scenario_id}:fresh-prefix"
                    )
                trace, receipt = cold_audit_lane.capture(
                    scenario_id,
                    "calibration",
                    calibration_destination,
                    lambda staging: _calibration_capture(
                        config,
                        environment,
                        backend,
                        manifest_path,
                        scenario_id,
                        staging,
                        scenario_runner,
                    ),
                )
            else:
                trace, receipt = performance_lane.capture(
                    "A", scenario_id, "calibration",
                    calibration_destination,
                    lambda staging: _calibration_capture(
                        config,
                        environment,
                        backend,
                        manifest_path,
                        scenario_id,
                        staging,
                        scenario_runner,
                    ),
                )
            entry = artifacts.scenario_suite_entry(manifest, scenario_id)
            scenario = artifacts.load_scenario(
                baseline_root / entry["scenario"]["path"], root=baseline_root,
            )
            calibrated_scenario = artifacts.calibrate_scenario_rng_transcript(
                scenario, trace, root=baseline_root,
            )
            calibrated_scenario["rng_transcript"]["flight_activation_seed_u32"] = \
                calibrated_scenario["rng_transcript"]["seed_u32"]
            calibrated_scenario["rng_transcript"][
                "flight_activation_dt_f32_bits"
            ] = [
                row["scripted_dt_f32_bits"]
                for row in receipt["flight_activation_clock"]["ticks"]
            ]
            calibrated_scenario["initial_state"]["values"] = \
                receipt["runtime_initial_state"]
            calibrated[scenario_id] = artifacts.validate_scenario(
                calibrated_scenario, root=baseline_root,
            )
            calibrated_activation_rng[scenario_id] = {
                "rng": receipt["flight_activation_rng"],
                "clock": receipt["flight_activation_clock"],
            }
            calibration_profile_sha256[scenario_id] = \
                receipt["observation_profile"]["sha256"]
            calibration_receipts.append({
                "id": scenario_id,
                "observation_profile_sha256":
                    receipt["observation_profile"]["sha256"],
                "path": f"calibration/{scenario_id}/calibration-run.json",
                "sha256": artifacts.sha256_file(
                    output_root / "calibration" / scenario_id / "calibration-run.json"
                ),
            })
            _assert_inputs_unchanged(config)

        suite_root = _resolved(config.suite_root)
        published = _publish_calibrated_suite(
            suite_root, _resolved(config.user_profile), calibrated,
            calibrated_activation_rng,
        )
        _assert_inputs_unchanged(config)
        exact_receipts = []
        for scenario_id in calibration_order:
            pair = []
            for repeat in (1, 2):
                exact_destination = (
                    output_root / "exact" / scenario_id / f"run-{repeat}"
                )
                if performance_lane is None:
                    assert cold_audit_lane is not None
                    cold_audit_lane.rebootstrap(
                        f"exact:{scenario_id}:run-{repeat}:fresh-prefix"
                    )
                    capture = cold_audit_lane.capture(
                        scenario_id,
                        f"exact-run-{repeat}",
                        exact_destination,
                        lambda staging: _exact_capture(
                            config, environment, backend,
                            suite_root / "suite-spec.json",
                            scenario_id, staging, scenario_runner,
                        ),
                    )
                else:
                    slot = native_runner.SLOTS[repeat - 1]
                    capture = performance_lane.capture(
                        slot, scenario_id, "exact", exact_destination,
                        lambda staging: _exact_capture(
                            config, environment, backend,
                            suite_root / "suite-spec.json",
                            scenario_id, staging, scenario_runner,
                        ),
                    )
                pair.append(capture)
                _assert_inputs_unchanged(config)
            _assert_exact_repeat_pair(scenario_id, pair[0], pair[1])
            if pair[0]["observation_profile"]["sha256"] != \
                    calibration_profile_sha256[scenario_id]:
                raise SuiteRunError(
                    f"calibration/exact observation profile drifted: {scenario_id}"
                )
            exact_receipts.append({
                "id": scenario_id,
                "run_1": f"exact/{scenario_id}/run-1/exact-run.json",
                "run_2": f"exact/{scenario_id}/run-2/exact-run.json",
                "observation_profile": pair[0]["observation_profile"],
                "semantic_sha256": pair[0]["semantic_sha256"],
                "framebuffer_raw_sha256": _channel_sha256(
                    pair[0]["framebuffer_raw_sha256"],
                    pair[0]["observation_profile"], "framebuffer",
                ),
                "framebuffer_rgba_sha256": _channel_sha256(
                    pair[0]["framebuffer_rgba_sha256"],
                    pair[0]["observation_profile"], "framebuffer",
                ),
                "flight_activation_rng_sha256": pair[0]["flight_activation_rng"]["sha256"],
                "flight_activation_clock_sha256": pair[0]["flight_activation_clock"]["sha256"],
                "particle_lifecycle_sha256": _channel_sha256(
                    pair[0]["particle_lifecycle"], pair[0]["observation_profile"],
                    "particle_lifecycle",
                ),
                "particle_activation_sha256": _channel_sha256(
                    pair[0]["particle_activation"], pair[0]["observation_profile"],
                    "particle_activation",
                ),
                "render_presentation_sha256": _channel_sha256(
                    pair[0]["render_presentation"], pair[0]["observation_profile"],
                    "render_presentation",
                ),
                "shadow_render_sha256": _channel_sha256(
                    pair[0]["shadow_render"], pair[0]["observation_profile"],
                    "shadow_render",
                ),
                "shadow_camera_render_sha256": _channel_sha256(
                    pair[0]["shadow_camera_render"],
                    pair[0]["observation_profile"], "shadow_camera_render",
                ),
                "shadow_render_room_sha256": _channel_sha256(
                    pair[0]["shadow_render_room"],
                    pair[0]["observation_profile"], "shadow_render_room",
                ),
                "shadow_visible_objects_sha256": _channel_sha256(
                    pair[0]["shadow_visible_objects"],
                    pair[0]["observation_profile"], "shadow_visible_objects",
                ),
                "shadow_visible_polygons_sha256": _channel_sha256(
                    pair[0]["shadow_visible_polygons"],
                    pair[0]["observation_profile"], "shadow_visible_polygons",
                ),
                "shadow_polygon_render_sha256": _channel_sha256(
                    pair[0]["shadow_polygon_render"],
                    pair[0]["observation_profile"], "shadow_polygon_render",
                ),
                "shadow_world_relation_sha256": _channel_sha256(
                    pair[0]["shadow_world_relation"],
                    pair[0]["observation_profile"], "shadow_world_relation",
                ),
                "shadow_rotation_setter_sha256": _channel_sha256(
                    pair[0]["shadow_rotation_setter"],
                    pair[0]["observation_profile"], "shadow_rotation_setter",
                ),
            })
        _assert_inputs_unchanged(config)
    receipt = {
        "schema": VERSION,
        "protocol": PROTOCOL,
        "status": "REPRODUCIBLE_CANDIDATE_ONLY",
        "production_claim": False,
        "scenario_order": list(artifacts.SCENARIO_ID_ORDER),
        "provenance": provenance,
        "prefix": prefix,
        "performance_lane": (
            None if performance_lane is None else {
                "strategy": "sealed-pair-clone-only",
                "identity": performance_lane.identity,
                "store": performance_lane.store_receipt,
                "captures": performance_lane.capture_receipts,
            }
        ),
        "cold_audit_lane": (
            None if cold_audit_lane is None else {
                "strategy": "cold-prefix-evidence-preserving-retry",
                "captures": cold_audit_lane.capture_receipts,
                "prefix_lifecycle": cold_audit_lane.prefix_receipts,
            }
        ),
        "calibration": calibration_receipts,
        "calibrated_suite": {
            "path": _bundle_relative_directory(
                output_root, suite_root, "calibrated_suite",
            ),
            "manifest_sha256": artifacts.sha256_file(suite_root / "suite-spec.json"),
            "scenario_order": published["scenario_order"],
            "flight_activation_rng_sha256": artifacts.sha256_file(
                suite_root / "flight-activation-rng.json"
            ),
        },
        "exact_runs": exact_receipts,
        "blocker": None,
    }
    _atomic_write(output_root / "calibrated-suite-run.json", receipt)
    return receipt


def run_calibrated_suite(
    config: SuiteRunConfig,
    *,
    execution_adapter: ExecutionAdapter | None = None,
    prefix_bootstrap: Callable[..., dict[str, Any]] = hangover_probe.bootstrap_prefix,
    scenario_runner: Callable[..., dict[str, Any]] = hangover_probe.run_native_semantic_scenario,
) -> dict[str, Any]:
    """Calibrate, bind, and prove two cold exact native runs per scenario."""

    with _exclusive_capture_lock(config) as lock_receipt:
        return _run_calibrated_suite_locked(
            config,
            lock_receipt=lock_receipt,
            execution_adapter=execution_adapter,
            prefix_bootstrap=prefix_bootstrap,
            scenario_runner=scenario_runner,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in (
        "source-executable", "disposable-target", "game-root", "state-root",
        "user-profile", "observer-dll", "observer-launcher", "proxy-dinput",
        "real-dinput", "smoke-executable", "wine-prefix", "suite-root",
        "output-root",
    ):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--backend-id", choices=sorted(BACKENDS), required=True)
    parser.add_argument("--backend-hodll", required=True)
    parser.add_argument("--container-image", required=True)
    parser.add_argument("--container-image-sha256", required=True)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--container-mount-root", type=Path, required=True)
    parser.add_argument("--expected-uid", type=int, required=True)
    parser.add_argument("--expected-gid", type=int)
    parser.add_argument("--backend-hodll-sha256")
    parser.add_argument(
        "--prefix-mode", choices=("cold-audit", "sealed"),
        default="cold-audit",
    )
    parser.add_argument(
        "--clean-state-root", type=Path, default=None,
        help=(
            "Verified clean snapshot of the game root used to reset the live "
            "game directory before every capture, preventing state from "
            "accumulating across sequential scenario boots."
        ),
    )
    parser.add_argument("--sealed-prefix-root", type=Path)
    parser.add_argument("--tmpfs-staging-root", type=Path)
    parser.add_argument(
        "--tmpfs-bytes-per-job", type=int,
        default=native_runner.DEFAULT_TMPFS_BYTES,
    )
    parser.add_argument(
        "--tmpfs-max-jobs", type=int,
        default=native_runner.DEFAULT_MAX_JOBS,
    )
    parser.add_argument(
        "--tmpfs-headroom-bytes", type=int,
        default=native_runner.DEFAULT_NO_SWAP_HEADROOM_BYTES,
    )
    for label in INPUT_LABELS:
        parser.add_argument(f"--{label.replace('_', '-')}-sha256", required=True)
    parser.add_argument(
        "--observe-ms", type=int,
        default=FEX_CALIBRATED_SUITE_OBSERVE_MS,
    )
    parser.add_argument("--max-records", type=int, default=100_000)
    parser.add_argument(
        "--runtime-readiness-timeout", type=int,
        default=hangover_probe.FEX_RUNTIME_READINESS_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--rpcss-readiness-timeout-ms", type=int,
        default=hangover_probe.FEX_RPCSS_READINESS_TIMEOUT_MS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = SuiteRunConfig(
        source_executable=args.source_executable,
        disposable_target=args.disposable_target,
        game_root=args.game_root,
        state_root=args.state_root,
        user_profile=args.user_profile,
        observer_dll=args.observer_dll,
        observer_launcher=args.observer_launcher,
        proxy_dinput=args.proxy_dinput,
        real_dinput=args.real_dinput,
        smoke_executable=args.smoke_executable,
        wine_prefix=args.wine_prefix,
        suite_root=args.suite_root,
        output_root=args.output_root,
        backend_id=args.backend_id,
        backend_hodll=args.backend_hodll,
        container_image=args.container_image,
        container_image_sha256=args.container_image_sha256,
        container_id=args.container_id,
        container_mount_root=args.container_mount_root,
        expected_uid=args.expected_uid,
        expected_gid=args.expected_gid,
        backend_hodll_sha256=args.backend_hodll_sha256,
        expected_sha256={
            label: getattr(args, f"{label}_sha256") for label in INPUT_LABELS
        },
        observe_ms=args.observe_ms,
        max_records=args.max_records,
        runtime_readiness_timeout=args.runtime_readiness_timeout,
        rpcss_readiness_timeout_ms=args.rpcss_readiness_timeout_ms,
        prefix_mode=args.prefix_mode,
        sealed_prefix_root=args.sealed_prefix_root,
        tmpfs_staging_root=args.tmpfs_staging_root,
        tmpfs_bytes_per_job=args.tmpfs_bytes_per_job,
        tmpfs_max_jobs=args.tmpfs_max_jobs,
        tmpfs_headroom_bytes=args.tmpfs_headroom_bytes,
        clean_state_root=args.clean_state_root,
    )
    receipt = run_calibrated_suite(config)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"native semantic suite failed closed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
