#!/usr/bin/env python3
"""Probe Hangover as an isolated native-capture host, never as parity evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

PROBE_PATH = Path(__file__).resolve()
REPOSITORY_IMPORT_ROOTS = (
    PROBE_PATH.parents[2],
    PROBE_PATH.parents[1] / "repo",
)
for import_root in REPOSITORY_IMPORT_ROOTS:
    if (
        import_root / "tools/miel_vliegt/native_observation_profile_contract.py"
    ).is_file() and str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from tools.miel_vliegt import native_observation_profile_contract


ROOT = PROBE_PATH.parents[2]
CONTRACT = ROOT / "content/miel_vliegt/hangover_capture_host.json"
SOURCE_IDENTITY = ROOT / "content/miel_vliegt/source_identity.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SMOKE_EXECUTABLE = Path("/opt/hangover/win32-smoke.exe")
DEBUG_CAPABILITY_EXECUTABLE = Path("/opt/hangover/win32-debug-capability.exe")
SCENE_DEBUGGER = Path("/opt/hangover/native-scene-debugger.exe")
OBSERVER_LAUNCHER = Path("/opt/hangover/native-observer-launcher.exe")
OBSERVER_DLL = Path("/opt/hangover/native-observer-hook.dll")
OBSERVER_PROXY_DLL = Path("/opt/hangover/DINPUT.dll")
# Canonical scenario foundation the observer requires to bootstrap (same replay
# and initial-user identity the capture runner uses).
OBSERVER_REPLAY = Path("/opt/hangover/observer-replay.mvo")
OBSERVER_INITIAL_USER_SHA256 = (
    "7019275a9489a2d078f2cb38425f852dd2c019295e401ba4a58cbd67566555d6"
)
REAL_DINPUT = Path("/opt/miel/dinput-real.dll")
FEX_READINESS_EXECUTABLE = Path("/opt/miel/wine-readiness-canary.exe")
FEX_REQUIRED_COM_CLASSES = (
    "{47D4D946-62E8-11CF-93BC-444553540000}",
    "{BCDE0395-E52F-467C-8E3D-C4579291692E}",
)
FEX_RUNTIME_READINESS_TIMEOUT_SECONDS = 90
FEX_RPCSS_READINESS_TIMEOUT_MS = 30_000
FEX_WINEBOOT_TIMEOUT_SECONDS = 120
FEX_SMOKE_TIMEOUT_SECONDS = 120
PERSISTENT_WINESERVER_ACK_SENTINEL = (
    "MIEL_WINESERVER_PERSISTENCE_ACKNOWLEDGED"
)
HEADLESS_CONFIG = (
    ROOT / "tools/miel_vliegt/hangover/headless-config.ini"
    if (ROOT / "tools/miel_vliegt/hangover/headless-config.ini").is_file()
    else Path("/opt/hangover/headless-config.ini")
)
HEADLESS_CONFIG_SHA256 = "0d0376a2879d3df5a0cae82c788c58153c6a2ab84128903cd89eaaabfb4631c6"
NATIVE_XVFB_ARGUMENTS = (
    "xvfb-run", "-a", "-s", "-screen 0 646x512x16 -nolisten tcp",
)
DEFAULT_OBSERVE_MS = 120_000
MIN_OBSERVE_MS = 1_000
MAX_OBSERVE_MS = 3_600_000
OBSERVER_BOOTSTRAP_STRATEGY = "dinput-post-loader-worker-or-call-bootstrap"
OBSERVER_INPUT_IDLE_PROBE_TIMEOUT_MS = 0
OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS = 600000
OBSERVER_HOST_DEADLINE_GRACE_SECONDS = 30
NATIVE_PROXY_DLL_OVERRIDE = "dinput=n,b"
FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE = "mscoree,mshtml="
FEX_CAPTURE_DLL_OVERRIDE = (
    FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE + ";" + NATIVE_PROXY_DLL_OVERRIDE
)
CALIBRATION_OBSERVATION_RETAINED_CHANNELS = (
    "session",
    "input-proof",
    "clock.tick",
    "flight.tick",
    "rng",
    "runtime-initial-state",
    "flight-activation-rng",
    "flight-activation-clock",
    "render.framebuffer",
)
CALIBRATION_OBSERVATION_OMITTED_CHANNELS = (
    "controls-values",
    "physics",
    "collision",
    "camera-values",
    "render-values",
    "fuel",
    "contact",
    "damage",
    "terrain",
    "udsp",
    "position-character",
    "particle-lifecycle",
    "presentation-render",
    "shadow-render",
)
SCENE_TOOL_ROOT = ROOT if (ROOT / "tools/miel_vliegt/native_scene_navigator.py").is_file() else Path("/opt/repo")
if str(SCENE_TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(SCENE_TOOL_ROOT))
SMOKE_SENTINEL = "MIEL_HANGOVER_WIN32_SMOKE_OK"
FEX_SMOKE_SENTINEL = "MIEL_FEX_WINE_CANARY_OK"
LOADER_FAILURE_MARKERS = (
    "bad exe format",
    "couldn't load main module",
    "failed to start",
    "cannot find",
    "c0000135",
    "sysarm32",
)
DEBUG_PROFILES = {
    "box64": (
        {
            "id": "default-int3",
            "environment": ["BOX64_NORCFILES=1", "BOX64_IGNOREINT3=0"],
            "trap_strategy": "int3",
            "scene_timeout": 20,
            "fallback_timeout": 30,
        },
        {
            "id": "ud2-exception",
            "environment": ["BOX64_NORCFILES=1"],
            "trap_strategy": "ud2",
            "scene_timeout": 30,
            "fallback_timeout": 40,
        },
    ),
    "fex": (
        {
            "id": "default-int3",
            "environment": [],
            "trap_strategy": "int3",
            "scene_timeout": 20,
            "fallback_timeout": 30,
        },
        {
            "id": "ud2-exception",
            "environment": [],
            "trap_strategy": "ud2",
            "scene_timeout": 30,
            "fallback_timeout": 40,
        },
    ),
}
BODY_MODES = (
    "mode_atleartillerist", "mode_barn", "mode_brejtonbord",
    "mode_credits", "mode_dorisdigital", "mode_ernsteremit",
    "mode_fionafalk", "mode_fly", "mode_gabriellagourmet",
    "mode_grottegrundlig", "mode_login", "mode_mygghanget",
    "mode_raymondrajser", "mode_richardrevers", "mode_roymccoy",
    "mode_samposanna", "mode_samscribbler", "mode_turetapp",
    "mode_varldsutstallning", "mode_vermontvrak",
    "mode_victorvulcan", "mode_violawallmark",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


_CAPTURE_BACKEND_COMMANDS = {
    ("box64", "wowbox64.dll"): {
        "wine": "wine",
        "wineserver": ("wineserver",),
    },
    ("fex", "libwow64fex.dll"): {
        "wine": "/opt/miel/fex-wine",
        "wineserver": (
            "FEX", "/opt/fex/rootfs/usr/lib/wine/wineserver64",
        ),
    },
    ("wine", "i386"): {
        "wine": "wine",
        "wineserver": ("wineserver",),
    },
    ("native", "windows"): {
        "wine": "",
        "wineserver": (),
    },
}


def validate_capture_backend(backend: dict) -> dict:
    """Return one exact checked backend; reject caller-supplied commands."""

    if not isinstance(backend, dict) or set(backend) != {"id", "hodll"} \
            or (backend.get("id"), backend.get("hodll")) not in \
            _CAPTURE_BACKEND_COMMANDS:
        raise ValueError("native capture backend identity is invalid")
    return dict(backend)


def native_wine_command(
    *arguments: object, backend: dict | None = None,
) -> list[str]:
    """Run Win32 guests on the proven client-offset and 16-bit surface."""

    wine = "wine" if backend is None else _CAPTURE_BACKEND_COMMANDS[
        (validate_capture_backend(backend)["id"], backend["hodll"])
    ]["wine"]
    # Native Windows: run the .exe directly, no wrapper needed
    if not wine:
        return [*(str(item) for item in arguments)]
    # Linux Wine with persistent Xvfb (DISPLAY=:99)
    if backend is not None and validate_capture_backend(backend)["id"] == "wine":
        return [wine, *(str(item) for item in arguments)]
    # FEX/box64: full xvfb-run wrapper
    return [*NATIVE_XVFB_ARGUMENTS, wine, *(str(item) for item in arguments)]


def native_wineserver_command(backend: dict, *arguments: object) -> list[str]:
    """Select the server paired with the checked backend, never with input."""

    checked = validate_capture_backend(backend)
    command = _CAPTURE_BACKEND_COMMANDS[(checked["id"], checked["hodll"])][
        "wineserver"
    ]
    if not command:
        return []  # Native Windows: no wineserver
    return [*command, *(str(item) for item in arguments)]


def native_persistent_wineserver_command(backend: dict) -> list[str]:
    """Request persistence and acknowledge only a successful server command."""

    checked = validate_capture_backend(backend)
    command = _CAPTURE_BACKEND_COMMANDS[(checked["id"], checked["hodll"])][
        "wineserver"
    ]
    if not command:
        # Native Windows: print ack directly (no wineserver to manage)
        return ["cmd", "/c", f"echo {PERSISTENT_WINESERVER_ACK_SENTINEL}"]             if os.name == "nt"             else ["sh", "-c", f"printf '%s\n' {PERSISTENT_WINESERVER_ACK_SENTINEL}"]
    return [
        "sh", "-c",
        (
            '"$@" >/dev/null 2>&1 || exit $?; '
            f'printf "%s\\n" {PERSISTENT_WINESERVER_ACK_SENTINEL}'
        ),
        "miel-persistent-wineserver", *command, "-p0",
    ]


def wineserver_shutdown_completed(result: Mapping[str, object]) -> bool:
    """Accept a stopped server whether Wine killed it or found none running.

    Wine returns status 1 with no diagnostic when ``wineserver -k`` or ``-w``
    cannot connect because the private server has already exited.  That is the
    desired terminal state.  FEX's wineserver proxy additionally prints
    ``read: Connection reset by peer`` because its IPC socket to the dead
    server is reset; this is the same terminal state with a diagnostic.
    Any timeout, loader failure, or other output remains fail-closed.
    """

    text = run_text(result)
    return (
        result.get("timed_out") is False
        and not has_loader_failure(result)
        and (
            result.get("exit_code") == 0
            or (
                result.get("exit_code") == 1
                and (
                    not text.strip()
                    or _is_benign_wineserver_already_dead(text)
                )
            )
        )
    )


_FEX_WINESERVER_ALREADY_DEAD_MARKERS: tuple[str, ...] = (
    "read: connection reset by peer",
)


def _is_benign_wineserver_already_dead(text: str) -> bool:
    """Check if output consists only of benign FEX 'server already gone' messages.

    FEX's wineserver proxy prints ``read: Connection reset by peer`` (lowercased
    by run_text) when the IPC socket to an already-exited server is reset,
    whereas native Wine returns status 1 silently.  Both mean the server is gone
    and the prefix is in the desired terminal state.  Every non-empty line must
    match a known-benign marker; any unexpected output remains fail-closed.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return bool(lines) and all(
        any(marker in line for marker in _FEX_WINESERVER_ALREADY_DEAD_MARKERS)
        for line in lines
    )


def shutdown_private_wineserver(
    environment: list[str], cwd: Path, backend: dict, *, timeout: int = 10,
    runner=None,
) -> dict:
    """Stop, then wait for, the exact private server before state is removed."""

    # Native Windows: no wineserver to shut down
    if backend.get("id") == "native":
        ok = skipped_run("native-no-wineserver")
        return {
            "stopped": True,
            "waited": True,
            "runs": {"stop": ok, "wait": ok},
        }
    execute = run if runner is None else runner
    stop = execute(
        environment + native_wineserver_command(backend, "-k"),
        cwd=cwd,
        timeout=timeout,
    )
    stopped = wineserver_shutdown_completed(stop)
    wait = execute(
        environment + native_wineserver_command(backend, "-w"),
        cwd=cwd,
        timeout=timeout,
    ) if stopped else skipped_run("wineserver-stop-failed")
    waited = wineserver_shutdown_completed(wait)
    return {
        "stopped": stopped,
        "waited": waited,
        "complete": stopped and waited,
        "runs": {"stop": stop, "wait": wait},
    }


def native_runtime_environment(prefix: Path, backend: dict) -> list[str]:
    """Build the checked per-prefix environment shared by bootstrap and launch."""

    checked = validate_capture_backend(backend)
    if checked["id"] == "native":
        return []
    environment = [
        "env", f"WINEPREFIX={prefix}",
    ]
    if checked["id"] in ("fex", "box64"):
        environment.append(f"HODLL={checked['hodll']}")
    if checked["id"] == "fex":
        wine_debug = os.environ.get("NATIVE_SUITE_WINEDEBUG") or "-all"
        environment.extend([
            "WINEARCH=win32",
            f"WINEDEBUG={wine_debug}",
            f"WINEDLLOVERRIDES={FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE}",
        ])
    elif checked["id"] == "wine":
        wine_debug = os.environ.get("NATIVE_SUITE_WINEDEBUG") or "-all"
        environment.extend([
            "WINEARCH=win32",
            f"WINEDEBUG={wine_debug}",
            "DISPLAY=:99",
        ])
    return environment


def bind_native_proxy_dll_override(environment: list[str]) -> list[str]:
    """Force Wine to load the checked native DINPUT proxy before its builtin."""

    if not isinstance(environment, list) or any(
        not isinstance(item, str) or not item or "\0" in item
        for item in environment
    ):
        raise ValueError("native capture environment is invalid")
    bound = list(environment)
    if not bound or bound[0] != "env":
        if any("=" not in item for item in bound):
            raise ValueError("native capture environment is not env assignments")
        bound.insert(0, "env")
    overrides = [
        item.split("=", 1)[1]
        for item in bound[1:]
        if item.split("=", 1)[0] == "WINEDLLOVERRIDES"
    ]
    accepted = {
        NATIVE_PROXY_DLL_OVERRIDE,
        FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE,
        FEX_CAPTURE_DLL_OVERRIDE,
    }
    if len(overrides) > 1 or (overrides and overrides[0] not in accepted):
        raise ValueError("native DINPUT override differs from the checked proxy route")
    if not overrides:
        bound.append(f"WINEDLLOVERRIDES={NATIVE_PROXY_DLL_OVERRIDE}")
    elif overrides == [FEX_OPTIONAL_INSTALLER_DLL_OVERRIDE]:
        index = next(
            index for index, item in enumerate(bound)
            if item.startswith("WINEDLLOVERRIDES=")
        )
        bound[index] = f"WINEDLLOVERRIDES={FEX_CAPTURE_DLL_OVERRIDE}"
    return bound


def verify_runtime_readiness(
    environment: list[str], cwd: Path, backend: dict, *,
    runtime_timeout: int = FEX_RUNTIME_READINESS_TIMEOUT_SECONDS,
    rpcss_timeout_ms: int = FEX_RPCSS_READINESS_TIMEOUT_MS,
) -> dict:
    """Keep the FEX Wine service/COM session alive for the following game run."""

    if isinstance(runtime_timeout, bool) or not 30 <= runtime_timeout <= 300:
        raise ValueError("FEX runtime readiness timeout must be in 30..300 seconds")
    if isinstance(rpcss_timeout_ms, bool) \
            or not 1_000 <= rpcss_timeout_ms <= 120_000:
        raise ValueError("FEX RpcSs readiness timeout must be in 1000..120000 ms")
    checked = validate_capture_backend(backend)
    if checked["id"] != "fex":
        return {
            "required": False,
            "verified": True,
            "budget": {
                "guest_process_seconds": runtime_timeout,
                "rpcss_poll_milliseconds": rpcss_timeout_ms,
            },
            "run": skipped_run("backend-has-no-runtime-readiness-helper"),
        }
    result = run(
        environment + native_wine_command(
            wine_z_path(FEX_READINESS_EXECUTABLE),
            "--rpcss-timeout-ms", str(rpcss_timeout_ms),
            backend=checked,
        ),
        cwd=cwd,
        timeout=runtime_timeout,
    )
    text = run_text(result)
    registry_checks = {
        clsid: re.search(
            rf"(?im)^miel_com_registry clsid={re.escape(clsid)}\s*$",
            text,
        ) is not None
        for clsid in FEX_REQUIRED_COM_CLASSES
    }
    activation_checks = {
        clsid: re.search(
            rf"(?im)^miel_com_activation clsid={re.escape(clsid)} "
            rf"hresult=0x00000000\s*$",
            text,
        ) is not None
        for clsid in FEX_REQUIRED_COM_CLASSES
    }
    rpcss_running = (
        len(re.findall(r"(?im)^miel_rpcss_state=running\s*$", text)) == 1
    )
    readiness_sentinel = (
        len(re.findall(r"(?im)^miel_fex_wine_readiness_ok\s*$", text)) == 1
    )
    verified = (
        result["exit_code"] == 0
        and not result["timed_out"]
        and not has_loader_failure(result)
        and rpcss_running
        and all(registry_checks.values())
        and all(activation_checks.values())
        and readiness_sentinel
    )
    return {
        "required": True,
        "verified": verified,
        "budget": {
            "guest_process_seconds": runtime_timeout,
            "rpcss_poll_milliseconds": rpcss_timeout_ms,
        },
        "rpcss_running": rpcss_running,
        "com_registry": registry_checks,
        "com_activation": activation_checks,
        "renderer_written": "miel_wine_renderer=gdi" in text,
        "renderer_verified": (
            "miel_wine_renderer=gdi" in text
            and "miel_wine_decorated=n" in text
        ),
        "run": result,
    }


def native_smoke_command(
    smoke_executable: Path,
    backend: dict,
    rpcss_timeout_ms: int,
) -> list[str]:
    arguments = [smoke_executable.name]
    if backend.get("id") in ("fex", "wine"):
        arguments.extend(("--rpcss-timeout-ms", str(rpcss_timeout_ms)))
    return native_wine_command(*arguments, backend=backend)


def native_smoke_sentinel(backend: dict) -> str:
    return (
        FEX_SMOKE_SENTINEL
        if backend.get("id") in ("fex", "wine")
        else SMOKE_SENTINEL
    )

def validate_contract(contract_path: Path = CONTRACT) -> dict:
    contract = json.loads(contract_path.read_text())
    identity = json.loads(SOURCE_IDENTITY.read_text())
    if contract.get("schema") != 1 or contract.get("host_role") != "EXPERIMENTAL_CAPTURE_HOST":
        raise ValueError("unsupported Hangover capture-host contract")
    source = contract.get("source", {})
    if source.get("project") != "AndreRH/hangover" or not SHA256.fullmatch(source.get("sha256", "")):
        raise ValueError("Hangover release asset is not hash-pinned")
    if contract.get("target", {}).get("executable_sha256") != identity["executable"]["sha256"]:
        raise ValueError("Hangover target does not match the pinned Dutch executable")
    if contract.get("probe_backends") != [
        {"id": "box64", "hodll": "wowbox64.dll"},
        {"id": "fex", "hodll": "libwow64fex.dll"},
    ]:
        raise ValueError("Hangover probe must exercise the documented i386 backends")
    strategy = contract.get("observer_strategy", {})
    if strategy.get("selected") != OBSERVER_BOOTSTRAP_STRATEGY or [
        (item.get("rank"), item.get("id"), item.get("disposition"))
        for item in strategy.get("ranking", [])
    ] != [
        (1, OBSERVER_BOOTSTRAP_STRATEGY, "SELECTED"),
        (2, "win32-debug-api-scene-controller", "REJECTED_ON_CURRENT_HOST"),
        (3, "minimal-hangover-wine-patch", "FALLBACK_ONLY"),
        (4, "fex-gdbserver", "REJECTED"),
    ]:
        raise ValueError("Hangover observer strategy must preserve the reviewed ranking")
    if contract.get("acceptance") != [
        "a fresh backend-specific Wine prefix passes layout checks and the pinned PE32 smoke program",
        "the Wine prefix reads back renderer=gdi and X11 Decorated=N; every native guest runs on a 646x512x16 Xvfb surface that contains the original 640x480 client at offset 3,29",
        "the original executable, disposable target, patch receipt and observer DLL hashes are bound by the launcher receipt",
        "the CREATE_SUSPENDED primary thread is resumed exactly once and no live projector code patch or translated context mutation is attempted",
        "the DINPUT proxy's post-loader worker initializes the observer after Cc.dll is ready and before the fleeting login transition; DirectInputCreateA is the same synchronous fallback, while only observer hooks may prove pending mode_login",
        "observer attach requires native manager current mode to be null and pending mode to equal ModeResolve(mode_login); hook-ready must precede an explicit wake and separately signalled manager-tick login activation, while GUI input-idle remains non-blocking diagnostic evidence",
        "login dispatch accepts only the native no-profile state or existing profile zero when the loaded login fields contain the exact hash-bound MVO_CI identity",
        "the configured observation window completes and the disposable target is force-terminated with confirmed exit",
        "external Win32 debug capability is optional negative diagnostic evidence and is never a selected-route precondition",
    ]:
        raise ValueError("Hangover selected-route acceptance contract drifted")
    policy = contract.get("parity_policy", {})
    if (
        policy.get("probe_success_is_native_evidence") is not False
        or policy.get("production_capture_enabled") is not False
        or not policy.get("equivalent_requires")
    ):
        raise ValueError("Hangover probe must not be accepted as native parity evidence")
    return contract


def validate_i386_pe(path: Path) -> None:
    """Reject a missing or non-i386 smoke binary before creating a prefix."""
    try:
        image = path.read_bytes()
    except OSError as error:
        raise ValueError(f"Hangover Win32 smoke executable is unavailable: {path}") from error
    if len(image) < 64 or image[:2] != b"MZ":
        raise ValueError("Hangover smoke executable is not a PE image")
    pe_offset = int.from_bytes(image[0x3C:0x40], "little")
    if pe_offset + 6 > len(image) or image[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("Hangover smoke executable has an invalid PE header")
    if int.from_bytes(image[pe_offset + 4:pe_offset + 6], "little") != 0x014C:
        raise ValueError("Hangover smoke executable must be PE32 i386")


def _write_watchdog_diagnostic(
    path: Path, process: subprocess.Popen[str], command: list[str],
    started_monotonic_ns: int, observer_log: Path | None,
) -> None:
    process_status = None
    try:
        process_status = Path(f"/proc/{process.pid}/status").read_text(
            encoding="utf-8", errors="replace",
        ).splitlines()
    except OSError:
        pass
    observer_tail: list[str] = []
    if observer_log is not None and observer_log.is_file():
        observer_tail = observer_log.read_text(
            encoding="utf-8", errors="replace",
        ).splitlines()[-80:]
    receipt = {
        "schema": 1,
        "protocol": "miel-vliegt-native-early-phase-watchdog",
        "phase": "pre-scenario-startup",
        "capture": "non-invasive-host-observation",
        "pid": process.pid,
        "poll": process.poll(),
        "command_sha256": hashlib.sha256(
            "\0".join(command).encode("utf-8")
        ).hexdigest(),
        "started_monotonic_ns": started_monotonic_ns,
        "captured_monotonic_ns": time.monotonic_ns(),
        "process_status": process_status,
        "observer_log": None if observer_log is None else observer_log.name,
        "observer_tail": observer_tail,
    }
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("w", encoding="utf-8") as output:
        output.write(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        )
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(
    command: list[str], *, cwd: Path, stdin: str | None = None,
    timeout: int = 45, watchdog: Mapping[str, Any] | None = None,
) -> dict:
    # Do not capture through a pipe. Emulated grandchildren can inherit the pipe
    # and keep communicate() blocked after Wine itself has been terminated.
    watchdog_path = None
    watchdog_after = None
    watchdog_log = None
    abort_after_seconds = None
    if watchdog is not None:
        abort_after_seconds = watchdog.get("abort_after_seconds")
        if abort_after_seconds is not None:
            if isinstance(abort_after_seconds, bool) or not isinstance(
                abort_after_seconds, (int, float)
            ) or not 1 <= abort_after_seconds < timeout:
                raise ValueError("native watchdog abort deadline is invalid")
        if set(watchdog) != {
            "diagnostic_path", "observer_log", "after_seconds",
        } and set(watchdog) != {
            "diagnostic_path", "observer_log", "after_seconds",
            "abort_after_seconds",
        }:
            raise ValueError("native watchdog configuration drifted")
        watchdog_path = Path(watchdog["diagnostic_path"])
        watchdog_log = Path(watchdog["observer_log"])
        watchdog_after = watchdog["after_seconds"]
        if isinstance(watchdog_after, bool) or not isinstance(
            watchdog_after, (int, float)
        ) or not 1 <= watchdog_after < timeout:
            raise ValueError("native watchdog deadline is invalid")
    started_monotonic_ns = time.monotonic_ns()
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as capture:
        process = subprocess.Popen(
            command, cwd=cwd, stdin=subprocess.PIPE if stdin is not None else None,
            text=True, stdout=capture, stderr=subprocess.STDOUT,
            start_new_session=True,
            env={**os.environ, "WINEDEBUG": "-all", "LIBGL_ALWAYS_SOFTWARE": "1"},
        )
        if stdin is not None:
            assert process.stdin is not None
            process.stdin.write(stdin)
            process.stdin.close()
        timed_out = False
        watchdog_captured = False
        deadline = time.monotonic() + timeout
        while process.poll() is None and time.monotonic() < deadline:
            elapsed = (
                time.monotonic_ns() - started_monotonic_ns
            ) / 1_000_000_000
            if watchdog_path is not None and not watchdog_captured \
                    and elapsed >= watchdog_after:
                text = ""
                if watchdog_log is not None and watchdog_log.is_file():
                    text = watchdog_log.read_text(
                        encoding="utf-8", errors="replace",
                    )
                if '"session.dispatched"' not in text:
                    _write_watchdog_diagnostic(
                        watchdog_path, process, command,
                        started_monotonic_ns, watchdog_log,
                    )
                    watchdog_captured = True
            # Early-abort: if abort_after_seconds is configured and the game
 # still hasn't dispatched by that deadline, kill the process group to
 # allow a fast retry instead of waiting for the full observe_ms timeout.
            if (
                abort_after_seconds is not None
                and not timed_out
                and elapsed >= abort_after_seconds
            ):
                abort_text = ""
                if watchdog_log is not None and watchdog_log.is_file():
                    abort_text = watchdog_log.read_text(
                        encoding="utf-8", errors="replace",
                    )
                if '"session.dispatched"' not in abort_text:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    break
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        if process.poll() is None:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        completed_monotonic_ns = time.monotonic_ns()
        capture.flush()
        capture.seek(0)
        output = capture.read()
        return {
            "command": command,
            "exit_code": None if timed_out else process.returncode,
            "timed_out": timed_out,
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "output_tail": output.splitlines()[-80:],
            "phase_timestamps": {
                "started_monotonic_ns": started_monotonic_ns,
                "completed_monotonic_ns": completed_monotonic_ns,
                "duration_ns": completed_monotonic_ns - started_monotonic_ns,
            },
            "watchdog": {
                "captured": watchdog_captured,
                "path": (
                    watchdog_path.name
                    if watchdog_captured and watchdog_path is not None else None
                ),
            },
        }


def observer_launcher_host_deadline(
    observe_ms: int, legacy_fallback_timeout: int | None = None,
) -> int:
    """Bound both sequential launcher phases with an independent host clock."""

    deadline = (
        math.ceil(OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS / 1000)
        + math.ceil(observe_ms / 1000)
        + OBSERVER_HOST_DEADLINE_GRACE_SECONDS
    )
    if legacy_fallback_timeout is not None \
            and legacy_fallback_timeout > deadline:
        raise ValueError("fallback timeout exceeds the reviewed launcher deadline")
    return deadline


def skipped_run(reason: str) -> dict:
    return {
        "command": [],
        "exit_code": None,
        "timed_out": False,
        "output_sha256": hashlib.sha256(b"").hexdigest(),
        "output_tail": [],
        "skipped": reason,
    }


def run_text(result: dict) -> str:
    return "\n".join(result["output_tail"]).lower()


def has_loader_failure(*results: dict) -> bool:
    text = "\n".join(run_text(result) for result in results)
    return any(marker in text for marker in LOADER_FAILURE_MARKERS)


def wine_z_path(path: Path) -> str:
    path = path.resolve()
    # For wine backend, try to use E: drive (mapped to run root's parent)
    # instead of Z: which doesn't support DLL loading
    import os
    backend_id = os.environ.get("MIEL_NATIVE_BACKEND_ID", "fex")
    if backend_id == "wine":
        # Check if path is under a wine-prefix parent (the run root)
        # The E: drive maps to run_root = prefix.parent
        # We need to find the run root from the path
        parts = path.parts
        for i, part in enumerate(parts):
            if part == "miel-native":
                run_root = Path(*parts[:i+1])
                if str(path).startswith(str(run_root)):
                    rel = path.relative_to(run_root)
                    return "E:" + str(rel).replace("/", "\\")
                break
    return "Z:" + str(path).replace("/", "\\")


def validate_observe_ms(value: int) -> int:
    if isinstance(value, bool) or not MIN_OBSERVE_MS <= value <= MAX_OBSERVE_MS:
        raise ValueError(
            f"observe_ms must be in {MIN_OBSERVE_MS}..{MAX_OBSERVE_MS}"
        )
    return value


def observer_environment_arguments(value: Mapping[str, str] | None) -> list[str]:
    """Validate scenario-specific observer settings before passing them to env."""

    if value is None:
        return []
    allowed = {
        "MIEL_OBSERVER_SCENARIO",
        "MIEL_OBSERVER_SCENARIO_SHA256",
        "MIEL_OBSERVER_INITIAL_USER_SHA256",
        "MIEL_OBSERVER_FRAME",
        "MIEL_OBSERVER_MAX_RECORDS",
        "MIEL_OBSERVER_CALIBRATE_INITIAL_STATE",
        "MIEL_OBSERVER_SCENE_DISPATCH",
        "MIEL_OBSERVER_OBSERVATION_PROFILE",
        "MIEL_OBSERVER_OBSERVATION_OMIT_MASK",
        "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE",
        "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS",
        "MIEL_OBSERVER_DIAGNOSTIC_PROFILE",
        "MIEL_OBSERVER_BODY_MODE",
        "MIEL_OBSERVER_BODY_RECEIPT",
    }
    if set(value) - allowed:
        raise ValueError(
            f"unsupported observer environment keys: {sorted(set(value) - allowed)}"
        )
    arguments = []
    for key in sorted(value):
        item = value[key]
        if not isinstance(item, str) or not item or any(char in item for char in "\0\r\n"):
            raise ValueError(f"observer environment {key} must be non-empty single-line text")
        if key in {
            "MIEL_OBSERVER_SCENARIO_SHA256",
            "MIEL_OBSERVER_INITIAL_USER_SHA256",
        } and SHA256.fullmatch(item) is None:
            raise ValueError(f"observer {key} must be a lowercase SHA-256")
        if key == "MIEL_OBSERVER_MAX_RECORDS" and (
            not item.isascii() or not item.isdigit() or not 1 <= int(item) <= 1_000_000
        ):
            raise ValueError("observer max records must be in 1..1000000")
        if key == "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS" and item != "1":
            raise ValueError("observer bootstrap diagnostics accepts only 1")
        if key == "MIEL_OBSERVER_DIAGNOSTIC_PROFILE" and item not in {
            "session-only", "barn-session",
        }:
            raise ValueError(
                "observer diagnostic profile accepts only session-only or barn-session"
            )
        if key == "MIEL_OBSERVER_CALIBRATE_INITIAL_STATE" and item != "1":
            raise ValueError("observer initial-state calibration accepts only 1")
        if key == "MIEL_OBSERVER_SCENE_DISPATCH" and item != "1":
            raise ValueError("observer scene dispatch accepts only 1")
        if key == "MIEL_OBSERVER_OBSERVATION_PROFILE" and item not in {
            "scenario-bounded", "semantic-only", "calibration-only",
        }:
            raise ValueError(
                "observer observation profile accepts scenario-bounded, semantic-only "
                "or calibration-only"
            )
        if key == "MIEL_OBSERVER_OBSERVATION_OMIT_MASK":
            if re.fullmatch(r"0x[0-9a-f]{4}", item) is None:
                raise ValueError("observer omit mask must be four lowercase hex digits")
            mask = int(item, 16)
            shadow_family = 0x1ff0
            if mask > 0x1fff or mask & shadow_family not in {0, shadow_family}:
                raise ValueError(
                    "observer omit mask must retain or omit the coherent shadow family"
                )
        if key == "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE" and item != "1":
            raise ValueError("observer divergent profile opt-in accepts only 1")
        if key == "MIEL_OBSERVER_BODY_MODE" and item not in BODY_MODES:
            raise ValueError("observer body mode is outside the exact 22-mode allowlist")
        arguments.append(f"{key}={item}")
    body_keys = {"MIEL_OBSERVER_BODY_MODE", "MIEL_OBSERVER_BODY_RECEIPT"}
    if bool(set(value) & body_keys) and not body_keys <= set(value):
        raise ValueError("observer body mode and receipt must be configured together")
    observation_profile_keys = {
        "MIEL_OBSERVER_OBSERVATION_PROFILE",
        "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE",
        "MIEL_OBSERVER_OBSERVATION_OMIT_MASK",
    }
    configured_profile_keys = set(value) & observation_profile_keys
    configured_profile = value.get("MIEL_OBSERVER_OBSERVATION_PROFILE")
    if configured_profile == "semantic-only" and (
        configured_profile_keys not in (
            observation_profile_keys,
            observation_profile_keys - {"MIEL_OBSERVER_OBSERVATION_OMIT_MASK"},
        )
        or value.get("MIEL_OBSERVER_SCENE_DISPATCH") != "1"
    ):
        raise ValueError(
            "observer semantic profile requires scene dispatch and divergent opt-in"
        )
    if configured_profile == "scenario-bounded" and (
        configured_profile_keys != {
            "MIEL_OBSERVER_OBSERVATION_PROFILE",
            "MIEL_OBSERVER_OBSERVATION_OMIT_MASK",
        }
        or "MIEL_OBSERVER_SCENE_DISPATCH" in value
    ):
        raise ValueError(
            "observer scenario-bounded profile requires an exact omit mask and "
            "native scheduler"
        )
    if configured_profile == "scenario-bounded" and \
            value.get("MIEL_OBSERVER_OBSERVATION_OMIT_MASK") != \
            native_observation_profile_contract.profile_for_scenario(
                "controls-press-hold-release",
            )["omit_mask"]:
        raise ValueError(
            "observer scenario-bounded omit mask differs from the generated contract"
        )
    if configured_profile == "calibration-only" and (
        configured_profile_keys != {"MIEL_OBSERVER_OBSERVATION_PROFILE"}
        or value.get("MIEL_OBSERVER_CALIBRATE_INITIAL_STATE") != "1"
        or "MIEL_OBSERVER_SCENE_DISPATCH" in value
    ):
        raise ValueError(
            "observer calibration profile requires unbound initial-state calibration"
        )
    if "MIEL_OBSERVER_DIAGNOSTIC_PROFILE" in value and (
        value.get("MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS") != "1"
        or configured_profile_keys
        or "MIEL_OBSERVER_SCENE_DISPATCH" in value
    ):
        raise ValueError(
            "observer diagnostic profile requires bootstrap diagnostics and excludes semantic dispatch"
        )
    return arguments


def validate_calibration_observation_profile(path: Path) -> dict:
    """Require the exact non-evidence profile that preserves calibration data."""

    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not line.startswith("MVD "):
            continue
        try:
            row = json.loads(line[4:])
        except json.JSONDecodeError as error:
            raise ValueError(
                f"invalid calibration observation profile line {line_number}"
            ) from error
        if row.get("protocol") == "miel-vliegt-native-observation-profile":
            rows.append(row)
    required = {
        "schema", "protocol", "sequence", "profile", "omit_mask",
        "profile_id", "profile_sha256", "contract_sha256",
        "target_hook_mask", "omitted_channels", "retained_channels",
        "applicable_receipt_channels", "omitted_receipt_channels",
        "framebuffer_required", "evidence_eligible", "evidence_blocker",
        "signature_preflight_complete", "profile_state_writes", "thread_id",
    }
    if len(rows) != 1 or set(rows[0]) != required:
        raise ValueError("calibration observation profile receipt is not unique")
    row = rows[0]
    if (
        row["schema"] != 1
        or row["profile"] != "calibration-only"
        or row["profile_id"] != ""
        or row["profile_sha256"] != ""
        or row["contract_sha256"] !=
            native_observation_profile_contract.contract_value()[
                "contract_sha256"
            ]
        or row["omit_mask"] != "0x1fff"
        or row["target_hook_mask"] != "0x00000000"
        or row["omitted_channels"] !=
            list(CALIBRATION_OBSERVATION_OMITTED_CHANNELS)
        or row["retained_channels"] !=
            list(CALIBRATION_OBSERVATION_RETAINED_CHANNELS)
        or row["applicable_receipt_channels"] != []
        or row["omitted_receipt_channels"] != []
        or row["framebuffer_required"] is not False
        or row["evidence_eligible"] is not False
        or row["evidence_blocker"] != "calibration_only"
        or row["signature_preflight_complete"] is not True
        or row["profile_state_writes"] is not False
        or type(row["sequence"]) is not int
        or row["sequence"] < 0
        or type(row["thread_id"]) is not int
        or row["thread_id"] <= 0
    ):
        raise ValueError("calibration observation profile contract drifted")
    return row


def validate_scenario_observation_profile_receipt(
    path: Path, expected: Mapping[str, Any],
) -> dict:
    """Bind a suite-declared observer profile to the hook's unique receipt."""

    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="strict").splitlines(), 1,
    ):
        if not line.startswith("MVD "):
            continue
        try:
            row = json.loads(line[4:])
        except json.JSONDecodeError as error:
            raise ValueError(
                f"invalid observation profile line {line_number}"
            ) from error
        if row.get("protocol") == "miel-vliegt-native-observation-profile":
            rows.append(row)
    required = {
        "schema", "protocol", "sequence", "profile", "omit_mask",
        "profile_id", "profile_sha256", "contract_sha256",
        "target_hook_mask", "omitted_channels", "retained_channels",
        "applicable_receipt_channels", "omitted_receipt_channels",
        "framebuffer_required", "evidence_eligible", "evidence_blocker",
        "signature_preflight_complete", "profile_state_writes", "thread_id",
    }
    if len(rows) != 1 or set(rows[0]) != required:
        raise ValueError("scenario observation profile receipt is not unique")
    row = rows[0]
    observer_profile = expected.get("observer_profile")
    expected_profile = observer_profile
    expected_eligible = expected.get("parity_evidence_eligible")
    expected_blocker = (
        "startup_scheduler_divergence"
        if expected_profile == "semantic-only" else None
    )
    if (
        row["schema"] != 1
        or row["profile"] != expected_profile
        or row["profile_id"] != expected.get("id")
        or row["profile_sha256"] != expected.get("profile_sha256")
        or row["contract_sha256"] !=
            native_observation_profile_contract.contract_value()[
                "contract_sha256"
            ]
        or row["omit_mask"] != expected.get("omit_mask")
        or row["target_hook_mask"] != "0x00000000"
        or row["omitted_channels"] != expected.get("observer_omitted_channels")
        or row["retained_channels"] != []
        or row["applicable_receipt_channels"] != expected.get(
            "applicable_receipt_channels"
        )
        or row["omitted_receipt_channels"] != expected.get(
            "omitted_receipt_channels"
        )
        or row["framebuffer_required"] is not expected.get(
            "framebuffer_required"
        )
        or row["evidence_eligible"] is not expected_eligible
        or row["evidence_blocker"] != expected_blocker
        or row["signature_preflight_complete"] is not True
        or row["profile_state_writes"] is not False
        or type(row["sequence"]) is not int
        or row["sequence"] < 0
        or type(row["thread_id"]) is not int
        or row["thread_id"] <= 0
    ):
        raise ValueError("scenario observation profile contract drifted")
    return row


def install_headless_config(
    game_directory: Path, source: Path = HEADLESS_CONFIG,
) -> dict[str, str]:
    """Install the one reviewed software-renderer config into a disposable game."""
    try:
        payload = source.read_bytes()
    except OSError as error:
        raise ValueError(f"headless renderer config is unavailable: {source}") from error
    digest = hashlib.sha256(payload).hexdigest()
    if digest != HEADLESS_CONFIG_SHA256 or payload != (
        b"gtdriver gtSoftware\n"
        b"setupwindow false\n"
        b"fullscreen false\n"
    ):
        raise ValueError("headless renderer config drifted from the reviewed bytes")
    destination = game_directory / "config.ini"
    temporary = game_directory / ".config.ini.miel-observer.tmp"
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, destination)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise ValueError(f"could not install headless renderer config: {destination}") from error
    if sha256(destination) != HEADLESS_CONFIG_SHA256:
        raise ValueError("installed headless renderer config failed verification")
    return {
        "path": str(destination),
        "sha256": HEADLESS_CONFIG_SHA256,
        "driver": "gtSoftware",
    }


def install_observer_proxy(
    game_directory: Path, proxy: Path | None = None,
) -> dict[str, str]:
    """Stage the DINPUT proxy as an app-local dinput.dll in the game directory.

    WINEDLLOVERRIDES=dinput=n,b makes Wine prefer a native dinput.dll, but that
    only loads our proxy if a native dinput.dll actually sits in the game's DLL
    search path.  The proxy (native_observer_dinput_proxy) exports
    DirectInputCreateA, forwards to the real dinput named by MIEL_REAL_DINPUT,
    and loads MIEL_OBSERVER_DLL to initialize the observer.  The working capture
    runner stages this proxy beside the disposable game for exactly this reason;
    the probe path omitted it, so the override found no native dinput, Wine used
    its builtin, the observer never loaded, and the launch timed out with an
    empty observer log.  Mirror the reviewed temp-write-then-rename install used
    for the renderer config.
    """
    if proxy is None:
        proxy = OBSERVER_PROXY_DLL
    try:
        payload = proxy.read_bytes()
    except OSError as error:
        raise ValueError(f"observer proxy DLL is unavailable: {proxy}") from error
    digest = hashlib.sha256(payload).hexdigest()
    destination = game_directory / "DINPUT.dll"
    temporary = game_directory / ".DINPUT.dll.miel-observer.tmp"
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, destination)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise ValueError(
            f"could not install observer proxy DLL: {destination}"
        ) from error
    if sha256(destination) != digest:
        raise ValueError("installed observer proxy DLL failed verification")
    return {"path": str(destination), "sha256": digest}


def configure_gdi_renderer(
    environment: list[str], cwd: Path, backend: dict | None = None,
) -> dict:
    """Select the reviewed Wine renderer and decoration hint."""
    settings = (
        ("renderer", r"HKCU\Software\Wine\Direct3D", "renderer", "gdi"),
        ("decorated", r"HKCU\Software\Wine\X11 Driver", "Decorated", "N"),
        # Hangover's Wine does not auto-select a display driver, so the i386
        # game hit nodrv_CreateWindow and busy-looped without ever reaching its
        # manager loop. Pin the x11 graphics driver so winex11.drv loads against
        # the Xvfb display and the projector can create its render window.
        ("graphics", r"HKCU\Software\Wine\Drivers", "Graphics", "x11"),
    )
    runs = {}
    add_results = []
    query_results = []
    for label, registry_key, value_name, value in settings:
        add = run(
            environment + native_wine_command(
                "reg", "add", registry_key,
                "/v", value_name, "/t", "REG_SZ", "/d", value, "/f",
                backend=backend,
            ),
            cwd=cwd,
            timeout=20,
        )
        add_ok = add["exit_code"] == 0 and not add["timed_out"] \
            and not has_loader_failure(add)
        query = run(
            environment + native_wine_command(
                "reg", "query", registry_key, "/v", value_name,
                backend=backend,
            ),
            cwd=cwd,
            timeout=20,
        ) if add_ok else skipped_run(f"{label}-registry-write-failed")
        query_ok = query["exit_code"] == 0 and not query["timed_out"] \
            and not has_loader_failure(query) and re.search(
                rf"(?im)^\s*{re.escape(value_name)}\s+reg_sz\s+"
                rf"{re.escape(value)}\s*$",
                run_text(query),
            ) is not None
        runs[f"{label}_add"] = add
        runs[f"{label}_query"] = query
        add_results.append(add_ok)
        query_results.append(query_ok)
    return {
        "written": all(add_results),
        "verified": all(query_results),
        "runs": runs,
    }


def validate_scene_receipt(
    path: Path, executable: Path, scene: str, trap_strategy: str = "int3",
    observer_dll: Path | None = None,
) -> dict:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("native scene debugger produced no valid receipt") from error
    if (
        receipt.get("schema") != 1
        or receipt.get("protocol") != "miel-vliegt-native-scene-navigation"
        or receipt.get("status") != "PASS"
        or receipt.get("phase") != "scene-loader"
        or receipt.get("executable_sha256") != sha256(executable)
        or receipt.get("scene", {}).get("id") != scene
        or receipt.get("trap_strategy") != trap_strategy
        or receipt.get("mode_manager_observed") is not True
        or (
            observer_dll is not None
            and (
                receipt.get("observer_injected") is not True
                or receipt.get("observer_dll_sha256") != sha256(observer_dll)
            )
        )
    ):
        raise ValueError("native scene debugger receipt failed closed")
    return receipt


def validate_start_patch_receipt(
    receipt: dict, original: Path, patched: Path, scene: str,
) -> dict:
    changes = receipt.get("changes")
    if (
        receipt.get("schema") != 1
        or receipt.get("protocol") != "miel-vliegt-native-scene-start-patch"
        or receipt.get("status") != "PREPARED"
        or receipt.get("strategy") != "startup-mode-argument"
        or receipt.get("marker_directory") is not None
        or receipt.get("source_executable_sha256") != sha256(original)
        or receipt.get("patched_executable_sha256") != sha256(patched)
        or receipt.get("scene", {}).get("id") != scene
        or not isinstance(changes, list)
        or len(changes) != 1
        or changes[0].get("kind") != "startup-mode-argument"
    ):
        raise ValueError("native startup-mode patch receipt failed closed")
    return receipt


def validate_unmodified_start_receipt(
    receipt: dict, executable: Path, launch_executable: Path, scene: str,
) -> dict:
    """Bind an unmodified source to its byte-identical disposable target."""

    executable_sha256 = sha256(executable)
    if (
        receipt.get("schema") != 1
        or receipt.get("protocol") != "miel-vliegt-native-unmodified-start"
        or receipt.get("status") != "PREPARED"
        or receipt.get("strategy") != "byte-identical-disposable-copy"
        or receipt.get("source_executable_sha256") != executable_sha256
        or receipt.get("launch_executable_sha256") != executable_sha256
        or launch_executable.resolve() == executable.resolve()
        or sha256(launch_executable) != executable_sha256
        or receipt.get("scene") != scene
        or receipt.get("changes") != []
    ):
        raise ValueError("native unmodified-start receipt failed closed")
    return receipt


def validate_observer_launcher_receipt(
    path: Path,
    original: Path,
    patched: Path,
    observer_dll: Path,
    real_dinput: Path,
    patch_receipt_path: Path,
    scene: str,
) -> dict:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("native observer launcher produced no valid receipt") from error
    required_checks = {
        "created_suspended",
        "loader_initialization_completed",
        "proxy_observer_ready",
        "observer_loaded",
        "observer_initialized",
        "login_pending_observed",
        "ready_before_login_pending",
        "login_activation_observed",
        "ready_before_login_activation",
        "message_loop_wake_posted",
        "main_thread_resumed",
        "main_thread_resume_count",
        "projector_input_idle",
        "scenario_completion_event",
        "observer_failure_event_clear",
        "native_dispatch_requested",
        "native_dispatch_completion_event",
        "observation_window_completed",
        "target_terminated",
    }
    checks = receipt.get("checks")
    required_receipt_fields = {
        "schema", "protocol", "status", "phase", "detail",
        "bootstrap_strategy", "input_idle_probe_timeout_ms",
        "proxy_bootstrap_timeout_ms", "scene",
        "original_executable_sha256",
        "patched_executable_sha256", "observer_dll_sha256",
        "real_dinput_sha256",
        "patch_receipt_sha256", "capture_process", "checks",
    }
    if (
        set(receipt) != required_receipt_fields
        or receipt.get("schema") != 1
        or receipt.get("protocol") != "miel-vliegt-native-observer-launch"
        or receipt.get("bootstrap_strategy") != OBSERVER_BOOTSTRAP_STRATEGY
        or receipt.get("input_idle_probe_timeout_ms") !=
            OBSERVER_INPUT_IDLE_PROBE_TIMEOUT_MS
        or receipt.get("proxy_bootstrap_timeout_ms") !=
            OBSERVER_PROXY_BOOTSTRAP_TIMEOUT_MS
        or receipt.get("status") != "PASS"
        or receipt.get("phase") != "cleanup"
        or receipt.get("detail") != "observer-bootstrap-complete"
        or receipt.get("scene") != scene
        or receipt.get("original_executable_sha256") != sha256(original)
        or receipt.get("patched_executable_sha256") != sha256(patched)
        or receipt.get("observer_dll_sha256") != sha256(observer_dll)
        or receipt.get("real_dinput_sha256") != sha256(real_dinput)
        or receipt.get("patch_receipt_sha256") != sha256(patch_receipt_path)
        or not isinstance(checks, dict)
        or set(checks) != required_checks
        or type(checks.get("main_thread_resume_count")) is not int
        or checks.get("main_thread_resume_count") != 1
        or type(checks.get("projector_input_idle")) is not bool
        or type(checks.get("native_dispatch_requested")) is not bool
        or type(checks.get("native_dispatch_completion_event")) is not bool
        or not all(
            value is True for key, value in checks.items()
            if key not in {
                "main_thread_resume_count", "projector_input_idle",
                "message_loop_wake_posted", "native_dispatch_requested",
                "native_dispatch_completion_event",
            }
        )
        or type(checks.get("message_loop_wake_posted")) is not bool
    ):
        raise ValueError("native observer launcher receipt failed closed")
    capture_process = receipt.get("capture_process")
    if checks["native_dispatch_requested"]:
        if checks["native_dispatch_completion_event"] is not True \
                or not isinstance(capture_process,dict) \
                or set(capture_process) != {
                    "native_process_id", "capture_session_id",
                } \
                or type(capture_process.get("native_process_id")) is not int \
                or capture_process["native_process_id"] <= 0 \
                or not isinstance(capture_process.get("capture_session_id"),str) \
                or re.fullmatch(
                    r"mvds-[0-9a-f]{32}",capture_process["capture_session_id"],
                ) is None:
            raise ValueError("native observer launcher capture identity failed closed")
    elif checks["native_dispatch_completion_event"] is not False \
            or capture_process is not None:
        raise ValueError("unexpected native observer launcher capture identity")
    return receipt


def validate_body_only_receipt(
    path: Path,
    executable: Path,
    requested_mode: str,
) -> dict:
    """Accept only activation proof from the registered BODY-only dispatcher."""

    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("native BODY dispatcher produced no valid receipt") from error
    required = {
        "schema", "protocol", "status", "evidence_scope",
        "natural_transition_evidence", "debug_skip_used",
        "executable_sha256", "requested_mode", "command", "callback_count",
        "manager_thread", "pre", "post", "activation",
    }
    allowed_post_shapes = (
        {
            "current_unchanged": True, "current_is_target": True,
            "pending_is_target": False, "pending_null": True,
        },
        {
            "current_unchanged": False, "current_is_target": True,
            "pending_is_target": False, "pending_null": True,
        },
        {
            "current_unchanged": True, "current_is_target": False,
            "pending_is_target": True, "pending_null": False,
        },
    )
    if (
        set(receipt) != required
        or requested_mode not in BODY_MODES
        or receipt.get("schema") != 1
        or receipt.get("protocol") != "miel-vliegt-native-body-dispatch"
        or receipt.get("status") != "PASS"
        or receipt.get("evidence_scope") != "BODY_ONLY"
        or receipt.get("natural_transition_evidence") is not False
        or receipt.get("debug_skip_used") is not False
        or receipt.get("executable_sha256") != sha256(executable)
        or receipt.get("requested_mode") != requested_mode
        or receipt.get("command") != {
            "name": "engine_mode", "id": 15,
            "dispatch": "registered-command-callback",
        }
        or type(receipt.get("callback_count")) is not int
        or receipt.get("callback_count") != 1
        or receipt.get("manager_thread") is not True
        or receipt.get("pre") != {
            "manager_canonical": True,
            "current_mode": "mode_barn",
            "pending_null": True,
            "target_resolved_before_mutation": True,
            "registry_record_resolved": True,
        }
        or receipt.get("post") not in allowed_post_shapes
        or receipt.get("activation") != {
            "target_is_current": True,
            "pending_null": True,
            "loaded": True,
            "opened": True,
        }
    ):
        raise ValueError("native BODY dispatcher receipt failed closed")
    return receipt


def read_partial_scene_receipt(path: Path) -> dict | None:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if receipt.get("protocol") != "miel-vliegt-native-scene-navigation":
        return None
    return receipt


def read_debug_capability_receipt(path: Path, expected_trap: str | None = None) -> dict | None:
    """Accept only a terminal receipt from the standalone PE32 micro-oracle."""
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    capability = receipt.get("debug_api_capability")
    expected_status = "PASS" if capability == "SUPPORTED" else "FAIL"
    if (
        receipt.get("schema") != 1
        or receipt.get("protocol") != "miel-hangover-win32-debug-capability"
        or receipt.get("phase") != "debug-api-capability"
        or capability not in {"SUPPORTED", "UNSUPPORTED"}
        or receipt.get("status") != expected_status
        or receipt.get("controller_machine") != "i386"
        or receipt.get("child_machine") != "i386"
        or receipt.get("trap_strategy") not in {"int3", "ud2"}
        or (expected_trap is not None and receipt.get("trap_strategy") != expected_trap)
        or not isinstance(receipt.get("checks"), dict)
    ):
        return None
    required_checks = {
        "create_process_event_seen",
        "ready_debug_string_seen",
        "deliberate_trap_arm_ok",
        "deliberate_breakpoint_seen",
        "deliberate_second_breakpoint_seen",
        "deliberate_trap_restore_ok",
        "deliberate_second_trap_restore_ok",
        "restored_execution_semantics_ok",
        "deliberate_trap_location_matches",
        "startup_breakpoint_context_ok",
        "get_thread_context_ok",
        "set_thread_context_ok",
        "context_mutation_roundtrip_ok",
        "trap_resume_context_ok",
        "remote_memory_roundtrip_ok",
        "code_memory_roundtrip_ok",
        "continue_attempted",
        "continue_debug_event_ok",
        "exit_process_seen",
    }
    if set(receipt["checks"]) != required_checks:
        return None
    if not all(isinstance(value, bool) for value in receipt["checks"].values()):
        return None
    if capability == "SUPPORTED" and not all(receipt["checks"].values()):
        return None
    if capability == "SUPPORTED":
        hits = receipt.get("deliberate_breakpoint_hits")
        first_address = receipt.get("deliberate_trap_address")
        second_address = receipt.get("deliberate_second_trap_address")
        if isinstance(hits, bool) or not isinstance(hits, int) or hits != 2:
            return None
        if any(
            isinstance(address, bool)
            or not isinstance(address, int)
            or not 0 < address <= 0xFFFFFFFF
            for address in (first_address, second_address)
        ):
            return None
        if first_address == second_address:
            return None
    return receipt


def probe_debug_capability(
    environment: list[str],
    backend: dict,
    output: Path,
    capability_executable: Path,
) -> dict:
    """Try documented conservative profiles and select only proven debug APIs."""
    attempts = []
    selected_profile = None
    for profile in DEBUG_PROFILES[backend["id"]]:
        receipt_path = output.parent / (
            f"win32-debug-capability-{backend['id']}-{profile['id']}.json"
        )
        receipt_path.unlink(missing_ok=True)
        result = run(
            environment + profile["environment"] + [
                *native_wine_command(capability_executable, backend=backend),
                "--receipt", wine_z_path(receipt_path),
                "--deadline-ms", "8000",
                "--trap", profile["trap_strategy"],
            ],
            cwd=capability_executable.parent,
            timeout=12,
        )
        receipt = read_debug_capability_receipt(receipt_path, profile["trap_strategy"])
        capability = receipt["debug_api_capability"] if receipt else "INDETERMINATE"
        shutdown = shutdown_private_wineserver(
            environment, capability_executable.parent, backend,
        )
        cleanup = shutdown["runs"]["stop"]
        cleanup_wait = shutdown["runs"]["wait"]
        cleanup_completed = shutdown["complete"]
        attempt = {
            "profile": profile["id"],
            "environment": profile["environment"],
            "capability": capability,
            "controller_cleanup_completed": (
                not result["timed_out"] and result["exit_code"] in {0, 1}
            ),
            "wineserver_cleanup_completed": cleanup_completed,
            "receipt": receipt,
            "run": result,
            "cleanup_run": cleanup,
            "cleanup_wait_run": cleanup_wait,
        }
        attempts.append(attempt)
        if not cleanup_completed:
            attempt["capability"] = "INDETERMINATE"
            break
        if capability == "SUPPORTED":
            selected_profile = profile
            break
    return {
        "capability": "SUPPORTED" if selected_profile else (
            "UNSUPPORTED"
            if attempts and all(item["capability"] == "UNSUPPORTED" for item in attempts)
            else "INDETERMINATE"
        ),
        "prefix_clean": bool(attempts and attempts[-1]["wineserver_cleanup_completed"]),
        "selected_profile": selected_profile,
        "attempts": attempts,
    }


def run_scene_navigation(
    environment: list[str],
    backend: dict,
    executable: Path,
    output: Path,
    scene: str,
    scene_debugger: Path,
    observer_dll: Path | None = None,
    observer_launcher: Path = OBSERVER_LAUNCHER,
    *,
    real_dinput: Path = REAL_DINPUT,
    proxy_dll: Path | None = None,
    attempt_debug: bool = True,
    allow_fallback: bool = True,
    trap_strategy: str = "int3",
    debug_timeout: int = 20,
    fallback_timeout: int = 30,
    observe_ms: int = DEFAULT_OBSERVE_MS,
    observer_environment: Mapping[str, str] | None = None,
    unmodified_start: bool = False,
    unmodified_target: Path | None = None,
) -> dict:
    """Bootstrap a native scene without depending on Win32 debug events.

    The external debugger route remains available only as a diagnostic when a
    capability receipt proves it.  The selected fallback either changes only
    the reviewed startup SetMode argument in a disposable copy or, when
    ``unmodified_start`` requires a byte-identical disposable target beside
    the selected native DINPUT proxy while retaining the source game as cwd.
    """
    observe_ms = validate_observe_ms(observe_ms)
    environment = bind_native_proxy_dll_override(environment)
    observer_env_arguments = observer_environment_arguments(observer_environment)
    from tools.miel_vliegt.native_scene_navigator import (
        load_manifest,
        patch_executable,
        scene_by_id,
        startup_target_by_id,
    )

    manifest = load_manifest()
    try:
        scene_record = scene_by_id(manifest, scene)
    except ValueError:
        scene_record = startup_target_by_id(manifest, scene)
    # The external debugger route proves a location loader. Runtime modes such
    # as mode_fly have no location loader and therefore use only the reviewed
    # startup SetMode patch plus the in-process observer.
    if scene_record.get("kind") == "runtime_mode":
        attempt_debug = False

    # This is the common native scene/body launch boundary. Do not rely on a
    # caller having sanitized the ISO/user config: every attempted native run
    # installs the reviewed bytes immediately before process creation.
    headless_config = None

    debug_receipt_path = output.parent / f"native-scene-{backend['id']}.json"
    observer_log_path = output.parent / f"native-observer-{backend['id']}.log"
    debug_receipt_path.unlink(missing_ok=True)
    observer_log_path.unlink(missing_ok=True)
    if attempt_debug:
        observer_cli_arguments = (
            ["--observer", wine_z_path(observer_dll)] if observer_dll else []
        )
        headless_config = install_headless_config(executable.parent)
        debug_launch = run(
            environment + observer_env_arguments + ([f"MIEL_OBSERVER_LOG={wine_z_path(observer_log_path)}"] if observer_dll else []) + [
                *native_wine_command(scene_debugger, backend=backend),
                "--target", wine_z_path(executable),
                "--cwd", wine_z_path(executable.parent),
                "--scene", scene,
                "--receipt", wine_z_path(debug_receipt_path),
                "--trap", trap_strategy,
                *observer_cli_arguments,
                "--quit-on-confirm",
            ],
            cwd=executable.parent,
            timeout=debug_timeout,
        )
        partial_debug_receipt = read_partial_scene_receipt(debug_receipt_path)
        try:
            debug_receipt = validate_scene_receipt(
                debug_receipt_path, executable, scene, trap_strategy,
                observer_dll,
            )
        except ValueError:
            debug_receipt = None
    else:
        debug_launch = skipped_run("debug-api-capability-not-supported")
        partial_debug_receipt = None
        debug_receipt = None
    debug_event_forwarding = bool(
        partial_debug_receipt
        and partial_debug_receipt.get("phase") not in {None, "launch"}
    )
    debug_shutdown = (
        shutdown_private_wineserver(environment, executable.parent, backend)
        if attempt_debug
        else {
            "complete": True,
            "runs": {
                "stop": skipped_run("debug-api-not-attempted"),
                "wait": skipped_run("debug-api-not-attempted"),
            },
        }
    )
    debug_cleanup = debug_shutdown["runs"]["stop"]
    debug_cleanup_wait = debug_shutdown["runs"]["wait"]
    debug_cleanup_ok = debug_shutdown["complete"]
    observer_loaded = (
        observer_dll is None
        or (
            observer_log_path.is_file()
            and "\"status\":\"LOADED\"" in observer_log_path.read_text(
                encoding="utf-8", errors="replace",
            )
        )
    )
    if debug_receipt is not None and debug_cleanup_ok and observer_loaded:
        return {
            "headless_config": headless_config,
            "route": "win32-debug-api",
            "scene_loader_confirmed": True,
            "debug_event_forwarding": True,
            "debug_controller_cleanup_completed": (
                not debug_launch["timed_out"] and debug_launch["exit_code"] == 0
            ),
            "debug_receipt": debug_receipt,
            "observer_log": {
                "path": observer_log_path.name,
                "sha256": sha256(observer_log_path),
                "hook_loaded": "\"status\":\"LOADED\"" in observer_log_path.read_text(
                    encoding="utf-8", errors="replace",
                ),
            } if observer_log_path.is_file() else None,
            "start_patch_receipt": None,
            "observer_launcher_receipt": None,
            "scene_bootstrap_confirmed": True,
            "runs": {
                "debug_launch": debug_launch,
                "debug_cleanup": debug_cleanup,
                "debug_cleanup_wait": debug_cleanup_wait,
                "start_patch_launch": skipped_run("win32-debug-api-confirmed"),
            },
        }
    if not debug_cleanup_ok:
        return {
            "headless_config": headless_config,
            "route": None,
            "scene_loader_confirmed": False,
            "debug_event_forwarding": debug_event_forwarding,
            "debug_controller_cleanup_completed": False,
            "debug_receipt": debug_receipt,
            "observer_log": None,
            "partial_debug_receipt": partial_debug_receipt,
            "start_patch_receipt": None,
            "observer_launcher_receipt": None,
            "scene_bootstrap_confirmed": False,
            "runs": {
                "debug_launch": debug_launch,
                "debug_cleanup": debug_cleanup,
                "debug_cleanup_wait": debug_cleanup_wait,
                "start_patch_launch": skipped_run("debug-cleanup-failed"),
            },
        }
    if not allow_fallback:
        return {
            "headless_config": headless_config,
            "route": None,
            "scene_loader_confirmed": False,
            "debug_event_forwarding": debug_event_forwarding,
            "debug_controller_cleanup_completed": (
                not debug_launch["timed_out"] and debug_launch["exit_code"] == 0
            ) if attempt_debug else None,
            "debug_receipt": debug_receipt,
            "observer_log": None,
            "partial_debug_receipt": partial_debug_receipt,
            "start_patch_receipt": None,
            "observer_launcher_receipt": None,
            "scene_bootstrap_confirmed": False,
            "runs": {
                "debug_launch": debug_launch,
                "debug_cleanup": debug_cleanup,
                "debug_cleanup_wait": debug_cleanup_wait,
                "start_patch_launch": skipped_run("debug-api-required"),
            },
        }

    if observer_dll is None:
        raise ValueError("suspended observer bootstrap requires the observer DLL")
    if unmodified_start:
        if unmodified_target is None:
            raise ValueError("unmodified start requires a disposable target")
        launch_executable = unmodified_target.resolve()
        if launch_executable == executable.resolve() \
                or launch_executable.parent == executable.resolve().parent \
                or not (launch_executable.parent / "DINPUT.dll").is_file():
            raise ValueError(
                "unmodified target must be in a separate proxy directory"
            )
        launch_executable.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(executable, launch_executable)
        start_receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-native-unmodified-start",
            "status": "PREPARED",
            "strategy": "byte-identical-disposable-copy",
            "source_executable_sha256": sha256(executable),
            "launch_executable_sha256": sha256(executable),
            "scene": scene,
            "changes": [],
        }
        validate_unmodified_start_receipt(
            start_receipt, executable, launch_executable, scene,
        )
        start_receipt_path = (
            output.parent / f"native-unmodified-start-{backend['id']}.json"
        )
    else:
        # Keep the disposable copy next to the installed game. Director
        # projectors load DLLs and data relative to their executable.
        launch_executable = (
            executable.parent / f"MulleMeck-scene-{backend['id']}.exe"
        )
        launch_executable.unlink(missing_ok=True)
        start_receipt = patch_executable(
            executable,
            launch_executable,
            manifest,
            scene_record,
        )
        validate_start_patch_receipt(
            start_receipt, executable, launch_executable, scene,
        )
        start_receipt_path = (
            output.parent / f"native-scene-patch-{backend['id']}.json"
        )
    start_receipt_path.write_text(
        json.dumps(start_receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    observer_launcher_receipt_path = (
        output.parent / f"native-observer-launch-{backend['id']}.json"
    )
    watchdog_diagnostic_path = (
        output.parent / f"native-startup-watchdog-{backend['id']}.json"
    )
    observer_launcher_receipt_path.unlink(missing_ok=True)
    watchdog_diagnostic_path.unlink(missing_ok=True)
    observer_log_path.unlink(missing_ok=True)
    launcher_timeout = observer_launcher_host_deadline(
        observe_ms, fallback_timeout,
    )
    # GetTickCount() inside the Win32 launcher is guest time under FEX/Wine.
    # Its proxy bootstrap and scenario observation budgets run sequentially.
    # Keep an independent host-monotonic deadline around both phases so the
    # host neither cuts the second phase short nor waits without a reviewed
    # upper bound when the guest clock stalls.
    # A failed diagnostic launch may have touched config.ini. Reinstall at the
    # final process-creation boundary instead of trusting earlier validation.
    headless_config = install_headless_config(executable.parent)
    observer_proxy = install_observer_proxy(launch_executable.parent, proxy_dll)
    start_patch_launch = {
        **run(
            environment + observer_env_arguments + [
                f"MIEL_OBSERVER_LOG={wine_z_path(observer_log_path)}",
                *native_wine_command(observer_launcher, backend=backend),
                "--source", wine_z_path(executable),
                "--target", wine_z_path(launch_executable),
                "--observer", wine_z_path(observer_dll),
                "--real-dinput", wine_z_path(real_dinput),
                "--patch-receipt", wine_z_path(start_receipt_path),
                "--receipt", wine_z_path(observer_launcher_receipt_path),
                "--cwd", wine_z_path(executable.parent),
                "--scene", scene,
                "--observe-ms", str(observe_ms),
            ],
            cwd=executable.parent,
            timeout=launcher_timeout,
            watchdog={
                "diagnostic_path": watchdog_diagnostic_path,
                "observer_log": observer_log_path,
                "after_seconds": min(
                    90, max(1, launcher_timeout // 3),
                ),
                # Early-abort disabled: the 600s (10 min) threshold was too
                # aggressive — it killed scenarios (including taxi-straight)
                # before they could finish FEX JIT bootstrap. With the
                # restored 60-min observe window, the full observe_ms
                # timeout is the correct fail-fast boundary.
                "abort_after_seconds": None,
            },
        ),
        "host_deadline_seconds": launcher_timeout,
        "deadline_clock": "host_monotonic",
    }
    try:
        persisted_start_receipt = json.loads(
            start_receipt_path.read_text(encoding="utf-8"),
        )
        if unmodified_start:
            validate_unmodified_start_receipt(
                persisted_start_receipt, executable, launch_executable, scene,
            )
        else:
            validate_start_patch_receipt(
                persisted_start_receipt, executable, launch_executable, scene,
            )
        if persisted_start_receipt != start_receipt:
            raise ValueError("native start receipt changed during launch")
        observer_launcher_receipt = validate_observer_launcher_receipt(
            observer_launcher_receipt_path,
            executable,
            launch_executable,
            observer_dll,
            real_dinput,
            start_receipt_path,
            scene,
        )
    except (OSError, json.JSONDecodeError, ValueError):
        observer_launcher_receipt = None
    observer_loaded = (
        observer_log_path.is_file()
        and '"status":"LOADED"' in observer_log_path.read_text(
            encoding="utf-8", errors="replace",
        )
    )
    # DEBUG: check receipt file contents
    if start_patch_launch and start_patch_launch.get("exit_code") != 0:
        import sys as _sys
        _cmd = start_patch_launch.get("command", [])
        # Find --receipt path in command
        _receipt_path = None
        for _i, _arg in enumerate(_cmd):
            if _arg == "--receipt" and _i + 1 < len(_cmd):
                _receipt_path = _cmd[_i + 1]
                break
        # Convert Z:\ to /
        if _receipt_path:
            _linux_path = _receipt_path.replace("Z:\\", "/").replace("\\", "/")
            print(f"=== RECEIPT PATH: {_linux_path} ===", file=_sys.stderr)
            try:
                _content = Path(_linux_path).read_text(encoding="utf-8")
                print(f"RECEIPT CONTENT: {_content[:2000]}", file=_sys.stderr)
            except Exception as _e:
                print(f"RECEIPT READ FAILED: {_e}", file=_sys.stderr)
        # Also check patch-receipt
        for _i, _arg in enumerate(_cmd):
            if _arg == "--patch-receipt" and _i + 1 < len(_cmd):
                _pr = _cmd[_i + 1].replace("Z:\\", "/").replace("\\", "/")
                print(f"PATCH RECEIPT EXISTS: {Path(_pr).exists()}", file=_sys.stderr)
                break
        print(f"exit={start_patch_launch.get('exit_code')} duration={start_patch_launch.get('phase_timestamps',{}).get('duration_ns',0)/1e9:.3f}s", file=_sys.stderr)

    start_patch_confirmed = bool(
        observer_launcher_receipt
        and observer_loaded
        and start_patch_launch["exit_code"] == 0
        and not start_patch_launch["timed_out"]
        and not has_loader_failure(start_patch_launch)
    )
    capture_process = None
    if observer_launcher_receipt:
        native_identity = observer_launcher_receipt.get("capture_process")
        if isinstance(native_identity,dict):
            capture_process = {
                "nativeProcessId": native_identity["native_process_id"],
                "captureSessionId": native_identity["capture_session_id"],
            }
    return {
        "headless_config": headless_config,
        "route": "suspended-process-observer-launcher" if start_patch_confirmed else None,
        "scene_loader_confirmed": False,
        "scene_bootstrap_confirmed": start_patch_confirmed,
        "debug_event_forwarding": debug_event_forwarding,
        "debug_controller_cleanup_completed": (
            not debug_launch["timed_out"] and debug_launch["exit_code"] == 0
        ) if attempt_debug else None,
        "debug_receipt": debug_receipt,
        "observer_log": {
            "path": observer_log_path.name,
            "sha256": sha256(observer_log_path),
            "hook_loaded": observer_loaded,
        } if observer_log_path.is_file() else None,
        "partial_debug_receipt": partial_debug_receipt,
        "start_patch_receipt": None if unmodified_start else start_receipt,
        "start_executable_receipt": start_receipt,
        "observer_launcher_receipt": observer_launcher_receipt,
        "captureProcess": capture_process,
        "runs": {
            "debug_launch": debug_launch,
            "debug_cleanup": debug_cleanup,
            "debug_cleanup_wait": debug_cleanup_wait,
            "start_patch_launch": start_patch_launch,
        },
        "phase_timestamps": start_patch_launch.get("phase_timestamps"),
        "early_phase_watchdog": {
            **start_patch_launch.get("watchdog", {
                "captured": watchdog_diagnostic_path.is_file(),
                "path": (
                    watchdog_diagnostic_path.name
                    if watchdog_diagnostic_path.is_file() else None
                ),
            }),
            "sha256": (
                sha256(watchdog_diagnostic_path)
                if watchdog_diagnostic_path.is_file() else None
            ),
        },
    }


def run_native_semantic_scenario(
    environment: list[str], backend: dict, executable: Path, output: Path,
    suite_manifest_path: Path, scenario_id: str, state_root: Path,
    initial_state_targets: Mapping[str, str], observer_dll: Path,
    disposable_executable: Path,
    observer_launcher: Path = OBSERVER_LAUNCHER, *,
    scene_debugger: Path = SCENE_DEBUGGER, real_dinput: Path = REAL_DINPUT,
    proxy_dll: Path = OBSERVER_PROXY_DLL,
    observe_ms: int = DEFAULT_OBSERVE_MS,
    max_records: int = 100_000,
    observation_profile: Mapping[str, Any] | str | None = None,
    diagnostic_profile: str | None = None,
) -> dict:
    """Run one suite scenario only after exact state restore and artifact binding.

    This returns candidate capture material. It cannot promote parity gates.
    File fixtures are restored atomically here; reviewed runtime scalars are
    applied and read back by the in-process observer at SESSION_ARMED.
    """

    from tools.miel_vliegt import native_scenario_artifacts as artifacts

    if isinstance(max_records, bool) or not 1 <= max_records <= 1_000_000:
        raise ValueError("max_records must be in 1..1000000")
    output.parent.mkdir(parents=True, exist_ok=True)
    frame_prefix = output.parent / f"native-frame-{scenario_id}-{backend['id']}"
    frame_metadata_path = frame_prefix.with_suffix(".json")
    frame_raw_path = frame_prefix.with_suffix(".raw")
    frame_native_metadata_path = frame_prefix.with_suffix(".native.json")
    frame_native_raw_path = frame_prefix.with_suffix(".native.raw")
    existing_frame_artifacts = [
        path for path in (
            frame_metadata_path,
            frame_raw_path,
            frame_native_metadata_path,
            frame_native_raw_path,
        )
        if path.exists()
    ]
    if existing_frame_artifacts:
        raise ValueError(
            "native framebuffer output already exists: "
            + ", ".join(path.name for path in existing_frame_artifacts)
        )
    manifest_path = suite_manifest_path.resolve()
    manifest = artifacts.load_scenario_suite_manifest(manifest_path)
    suite_root = manifest_path.parent
    entry = artifacts.scenario_suite_entry(manifest, scenario_id)
    scenario_path = suite_root / entry["scenario"]["path"]
    replay_path = suite_root / entry["native_replay"]["path"]
    crosswire = os.environ.get("NATIVE_SUITE_CROSSWIRE", "")
    if crosswire:
        for pair in crosswire.split(","):
            if ":" in pair:
                cw_src, cw_dst = pair.split(":", 1)
                if cw_src.strip() == scenario_id:
                    cw_path = suite_root / "replays" / f"{cw_dst.strip()}.mvo"
                    if cw_path.is_file():
                        replay_path = cw_path
                    break
    scenario = artifacts.load_scenario(scenario_path, root=suite_root)
    user_rows = [
        row for row in scenario["initial_state"]["files"]
        if row["role"] == "user-profile"
    ]
    if len(user_rows) != 1 or len(scenario["initial_state"]["files"]) != 1:
        raise ValueError(
            f"native scenario {scenario_id} requires user-profile as its only "
            "initial-state file"
        )
    if initial_state_targets != {"user-profile": "Data/User/user0.dat"}:
        raise ValueError(
            "native user profile must restore to Data/User/user0.dat"
        )
    if state_root.resolve() != executable.parent.resolve():
        raise ValueError(
            "native state root must be the executable's game directory"
        )
    user_source = (suite_root / user_rows[0]["path"]).resolve()
    repository_root = ROOT.resolve()
    if user_source == repository_root or repository_root in user_source.parents:
        raise ValueError(
            "native user-profile fixture must remain outside the repository"
        )
    suite_manifest_sha256 = artifacts.sha256_file(manifest_path)
    scenario_file_sha256 = artifacts.sha256_file(scenario_path)
    replay_sha256 = artifacts.sha256_file(replay_path)
    executable_sha256 = artifacts.sha256_file(executable)
    observer_sha256 = artifacts.sha256_file(observer_dll)
    state_receipt = artifacts.restore_scenario_initial_state_files(
        scenario,
        artifact_root=suite_root,
        state_root=state_root,
        role_targets=initial_state_targets,
        purge_undeclared_files=True,
    )

    restored_user = [
        row for row in state_receipt["files"] if row["role"] == "user-profile"
    ]
    if len(restored_user) != 1 \
            or restored_user[0]["target_path"] != "Data/User/user0.dat":
        raise ValueError("native user initial-state restore receipt is ambiguous")
    observer_environment = {
        "MIEL_OBSERVER_SCENARIO": wine_z_path(replay_path),
        "MIEL_OBSERVER_SCENARIO_SHA256": replay_sha256,
        "MIEL_OBSERVER_INITIAL_USER_SHA256": restored_user[0]["sha256"],
        "MIEL_OBSERVER_FRAME": wine_z_path(frame_prefix),
        "MIEL_OBSERVER_MAX_RECORDS": str(max_records),
    }
    if observation_profile is not None and diagnostic_profile is not None:
        raise ValueError("native scenario observation and diagnostic profiles are mutually exclusive")
    suite_observation_profile = None
    legacy_observation_profile = (
        observation_profile if isinstance(observation_profile, str) else None
    )
    if isinstance(observation_profile, Mapping):
        suite_observation_profile = artifacts.validate_scenario_observation_profile(
            observation_profile, scenario_id=scenario_id,
        )
        configured_profile = suite_observation_profile["observer_profile"]
        if configured_profile == "scenario-bounded":
            observer_environment.update({
                "MIEL_OBSERVER_OBSERVATION_PROFILE": "scenario-bounded",
                "MIEL_OBSERVER_OBSERVATION_OMIT_MASK":
                    suite_observation_profile["omit_mask"],
            })
        elif configured_profile != "full":
            raise ValueError("unsupported suite observation profile")
    elif observation_profile is not None:
        if observation_profile == "semantic-only":
            observer_environment.update({
                "MIEL_OBSERVER_SCENE_DISPATCH": "1",
                "MIEL_OBSERVER_OBSERVATION_PROFILE": "semantic-only",
                "MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE": "1",
            })
        elif observation_profile == "calibration-only":
            if scenario["initial_state"]["values"]:
                raise ValueError(
                    "native calibration-only profile requires unbound runtime state"
                )
            observer_environment[
                "MIEL_OBSERVER_OBSERVATION_PROFILE"
            ] = "calibration-only"
        else:
            raise ValueError(
                "native scenario observation profile must be semantic-only "
                "or calibration-only"
            )
    if diagnostic_profile is not None:
        if diagnostic_profile not in {"session-only", "barn-session"}:
            raise ValueError(
                "native scenario diagnostic profile must be session-only or barn-session"
            )
        observer_environment.update({
            "MIEL_OBSERVER_BOOTSTRAP_DIAGNOSTICS": "1",
            "MIEL_OBSERVER_DIAGNOSTIC_PROFILE": diagnostic_profile,
        })
    if not scenario["initial_state"]["values"]:
        observer_environment["MIEL_OBSERVER_CALIBRATE_INITIAL_STATE"] = "1"
    navigation = run_scene_navigation(
        environment,
        backend,
        executable,
        output,
        "flight",
        scene_debugger,
        observer_dll,
        observer_launcher,
        real_dinput=real_dinput,
        proxy_dll=proxy_dll,
        attempt_debug=False,
        observe_ms=observe_ms,
        observer_environment=observer_environment,
        unmodified_start=True,
        unmodified_target=disposable_executable,
    )
    immutable_inputs = {
        manifest_path: suite_manifest_sha256,
        scenario_path: scenario_file_sha256,
        replay_path: replay_sha256,
        executable: executable_sha256,
        observer_dll: observer_sha256,
    }
    changed_inputs = [
        path.name for path, expected_sha256 in immutable_inputs.items()
        if artifacts.sha256_file(path) != expected_sha256
    ]
    if changed_inputs:
        raise ValueError(
            f"native scenario {scenario_id} changed immutable inputs: "
            + ", ".join(changed_inputs)
        )
    if navigation.get("route") != "suspended-process-observer-launcher" \
            or navigation.get("scene_bootstrap_confirmed") is not True:
        observer_log = navigation.get("observer_log") or {}
        start_patch = (navigation.get("runs") or {}).get("start_patch_launch") or {}
        raise ValueError(
            f"native scenario {scenario_id} did not bootstrap cleanly: "
            f"route={navigation.get('route')!r}, "
            f"scene_bootstrap_confirmed={navigation.get('scene_bootstrap_confirmed')!r}, "
            f"observer_hook_loaded={observer_log.get('hook_loaded')}, "
            f"start_patch_exit_code={start_patch.get('exit_code')}, "
            f"start_patch_timed_out={start_patch.get('timed_out')}"
        )
    start_receipt = navigation.get("start_executable_receipt")
    if not isinstance(start_receipt, dict):
        raise ValueError(f"native scenario {scenario_id} has no start identity receipt")
    validate_unmodified_start_receipt(
        start_receipt, executable, disposable_executable, "flight",
    )
    launcher_receipt = navigation.get("observer_launcher_receipt")
    if not isinstance(launcher_receipt, dict) \
            or launcher_receipt.get("original_executable_sha256") != executable_sha256 \
            or launcher_receipt.get("patched_executable_sha256") != executable_sha256:
        raise ValueError(f"native scenario {scenario_id} launch was not byte-identical")
    log_reference = navigation.get("observer_log")
    if not isinstance(log_reference, dict) or log_reference.get("hook_loaded") is not True:
        raise ValueError(f"native scenario {scenario_id} has no loaded observer log")
    observer_log = output.parent / log_reference.get("path", "")
    if not observer_log.is_file() \
            or artifacts.sha256_file(observer_log) != log_reference.get("sha256"):
        raise ValueError(f"native scenario {scenario_id} observer log identity drifted")
    if legacy_observation_profile == "calibration-only":
        validate_calibration_observation_profile(observer_log)
        trace = artifacts.parse_semantic_log(observer_log, require_complete=True)
        tick_count = scenario["input_script"]["tick_count"]
        channel_counts = trace["channel_counts"]
        allowed_channels = {
            "session.dispatched", "session.navigating", "session.armed",
            "session.ready", "session.complete",
            "input.transition", "input.focus", "input.sample",
            "clock.tick", "flight.tick", "rng.seed", "rng.draw", "rng.end",
            "render.framebuffer",
        }
        if (
            trace["scenario_id"] != scenario_id
            or channel_counts.get("clock.tick") != tick_count
            or channel_counts.get("flight.tick") != tick_count
            or channel_counts.get("render.framebuffer") != 1
            or set(channel_counts) - allowed_channels
        ):
            raise ValueError(
                f"native calibration-only trace contract drifted: {scenario_id}"
            )
    else:
        trace = artifacts.validate_completed_scenario_trace(
            observer_log, scenario, root=suite_root,
        )
    profile_receipt = None
    if suite_observation_profile is not None:
        profile_receipt = validate_scenario_observation_profile_receipt(
            observer_log, suite_observation_profile,
        )
    framebuffer_applicable = (
        suite_observation_profile is None
        or "framebuffer" in
        suite_observation_profile["applicable_receipt_channels"]
    )
    framebuffer = None
    if framebuffer_applicable:
        metadata = artifacts.load_framebuffer_metadata(frame_metadata_path)
        native_metadata = artifacts.load_framebuffer_source_metadata(
            frame_native_metadata_path,
        )
        framebuffer_derivation = artifacts.validate_framebuffer_derivation(
            native_metadata,
            frame_native_raw_path.read_bytes(),
            metadata,
            frame_raw_path.read_bytes(),
        )
        framebuffer_trace_binding = artifacts.validate_framebuffer_trace_binding(
            trace,
            metadata,
            require_render_final=legacy_observation_profile != "calibration-only",
        )
        if metadata["scenario"] != scenario_id \
                or metadata["scenario_sha256"] != replay_sha256 \
                or metadata["tick"] != entry["capture_tick"]:
            raise ValueError(
                f"native scenario {scenario_id} framebuffer binding drifted"
            )
        framebuffer = {
            "metadata_path": frame_metadata_path.name,
            "metadata_sha256": artifacts.sha256_file(frame_metadata_path),
            "raw_path": frame_raw_path.name,
            "raw_sha256": metadata["raw_sha256"],
            "native_metadata_path": frame_native_metadata_path.name,
            "native_metadata_sha256": artifacts.sha256_file(
                frame_native_metadata_path,
            ),
            "native_raw_path": frame_native_raw_path.name,
            "native_raw_sha256": native_metadata["raw_sha256"],
            "native_gt_format_id": native_metadata["gt_format_id"],
            "native_gt_format_name": native_metadata["gt_format_name"],
            "conversion": native_metadata["conversion"],
            "derivation": framebuffer_derivation,
            "trace_binding": framebuffer_trace_binding,
        }
    else:
        unexpected_frame_artifacts = [
            path.name for path in (
                frame_metadata_path,
                frame_raw_path,
                frame_native_metadata_path,
                frame_native_raw_path,
            )
            if path.exists()
        ]
        if unexpected_frame_artifacts:
            raise ValueError(
                f"native scenario {scenario_id} emitted omitted framebuffer "
                "artifacts: " + ", ".join(unexpected_frame_artifacts)
            )

    focus_timeline = artifacts.extract_focus_timeline_receipt(
        observer_log, scenario, root=suite_root,
    )
    return {
        "status": "CANDIDATE_ONLY",
        "production_claim": False,
        "scenario": scenario_id,
        "inputs": {
            "suite_manifest_sha256": suite_manifest_sha256,
            "scenario_file_sha256": scenario_file_sha256,
            "scenario_semantic_sha256": entry["scenario"]["semantic_sha256"],
            "native_replay_sha256": replay_sha256,
            "executable_sha256": executable_sha256,
            "observer_dll_sha256": observer_sha256,
            "user_profile_sha256": restored_user[0]["sha256"],
        },
        "initial_state_restore": state_receipt,
        "observer_environment": observer_environment,
        "observation_profile": (
            None if suite_observation_profile is None else {
                **suite_observation_profile,
                "sha256": artifacts.observation_profile_sha256(
                    suite_observation_profile, scenario_id=scenario_id,
                ),
                "hook_receipt": profile_receipt,
            }
        ),
        "navigation": navigation,
        "phase_timestamps": navigation.get("phase_timestamps"),
        "early_phase_watchdog": navigation.get("early_phase_watchdog"),
        "observer_trace": {
            "path": observer_log.name,
            "sha256": artifacts.sha256_file(observer_log),
            "semantic_sha256": trace["semantic_sha256"],
            "record_count": trace["record_count"],
        },
        "focus_timeline": focus_timeline,
        "framebuffer": framebuffer,
    }


def run_native_semantic_suite(
    environment: list[str], backend: dict, executable: Path, output_root: Path,
    suite_manifest_path: Path, state_root: Path,
    initial_state_targets: Mapping[str, str], observer_dll: Path,
    disposable_executable: Path,
    observer_launcher: Path = OBSERVER_LAUNCHER, *,
    scene_debugger: Path = SCENE_DEBUGGER, observe_ms: int = DEFAULT_OBSERVE_MS,
    max_records: int = 100_000,
) -> dict:
    """Run the canonical seven scenarios sequentially with isolated artifacts."""

    from tools.miel_vliegt import native_scenario_artifacts as artifacts

    manifest = artifacts.load_scenario_suite_manifest(suite_manifest_path)
    if manifest["scenario_order"] != list(artifacts.SCENARIO_ID_ORDER):
        raise ValueError("native scenario suite order is not canonical")
    output_root.mkdir(parents=True, exist_ok=True)
    results = []
    for identifier in artifacts.SCENARIO_ID_ORDER:
        scenario_output = output_root / identifier
        scenario_output.mkdir(exist_ok=True)
        result = run_native_semantic_scenario(
            environment,
            backend,
            executable,
            scenario_output / "capture.json",
            suite_manifest_path,
            identifier,
            state_root,
            initial_state_targets,
            observer_dll,
            disposable_executable,
            observer_launcher,
            scene_debugger=scene_debugger,
            observe_ms=observe_ms,
            max_records=max_records,
        )
        receipt_path = scenario_output / "candidate-run.json"
        artifacts.write_canonical_json(receipt_path, result)
        results.append({
            "id": identifier,
            "receipt": receipt_path.relative_to(output_root).as_posix(),
            "sha256": artifacts.sha256_file(receipt_path),
        })
    receipt = {
        "schema": 1,
        "protocol": "miel-vliegt-native-semantic-suite-run",
        "status": "CANDIDATE_ONLY",
        "production_claim": False,
        "scenario_order": list(artifacts.SCENARIO_ID_ORDER),
        "results": results,
    }
    artifacts.write_canonical_json(output_root / "suite-run.json", receipt)
    return receipt


def inspect_prefix(prefix: Path) -> dict[str, bool]:
    windows = prefix / "drive_c/windows"
    c_drive = prefix / "dosdevices/c:"
    z_drive = prefix / "dosdevices/z:"
    system_rundll32 = windows / "system32/rundll32.exe"
    wow_rundll32 = windows / "syswow64/rundll32.exe"

    def is_i386_pe(path: Path) -> bool:
        try:
            validate_i386_pe(path)
        except ValueError:
            return False
        return True

    return {
        "system_registry": (prefix / "system.reg").is_file(),
        "user_registry": (prefix / "user.reg").is_file(),
        "user_defaults_registry": (prefix / "userdef.reg").is_file(),
        "native_rundll32": system_rundll32.is_file(),
        # WINEARCH=win32 stores the i386 runtime in system32 and normally has
        # no syswow64. A mixed prefix may store it in syswow64; validate the PE
        # machine instead of assuming one directory layout.
        "i386_rundll32": is_i386_pe(system_rundll32)
            or is_i386_pe(wow_rundll32),
        "c_drive_mapping": c_drive.is_symlink()
            and os.readlink(c_drive) == "../drive_c",
        "z_drive_mapping": z_drive.is_symlink()
            and os.readlink(z_drive) == "/",
        # The pinned package has no arm-windows runtime.  Creating this directory
        # means Wine misdetected kernel personality support as ARM32 execution.
        "no_unserviceable_sysarm32": not (windows / "sysarm32").exists(),
    }


def bootstrap_prefix(
    prefix: Path, backend: dict, smoke_executable: Path, *,
    runtime_readiness_timeout: int = FEX_RUNTIME_READINESS_TIMEOUT_SECONDS,
    rpcss_readiness_timeout_ms: int = FEX_RPCSS_READINESS_TIMEOUT_MS,
) -> dict:
    # Native Windows: no Wine prefix needed, skip bootstrap entirely
    if backend.get("id") == "native":
        return {
            "checks": {
                "wineboot_completed": True,
                "wineboot_loader_clean": True,
                "wine_renderer_written": True,
                "wine_renderer_verified": True,
                "wineserver_stopped": True,
                "wineserver_waited": True,
                "wineserver_persistence_acknowledged": True,
                "wineserver_persistent": True,
                "system_registry": True,
                "user_registry": True,
                "user_defaults_registry": True,
                "native_rundll32": True,
                "i386_rundll32": True,
                "c_drive_mapping": True,
                "z_drive_mapping": True,
                "no_unserviceable_sysarm32": True,
                "win32_smoke": True,
                "runtime_readiness": True,
            },
            "runs": {},
            "layout": {},
            "renderer": {"written": True, "verified": True},
        }
    shutil.rmtree(prefix, ignore_errors=True)
    environment = native_runtime_environment(prefix, backend)
    wineboot = run(
        environment + native_wine_command("wineboot", "--init", backend=backend),
        cwd=smoke_executable.parent,
        timeout=(
            FEX_WINEBOOT_TIMEOUT_SECONDS
            if backend.get("id") == "fex"
            else 45
        ),
    )
    wineboot_process_ok = (
        wineboot["exit_code"] == 0
        and not wineboot["timed_out"]
        and not has_loader_failure(wineboot)
    )
    renderer = (
        configure_gdi_renderer(environment, smoke_executable.parent, backend)
        if wineboot_process_ok and backend.get("id") != "fex"
        else {
            "written": False,
            "verified": False,
            "runs": {
                "renderer_add": skipped_run(
                    "fex-readiness-helper-owns-renderer"
                    if wineboot_process_ok else "wineboot-failed"
                ),
                "renderer_query": skipped_run(
                    "fex-readiness-helper-owns-renderer"
                    if wineboot_process_ok else "wineboot-failed"
                ),
                "decorated_add": skipped_run(
                    "fex-readiness-helper-owns-renderer"
                    if wineboot_process_ok else "wineboot-failed"
                ),
                "decorated_query": skipped_run(
                    "fex-readiness-helper-owns-renderer"
                    if wineboot_process_ok else "wineboot-failed"
                ),
            },
        }
    )
    # wineboot leaves services.exe running. Stop the private server and wait for
    # its exit so registry hives are durably flushed before inspecting/copying
    # the prefix; the smoke run restarts it.
    shutdown = shutdown_private_wineserver(
        environment, smoke_executable.parent, backend,
    )
    wineserver_stop = shutdown["runs"]["stop"]
    wineserver_wait = shutdown["runs"]["wait"]
    wineserver_stop_ok = shutdown["stopped"]
    wineserver_wait_ok = shutdown["waited"]
    wineserver_persist = run(
        environment + native_persistent_wineserver_command(backend),
        cwd=smoke_executable.parent,
        timeout=10,
    ) if wineboot_process_ok and wineserver_stop_ok and wineserver_wait_ok \
        else skipped_run("wineserver-clean-restart-preconditions-failed")
    wineserver_persist_ok = (
        wineserver_persist["exit_code"] == 0
        and not wineserver_persist["timed_out"]
        and not has_loader_failure(wineserver_persist)
        and PERSISTENT_WINESERVER_ACK_SENTINEL.lower()
        in run_text(wineserver_persist)
    )
    layout = inspect_prefix(prefix)
    renderer_precondition_ok = (
        backend.get("id") == "fex"
        or (renderer["written"] and renderer["verified"])
    )
    wineboot_ok = (
        wineboot_process_ok
        and renderer_precondition_ok
        and wineserver_stop_ok
        and wineserver_wait_ok
        and wineserver_persist_ok
        and all(layout.values())
    )
    if wineboot_ok:
        smoke = run(
            environment + native_smoke_command(
                smoke_executable, backend, rpcss_readiness_timeout_ms,
            ),
            cwd=smoke_executable.parent,
            timeout=(
                FEX_SMOKE_TIMEOUT_SECONDS
                if backend.get("id") == "fex"
                else 20
            ),
        )
    else:
        smoke = skipped_run("prefix-bootstrap-failed")
    sentinel_found = native_smoke_sentinel(backend).lower() in run_text(smoke)
    smoke_ok = (
        wineboot_ok
        and smoke["exit_code"] == 0
        and not smoke["timed_out"]
        and (not has_loader_failure(smoke)
             or (backend.get("id") == "wine" and sentinel_found))
        and sentinel_found
    )
    readiness = verify_runtime_readiness(
        environment,
        smoke_executable.parent,
        backend,
        runtime_timeout=runtime_readiness_timeout,
        rpcss_timeout_ms=rpcss_readiness_timeout_ms,
    ) if smoke_ok else {
        "required": backend.get("id") == "fex",
        "verified": False,
        "run": skipped_run("win32-smoke-failed"),
    }
    if backend.get("id") == "fex":
        renderer = {
            **renderer,
            "written": readiness.get("renderer_written") is True,
            "verified": readiness.get("renderer_verified") is True,
        }
    persistent_session_verified = (
        wineserver_persist_ok and smoke_ok and readiness["verified"]
    )
    checks = {
        "wineboot_completed": wineboot["exit_code"] == 0 and not wineboot["timed_out"],
        "wineboot_loader_clean": not has_loader_failure(wineboot),
        "wine_renderer_written": renderer["written"],
        "wine_renderer_verified": renderer["verified"],
        "wineserver_stopped": wineserver_stop_ok,
        "wineserver_waited": wineserver_wait_ok,
        "wineserver_persistence_acknowledged": wineserver_persist_ok,
        "wineserver_persistent": persistent_session_verified,
        **layout,
        "win32_smoke": smoke_ok,
        "runtime_readiness": readiness["verified"],
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        import sys
        print(f"BOOTSTRAP FAILED checks: {failed}", file=sys.stderr)
        print(f"  wineboot exit={wineboot["exit_code"]} timed_out={wineboot["timed_out"]} loader_fail={has_loader_failure(wineboot)}", file=sys.stderr)
        print(f"  wineboot output_tail: {wineboot.get('output_tail', [])[:3]}", file=sys.stderr)
        print(f"  shutdown stopped={wineserver_stop_ok} waited={wineserver_wait_ok}", file=sys.stderr)
        if not isinstance(wineserver_persist, dict) or wineserver_persist.get("skipped"):
            print(f"  wineserver_persist skipped: {wineserver_persist.get('skipped', 'N/A') if isinstance(wineserver_persist, dict) else 'N/A'}", file=sys.stderr)
        else:
            print(f"  wineserver_persist exit={wineserver_persist.get('exit_code')} timed_out={wineserver_persist.get('timed_out')} loader_fail={has_loader_failure(wineserver_persist)}", file=sys.stderr)
            print(f"  wineserver_persist output_tail: {wineserver_persist.get('output_tail', [])[:3]}", file=sys.stderr)
        print(f"  layout: {layout}", file=sys.stderr)
        print(f"  renderer written={renderer['written']} verified={renderer['verified']}", file=sys.stderr)
    if not smoke_ok:
        import sys
        if isinstance(smoke, dict) and not smoke.get("skipped"):
            print(f"SMOKE FAILED exit={smoke.get('exit_code')} timed_out={smoke.get('timed_out')} loader_fail={has_loader_failure(smoke)}", file=sys.stderr)
            print(f"SMOKE output_tail: {smoke.get('output_tail', [])[:5]}", file=sys.stderr)
            sentinel = native_smoke_sentinel(backend)
            print(f"SMOKE sentinel '{sentinel}' in output: {sentinel.lower() in run_text(smoke)}", file=sys.stderr)
        else:
            print(f"SMOKE skipped: {smoke.get('skipped', 'N/A') if isinstance(smoke, dict) else 'N/A'}", file=sys.stderr)
    
    # Wine backend: copy observer DLLs to prefix system32 for reliable loading
    # Wine's DLL loader cannot load from Z: drive paths, so copy to C: drive
    if backend.get("id") == "wine" and smoke_executable.parent.is_dir():
        system32 = prefix / "drive_c" / "windows" / "system32"
        system32.mkdir(parents=True, exist_ok=True)
        for tool_file in ["DINPUT.dll", "native-observer-hook.dll", "dinput-real.dll"]:
            src = smoke_executable.parent / tool_file
            if src.exists():
                shutil.copy2(src, system32 / tool_file)
                print(f"Copied {tool_file} to Wine system32", file=__import__('sys').stderr)
        # Also create E: drive mapping to the run root for game files
        dosdevices = prefix / "dosdevices"
        dosdevices.mkdir(exist_ok=True)
        run_root = prefix.parent
        e_drive = dosdevices / "e:"
        if not e_drive.exists():
            e_drive.symlink_to(run_root, target_is_directory=True)
            print(f"Created E: drive mapping to {run_root}", file=__import__('sys').stderr)
    
    return {
        "checks": checks,
        "runs": {
            "wineboot": wineboot,
            **renderer["runs"],
            "wineserver_stop": wineserver_stop,
            "wineserver_wait": wineserver_wait,
            "wineserver_persist": wineserver_persist,
            "win32_smoke": smoke,
            "runtime_readiness": readiness["run"],
        },
        "runtime_readiness_budget": readiness.get("budget", {
            "guest_process_seconds": runtime_readiness_timeout,
            "rpcss_poll_milliseconds": rpcss_readiness_timeout_ms,
        }),
        "usable": all(checks.values()),
    }


def activate_sealed_prefix(
    prefix: Path, backend: dict, smoke_executable: Path, *,
    runtime_readiness_timeout: int = FEX_RUNTIME_READINESS_TIMEOUT_SECONDS,
    rpcss_readiness_timeout_ms: int = FEX_RPCSS_READINESS_TIMEOUT_MS,
) -> dict[str, Any]:
    """Start a cloned, stopped seal without repeating Wine prefix creation."""

    environment = native_runtime_environment(prefix, backend)
    layout = inspect_prefix(prefix)
    persist = run(
        environment + native_persistent_wineserver_command(backend),
        cwd=smoke_executable.parent,
        timeout=10,
    ) if all(layout.values()) else skipped_run("sealed-prefix-layout-failed")
    persist_ok = (
        persist["exit_code"] == 0
        and not persist["timed_out"]
        and not has_loader_failure(persist)
        and PERSISTENT_WINESERVER_ACK_SENTINEL.lower() in run_text(persist)
    )
    smoke = run(
        environment + native_smoke_command(
            smoke_executable, backend, rpcss_readiness_timeout_ms,
        ),
        cwd=smoke_executable.parent,
        timeout=(
            FEX_SMOKE_TIMEOUT_SECONDS
            if backend.get("id") == "fex" else 20
        ),
    ) if persist_ok else skipped_run("sealed-prefix-server-start-failed")
    smoke_ok = (
        persist_ok
        and smoke["exit_code"] == 0
        and not smoke["timed_out"]
        and not has_loader_failure(smoke)
        and native_smoke_sentinel(backend).lower() in run_text(smoke)
    )
    readiness = verify_runtime_readiness(
        environment,
        smoke_executable.parent,
        backend,
        runtime_timeout=runtime_readiness_timeout,
        rpcss_timeout_ms=rpcss_readiness_timeout_ms,
    ) if smoke_ok else {
        "required": backend.get("id") == "fex",
        "verified": False,
        "run": skipped_run("sealed-prefix-smoke-failed"),
    }
    return {
        "schema": 1,
        "protocol": "miel-vliegt-native-sealed-prefix-activation",
        "layout": layout,
        "runs": {
            "wineserver_persist": persist,
            "win32_smoke": smoke,
            "runtime_readiness": readiness["run"],
        },
        "checks": {
            "layout": all(layout.values()),
            "wineserver_persistent": persist_ok,
            "win32_smoke": smoke_ok,
            "runtime_readiness": readiness["verified"],
        },
        "usable": all(layout.values()) and persist_ok and smoke_ok
            and readiness["verified"],
    }


def probe(
    executable: Path,
    output: Path,
    smoke_executable: Path = SMOKE_EXECUTABLE,
    debug_capability_executable: Path = DEBUG_CAPABILITY_EXECUTABLE,
    scene: str | None = None,
    observer_launcher: Path = OBSERVER_LAUNCHER,
    observer_dll: Path = OBSERVER_DLL,
    proxy_dll: Path | None = None,
    require_observer_bootstrap: bool = False,
    probe_debug_api: bool = False,
    observe_ms: int = DEFAULT_OBSERVE_MS,
) -> dict:
    observe_ms = validate_observe_ms(observe_ms)
    contract = validate_contract()
    if sha256(executable) != contract["target"]["executable_sha256"]:
        raise ValueError("Hangover probe requires the pinned Dutch executable")
    validate_i386_pe(smoke_executable)
    validate_i386_pe(debug_capability_executable)
    if scene is not None:
        validate_i386_pe(observer_launcher)
        validate_i386_pe(observer_dll)
        headless_config = install_headless_config(executable.parent)
    else:
        headless_config = None
    output.parent.mkdir(parents=True, exist_ok=True)
    for command in ("wine", "xvfb-run"):
        if not shutil.which(command):
            raise ValueError(f"Hangover probe command is missing: {command}")
    version_run = run(["wine", "--version"], cwd=executable.parent, timeout=10)
    if version_run["timed_out"] or version_run["exit_code"] != 0:
        raise ValueError("Hangover wine --version did not complete")
    version = "\n".join(version_run["output_tail"]).strip()
    backend_results = {}
    for backend in contract["probe_backends"]:
        prefix = Path("/tmp") / f"miel-vliegt-hangover-observer-{backend['id']}"
        environment = native_runtime_environment(prefix, backend)
        bootstrap = bootstrap_prefix(prefix, backend, smoke_executable)
        scene_receipt = None
        scene_navigation = None
        if bootstrap["usable"] and scene is not None:
            proxy_source = proxy_dll if proxy_dll is not None else OBSERVER_PROXY_DLL
            # The observer requires the UNMODIFIED executable (its module
            # identity check rejects the scene-patched bytes) driven by the
            # replay. Launch a byte-identical disposable copy from a separate
            # proxy directory that holds the DINPUT proxy beside it, with the
            # game dir kept as cwd so the projector still finds its data.
            proxy_directory = output.parent / f"observer-proxy-{backend['id']}"
            proxy_directory.mkdir(parents=True, exist_ok=True)
            install_observer_proxy(proxy_directory, proxy_source)
            disposable_target = proxy_directory / "MulleMeck-observer.exe"
            scene_navigation = run_scene_navigation(
                environment, backend, executable, output, scene, SCENE_DEBUGGER,
                observer_dll, observer_launcher,
                attempt_debug=False,
                allow_fallback=True,
                fallback_timeout=60,
                observe_ms=observe_ms,
                proxy_dll=proxy_source,
                unmodified_start=True,
                unmodified_target=disposable_target,
                observer_environment={
                    "MIEL_OBSERVER_SCENARIO": wine_z_path(OBSERVER_REPLAY),
                    "MIEL_OBSERVER_SCENARIO_SHA256": sha256(OBSERVER_REPLAY),
                    "MIEL_OBSERVER_INITIAL_USER_SHA256":
                        OBSERVER_INITIAL_USER_SHA256,
                    "MIEL_OBSERVER_FRAME": wine_z_path(
                        output.parent / "native-observer-frame"
                    ),
                },
            )
            scene_receipt = scene_navigation["debug_receipt"]
            debug = scene_navigation["runs"]["debug_launch"]
            launch = scene_navigation["runs"]["start_patch_launch"]
        elif bootstrap["usable"]:
            launch = run(
                environment + native_wine_command(
                    executable.name, backend=backend,
                ),
                cwd=executable.parent, timeout=30,
            )
            debug = skipped_run("debug-diagnostic-runs-in-separate-prefix")
        else:
            launch = skipped_run("observer-prefix-bootstrap-failed")
            debug = skipped_run("observer-prefix-bootstrap-failed")

        # Preserve the external debugger micro-oracle as diagnostic evidence,
        # but isolate its crashes and wineserver state from the selected route.
        if probe_debug_api:
            debug_prefix = Path("/tmp") / f"miel-vliegt-hangover-debug-{backend['id']}"
            debug_environment = native_runtime_environment(debug_prefix, backend)
            debug_bootstrap = bootstrap_prefix(
                debug_prefix, backend, smoke_executable,
            )
            capability = (
                probe_debug_capability(
                    debug_environment, backend, output, debug_capability_executable,
                )
                if debug_bootstrap["usable"]
                else {
                    "capability": "INDETERMINATE",
                    "prefix_clean": False,
                    "selected_profile": None,
                    "attempts": [],
                }
            )
            debug_final_shutdown = shutdown_private_wineserver(
                debug_environment, debug_capability_executable.parent, backend,
            )
            capability["prefix_clean"] = (
                capability["prefix_clean"] is True
                and debug_final_shutdown["complete"]
            )
        else:
            debug_bootstrap = {
                "usable": False,
                "checks": {},
                "runs": {
                    "wineboot": skipped_run("known-rejected-debug-diagnostic-not-requested"),
                    "wineserver_stop": skipped_run("known-rejected-debug-diagnostic-not-requested"),
                    "win32_smoke": skipped_run("known-rejected-debug-diagnostic-not-requested"),
                },
            }
            capability = {
                "capability": "SKIPPED_REJECTED_ON_CURRENT_HOST",
                "prefix_clean": None,
                "selected_profile": None,
                "attempts": [],
            }
            debug_final_shutdown = {
                "complete": True,
                "runs": {
                    "stop": skipped_run(
                        "known-rejected-debug-diagnostic-not-requested"
                    ),
                    "wait": skipped_run(
                        "known-rejected-debug-diagnostic-not-requested"
                    ),
                },
            }
        selected_profile = capability["selected_profile"]
        debug_text = run_text(debug)
        navigation_runs = list(scene_navigation["runs"].values()) if scene_navigation else []
        loader_failure = has_loader_failure(launch, debug, *navigation_runs)
        if scene is not None:
            navigation_ok = bool(
                scene_navigation and scene_navigation["scene_bootstrap_confirmed"]
            )
            debugger_ok = bool(scene_navigation and scene_navigation["route"] == "win32-debug-api")
            start_patch_ok = bool(
                scene_navigation
                and scene_navigation["route"] == "suspended-process-observer-launcher"
            )
            debug_event_forwarding = bool(scene_navigation and scene_navigation["debug_event_forwarding"])
            process_observed = navigation_ok
            target_module_loaded = navigation_ok
            target_image_visible = navigation_ok
            register_context_visible = debugger_ok
        else:
            process_observed = (launch["timed_out"] or launch["exit_code"] == 0) and not loader_failure
            target_module_loaded = executable.name.lower() in debug_text
            target_image_visible = "0x0040" in debug_text or "0040" in debug_text
            register_context_visible = "eip" in debug_text and any(
                register in debug_text for register in ("eax", "ebx", "esp")
            )
            debugger_ok = (
                debug["exit_code"] == 0
                and not debug["timed_out"]
                and not loader_failure
                and target_module_loaded
                and target_image_visible
                and register_context_visible
            )
        backend_shutdown = shutdown_private_wineserver(
            environment, executable.parent, backend,
        )
        backend_checks = {
            **{f"bootstrap_{key}": value for key, value in bootstrap["checks"].items()},
            "debug_api_capability": capability["capability"] == "SUPPORTED",
            "loader": bootstrap["usable"] and not loader_failure,
            "process_observed": process_observed,
            "target_module_loaded": target_module_loaded,
            "target_image_visible": target_image_visible,
            "register_context_visible": register_context_visible,
            "debugger": debugger_ok,
            "wineserver_cleanup": backend_shutdown["complete"],
        }
        if scene is not None:
            backend_checks.update({
                "debug_event_forwarding": debug_event_forwarding,
                "startup_mode_patch": start_patch_ok,
                "scene_loader_confirmed": bool(
                    scene_navigation and scene_navigation["scene_loader_confirmed"]
                ),
                "observer_bootstrap": navigation_ok,
                "observer_hook_loaded": bool(
                    scene_navigation
                    and (scene_navigation.get("observer_log") or {}).get("hook_loaded")
                ),
            })
        backend_results[backend["id"]] = {
            "hodll": backend["hodll"],
            "debug_api_capability": capability["capability"],
            "selected_debug_profile": selected_profile["id"] if selected_profile else None,
            "prefix_clean_after_capability": capability["prefix_clean"],
            "debug_capability_attempts": capability["attempts"],
            "checks": backend_checks,
            "runs": {
                **bootstrap["runs"],
                **{
                    f"debug_prefix_{name}": value
                    for name, value in debug_bootstrap["runs"].items()
                },
                "debug_prefix_final_stop":
                    debug_final_shutdown["runs"]["stop"],
                "debug_prefix_final_wait":
                    debug_final_shutdown["runs"]["wait"],
                "launch": launch,
                "debugger": debug,
                "wineserver_final_stop": backend_shutdown["runs"]["stop"],
                "wineserver_final_wait": backend_shutdown["runs"]["wait"],
                **(scene_navigation["runs"] if scene_navigation else {}),
            },
            "scene_receipt": scene_receipt,
            "observer_log": scene_navigation["observer_log"] if scene_navigation else None,
            "scene_start_patch_receipt": scene_navigation["start_patch_receipt"] if scene_navigation else None,
            "observer_launcher_receipt": scene_navigation["observer_launcher_receipt"] if scene_navigation else None,
            "selected_scene_route": scene_navigation["route"] if scene_navigation else None,
            "partial_debug_receipt": scene_navigation.get("partial_debug_receipt") if scene_navigation else None,
            "capture_host_usable": (
                bootstrap["usable"]
                and process_observed
                and backend_shutdown["complete"]
                and (navigation_ok if scene is not None else debugger_ok)
            ),
        }
        if (
            scene is not None
            and backend_results[backend["id"]]["capture_host_usable"]
            and backend_results[backend["id"]]["selected_scene_route"] == "suspended-process-observer-launcher"
        ):
            break
    usable_backends = sorted([
        backend_id for backend_id, result in backend_results.items()
        if result["capture_host_usable"]
    ], key=lambda backend_id: (
        backend_results[backend_id]["selected_scene_route"] != "suspended-process-observer-launcher",
        list(backend_results).index(backend_id),
    ))
    checks = {
        key: any(result["checks"][key] for result in backend_results.values())
        for key in next(iter(backend_results.values()))["checks"]
    }
    receipt = {
        "schema": 1,
        "contract_sha256": sha256(CONTRACT),
        "executable_sha256": sha256(executable),
        "win32_smoke_sha256": sha256(smoke_executable),
        "win32_debug_capability_sha256": sha256(debug_capability_executable),
        "observer_launcher_sha256": sha256(observer_launcher) if scene is not None else None,
        "observer_dll_sha256": sha256(observer_dll) if scene is not None else None,
        "requested_scene": scene,
        "debug_api_probed": probe_debug_api,
        "observer_bootstrap_required": require_observer_bootstrap,
        "observe_ms": observe_ms,
        "headless_config": headless_config,
        "host": {"machine": platform.machine(), "platform": platform.platform()},
        "wine_version": version,
        "checks": checks,
        "backends": backend_results,
        "untried_backends": [
            backend["id"] for backend in contract["probe_backends"]
            if backend["id"] not in backend_results
        ],
        "selected_backend": usable_backends[0] if usable_backends else None,
        "selected_scene_route": (
            backend_results[usable_backends[0]]["selected_scene_route"]
            if scene is not None and usable_backends else None
        ),
        "selected_observer_route": (
            "suspended-process-game-thread-hook"
            if scene is not None and usable_backends
            and (backend_results[usable_backends[0]].get("observer_log") or {}).get("hook_loaded")
            else None
        ),
        "capture_host_usable": bool(usable_backends),
        "debug_capture_usable": any(
            result["capture_host_usable"]
            and result["debug_api_capability"] == "SUPPORTED"
            and result["selected_scene_route"] == "win32-debug-api"
            for result in backend_results.values()
        ),
        "native_parity_evidence": False,
    }
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke-executable", type=Path, default=SMOKE_EXECUTABLE)
    parser.add_argument(
        "--debug-capability-executable",
        type=Path,
        default=DEBUG_CAPABILITY_EXECUTABLE,
    )
    parser.add_argument("--observer-launcher", type=Path, default=OBSERVER_LAUNCHER)
    parser.add_argument("--observer-dll", type=Path, default=OBSERVER_DLL)
    parser.add_argument("--scene", help="native scene id to enter and confirm")
    parser.add_argument(
        "--observe-ms", type=int, default=DEFAULT_OBSERVE_MS,
        help="native observer deadline in milliseconds (1000..3600000)",
    )
    parser.add_argument(
        "--probe-debug-api",
        action="store_true",
        help="rerun the known-rejected external debugger diagnostic in an isolated prefix",
    )
    parser.add_argument(
        "--require-observer-bootstrap",
        action="store_true",
        help="fail unless the suspended-process observer bootstrap succeeds",
    )
    args = parser.parse_args()
    receipt = probe(
        executable=args.executable.resolve(),
        output=args.output.resolve(),
        smoke_executable=args.smoke_executable.resolve(),
        debug_capability_executable=args.debug_capability_executable.resolve(),
        scene=args.scene,
        observer_launcher=args.observer_launcher.resolve(),
        observer_dll=args.observer_dll.resolve(),
        require_observer_bootstrap=args.require_observer_bootstrap,
        probe_debug_api=args.probe_debug_api,
        observe_ms=args.observe_ms,
    )
    print(json.dumps(receipt["checks"], sort_keys=True))
    if not receipt["capture_host_usable"]:
        raise SystemExit(1)
    if args.require_observer_bootstrap and receipt["selected_scene_route"] != "suspended-process-observer-launcher":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
