#!/usr/bin/env python3
"""Capture the pinned original flight game through Wine on macOS.

The runner never creates substitute native output. A preflight receipt records
source/tool provenance and explicit blockers. Capture artifacts are written
only after the original executable has actually launched and each artifact is
hashed immediately. Wine captures remain compatibility-host evidence until a
reviewer promotes a checkpoint in the existing pixel/audio/trace contracts.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from contextlib import contextmanager
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
IDENTITY_PATH = ROOT / "content/miel_vliegt/source_identity.json"
PROTOCOL = "miel-vliegt-wine-rendercapture"
VERSION = 1
CAPTURE_LOCK = Path(tempfile.gettempdir()) / "miel-vliegt-wine-rendercapture.lock"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ARCHIVES = ("data.up", "map.up", "sounds.up")
COMMON_WINE_PATHS = (
    str(Path.home() / "Applications/Wine Stable.app/Contents/Resources/wine/bin/wine64"),
    str(Path.home() / "Applications/Wine Stable.app/Contents/Resources/wine/bin/wine"),
    "/Applications/Wine Stable.app/Contents/Resources/wine/bin/wine64",
    "/Applications/Wine Stable.app/Contents/Resources/wine/bin/wine",
    "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine",
)
CAPTURE_HELPER_SOURCE = Path(__file__).with_name("win32_capture_window.c")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_identity(path: Path = IDENTITY_PATH) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != 1:
        raise ValueError("unsupported source identity")
    for key in ("iso", "executable", "launcher", "cc_dll", "udspack_dll"):
        item = value.get(key, {})
        if not SHA256.fullmatch(item.get("sha256", "")):
            raise ValueError(f"source identity has no pinned {key} hash")
    return value


def _run(
    command: list[str], cwd: Path | None = None, timeout: float = 60,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        command, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=env, start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
        return {
            "command": command,
            "exit_code": process.returncode,
            "timed_out": False,
            "duration_seconds": round(time.monotonic() - started, 6),
            "output": output,
        }
    except subprocess.TimeoutExpired:
        partial_output = ""
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                process.terminate()
            except (ProcessLookupError, PermissionError):
                pass
        try:
            output, _ = process.communicate(timeout=2)
            partial_output = output
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    process.kill()
                except (ProcessLookupError, PermissionError):
                    pass
            # A Wine child can inherit the stdout pipe after its Unix launcher
            # dies. Do not block on communicate() a third time: prefix-scoped
            # wineserver cleanup in capture() owns those descendants.
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            if process.stdout is not None:
                process.stdout.close()
            output = partial_output
        return {
            "command": command,
            "exit_code": None,
            "timed_out": True,
            "duration_seconds": round(time.monotonic() - started, 6),
            "output": output,
        }


def _tool(command: str) -> str | None:
    return shutil.which(command)


def discover_wine(explicit: str | None = None) -> Path | None:
    candidates = [explicit, os.environ.get("WINE"), _tool("wine64"), _tool("wine"), *COMMON_WINE_PATHS]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return Path(candidate).resolve()
    return None


def discover_media_root(iso: Path, explicit: Path | None = None) -> Path | None:
    candidates = [explicit, Path("/Volumes/Mielvliegt")]
    for candidate in candidates:
        if candidate and candidate.is_dir() and all((candidate / name).is_file() for name in ARCHIVES):
            return candidate.resolve()
    # Do not mount or copy hundreds of MB during inspection. Capture tells the
    # operator exactly how to mount the already hash-verified image.
    return None


def build_capture_helper(work_dir: Path) -> tuple[Path | None, dict[str, Any]]:
    work_dir.mkdir(parents=True, exist_ok=True)
    zig = _tool("zig")
    output = work_dir / "win32_capture_window.exe"
    provenance = {
        "source": str(CAPTURE_HELPER_SOURCE),
        "source_sha256": sha256_file(CAPTURE_HELPER_SOURCE),
        "compiler": zig,
        "compiler_version": None,
        "binary_sha256": None,
    }
    if not zig:
        return None, provenance
    version = _run([zig, "version"], timeout=10)
    provenance["compiler_version"] = version["output"].strip() if version["exit_code"] == 0 else None
    result = _run([
        zig, "cc", "-target", "x86-windows-gnu", "-O2", str(CAPTURE_HELPER_SOURCE),
        "-o", str(output), "-luser32", "-lgdi32",
    ], timeout=120)
    if result["exit_code"] != 0 or not output.is_file() or output.read_bytes()[:2] != b"MZ":
        provenance["build_output_tail"] = result["output"].splitlines()[-40:]
        return None, provenance
    _normalize_pe_timestamps(output)
    provenance["binary_sha256"] = sha256_file(output)
    return output, provenance


def _normalize_pe_timestamps(path: Path) -> None:
    """Zero linker timestamps so the reviewed helper rebuilds byte-identically."""
    data = bytearray(path.read_bytes())
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("capture helper has no PE signature")
    section_count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x10b:
        raise ValueError("capture helper is not PE32")
    struct.pack_into("<I", data, pe + 8, 0)
    debug_rva, debug_size = struct.unpack_from("<II", data, optional + 96 + 6 * 8)
    sections = optional + optional_size
    debug_offset = None
    for index in range(section_count):
        section = sections + index * 40
        name = bytes(data[section:section + 8]).rstrip(b"\0")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, section + 8)
        if name == b".buildid":
            data[raw_offset:raw_offset + raw_size] = b"\0" * raw_size
        if virtual_address <= debug_rva < virtual_address + max(virtual_size, raw_size):
            debug_offset = raw_offset + debug_rva - virtual_address
            break
    if debug_offset is not None:
        for offset in range(debug_offset, debug_offset + debug_size, 28):
            if offset + 8 <= len(data):
                struct.pack_into("<I", data, offset + 4, 0)
    path.write_bytes(data)


def extract_system_files(iso: Path, work_dir: Path, identity: dict[str, Any]) -> Path:
    """Extract only InstallShield system files, retaining no full ISO copy."""
    cached = work_dir / "installed/System_Files"
    executable = cached / identity["executable"]["filename"]
    if executable.is_file() and sha256_file(executable) == identity["executable"]["sha256"]:
        return cached
    seven_zip = _tool("7z") or _tool("7zz")
    unshield = _tool("unshield")
    if not seven_zip or not unshield:
        missing = [name for name, found in (("7z", seven_zip), ("unshield", unshield)) if not found]
        raise ValueError("source extraction tools missing: " + ", ".join(missing))
    cabinet = work_dir / "cabinet"
    installed = work_dir / "installed"
    shutil.rmtree(cabinet, ignore_errors=True)
    shutil.rmtree(installed, ignore_errors=True)
    cabinet.mkdir(parents=True)
    installed.mkdir(parents=True)
    result = _run([
        seven_zip, "x", "-y", f"-o{cabinet}", str(iso),
        "data1.cab", "data1.hdr", "data2.cab",
    ], timeout=120)
    if result["exit_code"] != 0:
        raise ValueError("7z could not extract the InstallShield cabinets")
    result = _run([unshield, "-g", "System Files", "x", str(cabinet / "data1.cab")], cwd=installed, timeout=120)
    if result["exit_code"] != 0:
        raise ValueError("unshield could not extract System Files")
    if not executable.is_file() or sha256_file(executable) != identity["executable"]["sha256"]:
        raise ValueError("extracted executable differs from pinned Dutch source")
    shutil.rmtree(cabinet, ignore_errors=True)
    return cached


def verify_source_files(system_root: Path, identity: dict[str, Any]) -> dict[str, Any]:
    mapping = {
        "executable": identity["executable"],
        "launcher": identity["launcher"],
        "cc_dll": identity["cc_dll"],
        "udspack_dll": identity["udspack_dll"],
    }
    result = {}
    for key, expected in mapping.items():
        path = system_root / expected["filename"]
        if not path.is_file():
            raise ValueError(f"extracted source file missing: {expected['filename']}")
        actual = sha256_file(path)
        if actual != expected["sha256"]:
            raise ValueError(f"extracted source hash drifted: {expected['filename']}")
        result[key] = {"filename": expected["filename"], "sha256": actual, "size": path.stat().st_size}
    return result


def list_avfoundation_devices(ffmpeg: Path | None) -> dict[str, list[dict[str, Any]]]:
    devices = {"video": [], "audio": []}
    if ffmpeg is None:
        return devices
    result = _run([str(ffmpeg), "-hide_banner", "-f", "avfoundation", "-list_devices", "true", "-i", ""], timeout=15)
    section = None
    for line in result["output"].splitlines():
        if "AVFoundation video devices" in line:
            section = "video"
        elif "AVFoundation audio devices" in line:
            section = "audio"
        else:
            match = re.search(r"\[(\d+)\]\s+(.+)$", line)
            if section and match:
                devices[section].append({"index": int(match.group(1)), "name": match.group(2).strip()})
    return devices


def select_loopback(devices: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    markers = ("blackhole", "soundflower", "loopback", "virtual audio")
    return next((item for item in devices["audio"] if any(marker in item["name"].lower() for marker in markers)), None)


def preflight(
    iso: Path, work_dir: Path, output: Path, *, wine: str | None = None,
    media_root: Path | None = None, system_root: Path | None = None,
) -> dict[str, Any]:
    identity = load_identity()
    iso = iso.resolve()
    if not iso.is_file() or sha256_file(iso) != identity["iso"]["sha256"]:
        raise ValueError("preflight requires the pinned Dutch Mielvliegt.iso")
    if system_root is None:
        system_root = extract_system_files(iso, work_dir, identity)
    else:
        system_root = system_root.resolve()
    source_files = verify_source_files(system_root, identity)
    media = discover_media_root(iso, media_root)
    wine_path = discover_wine(wine)
    ffmpeg_path = Path(_tool("ffmpeg")) if _tool("ffmpeg") else None
    ffprobe_path = Path(_tool("ffprobe")) if _tool("ffprobe") else None
    osascript_path = Path("/usr/bin/osascript") if Path("/usr/bin/osascript").is_file() else None
    capture_helper, capture_helper_provenance = build_capture_helper(work_dir)
    devices = list_avfoundation_devices(ffmpeg_path)
    loopback = select_loopback(devices)
    blockers = []
    limitations = []
    if wine_path is None:
        blockers.append({"code": "WINE_NOT_FOUND", "detail": "No executable Wine installation was found in PATH or standard macOS app locations."})
    if media is None:
        blockers.append({"code": "ISO_NOT_MOUNTED", "detail": "Mount the pinned ISO so data.up, map.up and sounds.up are available as a CD root."})
    if capture_helper is None:
        blockers.append({"code": "WIN32_CAPTURE_HELPER_BUILD_FAILED", "detail": "Zig could not build the tracked i386 Win32 BitBlt/WM_PRINTCLIENT helper."})
    if ffmpeg_path is None or ffprobe_path is None:
        limitations.append({"code": "FFMPEG_MISSING", "detail": "FFmpeg and ffprobe are required for lossless audio receipts."})
    if loopback is None:
        limitations.append({"code": "AUDIO_LOOPBACK_NOT_FOUND", "detail": "AVFoundation exposes no BlackHole/Soundflower/Loopback audio input; frame-only capture remains available."})
    wine_version = None
    if wine_path:
        try:
            _wineserver_for(wine_path)
        except ValueError as error:
            blockers.append({"code": "WINESERVER_NOT_FOUND", "detail": str(error)})
        version = _run([str(wine_path), "--version"], timeout=15)
        if version["exit_code"] != 0:
            blockers.append({"code": "WINE_VERSION_FAILED", "detail": "wine --version did not complete successfully."})
        else:
            wine_version = version["output"].strip()
    accessibility = None
    if osascript_path:
        result = _run([str(osascript_path), "-e", 'tell application "System Events" to get UI elements enabled'], timeout=10)
        accessibility = result["exit_code"] == 0 and result["output"].strip().lower() == "true"
        if not accessibility:
            limitations.append({"code": "ACCESSIBILITY_NOT_GRANTED", "detail": "System Events cannot inject deterministic keyboard input; no-input smoke captures can still run."})
    media_files = {}
    if media:
        media_files = {name: {"sha256": sha256_file(media / name), "size": (media / name).stat().st_size} for name in ARCHIVES}
    receipt = {
        "schema": 1,
        "protocol": PROTOCOL,
        "version": VERSION,
        "kind": "preflight",
        "status": "READY" if not blockers else "BLOCKED",
        "capture_host": {
            "kind": "wine-macos",
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "source": {
            "edition": identity["edition"],
            "iso": {"path": str(iso), "sha256": identity["iso"]["sha256"], "size": iso.stat().st_size},
            "system_files": source_files,
            "system_root": str(system_root),
            "media_root": str(media) if media else None,
            "media_files": media_files,
        },
        "tools": {
            "wine": {"path": str(wine_path) if wine_path else None, "version": wine_version, "sha256": sha256_file(wine_path) if wine_path else None},
            "ffmpeg": str(ffmpeg_path) if ffmpeg_path else None,
            "ffprobe": str(ffprobe_path) if ffprobe_path else None,
            "capture_helper": {"path": str(capture_helper) if capture_helper else None, **capture_helper_provenance},
            "osascript": str(osascript_path) if osascript_path else None,
            "avfoundation_devices": devices,
            "selected_loopback": loopback,
            "accessibility": accessibility,
        },
        "blockers": blockers,
        "limitations": limitations,
        "evidence_policy": {
            "executes_original_bytes": True,
            "native_windows_pixel_equivalence": False,
            "promotion_requires_review": True,
        },
        "parity_contracts": {
            "pixels": "content/miel_vliegt/ccf_render_checkpoints.json",
            "audio": "tools/parity/audio_parity.py",
            "runtime_trace": "tools/miel_vliegt/flight_trace_differential.py",
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def validate_scenario(value: Any) -> dict[str, Any]:
    required = {
        "schema", "id", "description", "target", "renderer",
        "duration_seconds", "window_rect", "frame_times_seconds", "inputs",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != 1:
        raise ValueError("invalid Wine capture scenario")
    if not isinstance(value["id"], str) or not value["id"]:
        raise ValueError("scenario id is required")
    if value["target"] not in {"launcher", "game"}:
        raise ValueError("scenario target must be launcher or game")
    if value["renderer"] not in {"default", "gdi"}:
        raise ValueError("scenario renderer must be default or gdi")
    if value["renderer"] == "gdi" and value["target"] != "launcher":
        raise ValueError("the GDI renderer is restricted to the 2D launcher; it is not valid 3D-game evidence")
    duration = value["duration_seconds"]
    if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not 0 < duration <= 300:
        raise ValueError("scenario duration_seconds must be in (0, 300]")
    rect = value["window_rect"]
    if not isinstance(rect, dict) or set(rect) != {"x", "y", "width", "height"} \
            or any(isinstance(rect[key], bool) or not isinstance(rect[key], int) for key in rect) \
            or rect["width"] <= 0 or rect["height"] <= 0:
        raise ValueError("scenario window_rect must contain integer x/y/width/height")
    times = value["frame_times_seconds"]
    if not isinstance(times, list) or not times or times != sorted(set(times)) \
            or any(isinstance(item, bool) or not isinstance(item, (int, float)) or item < 0 or item > duration for item in times):
        raise ValueError("frame_times_seconds must be unique, ordered and inside the scenario")
    if not isinstance(value["inputs"], list):
        raise ValueError("scenario inputs must be an array")
    previous = -1.0
    for event in value["inputs"]:
        if not isinstance(event, dict) or set(event) != {"at_seconds", "action", "key"} \
                or event["action"] not in {"key_down", "key_up", "key_press"} \
                or not isinstance(event["key"], str) or len(event["key"]) != 1 \
                or not isinstance(event["at_seconds"], (int, float)) or isinstance(event["at_seconds"], bool) \
                or event["at_seconds"] < previous or not 0 <= event["at_seconds"] <= duration:
            raise ValueError("scenario input events must be ordered single-key actions")
        previous = event["at_seconds"]
    return value


def _image_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[:26]
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        return struct.unpack(">II", data[16:24])
    if len(data) >= 26 and data[:2] == b"BM":
        width, height = struct.unpack_from("<ii", data, 18)
        return width, abs(height)
    raise ValueError(f"screen capture is not a supported lossless image: {path}")


def _canonicalize_bmp(path: Path, rgba_path: Path, png_path: Path) -> tuple[int, int, str]:
    data = path.read_bytes()
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("Win32 capture helper did not produce BMP")
    offset = struct.unpack_from("<I", data, 10)[0]
    width, signed_height = struct.unpack_from("<ii", data, 18)
    planes, bits = struct.unpack_from("<HH", data, 26)
    compression = struct.unpack_from("<I", data, 30)[0]
    height = abs(signed_height)
    if width != 640 or height != 480 or planes != 1 or bits != 32 or compression != 0:
        raise ValueError("Win32 capture is not canonical 640x480 BGRA32")
    source = data[offset:offset + width * height * 4]
    if len(source) != width * height * 4:
        raise ValueError("Win32 capture pixel payload is truncated")
    rows = [source[index * width * 4:(index + 1) * width * 4] for index in range(height)]
    if signed_height > 0:
        rows.reverse()
    rgba = bytearray(len(source))
    cursor = 0
    for row in rows:
        for index in range(0, len(row), 4):
            blue, green, red, _reserved = row[index:index + 4]
            rgba[cursor:cursor + 4] = bytes((red, green, blue, 255))
            cursor += 4
    if len(set(bytes(rgba[index:index + 4]) for index in range(0, len(rgba), 4))) < 2:
        raise ValueError("Win32 framebuffer is a flat colour, not render evidence")
    rgba_path.write_bytes(rgba)
    raw = b"".join(b"\x00" + rgba[row * width * 4:(row + 1) * width * 4] for row in range(height))
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff)
    png_path.write_bytes(
        b"\x89PNG\r\n\x1a\n" +
        chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)) +
        chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    )
    return width, height, sha256_file(rgba_path)


def _dispatch_key(osascript: str, event: dict[str, Any]) -> dict[str, Any]:
    action = event["action"]
    key = event["key"].replace('"', '\\"')
    statement = {
        "key_down": f'key down "{key}"',
        "key_up": f'key up "{key}"',
        "key_press": f'keystroke "{key}"',
    }[action]
    return _run([osascript, "-e", f'tell application "System Events" to {statement}'], timeout=5)


def _wine_z_path(path: Path) -> str:
    absolute = path.resolve()
    return "Z:" + str(absolute).replace("/", "\\")


def _terminate(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except PermissionError:
        try:
            process.terminate()
            process.wait(timeout=5)
        except (ProcessLookupError, PermissionError):
            return
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=5)
            except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
                return
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except PermissionError:
            try:
                process.kill()
            except (ProcessLookupError, PermissionError):
                return
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return


def _wineserver_for(wine: str | Path) -> Path:
    candidate = Path(wine).resolve().with_name("wineserver")
    if not candidate.is_file():
        raise ValueError(f"Wine installation has no sibling wineserver: {candidate}")
    return candidate


def _kill_wine_prefix(wine: str | Path, prefix: Path) -> None:
    """Stop only processes owned by this capture's private Wine prefix."""
    if not prefix.exists():
        return
    environment = {**os.environ, "WINEPREFIX": str(prefix)}
    server = _wineserver_for(wine)
    for action in ("-k", "-w"):
        try:
            subprocess.run(
                [str(server), action], env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            # Cleanup is retried by the next action/final filesystem cleanup;
            # never fall back to a machine-wide pkill.
            continue


@contextmanager
def _capture_lock(output_dir: Path):
    lock_path = Path(os.environ.get("MIEL_WINE_CAPTURE_LOCK", CAPTURE_LOCK))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            owner = os.read(descriptor, 4096).decode("utf-8", errors="replace").strip()
            raise ValueError(f"another Wine rendercapture is active: {owner or 'owner unknown'}") from error
        owner = canonical_json({"pid": os.getpid(), "output_dir": str(output_dir.resolve())}) + "\n"
        os.ftruncate(descriptor, 0)
        os.write(descriptor, owner.encode("utf-8"))
        os.fsync(descriptor)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _capture_unlocked(
    preflight_path: Path, scenario_path: Path, output_dir: Path,
    *, native_trace: Path | None = None, allow_missing_audio: bool = False,
) -> dict[str, Any]:
    preflight_receipt = json.loads(preflight_path.read_text(encoding="utf-8"))
    if preflight_receipt.get("protocol") != PROTOCOL or preflight_receipt.get("kind") != "preflight" \
            or preflight_receipt.get("status") != "READY":
        blockers = [item.get("code") for item in preflight_receipt.get("blockers", [])]
        raise ValueError("capture preflight is not READY: " + ", ".join(blockers))
    scenario = validate_scenario(json.loads(scenario_path.read_text(encoding="utf-8")))
    if scenario["inputs"] and not preflight_receipt.get("tools", {}).get("accessibility"):
        raise ValueError("scenario requires keyboard input but macOS Accessibility is not granted")
    output_dir.mkdir(parents=True, exist_ok=False)
    frames_dir = output_dir / "frames"
    frames_dir.mkdir()
    event_trace = output_dir / "capture-events.ndjson"
    launch_log = output_dir / "wine.log"
    audio_path = output_dir / "audio.wav"
    prefix = output_dir / "wine-prefix"
    wine = preflight_receipt["tools"]["wine"]["path"]
    osascript = preflight_receipt["tools"]["osascript"]
    capture_helper = preflight_receipt["tools"]["capture_helper"]["path"]
    ffmpeg = preflight_receipt["tools"]["ffmpeg"]
    loopback = preflight_receipt["tools"]["selected_loopback"]
    if (not ffmpeg or not loopback) and not allow_missing_audio:
        raise ValueError("lossless audio capture is unavailable; configure AVFoundation loopback or pass --allow-missing-audio")
    identity = load_identity()
    extracted = Path(preflight_receipt["source"]["system_root"])
    if not extracted.is_dir():
        raise ValueError("preflight System_Files directory is no longer present")
    verify_source_files(extracted, identity)
    media_root = Path(preflight_receipt["source"]["media_root"])
    runtime = output_dir / "game"
    shutil.copytree(extracted, runtime)
    for archive in ARCHIVES:
        (runtime / archive).symlink_to(media_root / archive)
    rect = scenario["window_rect"]
    environment = {
        **os.environ,
        "WINEPREFIX": str(prefix),
        "WINEDEBUG": "-all",
    }
    renderer_setup = None
    if scenario["renderer"] == "gdi":
        renderer_setup = _run([
            wine, "reg", "add", r"HKCU\Software\Wine\Direct3D",
            "/v", "renderer", "/t", "REG_SZ", "/d", "gdi", "/f",
        ], cwd=runtime, timeout=60, env=environment)
        if renderer_setup["exit_code"] != 0 or renderer_setup["timed_out"]:
            raise ValueError("Wine could not configure the reviewed launcher-only GDI renderer policy")
    target = identity["launcher"]["filename"] if scenario["target"] == "launcher" else identity["executable"]["filename"]
    command = [wine, "explorer", f"/desktop=MielVliegtCapture,{rect['width']}x{rect['height']}", target]
    events: list[dict[str, Any]] = []
    with launch_log.open("w", encoding="utf-8") as wine_log:
        process = subprocess.Popen(command, cwd=runtime, env=environment, stdout=wine_log, stderr=subprocess.STDOUT, start_new_session=True)
        audio = None
        ready_bmp = output_dir / "launch-ready.bmp"
        ready_deadline = time.monotonic() + 45
        ready_result = None
        while time.monotonic() < ready_deadline:
            if process.poll() is not None:
                raise ValueError(f"original executable exited before its render window became capturable: {process.returncode}")
            ready_result = _run([wine, capture_helper, "MielVliegtCapture", _wine_z_path(ready_bmp)], cwd=runtime, timeout=10, env=environment)
            if ready_result["exit_code"] == 0 and ready_bmp.is_file():
                try:
                    _canonicalize_bmp(ready_bmp, output_dir / "launch-ready.rgba", output_dir / "launch-ready.png")
                    break
                except ValueError:
                    pass
            time.sleep(0.25)
        else:
            tail = ready_result["output"].splitlines()[-10:] if ready_result else []
            raise ValueError("Wine render window was not capturable within 45 seconds: " + " | ".join(tail))
        for transient in (ready_bmp, output_dir / "launch-ready.rgba", output_dir / "launch-ready.png"):
            transient.unlink(missing_ok=True)
        if ffmpeg and loopback:
            audio = subprocess.Popen([
                ffmpeg, "-nostdin", "-y", "-f", "avfoundation", "-i", f":{loopback['index']}",
                "-t", str(scenario["duration_seconds"]), "-c:a", "pcm_s16le", str(audio_path),
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        started = time.monotonic()
        events.append({"record": "launch_ready", "sequence": 0, "observed_seconds": 0, "helper_output": ready_result["output"].strip()})
        pending_inputs = list(enumerate(scenario["inputs"]))
        pending_frames = list(enumerate(scenario["frame_times_seconds"]))
        try:
            while pending_inputs or pending_frames:
                elapsed = time.monotonic() - started
                if process.poll() is not None:
                    raise ValueError(f"original executable exited before capture completed: {process.returncode}")
                while pending_inputs and pending_inputs[0][1]["at_seconds"] <= elapsed:
                    index, event = pending_inputs.pop(0)
                    result = _dispatch_key(osascript, event)
                    events.append({"record": "input", "sequence": len(events), "index": index, "scheduled_seconds": event["at_seconds"], "observed_seconds": round(elapsed, 6), "event": event, "exit_code": result["exit_code"]})
                    if result["exit_code"] != 0:
                        raise ValueError(f"input injection failed at event {index}")
                while pending_frames and pending_frames[0][1] <= elapsed:
                    index, scheduled = pending_frames.pop(0)
                    frame_path = frames_dir / f"frame-{index:04d}.bmp"
                    rgba_path = frames_dir / f"frame-{index:04d}.rgba"
                    png_path = frames_dir / f"frame-{index:04d}.png"
                    result = _run([wine, capture_helper, "MielVliegtCapture", _wine_z_path(frame_path)], cwd=runtime, timeout=10, env=environment)
                    if result["exit_code"] != 0 or not frame_path.is_file():
                        raise ValueError(f"screen capture failed at frame {index}")
                    width, height, rgba_sha256 = _canonicalize_bmp(frame_path, rgba_path, png_path)
                    frame_path.unlink()
                    if (width, height) != (rect["width"], rect["height"]):
                        raise ValueError(f"captured frame dimensions drifted at frame {index}")
                    events.append({"record": "frame", "sequence": len(events), "index": index, "scheduled_seconds": scheduled, "time_microseconds": round(scheduled * 1_000_000), "observed_seconds": round(elapsed, 6), "rgba_sha256": rgba_sha256, "png_sha256": sha256_file(png_path), "width": width, "height": height})
                time.sleep(0.002)
            remaining = max(0.0, scenario["duration_seconds"] - (time.monotonic() - started))
            time.sleep(remaining)
        finally:
            _terminate(process)
            if audio is not None:
                _terminate(audio)
    event_trace.write_text("".join(canonical_json(event) + "\n" for event in events), encoding="utf-8")
    clock_transcript = output_dir / "clock-transcript.json"
    clock_value = {
        "schema": 1,
        "id": scenario["id"],
        "clock": "launch-ready-relative-monotonic",
        "frames": [{"frame": index, "time_microseconds": round(value * 1_000_000)} for index, value in enumerate(scenario["frame_times_seconds"])],
    }
    clock_transcript.write_text(json.dumps(clock_value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if audio is not None and (not audio_path.is_file() or audio_path.stat().st_size <= 44):
        raise ValueError("lossless loopback audio capture is absent or empty")
    artifacts = {
        "frames": [{
            "frame": index,
            "time_microseconds": round(scenario["frame_times_seconds"][index] * 1_000_000),
            "png": str(path.relative_to(output_dir)),
            "png_sha256": sha256_file(path),
            "rgba": str(path.with_suffix(".rgba").relative_to(output_dir)),
            "rgba_sha256": sha256_file(path.with_suffix(".rgba")),
            "rgba_size": path.with_suffix(".rgba").stat().st_size,
        } for index, path in enumerate(sorted(frames_dir.glob("*.png")))],
        "audio": {"path": audio_path.name, "sha256": sha256_file(audio_path), "size": audio_path.stat().st_size, "codec": "pcm_s16le"} if audio_path.is_file() else None,
        "capture_event_trace": {"path": event_trace.name, "sha256": sha256_file(event_trace), "records": len(events)},
        "clock_transcript": {"path": clock_transcript.name, "sha256": sha256_file(clock_transcript)},
        "native_state_trace": None,
        "wine_log": {"path": launch_log.name, "sha256": sha256_file(launch_log)},
        "capture_helper": preflight_receipt["tools"]["capture_helper"],
    }
    if native_trace is not None:
        if not native_trace.is_file():
            raise ValueError("configured native state trace is absent")
        destination = output_dir / "native-state-trace.ndjson"
        shutil.copy2(native_trace, destination)
        artifacts["native_state_trace"] = {"path": destination.name, "sha256": sha256_file(destination), "review_status": "UNREVIEWED"}
    receipt = {
        "schema": 1,
        "protocol": PROTOCOL,
        "version": VERSION,
        "kind": "capture",
        "status": "CAPTURED" if artifacts["audio"] else "PARTIAL_CAPTURE",
        "review_status": "UNREVIEWED",
        "preflight_sha256": sha256_file(preflight_path),
        "scenario": {"id": scenario["id"], "sha256": sha256_file(scenario_path)},
        "renderer_policy": {
            "requested": scenario["renderer"],
            "wine_registry": {
                "key": r"HKCU\Software\Wine\Direct3D",
                "value": "renderer",
                "data": "gdi",
            } if scenario["renderer"] == "gdi" else None,
            "scope": "launcher-only" if scenario["renderer"] == "gdi" else "default-wine-renderer",
            "setup_exit_code": renderer_setup["exit_code"] if renderer_setup else None,
            "native_windows_equivalence": False,
        },
        "source": preflight_receipt["source"],
        "capture_host": preflight_receipt["capture_host"],
        "capture_command": command,
        "artifacts": artifacts,
        "parity_import": {
            "pixels": "Map reviewed frame IDs into ccf_render_checkpoints.json; do not mark EQUIVALENT before camera trace parity.",
            "audio": "Compare captured PCM with the matching original/web playback window; absent audio remains an explicit blocker.",
            "trace": "Use flight_trace_differential.py only when native_state_trace is captured and reviewed.",
        },
    }
    candidate_manifest = {
        "schema": 1,
        "renderer_kind": "wine-original-executable-candidate",
        "review_status": "UNREVIEWED",
        "source": {
            "projector_sha256": identity["launcher"]["sha256"],
            "game_executable_sha256": identity["executable"]["sha256"],
            "director_intro_contract": "content/miel_vliegt/director_intro_render_oracle_contract.json",
            "flight_pixel_contract": "content/miel_vliegt/ccf_render_checkpoints.json",
        },
        "canonical_frame": {
            "width": 640, "height": 480, "pixel_format": "RGBA8888",
            "byte_order": "row-major-rgba", "origin": "top-left",
            "alpha": "straight", "colour_space": "srgb",
        },
        "renderer": {
            "surface": "original-executable-through-wine",
            "policy": scenario["renderer"],
            "capture_tool": "win32_capture_window.c",
            "capture_tool_sha256": preflight_receipt["tools"]["capture_helper"]["source_sha256"],
            "capture_binary_sha256": preflight_receipt["tools"]["capture_helper"]["binary_sha256"],
            "environment": preflight_receipt["tools"]["wine"]["version"],
        },
        "clock_transcript": artifacts["clock_transcript"],
        "frames": artifacts["frames"],
        "promotion_blockers": [
            "The captured checkpoint has not been mapped to a reviewed original scene/camera state.",
            "Wine is compatibility-host evidence, not reviewed native Windows DirectX equivalence.",
            "The Director intro contract requires an identical LibreShockwave clock transcript before comparison.",
        ],
    }
    candidate_path = output_dir / "native-oracle-candidate.json"
    candidate_path.write_text(json.dumps(candidate_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt["artifacts"]["native_oracle_candidate"] = {"path": candidate_path.name, "sha256": sha256_file(candidate_path)}
    receipt_path = output_dir / "capture-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    shutil.rmtree(prefix, ignore_errors=True)
    shutil.rmtree(runtime, ignore_errors=True)
    return receipt


def capture(
    preflight_path: Path, scenario_path: Path, output_dir: Path,
    *, native_trace: Path | None = None, allow_missing_audio: bool = False,
) -> dict[str, Any]:
    """Run one isolated capture and always reap its prefix-specific children."""
    wine = None
    prefix = output_dir / "wine-prefix"
    runtime = output_dir / "game"
    with _capture_lock(output_dir):
        try:
            if preflight_path.is_file():
                value = json.loads(preflight_path.read_text(encoding="utf-8"))
                wine = value.get("tools", {}).get("wine", {}).get("path")
            return _capture_unlocked(
                preflight_path, scenario_path, output_dir,
                native_trace=native_trace,
                allow_missing_audio=allow_missing_audio,
            )
        finally:
            try:
                if wine:
                    _kill_wine_prefix(wine, prefix)
            except (OSError, ValueError):
                # Preflight rejects Wine installations without wineserver.
                # Preserve the primary capture error if external files drift.
                pass
            finally:
                shutil.rmtree(prefix, ignore_errors=True)
                shutil.rmtree(runtime, ignore_errors=True)


def verify_receipt(path: Path) -> dict[str, Any]:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if receipt.get("schema") != 1 or receipt.get("protocol") != PROTOCOL or receipt.get("kind") != "capture" \
            or receipt.get("status") not in {"CAPTURED", "PARTIAL_CAPTURE"} or receipt.get("review_status") != "UNREVIEWED":
        raise ValueError("invalid Wine capture receipt")
    root = path.parent
    checked = 0
    artifacts = receipt.get("artifacts", {})
    records = []
    for frame in artifacts.get("frames", []):
        records.extend([
            {"path": frame["png"], "sha256": frame["png_sha256"]},
            {"path": frame["rgba"], "sha256": frame["rgba_sha256"]},
        ])
    for key in ("audio", "capture_event_trace", "clock_transcript", "native_state_trace", "wine_log", "native_oracle_candidate"):
        if artifacts.get(key):
            records.append(artifacts[key])
    for record in records:
        artifact = root / record["path"]
        if not artifact.is_file() or sha256_file(artifact) != record["sha256"]:
            raise ValueError(f"capture artifact missing or drifted: {record['path']}")
        checked += 1
    if not artifacts.get("frames") or not artifacts.get("capture_event_trace"):
        raise ValueError("capture receipt lacks frame or event-trace evidence")
    if receipt["status"] == "CAPTURED" and not artifacts.get("audio"):
        raise ValueError("complete capture receipt lacks audio")
    renderer = receipt.get("renderer_policy", {})
    if renderer.get("requested") not in {"default", "gdi"}:
        raise ValueError("capture receipt has no reviewed renderer policy")
    if renderer["requested"] == "gdi" and (
        renderer.get("scope") != "launcher-only"
        or renderer.get("wine_registry", {}).get("data") != "gdi"
    ):
        raise ValueError("capture receipt has an invalid launcher GDI policy")
    return {"artifacts": checked, "audio": artifacts.get("audio") is not None, "native_state_trace": artifacts.get("native_state_trace") is not None}


def write_capture_blocker(
    preflight_path: Path, scenario_path: Path, output_dir: Path, error: Exception,
) -> Path:
    """Persist an honest machine-readable failure without claiming render evidence."""
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    launch_log = output_dir / "wine.log"
    if launch_log.is_file():
        artifacts["wine_log"] = {
            "path": launch_log.name,
            "sha256": sha256_file(launch_log),
            "size": launch_log.stat().st_size,
        }
    value = {
        "schema": 1,
        "protocol": PROTOCOL,
        "version": VERSION,
        "kind": "capture_blocker",
        "status": "BLOCKED",
        "preflight_sha256": sha256_file(preflight_path) if preflight_path.is_file() else None,
        "scenario_sha256": sha256_file(scenario_path) if scenario_path.is_file() else None,
        "error": {"type": type(error).__name__, "detail": str(error)},
        "artifacts": artifacts,
        "evidence_policy": {
            "render_evidence_produced": False,
            "may_promote_to_parity_contract": False,
        },
    }
    path = output_dir / "capture-blocker.json"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect_parser = commands.add_parser("preflight")
    inspect_parser.add_argument("--iso", type=Path, required=True)
    inspect_parser.add_argument("--work-dir", type=Path, required=True)
    inspect_parser.add_argument("--output", type=Path, required=True)
    inspect_parser.add_argument("--wine")
    inspect_parser.add_argument("--media-root", type=Path)
    inspect_parser.add_argument("--system-root", type=Path)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--preflight", type=Path, required=True)
    capture_parser.add_argument("--scenario", type=Path, required=True)
    capture_parser.add_argument("--output-dir", type=Path, required=True)
    capture_parser.add_argument("--native-trace", type=Path)
    capture_parser.add_argument("--allow-missing-audio", action="store_true")
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            receipt = preflight(args.iso, args.work_dir, args.output, wine=args.wine, media_root=args.media_root, system_root=args.system_root)
            print(json.dumps({"status": receipt["status"], "blockers": [item["code"] for item in receipt["blockers"]]}, sort_keys=True))
            return 0 if receipt["status"] == "READY" else 1
        if args.command == "capture":
            receipt = capture(args.preflight, args.scenario, args.output_dir, native_trace=args.native_trace, allow_missing_audio=args.allow_missing_audio)
            print(json.dumps({"status": receipt["status"], "frames": len(receipt["artifacts"]["frames"])}, sort_keys=True))
            return 0
        print(json.dumps(verify_receipt(args.receipt), sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        if args.command == "capture":
            write_capture_blocker(args.preflight, args.scenario, args.output_dir, error)
        print(f"wine rendercapture failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
