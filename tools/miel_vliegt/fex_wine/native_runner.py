"""Fail-closed performance primitives for the ARM64 FEX/Wine native runner."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
try:
    import fcntl
except ImportError:
    fcntl = None
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Mapping


PROTOCOL = "miel-vliegt-fex-native-runner-performance"
VERSION = 1
DEFAULT_TMPFS_BYTES = 2 * 1024**3
DEFAULT_MAX_JOBS = 2
DEFAULT_NO_SWAP_HEADROOM_BYTES = 8 * 1024**3
SLOTS = ("A", "B")
STORE_PROTOCOL = "miel-vliegt-managed-sealed-prefix-store"
STORE_MARKER = ".miel-sealed-store.json"
STORE_RETENTION_LOCK = ".retention.lock"
IDENTITY_ACTIVITY = "activity.json"
DEFAULT_INACTIVE_IDENTITY_TTL_SECONDS = 30 * 24 * 60 * 60
_PRE_SCENARIO_RECORD_ORDER = ("loaded", "profile", "bootstrap")
_LOADED_KEYS = frozenset(("schema", "protocol", "status", "thread_id"))
_PROFILE_KEYS = frozenset((
    "schema", "protocol", "sequence", "profile", "profile_id",
    "profile_sha256", "contract_sha256", "omit_mask", "target_hook_mask",
    "omitted_channels", "retained_channels", "applicable_receipt_channels",
    "omitted_receipt_channels", "framebuffer_required", "evidence_eligible",
    "evidence_blocker", "signature_preflight_complete",
    "profile_state_writes", "thread_id",
))
_BOOTSTRAP_KEYS = frozenset((
    "schema", "protocol", "application", "controls", "dispatcher", "audio",
    "archive", "video", "presentation", "manager", "manager_alias",
    "current_mode", "current_is_login", "current_is_flight", "current_name",
    "current_is_mygghanget", "mygghanget_flight_start", "location_state",
    "location_manager_alias", "start_engine_faster_sample",
    "start_engine_throttle_f32_bits", "start_engine_timer_f32_bits",
    "start_engine_latched", "start_engine_audio_owner",
    "start_engine_audio_take", "start_engine_global_phase", "location_camera",
    "location_physics_alias", "location_shared_flight_alias", "flight_loaded",
    "flight_opened", "login_aliases", "user_id", "pending_mode",
    "native_preroll_state", "native_preroll_pending", "barn_view",
    "airplane_complete", "mode_count", "current_loaded", "current_opened",
    "manager_ticks",
))
_LAUNCHER_RECEIPT_KEYS = frozenset((
    "schema", "protocol", "status", "phase", "detail",
    "bootstrap_strategy", "input_idle_probe_timeout_ms",
    "proxy_bootstrap_timeout_ms", "scene",
    "original_executable_sha256", "patched_executable_sha256",
    "observer_dll_sha256", "real_dinput_sha256",
    "patch_receipt_sha256", "capture_process", "checks",
))
_LAUNCHER_CHECK_KEYS = frozenset((
    "created_suspended", "loader_initialization_completed",
    "proxy_observer_ready", "observer_loaded", "observer_initialized",
    "login_pending_observed", "ready_before_login_pending",
    "login_activation_observed", "ready_before_login_activation",
    "main_thread_resumed", "main_thread_resume_count",
    "message_loop_wake_posted", "projector_input_idle",
    "scenario_completion_event", "observer_failure_event_clear",
    "native_dispatch_requested", "native_dispatch_completion_event",
    "observation_window_completed", "target_terminated",
))
_LAUNCHER_IDENTITY_KEYS = frozenset((
    "original_executable_sha256", "patched_executable_sha256",
    "observer_dll_sha256", "real_dinput_sha256",
))
_PROXY_TIMEOUT_CHECKS = {
    "created_suspended": True,
    "loader_initialization_completed": True,
    "proxy_observer_ready": True,
    "observer_loaded": True,
    "observer_initialized": True,
    "login_pending_observed": False,
    "ready_before_login_pending": False,
    "login_activation_observed": False,
    "ready_before_login_activation": False,
    "main_thread_resumed": True,
    "main_thread_resume_count": 1,
    "message_loop_wake_posted": False,
    "projector_input_idle": False,
    "scenario_completion_event": False,
    "observer_failure_event_clear": False,
    "native_dispatch_requested": False,
    "native_dispatch_completion_event": False,
    "observation_window_completed": False,
    "target_terminated": True,
}
_SCENARIO_TIMEOUT_CHECKS = {
    **_PROXY_TIMEOUT_CHECKS,
    "login_pending_observed": True,
    "ready_before_login_pending": True,
    "login_activation_observed": True,
    "ready_before_login_activation": True,
    "message_loop_wake_posted": True,
    "projector_input_idle": True,
}
_RETRYABLE_TERMINAL_TIMEOUTS = {
    ("proxy", "proxy-bootstrap-timeout"):
        ("proxy-bootstrap-timeout", _PROXY_TIMEOUT_CHECKS),
    ("scenario", "scenario-completion-timeout"):
        ("scenario-completion-timeout", _SCENARIO_TIMEOUT_CHECKS),
}


class NativeRunnerError(ValueError):
    """The optimized runner cannot preserve the native evidence contract."""


@dataclass
class ManagedStoreLease:
    store: Path
    identity_sha256: str
    lock: BinaryIO
    ttl_seconds: int
    prune_receipt: Mapping[str, Any]
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        error: BaseException | None = None
        try:
            _write_identity_activity(
                self.store, self.identity_sha256, "inactive",
                inactive_since_unix_ns=time.time_ns(),
            )
        except BaseException as activity_error:
            error = activity_error
        try:
            fcntl.flock(self.lock.fileno(), fcntl.LOCK_UN)
        finally:
            self.lock.close()
            self.closed = True
        if error is not None:
            raise error


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    """Hash path, type, mode, link target, size and bytes deterministically."""

    if not root.is_dir() or root.is_symlink():
        raise NativeRunnerError(f"sealed prefix is not a real directory: {root}")
    digest = hashlib.sha256()
    root_information = root.lstat()
    digest.update(_canonical({
        "path": ".",
        "kind": "directory",
        "mode": f"{stat.S_IMODE(root_information.st_mode):04o}",
        "byte_length": 0,
    }))
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        information = path.lstat()
        mode = stat.S_IMODE(information.st_mode)
        if stat.S_ISLNK(information.st_mode):
            kind = "link"
            payload = os.readlink(path).encode("utf-8")
        elif stat.S_ISDIR(information.st_mode):
            kind = "directory"
            payload = b""
        elif stat.S_ISREG(information.st_mode):
            kind = "file"
            payload = path.read_bytes()
        else:
            raise NativeRunnerError(
                f"sealed prefix contains unsupported filesystem object: {relative}"
            )
        digest.update(_canonical({
            "path": relative,
            "kind": kind,
            "mode": f"{mode:04o}",
            "byte_length": len(payload),
        }))
        digest.update(payload)
    return digest.hexdigest()


def contract_identity(
    *,
    backend: Mapping[str, str],
    container_image: str,
    container_image_sha256: str,
    smoke_sha256: str,
    hodll_sha256: str,
    bootstrap_contract_sha256: str,
    startup_contract_sha256: str,
    expected_uid: int,
    expected_gid: int,
    fex_contract: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        identity = {
            "backend": {
                "id": backend["id"],
                "hodll": backend["hodll"],
            },
            "container": {
                "image": container_image,
                "sha256": container_image_sha256,
            },
            "wine": {
                "version": fex_contract["wine"]["version"],
                "snapshot": fex_contract["wine"]["snapshot"],
            },
            "fex": {
                "release": fex_contract["fex"]["release"],
                "package_version": fex_contract["fex"]["package_version"],
                "package_sha256": fex_contract["fex"]["package_sha256"],
                "rootfs_sha256": fex_contract["rootfs"]["sha256"],
            },
            "smoke_sha256": smoke_sha256,
            "hodll_sha256": hodll_sha256,
            "bootstrap_contract_sha256": bootstrap_contract_sha256,
            "startup_contract_sha256": startup_contract_sha256,
            "identity": {
                "uid": expected_uid,
                "gid": expected_gid,
            },
        }
    except (KeyError, TypeError) as error:
        raise NativeRunnerError("FEX runner identity contract is incomplete") from error
    for label, digest in (
        ("container image", container_image_sha256),
        ("smoke", smoke_sha256),
        ("HoDLL", hodll_sha256),
        ("bootstrap contract", bootstrap_contract_sha256),
        ("startup contract", startup_contract_sha256),
        ("FEX package", identity["fex"]["package_sha256"]),
        ("FEX rootfs", identity["fex"]["rootfs_sha256"]),
    ):
        if not isinstance(digest, str) or len(digest) != 64 \
                or any(character not in "0123456789abcdef" for character in digest):
            raise NativeRunnerError(f"{label} identity is not a lowercase SHA-256")
    if isinstance(expected_uid, bool) or not isinstance(expected_uid, int) \
            or expected_uid < 1 or isinstance(expected_gid, bool) \
            or not isinstance(expected_gid, int) or expected_gid < 0:
        raise NativeRunnerError("sealed prefix uid/gid identity is invalid")
    identity["sha256"] = hashlib.sha256(_canonical(identity)).hexdigest()
    return identity


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("wb") as output:
        output.write(_canonical(value))
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _managed_store_marker(expected_uid: int, expected_gid: int) -> dict[str, Any]:
    return {
        "schema": VERSION,
        "protocol": STORE_PROTOCOL,
        "owner_uid": expected_uid,
        "owner_gid": expected_gid,
        "identity_layout": "lowercase-sha256-directory",
        "activity_receipt": IDENTITY_ACTIVITY,
        "retention_lock": STORE_RETENTION_LOCK,
        "inactive_ttl_seconds": DEFAULT_INACTIVE_IDENTITY_TTL_SECONDS,
    }


def _initialize_managed_store(
    store: Path, expected_uid: int, expected_gid: int,
) -> dict[str, Any]:
    if store.exists() and (not store.is_dir() or store.is_symlink()):
        raise NativeRunnerError("sealed prefix store is not a real directory")
    store.mkdir(parents=True, mode=0o700, exist_ok=True)
    information = store.stat()
    if information.st_uid != expected_uid or information.st_gid != expected_gid:
        raise NativeRunnerError("sealed prefix store ownership drifted")
    if stat.S_IMODE(information.st_mode) != 0o700:
        raise NativeRunnerError("sealed prefix store must have mode 0700")
    marker_path = store / STORE_MARKER
    expected = _managed_store_marker(expected_uid, expected_gid)
    if marker_path.is_symlink():
        raise NativeRunnerError("sealed prefix store marker must not be a symlink")
    if not marker_path.exists():
        unmanaged = [
            path.name for path in store.iterdir()
            if path.name not in {STORE_RETENTION_LOCK}
        ]
        if unmanaged:
            raise NativeRunnerError(
                "refusing to adopt a non-empty unmanaged sealed prefix store"
            )
        _write_json_atomic(marker_path, expected)
    try:
        actual = json.loads(marker_path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeRunnerError("sealed prefix store marker is invalid") from error
    if actual != expected:
        raise NativeRunnerError("sealed prefix store marker drifted")
    return actual


def _write_identity_activity(
    store: Path, identity_sha256: str, state: str, *,
    inactive_since_unix_ns: int | None,
) -> dict[str, Any]:
    if len(identity_sha256) != 64 \
            or any(character not in "0123456789abcdef" for character in identity_sha256):
        raise NativeRunnerError("sealed store activity identity is invalid")
    if state not in {"active", "inactive"}:
        raise NativeRunnerError("sealed store activity state is invalid")
    identity_root = store / identity_sha256
    identity_root.mkdir(mode=0o700, exist_ok=True)
    information = identity_root.lstat()
    if not stat.S_ISDIR(information.st_mode) \
            or stat.S_ISLNK(information.st_mode) \
            or information.st_uid != store.stat().st_uid \
            or information.st_gid != store.stat().st_gid \
            or stat.S_IMODE(information.st_mode) != 0o700:
        raise NativeRunnerError("sealed store identity directory drifted")
    receipt = {
        "schema": VERSION,
        "protocol": STORE_PROTOCOL,
        "identity_sha256": identity_sha256,
        "state": state,
        "updated_unix_ns": time.time_ns(),
        "inactive_since_unix_ns": (
            inactive_since_unix_ns if state == "inactive" else None
        ),
    }
    _write_json_atomic(identity_root / IDENTITY_ACTIVITY, receipt)
    return receipt


def _prune_inactive_identities(
    store: Path, current_identity_sha256: str, ttl_seconds: int,
) -> dict[str, Any]:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) \
            or ttl_seconds < 24 * 60 * 60:
        raise NativeRunnerError("sealed store retention TTL must be at least one day")
    cutoff = time.time_ns() - ttl_seconds * 1_000_000_000
    removed: list[str] = []
    retained_unmanaged: list[str] = []
    for candidate in sorted(store.iterdir(), key=lambda path: path.name):
        name = candidate.name
        if name in {STORE_MARKER, STORE_RETENTION_LOCK} \
                or name == current_identity_sha256:
            continue
        if len(name) != 64 \
                or any(character not in "0123456789abcdef" for character in name) \
                or not candidate.is_dir() or candidate.is_symlink():
            retained_unmanaged.append(name)
            continue
        activity_path = candidate / IDENTITY_ACTIVITY
        try:
            activity = json.loads(activity_path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            retained_unmanaged.append(name)
            continue
        expected_keys = {
            "schema", "protocol", "identity_sha256", "state",
            "updated_unix_ns", "inactive_since_unix_ns",
        }
        inactive_since = activity.get("inactive_since_unix_ns")
        if set(activity) != expected_keys \
                or activity.get("schema") != VERSION \
                or activity.get("protocol") != STORE_PROTOCOL \
                or activity.get("identity_sha256") != name \
                or activity.get("state") != "inactive" \
                or isinstance(inactive_since, bool) \
                or not isinstance(inactive_since, int) \
                or inactive_since > cutoff:
            continue
        _remove_tree_force(candidate)
        removed.append(name)
    if removed:
        _fsync_directory(store)
    return {
        "ttl_seconds": ttl_seconds,
        "removed_identities": removed,
        "retained_unmanaged_entries": retained_unmanaged,
    }


def acquire_managed_store(
    store: Path, identity_sha256: str, *,
    expected_uid: int,
    expected_gid: int,
    ttl_seconds: int = DEFAULT_INACTIVE_IDENTITY_TTL_SECONDS,
) -> ManagedStoreLease:
    """Own a managed store and prevent retention while one suite uses it."""

    _initialize_managed_store(store, expected_uid, expected_gid)
    lock_path = store / STORE_RETENTION_LOCK
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    lock = os.fdopen(descriptor, "r+b", buffering=0)
    try:
        information = os.fstat(lock.fileno())
        if not stat.S_ISREG(information.st_mode) \
                or information.st_uid != expected_uid \
                or information.st_gid != expected_gid \
                or stat.S_IMODE(information.st_mode) != 0o600:
            raise NativeRunnerError("sealed store retention lock ownership drifted")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        prune_receipt = _prune_inactive_identities(
            store, identity_sha256, ttl_seconds,
        )
        _write_identity_activity(
            store, identity_sha256, "active", inactive_since_unix_ns=None,
        )
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        return ManagedStoreLease(
            store=store,
            identity_sha256=identity_sha256,
            lock=lock,
            ttl_seconds=ttl_seconds,
            prune_receipt=prune_receipt,
        )
    except BaseException:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        finally:
            lock.close()
        raise


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(mode & ~0o222)
    root.chmod(stat.S_IMODE(root.stat().st_mode) & ~0o222)


def _make_writable(root: Path) -> None:
    root.chmod(stat.S_IMODE(root.stat().st_mode) | 0o700)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(mode | (0o700 if path.is_dir() else 0o600))


def _remove_tree_force(root: Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    root.chmod(stat.S_IMODE(root.stat().st_mode) | 0o700)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(mode | (0o700 if path.is_dir() else 0o600))
    shutil.rmtree(root)


def seal_receipt_path(template: Path) -> Path:
    return template.parent / "seal.json"


def verify_seal(template: Path, expected_identity_sha256: str, slot: str) -> dict[str, Any]:
    receipt_path = seal_receipt_path(template)
    try:
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeRunnerError(f"sealed prefix {slot} has no valid receipt") from error
    required = {
        "schema", "protocol", "slot", "identity_sha256", "tree_sha256",
        "byte_count", "file_count", "created_monotonic_ns", "symlink_policy",
    }
    if set(receipt) != required \
            or receipt["schema"] != VERSION \
            or receipt["protocol"] != PROTOCOL \
            or receipt["slot"] != slot \
            or receipt["identity_sha256"] != expected_identity_sha256 \
            or receipt["symlink_policy"] != "preserve-link-never-follow":
        raise NativeRunnerError(f"sealed prefix {slot} identity drifted")
    actual = tree_sha256(template)
    if actual != receipt["tree_sha256"]:
        raise NativeRunnerError(f"sealed prefix {slot} content drifted")
    return receipt


def _tree_counts(root: Path) -> tuple[int, int]:
    files = 0
    bytes_total = 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            files += 1
            bytes_total += path.stat().st_size
    return files, bytes_total


def ensure_sealed_pair(
    store: Path,
    identity: Mapping[str, Any],
    bootstrap: Callable[[Path], Mapping[str, Any]],
) -> dict[str, Any]:
    """Build A/B independently once, or verify the existing content-addressed pair."""

    identity_sha256 = identity.get("sha256")
    if not isinstance(identity_sha256, str):
        raise NativeRunnerError("sealed prefix identity has no SHA-256")
    pair_root = store / identity_sha256
    pair_root.mkdir(parents=True, exist_ok=True)
    receipts: dict[str, Any] = {}
    for slot in SLOTS:
        template = pair_root / slot / "template"
        if template.exists():
            receipts[slot] = verify_seal(template, identity_sha256, slot)
            continue
        staging = pair_root / f".{slot}.building-{os.getpid()}"
        if staging.exists() or staging.is_symlink():
            raise NativeRunnerError(f"sealed prefix {slot} build staging already exists")
        staging.mkdir(parents=True)
        candidate = staging / "template"
        started = time.monotonic_ns()
        try:
            bootstrap_receipt = bootstrap(candidate)
            if bootstrap_receipt.get("usable") is not True:
                raise NativeRunnerError(f"sealed prefix {slot} bootstrap failed")
            if not candidate.is_dir() or candidate.is_symlink():
                raise NativeRunnerError(f"sealed prefix {slot} bootstrap made no prefix")
            _make_read_only(candidate)
            tree_digest = tree_sha256(candidate)
            file_count, byte_count = _tree_counts(candidate)
            receipt = {
                "schema": VERSION,
                "protocol": PROTOCOL,
                "slot": slot,
                "identity_sha256": identity_sha256,
                "tree_sha256": tree_digest,
                "byte_count": byte_count,
                "file_count": file_count,
                "created_monotonic_ns": started,
                "symlink_policy": "preserve-link-never-follow",
            }
            _write_json_atomic(staging / "seal.json", receipt)
            destination = pair_root / slot
            try:
                os.replace(staging, destination)
                _fsync_directory(pair_root)
            except OSError as error:
                if destination.exists():
                    _remove_tree_force(staging)
                    receipt = verify_seal(
                        destination / "template", identity_sha256, slot,
                    )
                else:
                    raise NativeRunnerError(
                        f"could not publish sealed prefix {slot}"
                    ) from error
        except BaseException:
            if staging.exists() and not staging.is_symlink():
                _remove_tree_force(staging)
            raise
        receipts[slot] = verify_seal(
            destination / "template", identity_sha256, slot,
        )
    return {
        "schema": VERSION,
        "protocol": PROTOCOL,
        "identity": dict(identity),
        "root": str(pair_root),
        "slots": receipts,
    }


def clone_sealed_prefix(
    pair_receipt: Mapping[str, Any], slot: str, destination: Path,
) -> dict[str, Any]:
    if slot not in SLOTS:
        raise NativeRunnerError(f"unknown sealed prefix slot: {slot}")
    pair_root = Path(str(pair_receipt["root"]))
    identity_sha256 = pair_receipt["identity"]["sha256"]
    template = pair_root / slot / "template"
    before = verify_seal(template, identity_sha256, slot)
    if destination.exists() or destination.is_symlink():
        raise NativeRunnerError(f"prefix clone destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.clone-{slot.lower()}-{os.getpid()}"
    )
    if temporary.exists() or temporary.is_symlink():
        raise NativeRunnerError(f"prefix clone staging already exists: {temporary}")
    started = time.monotonic_ns()
    try:
        shutil.copytree(
            template, temporary, symlinks=True, copy_function=shutil.copy2,
        )
        _make_writable(temporary)
        after = verify_seal(template, identity_sha256, slot)
        if before["tree_sha256"] != after["tree_sha256"]:
            raise NativeRunnerError(f"sealed prefix {slot} changed while cloning")
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            _remove_tree_force(temporary)
        raise
    return {
        "slot": slot,
        "identity_sha256": identity_sha256,
        "tree_sha256": before["tree_sha256"],
        "started_monotonic_ns": started,
        "completed_monotonic_ns": time.monotonic_ns(),
    }


def filesystem_type(path: Path) -> str:
    resolved = path.resolve()
    best: tuple[int, str] | None = None
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise NativeRunnerError("cannot inspect staging filesystem") from error
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        mountpoint = Path(fields[4].replace("\\040", " "))
        try:
            resolved.relative_to(mountpoint)
        except ValueError:
            continue
        candidate = (len(mountpoint.parts), fields[separator + 1])
        if best is None or candidate[0] > best[0]:
            best = candidate
    if best is None:
        raise NativeRunnerError("staging path has no mounted filesystem")
    return best[1]


def memory_status() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            label, raw = line.split(":", 1)
            number = int(raw.strip().split()[0]) * 1024
            values[label] = number
    except (OSError, ValueError, IndexError) as error:
        raise NativeRunnerError("cannot inspect host memory capacity") from error
    required = {"MemAvailable", "SwapTotal"}
    if not required <= values.keys():
        raise NativeRunnerError("host memory receipt is incomplete")
    return {key: values[key] for key in required}


def validate_tmpfs_staging(
    root: Path,
    *,
    bytes_per_job: int = DEFAULT_TMPFS_BYTES,
    max_jobs: int = DEFAULT_MAX_JOBS,
    headroom_bytes: int = DEFAULT_NO_SWAP_HEADROOM_BYTES,
) -> dict[str, Any]:
    if root.exists() and (not root.is_dir() or root.is_symlink()):
        raise NativeRunnerError("tmpfs staging root is not a real directory")
    root.mkdir(parents=True, exist_ok=True)
    if filesystem_type(root) != "tmpfs":
        raise NativeRunnerError("optimized native staging must be backed by tmpfs")
    if bytes_per_job < 1024**3 or bytes_per_job > 4 * 1024**3:
        raise NativeRunnerError("tmpfs bytes_per_job must be in 1..4 GiB")
    if max_jobs not in {1, 2}:
        raise NativeRunnerError("native tmpfs max_jobs must be one or two")
    memory = memory_status()
    if memory["SwapTotal"] != 0:
        raise NativeRunnerError("native tmpfs lane requires the reviewed no-swap host")
    required = bytes_per_job * max_jobs + headroom_bytes
    if memory["MemAvailable"] < required:
        raise NativeRunnerError(
            "native tmpfs lane would violate the no-swap memory headroom"
        )
    filesystem = os.statvfs(root)
    available = filesystem.f_bavail * filesystem.f_frsize
    capacity = filesystem.f_blocks * filesystem.f_frsize
    aggregate = bytes_per_job * max_jobs
    if available < aggregate:
        raise NativeRunnerError("tmpfs has insufficient capacity for bounded jobs")
    if capacity > aggregate:
        raise NativeRunnerError(
            "tmpfs staging mount exceeds the reviewed aggregate job bound"
        )
    return {
        "filesystem": "tmpfs",
        "root": str(root.resolve()),
        "bytes_per_job": bytes_per_job,
        "max_jobs": max_jobs,
        "aggregate_bytes": aggregate,
        "headroom_bytes": headroom_bytes,
        "mem_available_bytes": memory["MemAvailable"],
        "swap_total_bytes": memory["SwapTotal"],
        "filesystem_available_bytes": available,
        "filesystem_capacity_bytes": capacity,
    }


def atomic_copyout_tree(source: Path, destination: Path) -> dict[str, Any]:
    """Publish staged evidence without exposing a partial destination tree."""

    if not source.is_dir() or source.is_symlink():
        raise NativeRunnerError("evidence staging source is invalid")
    if destination.exists() or destination.is_symlink():
        raise NativeRunnerError("evidence destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.copyout-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise NativeRunnerError("evidence copyout staging already exists")
    try:
        shutil.copytree(source, temporary, symlinks=True, copy_function=shutil.copy2)
        source_sha256 = tree_sha256(source)
        copied_sha256 = tree_sha256(temporary)
        if source_sha256 != copied_sha256:
            raise NativeRunnerError("atomic evidence copyout changed staged bytes")
        for path in temporary.rglob("*"):
            if path.is_file() and not path.is_symlink():
                with path.open("rb") as handle:
                    os.fsync(handle.fileno())
        directories = [
            path for path in temporary.rglob("*")
            if path.is_dir() and not path.is_symlink()
        ]
        for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            _fsync_directory(path)
        _fsync_directory(temporary)
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary)
        raise
    return {
        "source_sha256": source_sha256,
        "destination_sha256": tree_sha256(destination),
        "destination": str(destination),
    }


def classify_pre_scenario_startup_hang(
    error: BaseException,
    attempt_root: Path,
    expected_launcher_identity: Mapping[str, str],
) -> dict[str, Any]:
    """Allow one retry only after a terminal launcher phase proves no dispatch."""

    log_paths = sorted(attempt_root.rglob("native-observer-*.log"))
    observer_record_count = 0
    pre_scenario_record_count = 0
    blocking_records: list[dict[str, Any]] = []
    for path in log_paths:
        expected_index = 0
        try:
            log_lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            observer_record_count += 1
            blocking_records.append({
                "path": path.name,
                "line": 0,
                "sha256": sha256_file(path),
            })
            continue
        for line_number, raw_line in enumerate(
            log_lines, start=1,
        ):
            line = raw_line.strip()
            if not line:
                continue
            observer_record_count += 1
            kind = _pre_scenario_observer_record_kind(line)
            if (
                kind is not None
                and expected_index < len(_PRE_SCENARIO_RECORD_ORDER)
                and kind == _PRE_SCENARIO_RECORD_ORDER[expected_index]
            ):
                pre_scenario_record_count += 1
                expected_index += 1
                continue
            # Unknown, malformed and newly introduced records fail closed.  A
            # retry is allowed only when every emitted record proves that the
            # game has not selected a mode, dispatched input or gained focus.
            blocking_records.append({
                "path": path.name,
                "line": line_number,
                "sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
            })
    semantic_started = bool(blocking_records)
    message = str(error).lower()
    startup_shape = any(fragment in message for fragment in (
        "did not bootstrap cleanly",
        "no loaded observer log",
        "timed out",
        "timeout",
        "observation window",
    ))
    launcher = _classify_launcher_terminal_phase(
        attempt_root, expected_launcher_identity,
    )
    inactive_bootstrap_sequence = bool(
        len(log_paths) == 1
        and observer_record_count == len(_PRE_SCENARIO_RECORD_ORDER)
        and pre_scenario_record_count == len(_PRE_SCENARIO_RECORD_ORDER)
        and not blocking_records
    )
    launcher_timeout_proven = bool(
        launcher["terminal_pre_scenario_timeout"]
        and (
            launcher["terminal_timeout_kind"] == "proxy-bootstrap-timeout"
            or inactive_bootstrap_sequence
        )
    )
    retryable = bool(
        startup_shape
        and not semantic_started
        and launcher_timeout_proven
    )
    if retryable:
        classification = "pre-scenario-startup-hang"
    elif startup_shape and not semantic_started and not launcher["receipts"]:
        classification = "host-deadline-before-launcher-receipt"
    else:
        classification = "non-retryable"
    return {
        "classification": classification,
        "retryable": retryable,
        "error_type": type(error).__name__,
        "error": str(error),
        "observer_logs": [path.name for path in log_paths],
        "semantic_or_focus_started": semantic_started,
        "observer_record_count": observer_record_count,
        "pre_scenario_record_count": pre_scenario_record_count,
        "inactive_bootstrap_sequence": inactive_bootstrap_sequence,
        "blocking_records": blocking_records,
        "launcher": launcher,
    }


def _classify_launcher_terminal_phase(
    attempt_root: Path,
    expected_identity: Mapping[str, str],
) -> dict[str, Any]:
    paths = sorted(attempt_root.rglob("native-observer-launch-*.json"))
    result = {
        "receipts": [path.name for path in paths],
        "terminal_pre_scenario_timeout": False,
        "terminal_timeout_kind": None,
        "blocking_reason": None,
    }
    if len(paths) != 1:
        result["blocking_reason"] = (
            "missing-launcher-receipt"
            if not paths else "ambiguous-launcher-receipts"
        )
        return result
    if (
        set(expected_identity) != _LAUNCHER_IDENTITY_KEYS
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in expected_identity.values()
        )
    ):
        result["blocking_reason"] = "invalid-expected-launcher-identity"
        return result
    start_receipts = sorted(
        attempt_root.rglob("native-unmodified-start-*.json")
    )
    if len(start_receipts) != 1:
        result["blocking_reason"] = (
            "missing-start-receipt"
            if not start_receipts else "ambiguous-start-receipts"
        )
        return result
    try:
        receipt = json.loads(paths[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        result["blocking_reason"] = "invalid-launcher-receipt"
        return result
    checks = receipt.get("checks") if isinstance(receipt, dict) else None
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _LAUNCHER_RECEIPT_KEYS
        or receipt.get("schema") != 1
        or receipt.get("protocol") != "miel-vliegt-native-observer-launch"
        or receipt.get("bootstrap_strategy") !=
            "dinput-post-loader-worker-or-call-bootstrap"
        or receipt.get("input_idle_probe_timeout_ms") != 0
        or receipt.get("proxy_bootstrap_timeout_ms") != 600_000
        or receipt.get("scene") != "flight"
        or any(
            receipt.get(key) != expected
            for key, expected in expected_identity.items()
        )
        or receipt.get("patch_receipt_sha256") !=
            sha256_file(start_receipts[0])
        or receipt.get("capture_process") is not None
        or not isinstance(checks, dict)
        or set(checks) != _LAUNCHER_CHECK_KEYS
        or not all(
            type(value) is bool
            for key, value in checks.items()
            if key != "main_thread_resume_count"
        )
        or type(checks.get("main_thread_resume_count")) is not int
    ):
        result["blocking_reason"] = "unproven-launcher-terminal-phase"
        return result
    timeout_shape = _RETRYABLE_TERMINAL_TIMEOUTS.get((
        receipt.get("phase"), receipt.get("detail"),
    ))
    if (
        receipt.get("status") != "FAIL"
        or timeout_shape is None
        or checks != timeout_shape[1]
    ):
        result["blocking_reason"] = "unproven-launcher-terminal-phase"
        return result
    result["terminal_pre_scenario_timeout"] = True
    result["terminal_timeout_kind"] = timeout_shape[0]
    return result


def _pre_scenario_observer_record_kind(line: str) -> str | None:
    """Recognize only records that positively prove runtime dispatch is absent."""

    try:
        prefix, encoded = line.split(" ", 1)
        record = json.loads(encoded)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict) or record.get("schema") != 1:
        return None
    protocol = record.get("protocol")
    if prefix == "MVO":
        return "loaded" if (
            set(record) == _LOADED_KEYS
            and protocol == "miel-vliegt-native-observer-hook"
            and record.get("status") == "LOADED"
            and type(record.get("thread_id")) is int
            and record["thread_id"] > 0
        ) else None
    if prefix != "MVD":
        return None
    if protocol == "miel-vliegt-native-observation-profile":
        return "profile" if (
            set(record) == _PROFILE_KEYS
            and type(record.get("sequence")) is int
            and record["sequence"] >= 0
            and type(record.get("thread_id")) is int
            and record["thread_id"] > 0
            and record.get("signature_preflight_complete") is True
            and record.get("profile_state_writes") is False
        ) else None
    if protocol != "miel-vliegt-native-bootstrap":
        return None
    false_fields = (
        "application", "controls", "dispatcher", "audio", "archive", "video",
        "presentation", "manager", "manager_alias", "current_mode",
        "current_is_login", "current_is_flight", "current_is_mygghanget",
        "location_manager_alias", "location_camera", "location_physics_alias",
        "location_shared_flight_alias", "login_aliases", "pending_mode",
        "native_preroll_pending",
    )
    zero_fields = (
        "mygghanget_flight_start", "flight_loaded", "flight_opened",
        "mode_count", "current_loaded", "current_opened", "manager_ticks",
    )
    sentinel_values = {
        "location_state": 0xFFFFFFFF,
        "start_engine_faster_sample": 255,
        "start_engine_throttle_f32_bits": "0xffffffff",
        "start_engine_timer_f32_bits": "0xffffffff",
        "start_engine_latched": 255,
        "start_engine_audio_owner": 0xFFFFFFFF,
        "start_engine_audio_take": 0xFFFFFFFF,
        "start_engine_global_phase": 0xFFFFFFFF,
        "user_id": -999,
        "native_preroll_state": 255,
        "barn_view": 0xFFFFFFFF,
        "airplane_complete": -1,
    }
    return "bootstrap" if (
        set(record) == _BOOTSTRAP_KEYS
        and all(record.get(field) is False for field in false_fields)
        and all(
            type(record.get(field)) is int and record[field] == 0
            for field in zero_fields
        )
        and record.get("current_name") == "unresolved"
        and all(record.get(field) == value for field, value in sentinel_values.items())
    ) else None
