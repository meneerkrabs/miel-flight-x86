#!/usr/bin/env python3
"""Run one immutable native-dispatch target in one disposable process.

This is a capture controller, not a trust boundary.  It launches the checked
target with the real observer and validates the complete on-disk MVDS stream
through :mod:`native_dispatch_semantic_wire` (which also executes the semantic
oracle).  A successful result remains ``CAPTURED_CANDIDATE`` and is never
parity eligible.

Only the cohorts declared in :mod:`native_capture_driver_cohorts` have a
deterministic driver: engine-mode dispatch after the flight bootstrap
(``GENERIC_LOCATION_CLEAN_V2``, ``MISSION_LOCATION_ENTER_V1``) and the
login-plus-natural-bootstrap traversals (``BOOTSTRAP_TRAVERSAL_V1``,
``MISSION_BARN_TRAVERSAL_V1``).  Each target's dispatch mode is compiled into
the observer allowlist; the runner passes no arbitrary mode.  Every other
target remains undriven and normally returns ``INCOMPLETE`` until its hook
occurrence happens naturally.  This module never fabricates an event,
capability, receipt, identity, or log.
"""

from __future__ import annotations

import copy
import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    from tools.miel_vliegt import hangover_probe
    from tools.miel_vliegt import native_capture_driver_cohorts as driver_cohorts
    from tools.miel_vliegt import native_dispatch_capture_job as capture_job
    from tools.miel_vliegt import native_dispatch_semantic_wire as semantic_wire
    from tools.miel_vliegt.native_dispatch_hook_contract import (
        EXECUTABLE_SHA256, producer_build_sha256,
    )
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import hangover_probe
    import native_capture_driver_cohorts as driver_cohorts
    import native_dispatch_capture_job as capture_job
    import native_dispatch_semantic_wire as semantic_wire
    from native_dispatch_hook_contract import EXECUTABLE_SHA256, producer_build_sha256


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "miel-vliegt-native-dispatch-capture-runner"
CAPTURED = "CAPTURED_CANDIDATE"
INCOMPLETE = "INCOMPLETE"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SESSION_ID = re.compile(r"^mvds-[0-9a-f]{32}$")
NATIVE_RENDERER_LOG = re.compile(
    r"^Log/gt(?:Software|Direct3d)-[0-9A-F]{12}\.log$"
)
WINE_SEH_EXCEPTION = re.compile(
    r"^[0-9a-f]{4}:warn:seh:dispatch_exception "
    r"EXCEPTION_ACCESS_VIOLATION exception \(code=([0-9a-f]{1,8})\) raised$"
)
WINE_PAGE_FAULT = re.compile(
    r"^wine: Unhandled page fault on (read|write|execute) access to "
    r"([0-9A-Fa-f]{8,16}) at address ([0-9A-Fa-f]{8,16}) "
    r"\(thread [0-9a-f]{4}\), starting debugger\.\.\.$"
)
WINEDBG_INVOKED = re.compile(
    r"^[0-9a-f]{4}:trace:seh:start_debugger Starting debugger "
    r'L"winedbg --auto [0-9]+ [0-9]+"$'
)
LAUNCH_DIAGNOSTIC_MAX_LINES = 80
LAUNCH_DIAGNOSTIC_MAX_LINE_CHARS = 4096
LAUNCH_DIAGNOSTIC_MAX_SIGNALS = 8
WINEBOOT_TIMEOUT_SECONDS = {"box64": 60, "fex": 180}
WINESERVER_TIMEOUT_SECONDS = {"box64": 10, "fex": 120}
DRIVER_MIN_OBSERVE_MS = 600_000
DRIVER_VERSION = driver_cohorts.GENERIC_LOCATION_CLEAN_V2
DRIVER_PROTOCOL = "miel-vliegt-native-dispatch-driver-receipt"
WINE_PROXY_DLL_OVERRIDE = "dinput=n,b"
# ``run_scene_navigation`` requires a manifest identity even for its
# byte-identical ``unmodified_start`` route.  ``flight`` is the reviewed
# runtime-mode identity in that manifest; no flight patch is applied here.
# The untouched projector therefore still executes its native mode_login
# startup transition before the observer's registered engine_mode callback
# drives the compiled target.
CAPTURE_SCENE = "flight"
DRIVER_BOOTSTRAP_PROFILE = driver_cohorts.DRIVER_BOOTSTRAP_PROFILE
DRIVER_BOOTSTRAP_PROFILE_SHA256 = driver_cohorts.DRIVER_BOOTSTRAP_PROFILE_SHA256
DRIVER_SCENARIO_SHA256 = driver_cohorts.DRIVER_SCENARIO_SHA256
DRIVER_INITIAL_USER_SHA256 = driver_cohorts.DRIVER_INITIAL_USER_SHA256
NATIVE_EMPTY_USER_SLOT = b"FORM\x00\x00\x00\x04USER"
NATIVE_EMPTY_USER_SLOT_SHA256 = (
    "4d015ed6650059d12ceb178e7f341326869826002e0132c5a8f16ad8d9fe663c"
)
DRIVER_FIXTURE_DIRECTORY = ROOT / "tools/miel_vliegt/fixtures/native_dispatch_driver"
DRIVER_REPLAY = DRIVER_FIXTURE_DIRECTORY / "replay.mvo"
DRIVER_INITIAL_USER_ARCHIVE = (
    DRIVER_FIXTURE_DIRECTORY / "initial-user0.dat.gz.b64"
)

_NATIVE_PREFIX = "MIEL_OBSERVER_NATIVE_DISPATCH_"
OBSERVER_ENV_KEYS = {
    "MIEL_OBSERVER_SCENE_DISPATCH",
    "MIEL_OBSERVER_NATIVE_DISPATCH",
    f"{_NATIVE_PREFIX}JOB_ID",
    f"{_NATIVE_PREFIX}SLICE_SHA256",
    f"{_NATIVE_PREFIX}BINARY_SHA256",
    f"{_NATIVE_PREFIX}BUILD_RECEIPT_SHA256",
    f"{_NATIVE_PREFIX}TARGET_SHA256",
    f"{_NATIVE_PREFIX}JOB_SHA256",
    f"{_NATIVE_PREFIX}CLAIM_ID",
    f"{_NATIVE_PREFIX}CLAIM_SHA256",
    f"{_NATIVE_PREFIX}SUBJECT_SHA256",
    f"{_NATIVE_PREFIX}EXPECTATION_SHA256",
    f"{_NATIVE_PREFIX}SCENARIO_SHA256",
    f"{_NATIVE_PREFIX}CAPTURE_PLAN_SHA256",
    f"{_NATIVE_PREFIX}PLAN_MANIFEST_SHA256",
}
DRIVER_ENV_KEYS = {
    f"{_NATIVE_PREFIX}DRIVER",
    f"{_NATIVE_PREFIX}DRIVER_RECEIPT",
}
DRIVER_BOOTSTRAP_ENV_KEYS = {
    f"{_NATIVE_PREFIX}DRIVER_BOOTSTRAP_PROFILE",
    f"{_NATIVE_PREFIX}DRIVER_BOOTSTRAP_PROFILE_SHA256",
}
FOUNDATION_ENV_KEYS = {
    "MIEL_OBSERVER_SCENARIO",
    "MIEL_OBSERVER_SCENARIO_SHA256",
    "MIEL_OBSERVER_INITIAL_USER_SHA256",
    "MIEL_OBSERVER_FRAME",
}


class NativeDispatchCaptureRunnerError(ValueError):
    """The process isolation or exact target binding failed closed."""


def _canonical_driver_foundation() -> tuple[bytes, bytes]:
    """Load the two immutable, previously successful native bootstrap inputs."""

    try:
        replay = DRIVER_REPLAY.read_bytes()
        encoded = DRIVER_INITIAL_USER_ARCHIVE.read_bytes()
        if encoded != encoded.strip() + b"\n" or b"\n" in encoded.strip():
            raise NativeDispatchCaptureRunnerError(
                "canonical native dispatch user fixture encoding differs"
            )
        compressed = base64.b64decode(encoded.strip(), validate=True)
        initial_user = gzip.decompress(compressed)
    except (OSError, binascii.Error, gzip.BadGzipFile, EOFError) as error:
        raise NativeDispatchCaptureRunnerError(
            "canonical native dispatch driver fixture is unavailable"
        ) from error
    if hashlib.sha256(replay).hexdigest() != DRIVER_SCENARIO_SHA256 \
            or hashlib.sha256(initial_user).hexdigest() != \
                DRIVER_INITIAL_USER_SHA256 \
            or len(replay) != 612 or len(initial_user) != 5587 \
            or not replay.startswith(b"MVO_REPLAY_V2\n") \
            or not initial_user.startswith(b"FORM") \
            or b"USERNAME\x00\x00\x00\x07MVO_CI\x00" not in initial_user:
        raise NativeDispatchCaptureRunnerError(
            "canonical native dispatch driver fixture identity differs"
        )
    return replay, initial_user


def _tree_snapshot(root: Path) -> dict[str, str]:
    """Hash one physical tree without following links or special files."""

    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise NativeDispatchCaptureRunnerError("game root is not a physical directory")
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise NativeDispatchCaptureRunnerError("game root contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise NativeDispatchCaptureRunnerError("game root contains a special file")
        snapshot[relative] = _sha256(path)
    return snapshot


def _snapshot_sha256(snapshot: Mapping[str, str]) -> str:
    return hashlib.sha256(json.dumps(
        dict(snapshot), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def _immutable_game_snapshot(snapshot: Mapping[str, str]) -> dict[str, str]:
    return {
        path: digest for path, digest in snapshot.items()
        if path != "config.ini"
        and not path.startswith("Data/User/")
        and NATIVE_RENDERER_LOG.fullmatch(path) is None
    }


def _changed_snapshot_paths(
    before: Mapping[str, str], after: Mapping[str, str], *, limit: int = 16,
) -> str:
    changed = [
        path for path in sorted(set(before) | set(after))
        if before.get(path) != after.get(path)
    ]
    visible = changed[:limit]
    suffix = f", ... (+{len(changed) - limit})" if len(changed) > limit else ""
    return ", ".join(visible) + suffix


def _copy_isolated_game(
    source: Path, destination: Path, initial_user: bytes,
) -> tuple[Path, dict[str, str], dict[str, str]]:
    """Create a physical per-run game root with one exact user fixture."""

    source = source.resolve(strict=True)
    source_before = _tree_snapshot(source)
    if (source / "Data" / "User").exists():
        raise NativeDispatchCaptureRunnerError(
            "source game template must have no Data/User state"
        )
    if destination.exists():
        raise NativeDispatchCaptureRunnerError("isolated game root is reused")
    destination.mkdir(mode=0o700)
    try:
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source)
            if relative.parts[:2] == ("Data", "User"):
                continue
            target = destination / relative
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                target.mkdir(mode=0o700, exist_ok=True)
            elif stat.S_ISREG(metadata.st_mode):
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copy2(path, target, follow_symlinks=False)
            else:
                raise NativeDispatchCaptureRunnerError(
                    "game root contains a link or special file"
                )
        user_directory = destination / "Data" / "User"
        user_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        user_path = user_directory / "user0.dat"
        with user_path.open("xb") as stream:
            stream.write(initial_user)
        if _sha256(user_path) != DRIVER_INITIAL_USER_SHA256 \
                or set(user_directory.iterdir()) != {user_path}:
            raise NativeDispatchCaptureRunnerError(
                "isolated game user fixture differs"
            )
        isolated_before = _immutable_game_snapshot(_tree_snapshot(destination))
        if isolated_before != _immutable_game_snapshot(source_before):
            raise NativeDispatchCaptureRunnerError(
                "isolated immutable game closure differs"
            )
        return destination, source_before, isolated_before
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _finish_isolated_game(
    source: Path, source_before: Mapping[str, str], isolated: Path,
    isolated_before: Mapping[str, str],
) -> dict[str, str]:
    """Verify both closures and remove the 416 MiB transient copy."""

    try:
        source_after = _tree_snapshot(source.resolve(strict=True))
        isolated_after_all = _tree_snapshot(isolated)
        isolated_after = _immutable_game_snapshot(isolated_after_all)
        user_rows = {
            path for path in isolated_after_all if path.startswith("Data/User/")
        }
        if source_after != dict(source_before):
            raise NativeDispatchCaptureRunnerError(
                "source game template changed during capture: "
                + _changed_snapshot_paths(source_before, source_after)
            )
        if isolated_after != dict(isolated_before):
            raise NativeDispatchCaptureRunnerError(
                "isolated immutable game closure changed during capture: "
                + _changed_snapshot_paths(isolated_before, isolated_after)
            )
        expected_user_rows = {
            f"Data/User/user{index}.dat" for index in range(11)
        }
        initial_user_rows = {"Data/User/user0.dat"}
        if user_rows not in (initial_user_rows, expected_user_rows):
            raise NativeDispatchCaptureRunnerError(
                "isolated game created an unexpected user entry: "
                + ",".join(sorted(user_rows))
            )
        empty_slots_validated = 0
        if user_rows == expected_user_rows:
            for index in range(1, 11):
                path = isolated / "Data" / "User" / f"user{index}.dat"
                if path.read_bytes() != NATIVE_EMPTY_USER_SLOT \
                        or _sha256(path) != NATIVE_EMPTY_USER_SLOT_SHA256:
                    raise NativeDispatchCaptureRunnerError(
                        "native empty user slot differs"
                    )
                empty_slots_validated += 1
        return {
            "sourceTemplateClosureSha256": _snapshot_sha256(source_before),
            "isolatedImmutableClosureSha256": _snapshot_sha256(isolated_before),
            "nativeEmptyUserSlotsValidated": str(empty_slots_validated),
        }
    finally:
        shutil.rmtree(isolated, ignore_errors=False)


def capture_driver_for_target(target: Mapping[str, Any]) -> dict[str, str] | None:
    """Select the one matching generated driver cohort; never accept a mode."""

    try:
        selected = driver_cohorts.cohort_for_target(target)
    except driver_cohorts.DriverCohortError as error:
        raise NativeDispatchCaptureRunnerError(str(error)) from error
    if selected is None:
        return None
    return {"version": selected["version"], "mode": selected["mode"]}


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise NativeDispatchCaptureRunnerError(
            f"capture artifact is unavailable: {path}"
        ) from error


def _evidence_path(path: Path, evidence_root: Path, label: str) -> str:
    try:
        relative = path.resolve(strict=True).relative_to(evidence_root)
    except ValueError as error:
        raise NativeDispatchCaptureRunnerError(
            f"{label} escapes the explicit evidence root"
        ) from error
    cursor = path
    while cursor != evidence_root:
        if cursor.is_symlink():
            raise NativeDispatchCaptureRunnerError(f"{label} uses a symlink")
        cursor = cursor.parent
    return relative.as_posix()


def _validate_evidence_root(path: Path) -> Path:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise NativeDispatchCaptureRunnerError(
            "evidence root must be an existing absolute non-symlink directory"
        )
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise NativeDispatchCaptureRunnerError("evidence root path is not canonical")
    return resolved


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise NativeDispatchCaptureRunnerError(
            f"cannot inspect evidence path component: {path}"
        ) from error


def _under_root(path: Path, evidence_root: Path, label: str) -> None:
    try:
        path.resolve(strict=True).relative_to(evidence_root)
    except (OSError, ValueError) as error:
        raise NativeDispatchCaptureRunnerError(
            f"{label} escapes the explicit evidence root"
        ) from error


def _safe_directory(
    evidence_root: Path, relative: Path, label: str,
) -> Path:
    """Create one directory chain without following pre-existing links."""

    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise NativeDispatchCaptureRunnerError(f"{label} path is not canonical")
    current = evidence_root
    for part in relative.parts:
        candidate = current / part
        metadata = _lstat(candidate)
        if metadata is None:
            try:
                candidate.mkdir(mode=0o700)
            except OSError as error:
                raise NativeDispatchCaptureRunnerError(
                    f"cannot create {label} without following links"
                ) from error
            metadata = _lstat(candidate)
        if metadata is None or stat.S_ISLNK(metadata.st_mode) \
                or not stat.S_ISDIR(metadata.st_mode):
            raise NativeDispatchCaptureRunnerError(
                f"{label} contains a symlink or non-directory component"
            )
        _under_root(candidate, evidence_root, label)
        current = candidate
    return current


def _remove_transient_process_directory(
    *, evidence_root: Path, run_directory: Path, process_directory: Path,
    wine_prefix: Path, isolated_game: Path | None,
) -> dict[str, bool]:
    """Remove only the exact per-run process tree after native shutdown."""

    expected = run_directory / "process"
    if process_directory != expected or wine_prefix != expected / "wineprefix":
        raise NativeDispatchCaptureRunnerError(
            "transient process cleanup boundary differs"
        )
    _under_root(run_directory, evidence_root, "capture run")
    metadata = _lstat(process_directory)
    if metadata is None:
        return {"winePrefixRemoved": True, "processDirectoryRemoved": True}
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        try:
            process_directory.unlink()
        except OSError as error:
            raise NativeDispatchCaptureRunnerError(
                "cannot remove replaced transient process cleanup target"
            ) from error
        raise NativeDispatchCaptureRunnerError(
            "transient process cleanup target is not a physical directory"
        )
    _under_root(process_directory, evidence_root, "capture process")
    if isolated_game is not None and _lstat(isolated_game) is not None:
        raise NativeDispatchCaptureRunnerError(
            "transient game must be verified before process cleanup"
        )
    shutil.rmtree(process_directory, ignore_errors=False)
    return {
        "winePrefixRemoved": _lstat(wine_prefix) is None,
        "processDirectoryRemoved": _lstat(process_directory) is None,
    }


def _safe_new_file_path(
    evidence_root: Path, path: Path, label: str,
) -> Path:
    try:
        relative = path.relative_to(evidence_root)
    except ValueError as error:
        raise NativeDispatchCaptureRunnerError(f"{label} path escapes evidence root") from error
    parent = _safe_directory(evidence_root, relative.parent, f"{label} parent")
    destination = parent / relative.name
    if _lstat(destination) is not None:
        raise NativeDispatchCaptureRunnerError(f"{label} path is reused")
    # The parent was re-opened and resolved immediately before the write.
    _under_root(parent, evidence_root, f"{label} parent")
    return destination


def _safe_existing_file(
    evidence_root: Path, path: Path, label: str,
) -> Path:
    metadata = _lstat(path)
    if metadata is None or stat.S_ISLNK(metadata.st_mode) \
            or not stat.S_ISREG(metadata.st_mode):
        raise NativeDispatchCaptureRunnerError(
            f"{label} is absent, linked, or not a regular file"
        )
    _under_root(path, evidence_root, label)
    return path


def _stage(
    source: Path, destination: Path, label: str, evidence_root: Path,
) -> tuple[Path, str]:
    expected = _sha256(source)
    destination = _safe_new_file_path(
        evidence_root, destination, f"staged {label}",
    )
    try:
        # Exclusive creation prevents a last-moment pre-existing leaf swap.
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
    except OSError as error:
        raise NativeDispatchCaptureRunnerError(
            f"cannot stage {label} safely"
        ) from error
    if destination.is_symlink():
        raise NativeDispatchCaptureRunnerError(f"staged {label} became a symlink")
    _under_root(destination, evidence_root, f"staged {label}")
    if _sha256(destination) != expected:
        raise NativeDispatchCaptureRunnerError(f"staged {label} bytes differ")
    destination.chmod(0o444)
    return destination, expected


def _checked_target(
    compilation: dict[str, Any], target: dict[str, Any], plan_path: Path,
) -> dict[str, Any]:
    try:
        capture_job.validate_compilation(compilation, plan_path)
    except capture_job.NativeDispatchCaptureJobError as error:
        raise NativeDispatchCaptureRunnerError(
            "capture compilation is not the checked target inventory"
        ) from error
    matches = [
        row for row in compilation["targets"]
        if row.get("targetSha256") == target.get("targetSha256")
    ]
    if len(matches) != 1 or capture_job.canonical_ascii_bytes(matches[0]) != \
            capture_job.canonical_ascii_bytes(target):
        raise NativeDispatchCaptureRunnerError(
            "target is not one exact checked capture target"
        )
    return copy.deepcopy(matches[0])


def _validate_build_receipt(
    path: Path, target: Mapping[str, Any], observer_sha256: str,
) -> str:
    try:
        source = path.read_bytes()
        receipt = json.loads(source.decode("ascii", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDispatchCaptureRunnerError(
            "observer build receipt is not exact ASCII JSON"
        ) from error
    expected = {
        "schema": 1,
        "protocol": semantic_wire.BUILD_RECEIPT_PROTOCOL,
        "capturePlanJobId": target["jobId"],
        "nativeSliceSha256": target["nativeSliceSha256"],
        "observerBinarySha256": observer_sha256,
        "producerBuildSha256": producer_build_sha256(),
    }
    if capture_driver_for_target(target) is not None:
        expected["captureDriverFoundation"] = {
            "profile": DRIVER_BOOTSTRAP_PROFILE,
            "profileSha256": DRIVER_BOOTSTRAP_PROFILE_SHA256,
            "scenarioSha256": DRIVER_SCENARIO_SHA256,
            "initialUserSha256": DRIVER_INITIAL_USER_SHA256,
        }
    if receipt != expected:
        raise NativeDispatchCaptureRunnerError(
            "observer build receipt differs from the checked target"
        )
    return hashlib.sha256(source).hexdigest()


def observer_environment(
    target: Mapping[str, Any], *, observer_binary_sha256: str,
    observer_build_receipt_sha256: str,
    driver_receipt: Path | None = None,
    foundation: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the sole observer environment cohort accepted by this runner."""

    values = {
        "MIEL_OBSERVER_SCENE_DISPATCH": "1",
        "MIEL_OBSERVER_NATIVE_DISPATCH": "1",
        f"{_NATIVE_PREFIX}JOB_ID": target["jobId"],
        f"{_NATIVE_PREFIX}SLICE_SHA256": target["nativeSliceSha256"],
        f"{_NATIVE_PREFIX}BINARY_SHA256": observer_binary_sha256,
        f"{_NATIVE_PREFIX}BUILD_RECEIPT_SHA256": observer_build_receipt_sha256,
        f"{_NATIVE_PREFIX}TARGET_SHA256": target["targetSha256"],
        f"{_NATIVE_PREFIX}JOB_SHA256": target["jobSha256"],
        f"{_NATIVE_PREFIX}CLAIM_ID": target["claimId"],
        f"{_NATIVE_PREFIX}CLAIM_SHA256": target["claimSha256"],
        f"{_NATIVE_PREFIX}SUBJECT_SHA256": target["subjectSha256"],
        f"{_NATIVE_PREFIX}EXPECTATION_SHA256": target["expectationSha256"],
        f"{_NATIVE_PREFIX}SCENARIO_SHA256": target["scenarioSha256"],
        f"{_NATIVE_PREFIX}CAPTURE_PLAN_SHA256": target["capturePlanSha256"],
        f"{_NATIVE_PREFIX}PLAN_MANIFEST_SHA256": target["planManifestSha256"],
    }
    driver = capture_driver_for_target(target)
    if driver is not None:
        if driver_receipt is None:
            raise NativeDispatchCaptureRunnerError(
                "driven capture requires an exclusive driver receipt path"
            )
        values.update({
            f"{_NATIVE_PREFIX}DRIVER": driver["version"],
            f"{_NATIVE_PREFIX}DRIVER_RECEIPT":
                hangover_probe.wine_z_path(driver_receipt),
            f"{_NATIVE_PREFIX}DRIVER_BOOTSTRAP_PROFILE":
                DRIVER_BOOTSTRAP_PROFILE,
            f"{_NATIVE_PREFIX}DRIVER_BOOTSTRAP_PROFILE_SHA256":
                DRIVER_BOOTSTRAP_PROFILE_SHA256,
        })
    elif driver_receipt is not None:
        raise NativeDispatchCaptureRunnerError(
            "undriven capture cannot receive a driver receipt path"
        )
    if foundation is not None:
        if set(foundation) != FOUNDATION_ENV_KEYS:
            raise NativeDispatchCaptureRunnerError(
                "observer foundation cohort drifted"
            )
        values.update(foundation)
    expected_keys = OBSERVER_ENV_KEYS \
        | ((DRIVER_ENV_KEYS | DRIVER_BOOTSTRAP_ENV_KEYS) if driver else set()) \
        | (FOUNDATION_ENV_KEYS if foundation is not None else set())
    if set(values) != expected_keys:
        raise NativeDispatchCaptureRunnerError("observer environment cohort drifted")
    for key, value in values.items():
        if not isinstance(value, str) or not value or not value.isascii() \
                or any(character in value for character in "\0\r\n"):
            raise NativeDispatchCaptureRunnerError(
                f"observer environment value is invalid: {key}"
            )
        if key.endswith("SHA256") and SHA256.fullmatch(value) is None:
            raise NativeDispatchCaptureRunnerError(
                f"observer environment hash is invalid: {key}"
            )
    return values


def _validate_driver_receipt(
    path: Path, *, target: Mapping[str, Any], process_identity: Mapping[str, Any],
    evidence_root: Path,
) -> dict[str, Any]:
    _safe_existing_file(evidence_root, path, "native dispatch driver receipt")
    try:
        receipt = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDispatchCaptureRunnerError(
            "native dispatch driver receipt is not exact ASCII JSON"
        ) from error
    driver = capture_driver_for_target(target)
    if driver is None or not isinstance(receipt, dict):
        raise NativeDispatchCaptureRunnerError("native dispatch driver receipt differs")
    if driver["version"] in (
        driver_cohorts.BOOTSTRAP_TRAVERSAL_V1,
        driver_cohorts.MISSION_BARN_TRAVERSAL_V1,
    ):
        return _validate_traversal_driver_receipt(
            receipt, target=target, driver=driver,
            process_identity=process_identity,
        )
    expected_schema = 2 if driver["version"] == \
        driver_cohorts.GENERIC_LOCATION_CLEAN_V2 else 4
    if set(receipt) != {
        "schema", "protocol", "status", "driver", "targetSha256",
        "nativeProcessId", "captureSessionId", "managerAddress",
        "entryPath", "sourceMode", "sourceModeAddress",
        "targetMode", "targetModeAddress", "callback", "ticks",
        "bootstrap", "naturalTransitionEvidence", "flightPrerequisite",
        "missionReadback", "semanticStateWritePolicy",
    }:
        raise NativeDispatchCaptureRunnerError("native dispatch driver receipt differs")
    callback = receipt.get("callback")
    bootstrap = receipt.get("bootstrap")
    ticks = receipt.get("ticks")
    readbacks = receipt.get("missionReadback")
    if receipt.get("schema") != expected_schema \
            or receipt.get("protocol") != DRIVER_PROTOCOL \
            or receipt.get("status") != "PASS" \
            or receipt.get("driver") != driver["version"] \
            or receipt.get("targetSha256") != target["targetSha256"] \
            or receipt.get("nativeProcessId") != process_identity["nativeProcessId"] \
            or receipt.get("captureSessionId") != process_identity["sessionId"] \
            or receipt.get("entryPath") != \
                "NATIVE_BARN_MYGGHANGET_FLIGHT_THEN_ENGINE_MODE" \
            or receipt.get("sourceMode") != "mode_fly" \
            or receipt.get("targetMode") != driver["mode"] \
            or receipt.get("naturalTransitionEvidence") is not False \
            or receipt.get("flightPrerequisite") not in ({
                "departureCallerSite": "0x00425c2e", "flightReady": True,
            }, {
                "departureCallerSite": "0x004262ee", "flightReady": True,
            }) \
            or bootstrap != {
                "profile": DRIVER_BOOTSTRAP_PROFILE,
                "profileSha256": DRIVER_BOOTSTRAP_PROFILE_SHA256,
                "scenarioSha256": DRIVER_SCENARIO_SHA256,
                "initialUserSha256": DRIVER_INITIAL_USER_SHA256,
            } \
            or type(receipt.get("managerAddress")) is not int \
            or type(receipt.get("sourceModeAddress")) is not int \
            or type(receipt.get("targetModeAddress")) is not int \
            or receipt["managerAddress"] <= 0 \
            or receipt["sourceModeAddress"] <= 0 \
            or receipt["targetModeAddress"] <= 0 \
            or receipt["sourceModeAddress"] == receipt["targetModeAddress"] \
            or callback != {"name": "engine_mode", "id": 15,
                            "address": 0x0041E1B0} \
            or not isinstance(ticks, dict) or set(ticks) != {
                "flightReady", "dispatch", "activation", "capture",
            } or any(type(ticks[key]) is not int or ticks[key] <= 0 for key in ticks) \
            or not ticks["flightReady"] <= ticks["dispatch"] \
                <= ticks["activation"] <= ticks["capture"] \
            or not isinstance(readbacks, dict) or set(readbacks) != {"before", "hook"} \
            or receipt.get("semanticStateWritePolicy") != {
                "policy": "NO_DIRECT_SEMANTIC_STATE_WRITES",
                "loginUiBootstrapException": True, "mission": False,
                "selector": False, "root": False, "projectedValues": False,
            }:
        raise NativeDispatchCaptureRunnerError("native dispatch driver receipt differs")
    expected_functions = {
        "applicationGetter": 0x00405A20,
        "missionLookup": 0x004375E0,
        "missionComplete": 0x00436090,
    }
    for phase in ("before", "hook"):
        readback = readbacks.get(phase)
        if not isinstance(readback, dict) or set(readback) != {
            "state", "missionPresent", "missionAddress", "functions",
        } or readback.get("state") not in {-1, 0} \
                or type(readback.get("missionPresent")) is not bool \
                or type(readback.get("missionAddress")) is not int \
                or readback.get("missionAddress") < 0 \
                or readback.get("functions") != expected_functions \
                or (readback["missionPresent"] !=
                    (readback["missionAddress"] != 0)):
            raise NativeDispatchCaptureRunnerError(
                "native dispatch driver mission readback differs"
            )
    if readbacks["before"] != readbacks["hook"]:
        raise NativeDispatchCaptureRunnerError(
            "native dispatch driver mission readbacks differ"
        )
    return receipt


def _validate_traversal_driver_receipt(
    receipt: Mapping[str, Any], *, target: Mapping[str, Any],
    driver: Mapping[str, str], process_identity: Mapping[str, Any],
) -> dict[str, Any]:
    ticks = receipt.get("ticks")
    if driver["version"] == driver_cohorts.BOOTSTRAP_TRAVERSAL_V1:
        expected_entry_path = "NATIVE_LOGIN_BARN_MYGGHANGET_TRAVERSAL"
        expected_source_mode = "mode_barn"
    else:
        expected_entry_path = "NATIVE_LOGIN_BARN_TRAVERSAL"
        expected_source_mode = "mode_login"
    if set(receipt) != {
        "schema", "protocol", "status", "driver", "targetSha256",
        "nativeProcessId", "captureSessionId", "managerAddress",
        "entryPath", "sourceMode", "targetMode", "ticks", "bootstrap",
        "naturalTransitionEvidence", "semanticStateWritePolicy",
    } or receipt.get("schema") != 3 \
            or receipt.get("protocol") != DRIVER_PROTOCOL \
            or receipt.get("status") != "PASS" \
            or receipt.get("driver") != driver["version"] \
            or receipt.get("targetSha256") != target["targetSha256"] \
            or receipt.get("nativeProcessId") != \
                process_identity["nativeProcessId"] \
            or receipt.get("captureSessionId") != \
                process_identity["sessionId"] \
            or type(receipt.get("managerAddress")) is not int \
            or receipt["managerAddress"] <= 0 \
            or receipt.get("entryPath") != expected_entry_path \
            or receipt.get("sourceMode") != expected_source_mode \
            or receipt.get("targetMode") != driver["mode"] \
            or receipt.get("naturalTransitionEvidence") is not False \
            or receipt.get("bootstrap") != {
                "profile": DRIVER_BOOTSTRAP_PROFILE,
                "profileSha256": DRIVER_BOOTSTRAP_PROFILE_SHA256,
                "scenarioSha256": DRIVER_SCENARIO_SHA256,
                "initialUserSha256": DRIVER_INITIAL_USER_SHA256,
            } \
            or not isinstance(ticks, dict) or set(ticks) != {
                "loginDispatched", "capture",
            } or any(type(ticks[key]) is not int or ticks[key] <= 0
                     for key in ticks) \
            or not ticks["loginDispatched"] <= ticks["capture"] \
            or receipt.get("semanticStateWritePolicy") != {
                "policy": "NO_DIRECT_SEMANTIC_STATE_WRITES",
                "loginUiBootstrapException": True, "mission": False,
                "selector": False, "root": False, "projectedValues": False,
            }:
        raise NativeDispatchCaptureRunnerError(
            "native dispatch driver receipt differs"
        )
    return dict(receipt)


def _isolated_environment(
    base: Iterable[str], cohort: Mapping[str, str], prefix: Path,
) -> list[str]:
    items = list(base)
    if items and items[0] == "env":
        items = items[1:]
    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str) or "=" not in item:
            raise NativeDispatchCaptureRunnerError(
                "capture environment must contain only env assignments"
            )
        key, value = item.split("=", 1)
        if not key or key in seen or not value or "\0" in value:
            raise NativeDispatchCaptureRunnerError("capture environment is invalid")
        if key.startswith("MIEL_OBSERVER_") or key in {
            "MIEL_REAL_DINPUT", "WINEPREFIX", "WINEARCH",
            "WINEDLLOVERRIDES",
        }:
            raise NativeDispatchCaptureRunnerError(
                f"loose observer environment is forbidden: {key}"
            )
        seen.add(key)
        parsed.append((key, value))
    isolated = ["env", *(f"{key}={value}" for key, value in parsed)]
    isolated.extend((
        f"WINEPREFIX={prefix}", "WINEARCH=win32",
        f"WINEDLLOVERRIDES={WINE_PROXY_DLL_OVERRIDE}",
    ))
    isolated.extend(f"{key}={cohort[key]}" for key in sorted(cohort))
    return isolated


def _native_launch(**arguments: Any) -> dict[str, Any]:
    """Fixed production launch boundary; tests patch this private symbol only."""

    return hangover_probe.run_scene_navigation(**arguments)


def _run_wineserver(
    environment: list[str], cwd: Path, backend: dict[str, str], argument: str,
) -> dict[str, Any]:
    """Fixed production cleanup boundary; tests patch this private symbol only."""

    return hangover_probe.run(
        [
            *environment,
            *hangover_probe.native_wineserver_command(backend, argument),
        ],
        cwd=cwd, timeout=WINESERVER_TIMEOUT_SECONDS[backend["id"]],
    )


def _prefix_bootstrap_environment(environment: list[str]) -> list[str]:
    """Remove capture-only guest variables from the Wine bootstrap process."""

    if not environment or environment[0] != "env":
        raise NativeDispatchCaptureRunnerError(
            "capture prefix environment is invalid"
        )
    bootstrap = ["env"]
    for item in environment[1:]:
        if "=" not in item:
            raise NativeDispatchCaptureRunnerError(
                "capture prefix environment is invalid"
            )
        key = item.split("=", 1)[0]
        if key.startswith("MIEL_OBSERVER_") or key == "WINEDLLOVERRIDES":
            continue
        bootstrap.append(item)
    return bootstrap


def _run_wineboot(
    environment: list[str], cwd: Path, backend: dict[str, str],
) -> dict[str, Any]:
    """Initialize/update one private prefix through the checked backend."""

    return hangover_probe.run(
        [
            *environment,
            *hangover_probe.native_wine_command(
                "wineboot", "--init", backend=backend,
            ),
        ],
        cwd=cwd,
        timeout=WINEBOOT_TIMEOUT_SECONDS[backend["id"]],
    )


def _prepare_wine_prefix(
    *, environment: list[str], cwd: Path, backend: dict[str, str], prefix: Path,
) -> dict[str, Any]:
    """Bootstrap, flush and validate a prefix before any evidence process."""

    bootstrap_environment = _prefix_bootstrap_environment(environment)
    values = dict(
        item.split("=", 1) for item in bootstrap_environment[1:]
    )
    if values.get("WINEPREFIX") != str(prefix) \
            or values.get("WINEARCH") != "win32":
        raise NativeDispatchCaptureRunnerError(
            "capture prefix identity is invalid"
        )
    wineboot = _run_wineboot(bootstrap_environment, cwd, backend)
    wineboot_ok = (
        wineboot.get("exit_code") == 0
        and wineboot.get("timed_out") is False
        and not hangover_probe.has_loader_failure(wineboot)
    )
    try:
        _cleanup_wineserver(
            environment=bootstrap_environment, cwd=cwd, backend=backend,
        )
    except Exception as error:
        if not wineboot_ok:
            error.add_note("wineboot also failed before prefix flush")
        raise
    if not wineboot_ok:
        raise NativeDispatchCaptureRunnerError(
            "capture prefix wineboot failed"
        )
    layout = hangover_probe.inspect_prefix(prefix)
    if not all(layout.values()):
        missing = ",".join(sorted(
            name for name, present in layout.items() if not present
        ))
        raise NativeDispatchCaptureRunnerError(
            f"capture prefix is incomplete after wineserver flush: {missing}"
        )
    return {
        "prefixBootstrap": {
            "winebootCompleted": True,
            "wineserverFlushed": True,
            **layout,
        },
    }


def _cleanup_wineserver(
    *, environment: list[str], cwd: Path, backend: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    stopped = _run_wineserver(environment, cwd, backend, "-k")
    waited = _run_wineserver(
        environment, cwd, backend, "-w",
    ) if _cleanup_ok(stopped) else {}
    if not _cleanup_ok(stopped) or not _cleanup_ok(waited):
        raise NativeDispatchCaptureRunnerError(
            "explicit wineserver -k/-w cleanup failed; no later target may start"
        )
    return stopped, waited


def _cleanup_ok(result: Any) -> bool:
    return isinstance(result, dict) \
        and result.get("exit_code") == 0 \
        and result.get("timed_out") is False \
        and not hangover_probe.has_loader_failure(result)


def _incomplete(
    target: Mapping[str, Any], reason: str, isolation: Mapping[str, Any],
    diagnostic: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": INCOMPLETE,
        "reason": reason,
        "productionClaim": False,
        "parityEligible": False,
        "targetSha256": target["targetSha256"],
        "jobId": target["jobId"],
        "claimId": target["claimId"],
        "isolation": dict(isolation),
    }
    if diagnostic is not None:
        result["launchDiagnostic"] = dict(diagnostic)
    return result


def _process_identity(navigation: Mapping[str, Any]) -> dict[str, Any] | None:
    launcher = navigation.get("observer_launcher_receipt")
    value = launcher.get("capture_process") if isinstance(launcher, dict) else None
    if not isinstance(value, dict) or set(value) != {
        "native_process_id", "capture_session_id",
    }:
        return None
    process_id = value.get("native_process_id")
    session_id = value.get("capture_session_id")
    exposed = navigation.get("captureProcess")
    if type(process_id) is not int or process_id <= 0 \
            or not isinstance(session_id, str) \
            or SESSION_ID.fullmatch(session_id) is None \
            or exposed != {
                "nativeProcessId": process_id,
                "captureSessionId": session_id,
            }:
        return None
    return {"nativeProcessId": process_id, "sessionId": session_id}


def _validate_launcher_material(
    navigation: Mapping[str, Any], *, output_directory: Path,
    backend_id: str, executable: Path, disposable: Path, observer_dll: Path,
    real_dinput: Path,
    scene: str, evidence_root: Path,
) -> bool:
    start_path = output_directory / f"native-unmodified-start-{backend_id}.json"
    launcher_path = output_directory / f"native-observer-launch-{backend_id}.json"
    try:
        _safe_existing_file(evidence_root, start_path, "unmodified-start receipt")
        _safe_existing_file(evidence_root, launcher_path, "observer-launch receipt")
        _safe_existing_file(evidence_root, disposable, "disposable executable")
        start = json.loads(start_path.read_text(encoding="utf-8"))
        hangover_probe.validate_unmodified_start_receipt(
            start, executable, disposable, scene,
        )
        launcher = hangover_probe.validate_observer_launcher_receipt(
            launcher_path, executable, disposable, observer_dll, real_dinput,
            start_path, scene,
        )
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    return navigation.get("route") == "suspended-process-observer-launcher" \
        and navigation.get("scene_bootstrap_confirmed") is True \
        and navigation.get("start_executable_receipt") == start \
        and navigation.get("observer_launcher_receipt") == launcher


def _completed_process(navigation: Mapping[str, Any]) -> bool:
    runs = navigation.get("runs")
    launch = runs.get("start_patch_launch") if isinstance(runs, dict) else None
    return isinstance(launch, dict) \
        and launch.get("exit_code") == 0 \
        and launch.get("timed_out") is False \
        and not hangover_probe.has_loader_failure(launch)


def _bounded_launch_diagnostic(
    navigation: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Normalize launch failure signals without copying commands or log text."""

    runs = navigation.get("runs")
    launch = runs.get("start_patch_launch") if isinstance(runs, Mapping) else None
    if not isinstance(launch, Mapping):
        return None
    exit_code = launch.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) \
            or not -(2 ** 31) <= exit_code < 2 ** 32:
        exit_code = None
    timed_out = launch.get("timed_out")
    if not isinstance(timed_out, bool):
        timed_out = None
    output_sha256 = launch.get("output_sha256")
    if not isinstance(output_sha256, str) or SHA256.fullmatch(output_sha256) is None:
        output_sha256 = None
    output_tail = launch.get("output_tail")
    lines = output_tail if isinstance(output_tail, (list, tuple)) else []
    signals: list[dict[str, Any]] = []
    truncated = len(lines) > LAUNCH_DIAGNOSTIC_MAX_LINES

    def add_signal(signal: dict[str, Any]) -> None:
        nonlocal truncated
        if signal in signals:
            return
        if len(signals) == LAUNCH_DIAGNOSTIC_MAX_SIGNALS:
            truncated = True
            return
        signals.append(signal)

    for raw_line in lines[-LAUNCH_DIAGNOSTIC_MAX_LINES:]:
        if not isinstance(raw_line, str):
            continue
        if len(raw_line) > LAUNCH_DIAGNOSTIC_MAX_LINE_CHARS:
            truncated = True
        line = raw_line[:LAUNCH_DIAGNOSTIC_MAX_LINE_CHARS]
        match = WINE_SEH_EXCEPTION.fullmatch(line)
        if match:
            add_signal({
                "kind": "wine-seh-exception",
                "name": "ACCESS_VIOLATION",
                "exceptionCode": f"0x{match.group(1).lower().zfill(8)}",
            })
            continue
        match = WINE_PAGE_FAULT.fullmatch(line)
        if match:
            add_signal({
                "kind": "wine-page-fault",
                "access": match.group(1),
                "accessAddress": f"0x{match.group(2).lower()}",
                "instructionAddress": f"0x{match.group(3).lower()}",
            })
            continue
        if WINEDBG_INVOKED.fullmatch(line):
            add_signal({"kind": "winedbg-invoked"})

    return {
        "schema": 1,
        "protocol": "miel-vliegt-native-launch-diagnostic",
        "status": "DIAGNOSTIC_ONLY",
        "productionClaim": False,
        "parityEligible": False,
        "exitCode": exit_code,
        "timedOut": timed_out,
        "outputSha256": output_sha256,
        "signals": signals,
        "signalsTruncated": truncated,
    }


_BOUNDARY_TOKEN = object()


def _launch_capture_with_game_guard(
    *, launch_arguments: Mapping[str, Any], cleanup_environment: list[str],
    cleanup_backend: dict[str, str], source_game: Path,
    source_game_before: Mapping[str, str] | None, isolated_game: Path | None,
    isolated_game_before: Mapping[str, str] | None,
    output_directory: Path, disposable: Path, observer_dll: Path,
    real_dinput: Path, scene: str, evidence_root: Path,
    run_directory: Path, process_directory: Path, wine_prefix: Path,
) -> tuple[dict[str, Any], bool, bool, dict[str, Any]]:
    """Launch once and always remove the complete transient process tree."""

    navigation: dict[str, Any] | None = None
    primary_error: Exception | None = None
    closure: dict[str, Any] = {}
    cleanup_attempted = False
    try:
        closure.update(_prepare_wine_prefix(
            environment=cleanup_environment,
            cwd=Path(launch_arguments["executable"]).parent,
            backend=cleanup_backend,
            prefix=wine_prefix,
        ))
        navigation = _native_launch(**dict(launch_arguments))
        cleanup_attempted = True
        _cleanup_wineserver(
            environment=cleanup_environment,
            cwd=Path(launch_arguments["executable"]).parent,
            backend=cleanup_backend,
        )
        if not isinstance(navigation, dict):
            raise NativeDispatchCaptureRunnerError(
                "native target launcher returned no result"
            )
        completed = _completed_process(navigation)
        launcher_valid = completed and _validate_launcher_material(
            navigation, output_directory=output_directory,
            backend_id=cleanup_backend["id"],
            executable=Path(launch_arguments["executable"]),
            disposable=disposable, observer_dll=observer_dll,
            real_dinput=real_dinput, scene=scene, evidence_root=evidence_root,
        )
        return navigation, completed, launcher_valid, closure
    except Exception as error:
        primary_error = error
        if not cleanup_attempted:
            try:
                _cleanup_wineserver(
                    environment=cleanup_environment,
                    cwd=Path(launch_arguments["executable"]).parent,
                    backend=cleanup_backend,
                )
            except Exception as cleanup_error:
                error.add_note(
                    f"wineserver cleanup also failed: {cleanup_error}"
                )
        raise
    finally:
        try:
            try:
                if isolated_game is not None:
                    closure.update(_finish_isolated_game(
                        source_game, source_game_before or {}, isolated_game,
                        isolated_game_before or {},
                    ))
                    closure["transientGameRootRemoved"] = not isolated_game.exists()
            finally:
                closure.update(_remove_transient_process_directory(
                    evidence_root=evidence_root, run_directory=run_directory,
                    process_directory=process_directory, wine_prefix=wine_prefix,
                    isolated_game=isolated_game,
                ))
        except Exception as cleanup_error:
            if primary_error is not None:
                primary_error.add_note(
                    f"transient process cleanup also failed: {cleanup_error}"
                )
            else:
                raise


def _run_capture_target(
    *, compilation: dict[str, Any], target: dict[str, Any], plan_path: Path,
    environment: Iterable[str], backend: dict[str, Any], executable: Path,
    evidence_root: Path, observer_dll: Path, observer_build_receipt: Path,
    proxy_dll: Path, real_dinput_dll: Path, observer_launcher: Path,
    expected_launcher_sha256: str,
    observe_ms: int = hangover_probe.DEFAULT_OBSERVE_MS,
    _token: object | None = None,
) -> dict[str, Any]:
    """Capture one target, then stop and clean its private Wine server."""

    if _token is not _BOUNDARY_TOKEN:
        raise NativeDispatchCaptureRunnerError("private capture boundary required")
    evidence_root = _validate_evidence_root(evidence_root)
    checked = _checked_target(compilation, target, plan_path)
    snapshot = capture_job.canonical_ascii_bytes(checked)
    try:
        checked_backend = hangover_probe.validate_capture_backend(backend)
    except ValueError as error:
        raise NativeDispatchCaptureRunnerError(
            "capture backend identity is invalid"
        ) from error
    try:
        observe_ms = hangover_probe.validate_observe_ms(observe_ms)
    except ValueError as error:
        raise NativeDispatchCaptureRunnerError(
            "capture observation window is invalid"
        ) from error
    if capture_driver_for_target(checked) is not None:
        observe_ms = max(observe_ms, DRIVER_MIN_OBSERVE_MS)
    if SHA256.fullmatch(expected_launcher_sha256) is None \
            or _sha256(observer_launcher) != expected_launcher_sha256:
        raise NativeDispatchCaptureRunnerError("observer launcher identity differs")
    if _sha256(executable) != EXECUTABLE_SHA256:
        raise NativeDispatchCaptureRunnerError("native executable identity differs")
    observer_sha = _sha256(observer_dll)
    _validate_build_receipt(observer_build_receipt, checked, observer_sha)
    if _sha256(plan_path) != checked["capturePlanSha256"]:
        raise NativeDispatchCaptureRunnerError("capture plan bytes drifted")
    run_directory = evidence_root / "runs" / checked["targetSha256"]
    run_relative = Path("runs") / checked["targetSha256"]
    if _lstat(run_directory) is not None:
        raise NativeDispatchCaptureRunnerError("capture output directory is reused")
    run_directory = _safe_directory(evidence_root, run_relative, "capture run")
    proxy_directory = _safe_directory(
        evidence_root, run_relative / "proxy", "capture proxy",
    )
    output_directory = _safe_directory(
        evidence_root, run_relative / "output", "capture output",
    )
    staged_directory = _safe_directory(
        evidence_root, run_relative / "evidence", "staged evidence",
    )
    staged_plan, _ = _stage(
        plan_path, staged_directory / "capture-plan.json", "capture plan",
        evidence_root,
    )
    staged_observer, staged_observer_sha = _stage(
        observer_dll, staged_directory / "native-observer-hook.dll", "observer binary",
        evidence_root,
    )
    staged_receipt, build_receipt_sha = _stage(
        observer_build_receipt,
        staged_directory / "observer-build-receipt.json",
        "observer build receipt",
        evidence_root,
    )
    staged_launcher, staged_launcher_sha = _stage(
        observer_launcher,
        staged_directory / "native-observer-launcher.exe",
        "observer launcher",
        evidence_root,
    )
    staged_proxy, _ = _stage(
        proxy_dll, staged_directory / "DINPUT.dll", "observer proxy", evidence_root,
    )
    staged_real_dinput, real_dinput_sha = _stage(
        real_dinput_dll, staged_directory / "dinput-real.dll", "real dinput",
        evidence_root,
    )
    if staged_observer_sha != observer_sha \
            or staged_launcher_sha != expected_launcher_sha256:
        raise NativeDispatchCaptureRunnerError("staged native binary identity differs")
    staged_hashes = {
        staged_plan: checked["capturePlanSha256"],
        staged_observer: staged_observer_sha,
        staged_receipt: build_receipt_sha,
        staged_launcher: staged_launcher_sha,
        staged_proxy: _sha256(staged_proxy),
        staged_real_dinput: real_dinput_sha,
    }
    driver = capture_driver_for_target(checked)
    foundation = None
    initial_user = None
    if driver is not None:
        replay_bytes, initial_user = _canonical_driver_foundation()
        staged_replay, replay_sha = _stage(
            DRIVER_REPLAY, staged_directory / "observer-replay.mvo",
            "observer scenario replay", evidence_root,
        )
        if staged_replay.read_bytes() != replay_bytes:
            raise NativeDispatchCaptureRunnerError(
                "staged canonical observer replay differs"
            )
        staged_hashes[staged_replay] = replay_sha
        foundation = {
            "MIEL_OBSERVER_SCENARIO": hangover_probe.wine_z_path(staged_replay),
            "MIEL_OBSERVER_SCENARIO_SHA256": replay_sha,
            "MIEL_OBSERVER_INITIAL_USER_SHA256": DRIVER_INITIAL_USER_SHA256,
            "MIEL_OBSERVER_FRAME": hangover_probe.wine_z_path(
                output_directory / "native-dispatch-frame"
            ),
        }
    driver_receipt_path = None
    if driver is not None:
        driver_receipt_path = _safe_new_file_path(
            evidence_root, output_directory / "native-dispatch-driver.json",
            "native dispatch driver receipt",
        )
    cohort = observer_environment(
        checked,
        observer_binary_sha256=staged_observer_sha,
        observer_build_receipt_sha256=build_receipt_sha,
        driver_receipt=driver_receipt_path,
        foundation=foundation,
    )
    disposable = _safe_new_file_path(
        evidence_root, proxy_directory / executable.name,
        "disposable executable",
    )
    proxy_destination = _safe_new_file_path(
        evidence_root, proxy_directory / "DINPUT.dll", "capture proxy DLL",
    )
    try:
        with staged_proxy.open("rb") as input_stream, \
                proxy_destination.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
    except OSError as error:
        raise NativeDispatchCaptureRunnerError("cannot copy capture proxy safely") from error
    _under_root(proxy_destination, evidence_root, "capture proxy DLL")
    output = _safe_new_file_path(
        evidence_root, output_directory / "capture.json", "capture output",
    )

    source_game = executable.parent.resolve(strict=True)
    if driver is not None:
        if initial_user is None:
            raise NativeDispatchCaptureRunnerError(
                "canonical initial user was not materialized"
            )
        if evidence_root == source_game or evidence_root.is_relative_to(source_game):
            raise NativeDispatchCaptureRunnerError(
                "evidence root must be outside the source game template"
            )

    process_directory = _safe_directory(
        evidence_root, run_relative / "process", "capture process",
    )
    prefix = process_directory / "wineprefix"
    try:
        isolated_environment = _isolated_environment(environment, cohort, prefix)
    except Exception:
        _remove_transient_process_directory(
            evidence_root=evidence_root, run_directory=run_directory,
            process_directory=process_directory, wine_prefix=prefix,
            isolated_game=None,
        )
        raise
    isolation = {
        "runDirectory": str(run_directory.resolve()),
        "proxyDirectory": str(proxy_directory.resolve()),
        "processDirectory": str(process_directory.resolve()),
        "outputDirectory": str(output_directory.resolve()),
        "winePrefix": str(prefix.resolve()),
    }

    isolated_executable = executable
    source_game_before = None
    isolated_game_before = None
    isolated_game = None
    if driver is not None:
        try:
            isolated_game, source_game_before, isolated_game_before = \
                _copy_isolated_game(
                    source_game, process_directory / "game", initial_user,
                )
        except Exception:
            _remove_transient_process_directory(
                evidence_root=evidence_root, run_directory=run_directory,
                process_directory=process_directory, wine_prefix=prefix,
                isolated_game=None,
            )
            raise
        try:
            isolated_executable = isolated_game / executable.name
            if _sha256(isolated_executable) != EXECUTABLE_SHA256:
                raise NativeDispatchCaptureRunnerError(
                    "isolated native executable identity differs"
                )
            isolation["transientGameRoot"] = str(isolated_game)
            isolation["sourceTemplateClosureSha256"] = _snapshot_sha256(
                source_game_before,
            )
            isolation["isolatedImmutableClosureSha256"] = _snapshot_sha256(
                isolated_game_before,
            )
            isolation["driverBootstrapProfileSha256"] = \
                DRIVER_BOOTSTRAP_PROFILE_SHA256
            isolation["driverScenarioSha256"] = DRIVER_SCENARIO_SHA256
            isolation["driverInitialUserSha256"] = DRIVER_INITIAL_USER_SHA256
        except Exception as error:
            try:
                _finish_isolated_game(
                    source_game, source_game_before, isolated_game,
                    isolated_game_before,
                )
            except Exception as cleanup_error:
                error.add_note(
                    f"isolated game cleanup also failed: {cleanup_error}"
                )
            try:
                _remove_transient_process_directory(
                    evidence_root=evidence_root, run_directory=run_directory,
                    process_directory=process_directory, wine_prefix=prefix,
                    isolated_game=isolated_game,
                )
            except Exception as cleanup_error:
                error.add_note(
                    f"transient process cleanup also failed: {cleanup_error}"
                )
            raise

    launch_arguments = {
            "environment": isolated_environment,
            "backend": copy.deepcopy(checked_backend),
            "executable": isolated_executable,
            "output": output,
            "scene": CAPTURE_SCENE,
            "scene_debugger": hangover_probe.SCENE_DEBUGGER,
            "observer_dll": staged_observer,
            "observer_launcher": staged_launcher,
            "real_dinput": staged_real_dinput,
            "attempt_debug": False,
            "allow_fallback": True,
            "observe_ms": observe_ms,
            "observer_environment": None,
            "unmodified_start": True,
            "unmodified_target": disposable,
    }
    try:
        navigation, completed_process, launcher_material_valid, closure = \
            _launch_capture_with_game_guard(
                launch_arguments=launch_arguments,
                cleanup_environment=isolated_environment,
                cleanup_backend=checked_backend,
                source_game=source_game,
                source_game_before=source_game_before,
                isolated_game=isolated_game,
                isolated_game_before=isolated_game_before,
                output_directory=output_directory,
                disposable=disposable,
                observer_dll=staged_observer,
                real_dinput=staged_real_dinput,
                scene=CAPTURE_SCENE,
                evidence_root=evidence_root,
                run_directory=run_directory,
                process_directory=process_directory,
                wine_prefix=prefix,
            )
    except NativeDispatchCaptureRunnerError:
        raise
    except Exception as error:
        raise NativeDispatchCaptureRunnerError(
            "native target launcher or isolation failed"
        ) from error
    isolation.update(closure)

    try:
        capture_job.validate_compilation(compilation, plan_path)
    except capture_job.NativeDispatchCaptureJobError as error:
        raise NativeDispatchCaptureRunnerError("target drifted during native launch") from error
    if capture_job.canonical_ascii_bytes(target) != snapshot \
            or _sha256(plan_path) != checked["capturePlanSha256"]:
        raise NativeDispatchCaptureRunnerError("target drifted during native launch")
    if any(_sha256(path) != digest for path, digest in staged_hashes.items()):
        raise NativeDispatchCaptureRunnerError(
            "immutable staged evidence drifted during native launch"
        )
    if not completed_process:
        return _incomplete(
            checked, "NATIVE_PROCESS_DID_NOT_COMPLETE", isolation,
            diagnostic=_bounded_launch_diagnostic(navigation),
        )
    if not launcher_material_valid:
        return _incomplete(checked, "LAUNCHER_IDENTITY_NOT_CONFIRMED", isolation)
    process_identity = _process_identity(navigation)
    if process_identity is None:
        return _incomplete(checked, "PROCESS_IDENTITY_NOT_OBSERVED", isolation)
    driver_receipt = None
    if driver_receipt_path is not None:
        if _lstat(driver_receipt_path) is None:
            return _incomplete(
                checked, "DETERMINISTIC_DRIVER_DID_NOT_COMPLETE", isolation,
            )
        driver_receipt = _validate_driver_receipt(
            driver_receipt_path, target=checked,
            process_identity=process_identity, evidence_root=evidence_root,
        )

    raw_path = output_directory / f"native-observer-{backend['id']}.log"
    try:
        _safe_existing_file(evidence_root, raw_path, "full observer log")
        raw_bytes = raw_path.read_bytes()
        lines = raw_bytes.decode("ascii", errors="strict").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise NativeDispatchCaptureRunnerError(
            "full unsliced observer log is unavailable"
        ) from error
    observer_log = navigation.get("observer_log")
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    if not isinstance(observer_log, dict) \
            or observer_log.get("path") != raw_path.name \
            or observer_log.get("sha256") != raw_sha \
            or observer_log.get("hook_loaded") is not True:
        raise NativeDispatchCaptureRunnerError("observer log identity differs")
    wire_lines = [row for row in lines if row.startswith(semantic_wire.WIRE_PREFIX)]
    if not wire_lines:
        return _incomplete(checked, "EXACT_NATIVE_TARGET_NOT_OBSERVED", isolation)
    try:
        wire_records = [
            json.loads(row[len(semantic_wire.WIRE_PREFIX):]) for row in wire_lines
        ]
        kinds = [row.get("record") for row in wire_records]
    except json.JSONDecodeError as error:
        raise NativeDispatchCaptureRunnerError("observer MVDS record is invalid") from error
    if len(wire_lines) != 2 or kinds != ["CAPABILITY", "EVENT"]:
        raise NativeDispatchCaptureRunnerError(
            "full observer log must contain exactly one CAPABILITY and EVENT"
        )
    if any(
        row.get("nativeProcessId") != process_identity["nativeProcessId"]
        or row.get("captureSessionId") != process_identity["sessionId"]
        for row in wire_records
    ):
        raise NativeDispatchCaptureRunnerError(
            "launcher process/session identity differs from CAPABILITY/EVENT"
        )

    binding = {
        "capturePlanJobId": checked["jobId"],
        "nativeSliceSha256": checked["nativeSliceSha256"],
        "observerBinarySha256": observer_sha,
        "observerBuildReceiptSha256": build_receipt_sha,
        "capturePlanPath": _evidence_path(staged_plan, evidence_root, "capture plan"),
        "capturePlanSha256": checked["capturePlanSha256"],
        "observerBinaryPath": _evidence_path(
            staged_observer, evidence_root, "observer binary",
        ),
        "observerBuildReceiptPath": _evidence_path(
            staged_receipt, evidence_root, "observer build receipt",
        ),
    }
    try:
        documents = semantic_wire.parse_lines(
            lines, capture_binding=binding, evidence_root=evidence_root,
        )
    except semantic_wire.NativeDispatchWireError as error:
        raise NativeDispatchCaptureRunnerError(
            "observer wire or semantic oracle differs from the checked job"
        ) from error
    if len(documents) != 1 or documents[0].get("claimId") != checked["claimId"] \
            or documents[0].get("evidenceClass") != checked["evidenceClass"] \
            or documents[0].get("parityEligible") is not False:
        raise NativeDispatchCaptureRunnerError(
            "semantic candidate differs from the checked target"
        )
    isolation["observerLog"] = str(raw_path.resolve())
    result = {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": CAPTURED,
        "productionClaim": False,
        "parityEligible": False,
        "targetSha256": checked["targetSha256"],
        "jobId": checked["jobId"],
        "claimId": checked["claimId"],
        "processIdentity": process_identity,
        "rawLog": {
            "path": str(raw_path.resolve()),
            "sha256": raw_sha,
            "size": len(raw_bytes),
            "fullUnslicedFile": True,
        },
        "semanticCandidate": documents[0],
        "isolation": isolation,
    }
    if driver_receipt is not None and driver_receipt_path is not None:
        result["driverReceipt"] = {
            "path": _evidence_path(
                driver_receipt_path, evidence_root, "native dispatch driver receipt",
            ),
            "sha256": _sha256(driver_receipt_path),
            "receipt": driver_receipt,
        }
    return result


def run_capture_target(
    *, compilation: dict[str, Any], target: dict[str, Any], plan_path: Path,
    environment: Iterable[str], backend: dict[str, Any], executable: Path,
    evidence_root: Path, observer_dll: Path, observer_build_receipt: Path,
    proxy_dll: Path, real_dinput_dll: Path, observer_launcher: Path,
    expected_launcher_sha256: str,
    observe_ms: int = hangover_probe.DEFAULT_OBSERVE_MS,
) -> dict[str, Any]:
    """Public fixed-boundary entry point; callers cannot inject producers."""

    return _run_capture_target(
        compilation=compilation, target=target, plan_path=plan_path,
        environment=environment, backend=backend, executable=executable,
        evidence_root=evidence_root, observer_dll=observer_dll,
        observer_build_receipt=observer_build_receipt, proxy_dll=proxy_dll,
        real_dinput_dll=real_dinput_dll,
        observer_launcher=observer_launcher,
        expected_launcher_sha256=expected_launcher_sha256,
        observe_ms=observe_ms,
        _token=_BOUNDARY_TOKEN,
    )


def run_capture_suite(
    *, compilation: dict[str, Any], targets: Iterable[dict[str, Any]],
    plan_path: Path, environment: Iterable[str], backend: dict[str, Any],
    executable: Path, evidence_root: Path, observer_dll: Path,
    observer_build_receipts: Mapping[str, Path], proxy_dll: Path,
    real_dinput_dll: Path, observer_launcher: Path,
    expected_launcher_sha256: str,
    observe_ms: int = hangover_probe.DEFAULT_OBSERVE_MS,
) -> dict[str, Any]:
    """Run unique targets sequentially; never continue after an incomplete run."""

    selected = list(targets)
    identities = [row.get("targetSha256") for row in selected]
    if not selected or len(set(identities)) != len(identities):
        raise NativeDispatchCaptureRunnerError("suite targets must be non-empty and unique")
    exact_inventory = selected == compilation.get("targets") \
        and len(selected) == 155
    results: list[dict[str, Any]] = []
    process_ids: set[int] = set()
    sessions: set[str] = set()
    outputs: set[str] = set()
    logs: set[str] = set()
    for target in selected:
        receipt = observer_build_receipts.get(target.get("jobId"))
        if not isinstance(receipt, Path):
            raise NativeDispatchCaptureRunnerError(
                "suite has no exact observer build receipt for target"
            )
        result = _run_capture_target(
            compilation=compilation,
            target=target,
            plan_path=plan_path,
            environment=environment,
            backend=backend,
            executable=executable,
            evidence_root=evidence_root,
            observer_dll=observer_dll,
            observer_build_receipt=receipt,
            proxy_dll=proxy_dll,
            real_dinput_dll=real_dinput_dll,
            observer_launcher=observer_launcher,
            expected_launcher_sha256=expected_launcher_sha256,
            observe_ms=observe_ms,
            _token=_BOUNDARY_TOKEN,
        )
        results.append(result)
        if result["status"] != CAPTURED:
            return {
                "schema": 1, "protocol": PROTOCOL, "status": INCOMPLETE,
                "productionClaim": False, "parityEligible": False,
                "results": results,
            }
        identity = result["processIdentity"]
        process_id = identity["nativeProcessId"]
        session_id = identity["sessionId"]
        output_path = result["isolation"]["outputDirectory"]
        log_path = result["rawLog"]["path"]
        if process_id in process_ids or session_id in sessions:
            raise NativeDispatchCaptureRunnerError(
                "native process/session identity is reused"
            )
        if output_path in outputs or log_path in logs:
            raise NativeDispatchCaptureRunnerError(
                "native output/log path is reused"
            )
        process_ids.add(process_id)
        sessions.add(session_id)
        outputs.add(output_path)
        logs.add(log_path)
    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": CAPTURED if exact_inventory else "PARTIAL_CANDIDATE",
        "productionClaim": False,
        "parityEligible": False,
        "results": results,
    }
