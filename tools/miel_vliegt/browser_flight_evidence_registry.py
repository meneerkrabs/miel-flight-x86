#!/usr/bin/env python3
"""Import and verify one immutable production-browser flight capture.

The registry is a fixed, single-slot trust root.  Import is serialized across
processes, vendors the complete byte closure, survives a crash between content
publication and registry publication, and never trusts caller-provided hashes
or a caller-selected registry.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterator
from urllib.parse import urljoin

try:
    from tools.miel_vliegt import browser_flight_capture_artifacts as capture
    from tools.miel_vliegt import browser_flight_runtime_receipts as receipts
    from tools.miel_vliegt import native_scenario_artifacts as scenarios
except ModuleNotFoundError:
    import browser_flight_capture_artifacts as capture
    import browser_flight_runtime_receipts as receipts
    import native_scenario_artifacts as scenarios


REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_REFERENCE = "content/miel_vliegt/browser_flight_evidence_registry.json"
LOCK_DIRECTORY_NAME = "miel-vliegt-browser-flight-evidence-locks"
FALLBACK_RUNTIME_DIRECTORY_PREFIX = "miel-vliegt-runtime"
STORE_REFERENCE = "content/miel_vliegt/browser_flight_evidence"
PROTOCOL = "miel-vliegt-browser-flight-evidence-registry"
SHA256 = set("0123456789abcdef")


class BrowserEvidenceRegistryError(ValueError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in SHA256 for character in value)
    )


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        return receipts.load_json(path, label)
    except receipts.BrowserFlightRuntimeReceiptError as error:
        raise BrowserEvidenceRegistryError(str(error)) from error


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BrowserEvidenceRegistryError(f"{label} has an invalid shape")
    return value


def _empty_registry() -> dict[str, Any]:
    return {"schema": 1, "protocol": PROTOCOL, "capture": None}


def _render(value: Any) -> bytes:
    return (
        json.dumps(
            value, indent=2, ensure_ascii=False, sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _registry_path(root: Path) -> Path:
    return root / REGISTRY_REFERENCE


def _store_path(root: Path) -> Path:
    return root / STORE_REFERENCE


def _is_private_runtime_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _create_private_runtime_directory(path: Path, label: str) -> Path:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise BrowserEvidenceRegistryError(
            f"{label} could not be created: {path}",
        ) from error
    if not _is_private_runtime_directory(path):
        raise BrowserEvidenceRegistryError(
            f"{label} must be a user-owned 0700 directory: {path}",
        )
    return path


def _runtime_lock_root() -> Path:
    configured = os.environ.get("XDG_RUNTIME_DIR")
    if configured:
        candidate = Path(configured)
        if candidate.is_absolute() and _is_private_runtime_directory(candidate):
            return candidate.resolve(strict=True)

    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    fallback = (
        temporary_root
        / f"{FALLBACK_RUNTIME_DIRECTORY_PREFIX}-{os.getuid()}"
    )
    return _create_private_runtime_directory(
        fallback, "browser evidence fallback runtime directory",
    )


def _registry_lock_directory() -> Path:
    return _create_private_runtime_directory(
        _runtime_lock_root() / LOCK_DIRECTORY_NAME,
        "browser evidence lock directory",
    )


def _registry_lock_path(root: Path) -> Path:
    canonical_root = root.resolve(strict=True)
    repository_key = hashlib.sha256(
        os.fsencode(str(canonical_root)),
    ).hexdigest()
    return _registry_lock_directory() / f"{repository_key}.lock"


def _path_reference(path: Path, root: Path, label: str) -> str:
    try:
        return path.absolute().relative_to(root.absolute()).as_posix()
    except ValueError as error:
        raise BrowserEvidenceRegistryError(
            f"{label} is outside the repository",
        ) from error


def _canonical_reference(reference: Any, label: str) -> PurePosixPath:
    if not isinstance(reference, str) or not reference:
        raise BrowserEvidenceRegistryError(f"{label} must be a repository path")
    pure = PurePosixPath(reference)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != reference:
        raise BrowserEvidenceRegistryError(f"{label} escapes the repository")
    return pure


def _reject_symlink_components(path: Path, stop: Path, label: str) -> None:
    path = path.absolute()
    stop = stop.absolute()
    try:
        relative = path.relative_to(stop)
    except ValueError as error:
        raise BrowserEvidenceRegistryError(
            f"{label} is outside its declared root",
        ) from error
    current = stop
    if current.is_symlink():
        raise BrowserEvidenceRegistryError(f"{label} root may not be a symlink")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise BrowserEvidenceRegistryError(
                f"{label} may not traverse a symlink",
            )


def _repository_path(root: Path, reference: Any, label: str) -> Path:
    pure = _canonical_reference(reference, label)
    root = root.absolute()
    path = root.joinpath(*pure.parts)
    _reject_symlink_components(path, root, label)
    if not path.is_file():
        raise BrowserEvidenceRegistryError(f"{label} does not exist: {reference}")
    return path


def _source_file(path: Path, source_root: Path, label: str) -> Path:
    path = path.absolute()
    source_root = source_root.absolute()
    _reject_symlink_components(path, source_root, label)
    if not path.is_file():
        raise BrowserEvidenceRegistryError(f"{label} does not exist: {path}")
    if path.suffix == ".json":
        _load(path, label)
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_file(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    _fsync_directory(path.parent)


def _copy_exact(source: Path, destination: Path) -> None:
    payload = source.read_bytes()
    if destination.exists() or destination.is_symlink():
        if (
            destination.is_symlink()
            or not destination.is_file()
            or destination.read_bytes() != payload
        ):
            raise BrowserEvidenceRegistryError(
                f"nonidentical evidence overwrite rejected: {destination}",
            )
        return
    _write_file(destination, payload)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextlib.contextmanager
def _registry_lock(root: Path) -> Iterator[None]:
    lock_path = _registry_lock_path(root)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise BrowserEvidenceRegistryError(
                "browser evidence lock must be a regular file",
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _suite_dependencies(
    suite_path: Path,
) -> list[tuple[Path, Path]]:
    suite_path = suite_path.absolute()
    suite_root = suite_path.parent
    _source_file(suite_path, suite_root, "scenario suite")
    suite = scenarios.load_scenario_suite_manifest(suite_path)
    dependencies: list[tuple[Path, Path]] = [
        (suite_path, Path("suite/suite-spec.json")),
    ]
    seen = {Path("suite/suite-spec.json")}
    for entry in suite["scenarios"]:
        for field in ("scenario", "native_replay"):
            relative = Path(entry[field]["path"])
            destination = Path("suite") / relative
            source = _source_file(
                suite_root / relative, suite_root,
                f"scenario suite {entry['id']} {field}",
            )
            if destination in seen:
                raise BrowserEvidenceRegistryError(
                    f"duplicate suite dependency: {destination}",
                )
            seen.add(destination)
            dependencies.append((source, destination))
        scenario_path = suite_root / entry["scenario"]["path"]
        scenario = scenarios.load_scenario(scenario_path, root=suite_root)
        for initial_file in scenario["initial_state"]["files"]:
            relative = Path(initial_file["path"])
            destination = Path("suite") / relative
            source = _source_file(
                suite_root / relative, suite_root,
                f"scenario suite {entry['id']} initial state",
            )
            if destination in seen:
                existing = next(
                    candidate for candidate, target in dependencies
                    if target == destination
                )
                if existing.read_bytes() != source.read_bytes():
                    raise BrowserEvidenceRegistryError(
                        f"mixed suite dependency bytes: {destination}",
                    )
                continue
            seen.add(destination)
            dependencies.append((source, destination))
    return dependencies


def _capture_dependencies(
    manifest_path: Path,
) -> list[tuple[Path, Path]]:
    manifest_path = manifest_path.absolute()
    capture_root = manifest_path.parent.parent
    _source_file(manifest_path, capture_root, "capture manifest")
    manifest = _load(manifest_path, "capture manifest")
    dependencies: list[tuple[Path, Path]] = [
        (manifest_path, Path("manifests") / manifest_path.name),
    ]
    seen = {dependencies[0][1]}
    rows = manifest.get("artifacts")
    if not isinstance(rows, list):
        raise BrowserEvidenceRegistryError("capture artifacts must be an array")
    for row in rows:
        if not isinstance(row, dict):
            raise BrowserEvidenceRegistryError(
                "capture artifact has an invalid shape",
            )
        references = [row.get("path")]
        framebuffers = row.get("framebuffer_artifacts")
        if not isinstance(framebuffers, list):
            raise BrowserEvidenceRegistryError(
                "capture framebuffer artifacts must be an array",
            )
        references.extend(
            framebuffer.get("path") if isinstance(framebuffer, dict) else None
            for framebuffer in framebuffers
        )
        for reference in references:
            pure = _canonical_reference(
                reference, "capture dependency",
            )
            relative = Path(*pure.parts)
            if relative in seen:
                continue
            seen.add(relative)
            source = _source_file(
                capture_root / relative, capture_root, "capture dependency",
            )
            dependencies.append((source, relative))
    return dependencies


def _runtime_dependencies(
    root: Path, receipt_path: Path,
) -> tuple[dict[str, Any], list[tuple[Path, Path]]]:
    try:
        receipt, paths = receipts.verify_reviewed_receipt(
            receipt_path, root=root,
        )
    except receipts.BrowserFlightRuntimeReceiptError as error:
        raise BrowserEvidenceRegistryError(str(error)) from error
    dependencies = []
    seen: set[Path] = set()
    for source in paths:
        reference = _path_reference(source, root, "runtime receipt dependency")
        destination = Path("runtime/repository") / Path(reference)
        if destination in seen:
            continue
        seen.add(destination)
        dependencies.append((source, destination))
    return receipt, dependencies


def _match_runtime_identity(
    manifest: dict[str, Any], receipt: dict[str, Any],
) -> None:
    runtime = manifest.get("runtime_identity")
    if not isinstance(runtime, dict):
        raise BrowserEvidenceRegistryError(
            "capture runtime identity is unavailable",
        )
    artifacts = receipt["artifacts"]
    bundle = runtime.get("bundle")
    if (
        not isinstance(bundle, dict)
        or bundle.get("url") != artifacts["bundle"]["url"]
        or bundle.get("sha256") != artifacts["bundle"]["sha256"]
    ):
        raise BrowserEvidenceRegistryError(
            "capture bundle differs from reviewed runtime receipt",
        )
    expected_assets = {
        (row["url"], row["sha256"]) for row in artifacts["assets"]
    }
    parts = runtime.get("parts")
    if not isinstance(parts, dict):
        raise BrowserEvidenceRegistryError(
            "capture parts differ from reviewed runtime receipt",
        )
    origin = receipt["origin"].rstrip("/") + "/"
    texture_assets = runtime.get("texture_assets")
    if not isinstance(texture_assets, list):
        raise BrowserEvidenceRegistryError(
            "capture texture assets are unavailable",
        )
    observed_assets = {(parts.get("url"), parts.get("sha256"))}
    for asset in texture_assets:
        if not isinstance(asset, dict):
            raise BrowserEvidenceRegistryError(
                "capture texture asset is invalid",
            )
        observed_assets.add((
            urljoin(origin, asset.get("asset_url", "")),
            asset.get("observed_sha256"),
        ))
    if observed_assets != expected_assets:
        raise BrowserEvidenceRegistryError(
            "capture textures differ from reviewed runtime receipt",
        )


def _walk_regular_files(root: Path, label: str) -> list[Path]:
    files: list[Path] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            child = directory_path / name
            if child.is_symlink():
                raise BrowserEvidenceRegistryError(
                    f"{label} contains a symlink",
                )
        for name in filenames:
            child = directory_path / name
            if child.is_symlink() or not child.is_file():
                raise BrowserEvidenceRegistryError(
                    f"{label} contains a non-regular file",
                )
            files.append(child)
    return sorted(files)


def _fsync_tree(root: Path) -> None:
    directories = [Path(directory) for directory, _names, _files in os.walk(root)]
    for directory in sorted(
        directories, key=lambda path: len(path.parts), reverse=True,
    ):
        _fsync_directory(directory)


def _entry_for_staged(
    capture_id: str, staged_capture: Path, trusted_receipt_path: str,
    trusted_receipt: dict[str, Any],
) -> dict[str, Any]:
    manifest_path = staged_capture / "manifests" / f"{capture_id}.json"
    suite_path = staged_capture / "suite/suite-spec.json"
    report = capture.verify_capture(manifest_path, suite_path)
    if [row["scenario"] for row in report["verified"]] != list(
        scenarios.SCENARIO_ID_ORDER
    ):
        raise BrowserEvidenceRegistryError(
            "verified capture is not the canonical seven-scenario suite",
        )
    manifest = _load(manifest_path, "vendored capture manifest")
    _match_runtime_identity(manifest, trusted_receipt)
    artifact_by_id: dict[str, dict[str, Any]] = {}
    for row in manifest["artifacts"]:
        if row["scenario"] in artifact_by_id:
            raise BrowserEvidenceRegistryError(
                "vendored capture contains duplicate scenarios",
            )
        artifact_by_id[row["scenario"]] = row
    if set(artifact_by_id) != set(scenarios.SCENARIO_ID_ORDER):
        raise BrowserEvidenceRegistryError(
            "vendored capture scenarios are incomplete",
        )
    prefix = f"{STORE_REFERENCE}/{capture_id}"
    receipt_id = _sha256(Path(staged_capture) / "runtime/repository" / trusted_receipt_path)
    files = [{
        "path": f"{prefix}/{path.relative_to(staged_capture).as_posix()}",
        "sha256": _sha256(path),
    } for path in _walk_regular_files(staged_capture, "staged capture")]
    return {
        "id": capture_id,
        "manifest": {
            "path": f"{prefix}/manifests/{capture_id}.json",
            "sha256": capture_id,
        },
        "suite": {
            "path": f"{prefix}/suite/suite-spec.json",
            "sha256": _sha256(suite_path),
        },
        "runtime_receipt": {
            "id": receipt_id,
            "trusted_path": trusted_receipt_path,
            "vendored_path": (
                f"{prefix}/runtime/repository/{trusted_receipt_path}"
            ),
            "origin": trusted_receipt["origin"],
            "source_commit": trusted_receipt["source"]["commit"],
            "image_digest": trusted_receipt["image"]["digest"],
        },
        "scenarios": [{
            "id": identifier,
            "web_output": f"{prefix}/{artifact_by_id[identifier]['path']}",
            "sha256": artifact_by_id[identifier]["sha256"],
        } for identifier in scenarios.SCENARIO_ID_ORDER],
        "files": files,
    }


def _compare_trees(left: Path, right: Path) -> bool:
    left_files = {
        path.relative_to(left).as_posix(): _sha256(path)
        for path in _walk_regular_files(left, "staged capture")
    }
    right_files = {
        path.relative_to(right).as_posix(): _sha256(path)
        for path in _walk_regular_files(right, "published capture")
    }
    return left_files == right_files


def _validate_entry(
    root: Path, entry: Any,
) -> tuple[dict[str, Any], dict[str, str]]:
    entry = _exact(
        entry,
        {"id", "manifest", "suite", "runtime_receipt", "scenarios", "files"},
        "browser evidence capture",
    )
    if not _hash(entry["id"]):
        raise BrowserEvidenceRegistryError("browser evidence capture id is invalid")
    prefix = f"{STORE_REFERENCE}/{entry['id']}"
    capture_root = root / prefix
    _reject_symlink_components(capture_root, root, "browser evidence store")
    if not capture_root.is_dir():
        raise BrowserEvidenceRegistryError(
            "browser evidence capture root does not exist",
        )
    manifest_ref = _exact(
        entry["manifest"], {"path", "sha256"}, "browser evidence manifest",
    )
    suite_ref = _exact(
        entry["suite"], {"path", "sha256"}, "browser evidence suite",
    )
    expected_manifest = f"{prefix}/manifests/{entry['id']}.json"
    expected_suite = f"{prefix}/suite/suite-spec.json"
    if (
        manifest_ref != {"path": expected_manifest, "sha256": entry["id"]}
        or suite_ref.get("path") != expected_suite
        or not _hash(suite_ref.get("sha256"))
    ):
        raise BrowserEvidenceRegistryError(
            "browser evidence paths are not canonical",
        )
    manifest_path = _repository_path(
        root, manifest_ref["path"], "browser evidence manifest",
    )
    suite_path = _repository_path(
        root, suite_ref["path"], "browser evidence suite",
    )
    if (
        _sha256(manifest_path) != manifest_ref["sha256"]
        or _sha256(suite_path) != suite_ref["sha256"]
    ):
        raise BrowserEvidenceRegistryError("browser evidence identity drifted")

    receipt_ref = _exact(
        entry["runtime_receipt"],
        {
            "id", "trusted_path", "vendored_path", "origin",
            "source_commit", "image_digest",
        },
        "browser evidence runtime receipt",
    )
    if not _hash(receipt_ref["id"]):
        raise BrowserEvidenceRegistryError(
            "browser evidence runtime receipt id is invalid",
        )
    trusted_path = _repository_path(
        root, receipt_ref["trusted_path"], "trusted runtime receipt",
    )
    expected_vendored = (
        f"{prefix}/runtime/repository/{receipt_ref['trusted_path']}"
    )
    if receipt_ref["vendored_path"] != expected_vendored:
        raise BrowserEvidenceRegistryError(
            "browser evidence runtime receipt path is not canonical",
        )
    vendored_path = _repository_path(
        root, receipt_ref["vendored_path"], "vendored runtime receipt",
    )
    try:
        trusted_receipt, dependencies = receipts.verify_reviewed_receipt(
            trusted_path, root=root,
        )
    except receipts.BrowserFlightRuntimeReceiptError as error:
        raise BrowserEvidenceRegistryError(str(error)) from error
    if (
        _sha256(trusted_path) != receipt_ref["id"]
        or trusted_path.read_bytes() != vendored_path.read_bytes()
        or receipt_ref["origin"] != trusted_receipt["origin"]
        or receipt_ref["source_commit"] != trusted_receipt["source"]["commit"]
        or receipt_ref["image_digest"] != trusted_receipt["image"]["digest"]
    ):
        raise BrowserEvidenceRegistryError(
            "browser evidence runtime receipt identity drifted",
        )
    for dependency in dependencies:
        reference = _path_reference(
            dependency, root, "runtime receipt dependency",
        )
        vendored = _repository_path(
            root, f"{prefix}/runtime/repository/{reference}",
            "vendored runtime receipt dependency",
        )
        if dependency.read_bytes() != vendored.read_bytes():
            raise BrowserEvidenceRegistryError(
                "vendored runtime receipt dependency drifted",
            )

    manifest = _load(manifest_path, "browser evidence manifest")
    _match_runtime_identity(manifest, trusted_receipt)
    artifacts = {
        row["scenario"]: row for row in manifest.get("artifacts", [])
        if isinstance(row, dict) and isinstance(row.get("scenario"), str)
    }
    rows = entry["scenarios"]
    if not isinstance(rows, list) or len(rows) != len(
        scenarios.SCENARIO_ID_ORDER
    ):
        raise BrowserEvidenceRegistryError(
            "browser evidence needs exactly seven scenario rows",
        )
    outputs: dict[str, str] = {}
    for expected_id, row in zip(scenarios.SCENARIO_ID_ORDER, rows, strict=True):
        row = _exact(
            row, {"id", "web_output", "sha256"},
            f"browser evidence scenario {expected_id}",
        )
        artifact = artifacts.get(expected_id)
        expected_output = (
            f"{prefix}/{artifact['path']}"
            if isinstance(artifact, dict) and isinstance(artifact.get("path"), str)
            else None
        )
        if (
            row["id"] != expected_id
            or expected_id in outputs
            or not _hash(row["sha256"])
            or row["web_output"] != expected_output
        ):
            raise BrowserEvidenceRegistryError(
                "browser evidence scenarios are duplicate, out of order, "
                "or noncanonical",
            )
        output = _repository_path(
            root, row["web_output"],
            f"browser evidence scenario {expected_id}",
        )
        if _sha256(output) != row["sha256"]:
            raise BrowserEvidenceRegistryError(
                f"browser evidence scenario hash drifted: {expected_id}",
            )
        outputs[expected_id] = row["web_output"]

    files = entry["files"]
    if not isinstance(files, list) or not files:
        raise BrowserEvidenceRegistryError("browser evidence file closure is empty")
    declared: dict[str, str] = {}
    previous = ""
    for index, row in enumerate(files):
        row = _exact(
            row, {"path", "sha256"}, f"browser evidence file {index}",
        )
        if (
            not isinstance(row["path"], str)
            or row["path"] <= previous
            or not row["path"].startswith(f"{prefix}/")
            or not _hash(row["sha256"])
        ):
            raise BrowserEvidenceRegistryError(
                "browser evidence file closure is duplicate, unsorted, "
                "or outside the capture root",
            )
        previous = row["path"]
        path = _repository_path(
            root, row["path"], f"browser evidence file {index}",
        )
        if path.suffix == ".json":
            _load(path, f"browser evidence file {index}")
        if _sha256(path) != row["sha256"]:
            raise BrowserEvidenceRegistryError(
                f"browser evidence file hash drifted: {row['path']}",
            )
        declared[row["path"]] = row["sha256"]
    actual = {
        f"{prefix}/{path.relative_to(capture_root).as_posix()}": _sha256(path)
        for path in _walk_regular_files(capture_root, "browser evidence capture")
    }
    if declared != actual:
        raise BrowserEvidenceRegistryError(
            "browser evidence file closure is partial or contains undeclared files",
        )
    report = capture.verify_capture(manifest_path, suite_path)
    verified = {
        row["scenario"]: row["trace_sha256"] for row in report["verified"]
    }
    for row in rows:
        if verified.get(row["id"]) != row["sha256"]:
            raise BrowserEvidenceRegistryError(
                f"browser evidence verifier disagrees for {row['id']}",
            )
    return entry, outputs


def verify_registry(
    *, root: Path = REPO_ROOT,
) -> tuple[dict[str, Any], dict[str, str]]:
    root = root.absolute()
    registry_path = _registry_path(root)
    _reject_symlink_components(
        registry_path, root, "browser evidence registry",
    )
    try:
        receipts.verify_registry(root=root)
    except receipts.BrowserFlightRuntimeReceiptError as error:
        raise BrowserEvidenceRegistryError(str(error)) from error
    registry = _exact(
        _load(registry_path, "browser evidence registry"),
        {"schema", "protocol", "capture"},
        "browser evidence registry",
    )
    if registry["schema"] != 1 or registry["protocol"] != PROTOCOL:
        raise BrowserEvidenceRegistryError(
            "unsupported browser evidence registry",
        )
    if registry["capture"] is None:
        return registry, {}
    _entry, outputs = _validate_entry(root, registry["capture"])
    return registry, outputs


def import_capture(
    manifest_path: Path, suite_path: Path, runtime_receipt_path: Path,
    *, root: Path = REPO_ROOT,
) -> dict[str, Any]:
    """Verify, vendor, and atomically publish one canonical capture."""

    root = root.absolute()
    manifest_path = manifest_path.absolute()
    suite_path = suite_path.absolute()
    runtime_receipt_path = runtime_receipt_path.absolute()
    # Source validation precedes all writes.
    _load(manifest_path, "capture manifest")
    _load(suite_path, "scenario suite")
    capture.verify_capture(manifest_path, suite_path)
    trusted_receipt, runtime_dependencies = _runtime_dependencies(
        root, runtime_receipt_path,
    )
    manifest_value = _load(manifest_path, "capture manifest")
    _match_runtime_identity(manifest_value, trusted_receipt)
    capture_id = _sha256(manifest_path)
    destination = _store_path(root) / capture_id
    registry_path = _registry_path(root)

    with _registry_lock(root):
        registry, _outputs = verify_registry(root=root)
        old_registry_bytes = registry_path.read_bytes()
        staging_parent = _store_path(root)
        _reject_symlink_components(
            staging_parent, root, "browser evidence store",
        )
        staging_parent.mkdir(parents=True, exist_ok=True)
        _fsync_directory(staging_parent.parent)
        destination_created = False
        published_payload: bytes | None = None
        entry: dict[str, Any]
        try:
            with tempfile.TemporaryDirectory(
                prefix=f".{capture_id}.", dir=staging_parent,
            ) as temporary:
                staged = Path(temporary)
                all_dependencies = (
                    _capture_dependencies(manifest_path)
                    + _suite_dependencies(suite_path)
                    + runtime_dependencies
                )
                seen_destinations: dict[Path, bytes] = {}
                for source, relative in all_dependencies:
                    payload = source.read_bytes()
                    if relative in seen_destinations:
                        if seen_destinations[relative] != payload:
                            raise BrowserEvidenceRegistryError(
                                f"mixed dependency bytes: {relative}",
                            )
                        continue
                    seen_destinations[relative] = payload
                    _copy_exact(source, staged / relative)
                trusted_reference = _path_reference(
                    runtime_receipt_path, root, "trusted runtime receipt",
                )
                entry = _entry_for_staged(
                    capture_id, staged, trusted_reference, trusted_receipt,
                )
                _fsync_tree(staged)
                existing = registry["capture"]
                if existing is not None:
                    if existing != entry:
                        raise BrowserEvidenceRegistryError(
                            "nonidentical browser evidence registry overwrite rejected",
                        )
                    _validate_entry(root, existing)
                    return registry
                if destination.exists() or destination.is_symlink():
                    if destination.is_symlink() or not destination.is_dir():
                        raise BrowserEvidenceRegistryError(
                            "browser evidence destination is not a directory",
                        )
                    if not _compare_trees(staged, destination):
                        raise BrowserEvidenceRegistryError(
                            "unregistered browser evidence destination is "
                            "partial or nonidentical",
                        )
                    # Exact content-addressed orphan from a prior interrupted
                    # publication is safe to reuse.
                else:
                    os.replace(staged, destination)
                    destination_created = True
                    _fsync_directory(staging_parent)

            published = {
                "schema": 1,
                "protocol": PROTOCOL,
                "capture": entry,
            }
            published_payload = _render(published)
            _atomic_write(registry_path, published_payload)
            verified, _outputs = verify_registry(root=root)
            if (
                registry_path.read_bytes() != published_payload
                or verified != published
            ):
                raise BrowserEvidenceRegistryError(
                    "post-publication registry differs from this importer",
                )
            return published
        except Exception:
            if registry_path.is_file() and not registry_path.is_symlink():
                current_registry_bytes = registry_path.read_bytes()
                if (
                    published_payload is not None
                    and current_registry_bytes == published_payload
                ):
                    _atomic_write(registry_path, old_registry_bytes)
                    current_registry_bytes = old_registry_bytes
                if (
                    destination_created
                    and current_registry_bytes == old_registry_bytes
                    and destination.exists()
                ):
                    shutil.rmtree(destination, ignore_errors=False)
                    _fsync_directory(destination.parent)
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--runtime-receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        registry = import_capture(
            args.manifest, args.suite, args.runtime_receipt,
        )
    except (OSError, TypeError, ValueError) as error:
        print(f"BROWSER EVIDENCE IMPORT FAILED: {error}", file=sys.stderr)
        return 2
    print(
        "browser evidence registry: "
        f"capture={registry['capture']['id']} scenarios=7",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
