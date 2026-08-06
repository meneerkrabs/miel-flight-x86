#!/usr/bin/env python3
"""Verify reviewed browser build/deploy receipts without granting trust.

Candidate receipts are inert.  A receipt is trusted only when its exact
content hash and canonical repository path occur in the fixed reviewed
registry.  This module never writes that registry.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

try:
    from tools.miel_vliegt import (
        browser_flight_runtime_source_manifest as runtime_source_manifest,
    )
except ModuleNotFoundError:
    import browser_flight_runtime_source_manifest as runtime_source_manifest


REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_REFERENCE = (
    "content/miel_vliegt/browser_flight_runtime_receipt_registry.json"
)
STORE_REFERENCE = "content/miel_vliegt/browser_flight_runtime_receipts"
SOURCE_STORE_REFERENCE = (
    "content/miel_vliegt/browser_flight_runtime_source_snapshots"
)
PROTOCOL = "miel-vliegt-browser-flight-runtime-receipt"
REGISTRY_PROTOCOL = "miel-vliegt-browser-flight-runtime-receipt-registry"
SHA256 = set("0123456789abcdef")


class BrowserFlightRuntimeReceiptError(ValueError):
    pass


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii"))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrowserFlightRuntimeReceiptError(
                f"duplicate JSON object key: {key}",
            )
        result[key] = value
    return result


def _float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise BrowserFlightRuntimeReceiptError("non-finite JSON number")
    return parsed


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                BrowserFlightRuntimeReceiptError(
                    f"non-finite JSON number: {token}",
                ),
            ),
            parse_float=_float,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrowserFlightRuntimeReceiptError(
            f"{label}: invalid JSON",
        ) from error
    if not isinstance(value, dict):
        raise BrowserFlightRuntimeReceiptError(f"{label} must be an object")
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BrowserFlightRuntimeReceiptError(f"{label} has an invalid shape")
    return value


def _hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in SHA256 for character in value)
    )


def _regular_repository_file(root: Path, reference: Any, label: str) -> Path:
    if not isinstance(reference, str) or not reference:
        raise BrowserFlightRuntimeReceiptError(f"{label} path is invalid")
    pure = PurePosixPath(reference)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != reference:
        raise BrowserFlightRuntimeReceiptError(f"{label} escapes the repository")
    root = root.absolute()
    path = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise BrowserFlightRuntimeReceiptError(
                f"{label} may not traverse a symlink",
            )
    if not path.is_file():
        raise BrowserFlightRuntimeReceiptError(f"{label} does not exist")
    return path


def _origin(value: Any) -> str:
    if not isinstance(value, str):
        raise BrowserFlightRuntimeReceiptError("runtime receipt origin is invalid")
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
        or value.rstrip("/") != f"{parsed.scheme}://{parsed.netloc}"
    ):
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt origin must be a canonical HTTP(S) origin",
        )
    return value.rstrip("/")


def _artifact(
    root: Path, value: Any, label: str, origin: str,
) -> tuple[dict[str, Any], Path]:
    row = _exact(value, {"url", "path", "sha256"}, label)
    if not _hash(row["sha256"]):
        raise BrowserFlightRuntimeReceiptError(f"{label} hash is invalid")
    parsed = urlparse(row["url"]) if isinstance(row["url"], str) else None
    if parsed is None or f"{parsed.scheme}://{parsed.netloc}" != origin:
        raise BrowserFlightRuntimeReceiptError(
            f"{label} URL is outside the reviewed origin",
        )
    path = _regular_repository_file(root, row["path"], label)
    if sha256_file(path) != row["sha256"]:
        raise BrowserFlightRuntimeReceiptError(f"{label} bytes drifted")
    return row, path


def validate_receipt(
    path: Path, *, root: Path = REPO_ROOT,
) -> tuple[dict[str, Any], list[Path]]:
    """Recompute every byte identity in one already-reviewed receipt."""

    root = root.absolute()
    if path.is_symlink():
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt may not be a symlink",
        )
    receipt = _exact(
        load_json(path, "runtime receipt"),
        {
            "schema", "protocol", "origin", "source", "image", "artifacts",
            "identity_sha256",
        },
        "runtime receipt",
    )
    if receipt["schema"] != 1 or receipt["protocol"] != PROTOCOL:
        raise BrowserFlightRuntimeReceiptError("unsupported runtime receipt")
    origin = _origin(receipt["origin"])
    source = _exact(
        receipt["source"],
        {
            "commit", "runtime_source_manifest", "tracked_inputs",
            "tracked_inputs_sha256",
        },
        "runtime receipt source",
    )
    commit = source["commit"]
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in SHA256 for character in commit)
    ):
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt source commit is invalid",
        )
    try:
        object_type = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-t", commit],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt source commit is unavailable",
        ) from error
    if object_type != "commit":
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt source identity is not a commit object",
        )
    try:
        runtime_source = runtime_source_manifest.validate_manifest(
            source["runtime_source_manifest"],
            root=root,
            commit=commit,
        )
    except runtime_source_manifest.BrowserFlightRuntimeSourceManifestError as error:
        raise BrowserFlightRuntimeReceiptError(str(error)) from error
    inputs = source["tracked_inputs"]
    if not isinstance(inputs, list) or not inputs:
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt tracked input closure is empty",
        )
    input_snapshots: list[Path] = []
    previous = ""
    for index, item in enumerate(inputs):
        row = _exact(
            item, {"path", "snapshot_path", "sha256"},
            f"runtime receipt tracked input {index}",
        )
        if (
            not isinstance(row["path"], str)
            or row["path"] <= previous
            or not _hash(row["sha256"])
            or row["snapshot_path"]
            != f"{SOURCE_STORE_REFERENCE}/{row['sha256']}.blob"
        ):
            raise BrowserFlightRuntimeReceiptError(
                "runtime receipt tracked inputs are duplicate or unsorted",
            )
        previous = row["path"]
        source_reference = PurePosixPath(row["path"])
        if (
            source_reference.is_absolute()
            or ".." in source_reference.parts
            or str(source_reference) != row["path"]
        ):
            raise BrowserFlightRuntimeReceiptError(
                "runtime receipt tracked source path is invalid",
            )
        snapshot_path = _regular_repository_file(
            root, row["snapshot_path"],
            f"runtime receipt tracked input snapshot {index}",
        )
        if sha256_file(snapshot_path) != row["sha256"]:
            raise BrowserFlightRuntimeReceiptError(
                f"runtime receipt tracked input snapshot drifted: {row['path']}",
            )
        try:
            git_object = subprocess.run(
                ["git", "-C", str(root), "show", f"{commit}:{row['path']}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as error:
            raise BrowserFlightRuntimeReceiptError(
                f"runtime receipt source commit does not contain {row['path']}",
            ) from error
        if sha256_bytes(git_object) != row["sha256"]:
            raise BrowserFlightRuntimeReceiptError(
                f"runtime receipt source snapshot differs from {commit}",
            )
        input_snapshots.append(snapshot_path)
    if source["tracked_inputs_sha256"] != canonical_sha256(inputs):
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt tracked input identity drifted",
        )
    expected_runtime_inputs = runtime_source["inputs"]
    actual_runtime_inputs = [
        {"path": row["path"], "sha256": row["sha256"]}
        for row in inputs
    ]
    if actual_runtime_inputs != expected_runtime_inputs:
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt tracked inputs do not exactly cover the "
            "production runtime source manifest",
        )

    image = _exact(
        receipt["image"],
        {"reference", "digest", "platform"},
        "runtime receipt image",
    )
    expected_digest = (
        image["digest"][7:]
        if isinstance(image["digest"], str)
        and image["digest"].startswith("sha256:")
        else None
    )
    if (
        not _hash(expected_digest)
        or not isinstance(image["reference"], str)
        or not image["reference"].endswith(f"@sha256:{expected_digest}")
        or image["platform"] not in {"linux/amd64", "linux/arm64"}
    ):
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt image identity is invalid",
        )

    artifacts = _exact(
        receipt["artifacts"],
        {"bundle", "version", "web_transition_build", "assets"},
        "runtime receipt artifacts",
    )
    bundle, bundle_path = _artifact(
        root, artifacts["bundle"], "runtime receipt bundle", origin,
    )
    version, version_path = _artifact(
        root, artifacts["version"], "runtime receipt version", origin,
    )
    transition, transition_path = _artifact(
        root,
        artifacts["web_transition_build"],
        "runtime receipt web transition build",
        origin,
    )
    assets = artifacts["assets"]
    if not isinstance(assets, list) or not assets:
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt asset closure is empty",
        )
    asset_paths: list[Path] = []
    previous_url = ""
    for index, item in enumerate(assets):
        row, asset_path = _artifact(
            root, item, f"runtime receipt asset {index}", origin,
        )
        if row["url"] <= previous_url:
            raise BrowserFlightRuntimeReceiptError(
                "runtime receipt assets are duplicate or unsorted",
            )
        previous_url = row["url"]
        asset_paths.append(asset_path)
    transition_value = load_json(
        transition_path, "runtime receipt web transition build",
    )
    transition_value = _exact(
        transition_value,
        {"schema", "protocol", "inputs", "build_sha256"},
        "runtime receipt web transition build",
    )
    if (
        transition_value.get("schema") != 1
        or transition_value.get("protocol")
        != "miel-web-scene-transition-build"
        or transition_value.get("build_sha256")
        != canonical_sha256({
            "schema": transition_value.get("schema"),
            "protocol": transition_value.get("protocol"),
            "inputs": transition_value.get("inputs"),
        })
    ):
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt web transition build identity is invalid",
        )
    transition_inputs = transition_value.get("inputs")
    if not isinstance(transition_inputs, list):
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt web transition build inputs are invalid",
        )
    tracked_by_path = {row["path"]: row["sha256"] for row in inputs}
    seen_transition_paths: set[str] = set()
    for row in transition_inputs:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256"}
            or not isinstance(row["path"], str)
            or row["path"] in seen_transition_paths
            or tracked_by_path.get(row["path"]) != row["sha256"]
        ):
            raise BrowserFlightRuntimeReceiptError(
                "web transition build is not covered by tracked inputs",
            )
        seen_transition_paths.add(row["path"])
    version_text = version_path.read_text(encoding="utf-8").strip()
    if commit[:12] not in version_text:
        raise BrowserFlightRuntimeReceiptError(
            "runtime version does not bind the source commit",
        )
    identity = {
        "schema": receipt["schema"],
        "protocol": receipt["protocol"],
        "origin": origin,
        "source": source,
        "image": image,
        "artifacts": artifacts,
    }
    if receipt["identity_sha256"] != canonical_sha256(identity):
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt identity drifted",
        )
    return receipt, [
        path, bundle_path, version_path, transition_path,
        *asset_paths, *input_snapshots,
    ]


def verify_reviewed_receipt(
    receipt_path: Path, *, root: Path = REPO_ROOT,
) -> tuple[dict[str, Any], list[Path]]:
    """Require exact membership in the fixed, reviewed trust registry."""

    root = root.absolute()
    verify_registry(root=root)
    registry_path = root / REGISTRY_REFERENCE
    if registry_path.is_symlink():
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt registry may not be a symlink",
        )
    registry = _exact(
        load_json(registry_path, "runtime receipt registry"),
        {"schema", "protocol", "receipts"},
        "runtime receipt registry",
    )
    if (
        registry["schema"] != 1
        or registry["protocol"] != REGISTRY_PROTOCOL
        or not isinstance(registry["receipts"], list)
    ):
        raise BrowserFlightRuntimeReceiptError(
            "unsupported runtime receipt registry",
        )
    supplied = receipt_path.absolute()
    matches = []
    seen: set[str] = set()
    for index, item in enumerate(registry["receipts"]):
        row = _exact(
            item, {"id", "path"}, f"runtime receipt registry row {index}",
        )
        if (
            not _hash(row["id"])
            or row["id"] in seen
            or row["path"] != f"{STORE_REFERENCE}/{row['id']}.json"
        ):
            raise BrowserFlightRuntimeReceiptError(
                "runtime receipt registry contains duplicate identities",
            )
        seen.add(row["id"])
        reviewed_path = _regular_repository_file(
            root, row["path"], f"runtime receipt registry row {index}",
        )
        if reviewed_path.absolute() == supplied:
            matches.append((row, reviewed_path))
    if len(matches) != 1:
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt is not present exactly once in the reviewed registry",
        )
    row, reviewed_path = matches[0]
    if sha256_file(reviewed_path) != row["id"]:
        raise BrowserFlightRuntimeReceiptError(
            "reviewed runtime receipt content hash drifted",
        )
    receipt, dependencies = validate_receipt(reviewed_path, root=root)
    return receipt, dependencies


def verify_registry(*, root: Path = REPO_ROOT) -> dict[str, Any]:
    """Validate the complete reviewed trust root, including every receipt."""

    root = root.absolute()
    registry_path = root / REGISTRY_REFERENCE
    if registry_path.is_symlink():
        raise BrowserFlightRuntimeReceiptError(
            "runtime receipt registry may not be a symlink",
        )
    registry = _exact(
        load_json(registry_path, "runtime receipt registry"),
        {"schema", "protocol", "receipts"},
        "runtime receipt registry",
    )
    if (
        registry["schema"] != 1
        or registry["protocol"] != REGISTRY_PROTOCOL
        or not isinstance(registry["receipts"], list)
    ):
        raise BrowserFlightRuntimeReceiptError(
            "unsupported runtime receipt registry",
        )
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, item in enumerate(registry["receipts"]):
        row = _exact(
            item, {"id", "path"}, f"runtime receipt registry row {index}",
        )
        if (
            not _hash(row["id"])
            or row["id"] in seen_ids
            or not isinstance(row["path"], str)
            or row["path"] in seen_paths
            or row["path"] != f"{STORE_REFERENCE}/{row['id']}.json"
        ):
            raise BrowserFlightRuntimeReceiptError(
                "runtime receipt registry contains duplicate or noncanonical "
                "identities",
            )
        seen_ids.add(row["id"])
        seen_paths.add(row["path"])
        reviewed_path = _regular_repository_file(
            root, row["path"], f"runtime receipt registry row {index}",
        )
        if sha256_file(reviewed_path) != row["id"]:
            raise BrowserFlightRuntimeReceiptError(
                "reviewed runtime receipt content hash drifted",
            )
        validate_receipt(reviewed_path, root=root)
    return registry
