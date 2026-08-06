#!/usr/bin/env python3
"""Validate the reviewed LibreShockwave renderer source pin without building it."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "tools/miel_vliegt/libreshockwave.json"
EXPECTED_REPOSITORY = "https://github.com/Quackster/LibreShockwave.git"
EXPECTED_COMMIT = "f8efd3f61fd4032b7176302b6a681a1fca7257fe"
EXPECTED_COMMIT_DATE = "2026-07-06T04:52:36Z"
EXPECTED_ARCHIVE_SHA256 = "b0c2b0dee2f14fbee6a58d9eaf5c1d6d1e53c38eeb7740eb538370256a7156dd"
EXPECTED_LICENSE_SHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
EXPECTED_EXPORTER_PATH = "tools/miel_vliegt/director_renderer/Exporter.cpp"
EXPECTED_FONT_MAP_PROBE_PATH = (
    "tools/miel_vliegt/director_renderer/FontMapProbe.cpp"
)
EXPECTED_PATHS = (
    "CMakeLists.txt",
    "LICENCE",
    "cpp/CMakeLists.txt",
    "cpp/apps/tools/RenderProbe.cpp",
    "cpp/src/chunks/ScoreChunk.cpp",
    "cpp/include/libreshockwave/player/render/output/SoftwareFrameRenderer.hpp",
    "cpp/include/libreshockwave/player/render/pipeline/FrameRenderPipeline.hpp",
    "cpp/src/player/render/output/SoftwareFrameRenderer.cpp",
    "cpp/src/player/render/pipeline/FrameRenderPipeline.cpp",
)
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def validate_manifest(path: Path = DEFAULT_MANIFEST, *, root: Path = ROOT) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read LibreShockwave manifest {path}: {exc}") from exc

    required = {
        "schema", "repository", "commit", "commit_date", "archive_sha256",
        "license", "license_file_sha256", "integration_mode", "build_target",
        "minimum_cmake", "language_standard", "runtime_status", "expected_paths",
        "compatibility_patch", "compatibility_patch_sha256",
        "exporter_path", "exporter_sha256",
        "font_map_probe_build_target", "font_map_probe_path",
        "font_map_probe_sha256",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError(
            "LibreShockwave manifest fields drifted: "
            f"expected={sorted(required)}, actual={sorted(document) if isinstance(document, dict) else type(document).__name__}")
    if document["schema"] != 1:
        raise ValueError("LibreShockwave manifest schema must be 1")
    if document["repository"] != EXPECTED_REPOSITORY:
        raise ValueError("LibreShockwave repository must use the reviewed canonical HTTPS remote")
    if not isinstance(document["commit"], str) or not SHA1.fullmatch(document["commit"]):
        raise ValueError("LibreShockwave commit must be a lowercase full 40-hex Git SHA")
    if document["commit"] != EXPECTED_COMMIT:
        raise ValueError("LibreShockwave commit differs from the reviewed renderer pin")
    if not isinstance(document["commit_date"], str) or not UTC_TIMESTAMP.fullmatch(document["commit_date"]):
        raise ValueError("LibreShockwave commit_date must be a second-precision UTC timestamp")
    if document["commit_date"] != EXPECTED_COMMIT_DATE:
        raise ValueError("LibreShockwave commit date differs from the reviewed renderer pin")
    if not isinstance(document["archive_sha256"], str) or not SHA256.fullmatch(document["archive_sha256"]):
        raise ValueError("LibreShockwave archive_sha256 must be lowercase 64-hex")
    if document["archive_sha256"] != EXPECTED_ARCHIVE_SHA256:
        raise ValueError("LibreShockwave source archive hash differs from the reviewed pin")
    if document["license"] != "AGPL-3.0-only":
        raise ValueError("LibreShockwave license must remain AGPL-3.0-only")
    if not isinstance(document["license_file_sha256"], str) or not SHA256.fullmatch(document["license_file_sha256"]):
        raise ValueError("LibreShockwave license_file_sha256 must be lowercase 64-hex")
    if document["license_file_sha256"] != EXPECTED_LICENSE_SHA256:
        raise ValueError("LibreShockwave license file hash differs from the reviewed pin")
    if document["integration_mode"] != "external-build-tool":
        raise ValueError("LibreShockwave must remain an external build tool, not shipped runtime code")
    expected_contract = {
        "build_target": "miel_director_exporter",
        "minimum_cmake": "3.20",
        "language_standard": "C++20",
        "runtime_status": "upstream-player-in-development",
    }
    for field, expected in expected_contract.items():
        if document[field] != expected:
            raise ValueError(f"LibreShockwave {field} differs from the reviewed renderer contract")
    if document["compatibility_patch"] != "tools/miel_vliegt/patches/libreshockwave-director8-score.patch":
        raise ValueError("LibreShockwave compatibility patch path drifted")
    if not SHA256.fullmatch(document["compatibility_patch_sha256"]):
        raise ValueError("LibreShockwave compatibility patch hash must be lowercase 64-hex")
    patch_path = root / document["compatibility_patch"]
    if not patch_path.is_file():
        raise ValueError("LibreShockwave compatibility patch is missing")
    if hashlib.sha256(patch_path.read_bytes()).hexdigest() != document["compatibility_patch_sha256"]:
        raise ValueError("LibreShockwave compatibility patch hash drifted")

    if document["exporter_path"] != EXPECTED_EXPORTER_PATH:
        raise ValueError("LibreShockwave exporter path drifted")
    if not isinstance(document["exporter_sha256"], str) \
            or not SHA256.fullmatch(document["exporter_sha256"]):
        raise ValueError("LibreShockwave exporter_sha256 must be lowercase 64-hex")
    exporter_path = (root / document["exporter_path"]).resolve()
    try:
        exporter_path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("LibreShockwave exporter path escapes the repository") from error
    if not exporter_path.is_file():
        raise ValueError("LibreShockwave exporter source is missing")
    if hashlib.sha256(exporter_path.read_bytes()).hexdigest() != document["exporter_sha256"]:
        raise ValueError("LibreShockwave exporter_sha256 drifted")

    if document["font_map_probe_build_target"] != "miel_director_font_map_probe":
        raise ValueError("LibreShockwave font_map_probe_build_target drifted")
    if document["font_map_probe_path"] != EXPECTED_FONT_MAP_PROBE_PATH:
        raise ValueError("LibreShockwave font-map probe path drifted")
    if not isinstance(document["font_map_probe_sha256"], str) \
            or not SHA256.fullmatch(document["font_map_probe_sha256"]):
        raise ValueError("LibreShockwave font_map_probe_sha256 must be lowercase 64-hex")
    probe_path = (root / document["font_map_probe_path"]).resolve()
    try:
        probe_path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError("LibreShockwave font-map probe path escapes the repository") from error
    if not probe_path.is_file():
        raise ValueError("LibreShockwave font-map probe source is missing")
    if hashlib.sha256(probe_path.read_bytes()).hexdigest() != document["font_map_probe_sha256"]:
        raise ValueError("LibreShockwave font_map_probe_sha256 drifted")

    paths = document["expected_paths"]
    if not isinstance(paths, list) or paths != list(EXPECTED_PATHS):
        raise ValueError("LibreShockwave renderer source-path contract drifted")
    for value in paths:
        parsed = PurePosixPath(value)
        if parsed.is_absolute() or ".." in parsed.parts or str(parsed) != value:
            raise ValueError(f"unsafe LibreShockwave source path: {value!r}")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    manifest = validate_manifest(args.manifest)
    print(
        "LibreShockwave renderer pin OK: "
        f"{manifest['commit']} ({len(manifest['expected_paths'])} required upstream paths, "
        "manifest and local exporter source checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
