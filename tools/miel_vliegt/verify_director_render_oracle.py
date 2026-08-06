#!/usr/bin/env python3
"""Validate LibreShockwave and native Director render-oracle evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.verify_libreshockwave_pin import validate_manifest
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from verify_libreshockwave_pin import validate_manifest


ALLOWED_STATUSES = {
    "BLOCKED_ORACLE", "CAPTURED_RENDERERS", "ORACLE_EQUIVALENT", "ORACLE_DIVERGENT",
}
LIBRESHOCKWAVE_MANIFEST = "tools/miel_vliegt/libreshockwave.json"
LIBRESHOCKWAVE_TREE = "a16ee5f260d858d33ce349c069124e1226414bd9a"
LIBRESHOCKWAVE_SURFACE = "native-cpp-software-frame"


def expected_libreshockwave_renderer(repository: Path) -> dict[str, Any]:
    """Build the render identity from the canonical, source-checked pin."""
    pin = validate_manifest(repository / LIBRESHOCKWAVE_MANIFEST, root=repository)
    return {
        "repository": pin["repository"],
        "commit": pin["commit"],
        "tree": LIBRESHOCKWAVE_TREE,
        "archive_sha256": pin["archive_sha256"],
        "compatibility_patch": pin["compatibility_patch"],
        "compatibility_patch_sha256": pin["compatibility_patch_sha256"],
        "exporter_path": pin["exporter_path"],
        "exporter_sha256": pin["exporter_sha256"],
        "build_target": pin["build_target"],
        "surface": LIBRESHOCKWAVE_SURFACE,
        "maturity": pin["runtime_status"],
    }


CANONICAL_FRAME = {
    "width": 640,
    "height": 480,
    "pixel_format": "RGBA8888",
    "byte_order": "row-major-rgba",
    "origin": "top-left",
    "alpha": "straight",
    "colour_space": "srgb",
}
EXACT_COMPARISON = {
    "policy": "exact-canonical-rgba",
    "maximum_different_pixels": 0,
    "maximum_channel_delta": 0,
}


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not readable JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 \
        and all(character in "0123456789abcdef" for character in value)


def _artifact(root: Path, reference: Any, label: str) -> Path:
    if not isinstance(reference, str) or not reference:
        raise ValueError(f"{label} must be a non-empty relative artifact path")
    candidate = (root / reference).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the render-oracle artifact root") from error
    if not candidate.is_file():
        raise ValueError(f"{label} is missing: {reference}")
    return candidate


def _validate_contract_identity(contract: dict[str, Any], repository: Path) -> None:
    source = contract.get("source", {})
    intro_path = repository / source.get("flight_intro_contract", "")
    intro = _load(intro_path, "flight intro contract")
    projector = intro.get("projector_source", {}).get("projector", {})
    movies = intro.get("projector_source", {}).get("movies", [])
    intro_index = intro.get("projector_source", {}).get("intro_index")
    try:
        intro_movie = movies[intro_index]
    except (IndexError, TypeError) as error:
        raise ValueError("flight intro contract has no indexed projector intro") from error
    if source.get("projector_sha256") != projector.get("sha256"):
        raise ValueError("render oracle projector identity drifted from flight intro contract")
    if source.get("intro_movie_sha256") != intro_movie.get("sha256"):
        raise ValueError("render oracle movie identity drifted from flight intro contract")
    native = contract.get("renderers", {}).get("native_oracle", {})
    if native.get("projector_sha256") != source.get("projector_sha256"):
        raise ValueError("native render oracle does not target the pinned projector")
    libre = contract.get("renderers", {}).get("libreshockwave", {})
    for path_field, hash_field in (
        ("compatibility_patch", "compatibility_patch_sha256"),
        ("exporter_path", "exporter_sha256"),
    ):
        relative = libre.get(path_field)
        if not isinstance(relative, str):
            raise ValueError(f"LibreShockwave {path_field} is missing")
        path = (repository / relative).resolve()
        try:
            path.relative_to(repository.resolve())
        except ValueError as error:
            raise ValueError(f"LibreShockwave {path_field} escapes the repository") from error
        if not path.is_file() or libre.get(hash_field) != _sha256(path):
            raise ValueError(f"LibreShockwave {hash_field} drifted")


def _validate_manifest(
    manifest: dict[str, Any], kind: str, contract: dict[str, Any], artifact_root: Path,
) -> list[tuple[int, int, bytes]]:
    if manifest.get("schema") != 1 or manifest.get("renderer_kind") != kind:
        raise ValueError(f"invalid {kind} render manifest identity")
    source = contract["source"]
    if manifest.get("intro_movie_sha256") != source["intro_movie_sha256"]:
        raise ValueError(f"{kind} manifest targets a different intro movie")
    if manifest.get("canonical_frame") != contract["canonical_frame"]:
        raise ValueError(f"{kind} manifest canonical frame metadata drifted")
    renderer = manifest.get("renderer", {})
    if kind == "libreshockwave":
        expected = contract["renderers"]["libreshockwave"]
        for field in (
            "commit", "tree", "archive_sha256", "compatibility_patch_sha256",
            "exporter_sha256", "build_target", "surface",
        ):
            if renderer.get(field) != expected[field]:
                raise ValueError(f"LibreShockwave manifest renderer {field} drifted")
        if not _is_sha256(renderer.get("binary_sha256")):
            raise ValueError("LibreShockwave manifest must identify the rendered binary")
        for field in ("build_environment", "capture_tool"):
            if not isinstance(renderer.get(field), str) or not renderer[field]:
                raise ValueError(f"LibreShockwave manifest must identify {field}")
        if not _is_sha256(renderer.get("capture_tool_sha256")):
            raise ValueError("LibreShockwave manifest must hash its RGBA capture adapter")
    else:
        expected = contract["renderers"]["native_oracle"]
        for field in ("surface", "capture_method", "projector_sha256"):
            if renderer.get(field) != expected[field]:
                raise ValueError(f"native oracle manifest renderer {field} drifted")
        if not isinstance(renderer.get("capture_tool"), str) or not renderer["capture_tool"]:
            raise ValueError("native oracle manifest must identify its capture tool/environment")
        if not isinstance(renderer.get("environment"), str) or not renderer["environment"]:
            raise ValueError("native oracle manifest must identify its native environment")
        if not _is_sha256(renderer.get("capture_tool_sha256")):
            raise ValueError("native oracle manifest must hash its framebuffer capture tool")

    transcript = manifest.get("clock_transcript")
    if not isinstance(transcript, dict) or not isinstance(transcript.get("id"), str) \
            or not _is_sha256(transcript.get("sha256")):
        raise ValueError(f"{kind} manifest lacks a pinned clock transcript")
    transcript_path = _artifact(
        artifact_root, transcript.get("path"), f"{kind} clock transcript"
    )
    if transcript["sha256"] != _sha256(transcript_path):
        raise ValueError(f"{kind} clock transcript hash drifted")
    frames = manifest.get("frames")
    if not isinstance(frames, list) or not frames:
        raise ValueError(f"{kind} manifest must contain at least one frame")
    expected_bytes = contract["canonical_frame"]["width"] \
        * contract["canonical_frame"]["height"] * 4
    result = []
    identities = set()
    for row in frames:
        if not isinstance(row, dict):
            raise ValueError(f"{kind} manifest frame must be an object")
        identity = (row.get("frame"), row.get("time_microseconds"))
        if not all(isinstance(value, int) and value >= 0 for value in identity):
            raise ValueError(f"{kind} manifest frame identity is invalid")
        if identity in identities:
            raise ValueError(f"{kind} manifest contains duplicate frame identities")
        identities.add(identity)
        rgba = _artifact(artifact_root, row.get("rgba"), f"{kind} frame RGBA")
        if rgba.stat().st_size != expected_bytes or row.get("rgba_sha256") != _sha256(rgba):
            raise ValueError(f"{kind} frame RGBA size or hash drifted")
        result.append((identity[0], identity[1], rgba.read_bytes()))
    if result != sorted(result, key=lambda item: (item[0], item[1])):
        raise ValueError(f"{kind} manifest frames are not deterministically ordered")
    return result


def _validate_receipt(
    receipt: dict[str, Any], contract: dict[str, Any], libre_path: Path,
    native_path: Path, libre_frames: list[tuple[int, int, bytes]],
    native_frames: list[tuple[int, int, bytes]],
) -> str:
    if receipt.get("schema") != 1 or receipt.get("policy") != contract["comparison"]:
        raise ValueError("render oracle comparison receipt policy drifted")
    if receipt.get("libreshockwave_manifest_sha256") != _sha256(libre_path) \
            or receipt.get("native_oracle_manifest_sha256") != _sha256(native_path):
        raise ValueError("render oracle comparison receipt manifest hashes drifted")
    if [(frame, time) for frame, time, _ in libre_frames] != [
        (frame, time) for frame, time, _ in native_frames
    ]:
        raise ValueError("render oracle frame/clock transcripts differ")
    differing_pixels = 0
    maximum_delta = 0
    for (_frame, _time, libre), (_native_frame, _native_time, native) in zip(
        libre_frames, native_frames
    ):
        for offset in range(0, len(libre), 4):
            left, right = libre[offset:offset + 4], native[offset:offset + 4]
            if left != right:
                differing_pixels += 1
                maximum_delta = max(maximum_delta, *(abs(a - b) for a, b in zip(left, right)))
    observed = {
        "frames": len(libre_frames),
        "different_pixels": differing_pixels,
        "maximum_channel_delta": maximum_delta,
    }
    if receipt.get("observed") != observed:
        raise ValueError("render oracle comparison receipt observations drifted")
    expected_status = "PASS" if differing_pixels == 0 and maximum_delta == 0 else "FAIL"
    if receipt.get("status") != expected_status:
        raise ValueError("render oracle comparison receipt status is false")
    return expected_status


def validate(contract: dict[str, Any], repository: Path, artifact_root: Path) -> None:
    if contract.get("schema") != 1 or contract.get("status") not in ALLOWED_STATUSES:
        raise ValueError("unsupported Director render oracle contract")
    _validate_contract_identity(contract, repository)
    if contract.get("renderers", {}).get("libreshockwave") != \
            expected_libreshockwave_renderer(repository):
        raise ValueError("LibreShockwave renderer identity drifted from the reviewed revision")
    if contract.get("canonical_frame") != CANONICAL_FRAME:
        raise ValueError("Director render oracle canonical frame format drifted")
    if contract.get("comparison") != EXACT_COMPARISON:
        raise ValueError("Director render oracle comparison is no longer fail-closed exact RGBA")
    artifact_policy = contract.get("artifact_policy", {})
    if artifact_policy.get("tracked") is not False or artifact_policy.get("root") != \
            "content/miel_vliegt/projector-movies/render-oracles":
        raise ValueError("render oracle payloads must remain under the gitignored projector root")
    artifacts = contract.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("render oracle contract lacks artifact slots")
    status = contract["status"]
    if status == "BLOCKED_ORACLE":
        if any(artifacts.get(field) is not None for field in (
            "libreshockwave_manifest", "native_oracle_manifest", "comparison_receipt",
        )):
            raise ValueError("blocked render oracle must not claim capture artifacts")
        if not contract.get("blockers"):
            raise ValueError("blocked render oracle must record blockers")
        return

    libre_path = _artifact(
        artifact_root, artifacts.get("libreshockwave_manifest"), "LibreShockwave manifest"
    )
    native_path = _artifact(
        artifact_root, artifacts.get("native_oracle_manifest"), "native oracle manifest"
    )
    libre = _load(libre_path, "LibreShockwave manifest")
    native = _load(native_path, "native oracle manifest")
    libre_frames = _validate_manifest(libre, "libreshockwave", contract, artifact_root)
    native_frames = _validate_manifest(native, "native-oracle", contract, artifact_root)
    if libre.get("clock_transcript") != native.get("clock_transcript"):
        raise ValueError("render manifests use different clock transcripts")
    if status == "CAPTURED_RENDERERS":
        if artifacts.get("comparison_receipt") is not None:
            raise ValueError("captured-only render oracle must not claim a comparison receipt")
        return
    receipt_path = _artifact(
        artifact_root, artifacts.get("comparison_receipt"), "comparison receipt"
    )
    receipt = _load(receipt_path, "comparison receipt")
    observed = _validate_receipt(
        receipt, contract, libre_path, native_path, libre_frames, native_frames
    )
    required = "PASS" if status == "ORACLE_EQUIVALENT" else "FAIL"
    if observed != required:
        raise ValueError(f"render oracle status {status} contradicts observed {observed}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    repository = Path(__file__).resolve().parents[2]
    parser.add_argument(
        "--contract", type=Path,
        default=repository / "content/miel_vliegt/director_intro_render_oracle_contract.json",
    )
    parser.add_argument("--repository", type=Path, default=repository)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()
    contract = _load(args.contract, "render oracle contract")
    root = args.artifact_root or args.repository / contract["artifact_policy"]["root"]
    validate(contract, args.repository, root)
    print(f"Director render oracle contract OK: {contract['status']}")


if __name__ == "__main__":
    main()
