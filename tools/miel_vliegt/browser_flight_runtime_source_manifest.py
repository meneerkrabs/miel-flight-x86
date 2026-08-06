#!/usr/bin/env python3
"""Build the complete committed source closure for browser flight captures.

The production Webpack image copies the complete ``src`` and ``content/data``
trees.  Treating both trees as the source universe is intentionally
conservative: it also covers dynamic module contexts that a static import
walker could miss.  The remaining fixed inputs mirror the build configuration
and reviewed flight contracts copied into the production image.
"""

from __future__ import annotations

import argparse
import copy
import functools
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "miel-vliegt-browser-flight-runtime-source-manifest"
INPUT_POLICY = (
    "ALL_COMMITTED_SRC_CONTENT_DATA_AND_PRODUCTION_FLIGHT_BUILD_INPUTS_V2"
)
ENTRYPOINT = "src/index.js"
INPUT_PATH_PREFIXES = ("src/", "content/data/")

FIXED_INPUT_PATHS = (
    "content/miel_vliegt/ccf_material_contract.json",
    "content/miel_vliegt/dutch_help_contract.json",
    "content/miel_vliegt/executable_udsp_scene_scripts.json",
    "content/miel_vliegt/flight_frontend_contract.json",
    "content/miel_vliegt/flight_hangar_contract.json",
    "content/miel_vliegt/flight_intro_contract.json",
    "content/miel_vliegt/flight_location_presentation_contract.json",
    "content/miel_vliegt/flight_scene_asset_contract.json",
    "content/miel_vliegt/native_barn_interaction_contract.json",
    "content/miel_vliegt/native_barn_render_contract.json",
    "content/miel_vliegt/native_scene_transitions.json",
    "content/miel_vliegt/native_udsp_scene_commands.json",
    "content/miel_vliegt/scene_dispatch_contract.json",
    "content/miel_vliegt/uds_barn_contracts.json",
    "content/miel_vliegt/uds_flight_attachment_targets.json",
    "content/miel_vliegt/uds_flight_contracts.json",
    "content/miel_vliegt/uds_flight_part_components.json",
    "content/miel_vliegt/uds_hangar_masks.json",
    "content/miel_vliegt/uds_scene_scripts.json",
    "content/miel_vliegt/web_scene_transition_runtime.json",
    "content/miel_vliegt/web_transition_build.json",
    "deployment/docker/Dockerfile.boten",
    "package-lock.json",
    "package.json",
    "tools/parity/descoped.json",
    "webpack.common.js",
    "webpack.prod.js",
)

ESSENTIAL_INPUT_PATHS = (
    ENTRYPOINT,
    "content/data/director_member_identity.json",
    "content/data/sea_maps.hash.json",
    "src/flight/runtime/FlightProductionTraceCapture.js",
    "src/scenes/flight_world.js",
    "deployment/docker/Dockerfile.boten",
    "package-lock.json",
    "webpack.prod.js",
)


class BrowserFlightRuntimeSourceManifestError(ValueError):
    pass


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _git(
    root: Path, arguments: list[str], *, input_bytes: bytes | None = None,
) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            input=input_bytes,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise BrowserFlightRuntimeSourceManifestError(
            f"unable to inspect committed runtime source: {' '.join(arguments)}",
        ) from error


def _commit(root: Path, commit: str) -> str:
    value = _git(root, ["rev-parse", "--verify", f"{commit}^{{commit}}"])
    resolved = value.decode("ascii").strip()
    if (
        len(resolved) != 40
        or any(character not in "0123456789abcdef" for character in resolved)
    ):
        raise BrowserFlightRuntimeSourceManifestError(
            "runtime source commit is invalid",
        )
    return resolved


def _tree_blobs(root: Path, commit: str) -> dict[str, str]:
    output = _git(root, ["ls-tree", "-r", "-z", commit])
    blobs: dict[str, str] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise BrowserFlightRuntimeSourceManifestError(
                "runtime source tree contains an invalid entry",
            ) from error
        if path.startswith(INPUT_PATH_PREFIXES) or path in FIXED_INPUT_PATHS:
            if object_type != "blob" or mode == "120000":
                raise BrowserFlightRuntimeSourceManifestError(
                    f"runtime source input is not a regular blob: {path}",
                )
            blobs[path] = object_id
    required = set(FIXED_INPUT_PATHS) | set(ESSENTIAL_INPUT_PATHS)
    missing = sorted(required - set(blobs))
    if missing:
        raise BrowserFlightRuntimeSourceManifestError(
            f"runtime source tree is missing required inputs: {', '.join(missing)}",
        )
    return blobs


def _blob_payloads(
    root: Path, blobs: dict[str, str],
) -> dict[str, bytes]:
    ordered = sorted(blobs.items())
    process = subprocess.Popen(
        ["git", "-C", str(root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    try:
        process.stdin.write(
            b"".join(f"{object_id}\n".encode("ascii") for _, object_id in ordered),
        )
        process.stdin.close()
        payloads: dict[str, bytes] = {}
        for path, expected_id in ordered:
            header = process.stdout.readline().decode("ascii").strip().split()
            if (
                len(header) != 3
                or header[0] != expected_id
                or header[1] != "blob"
            ):
                raise BrowserFlightRuntimeSourceManifestError(
                    f"unable to read runtime source blob: {path}",
                )
            try:
                size = int(header[2])
            except ValueError as error:
                raise BrowserFlightRuntimeSourceManifestError(
                    f"runtime source blob has an invalid size: {path}",
                ) from error
            payload = process.stdout.read(size)
            terminator = process.stdout.read(1)
            if len(payload) != size or terminator != b"\n":
                raise BrowserFlightRuntimeSourceManifestError(
                    f"runtime source blob was truncated: {path}",
                )
            payloads[path] = payload
        stderr = process.stderr.read()
        if process.wait() != 0:
            raise BrowserFlightRuntimeSourceManifestError(
                "git cat-file failed while reading runtime source blobs: "
                f"{stderr.decode('utf-8', errors='replace').strip()}",
            )
        return payloads
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
        if not process.stdin.closed:
            process.stdin.close()


def committed_input_payloads(
    root: Path = REPO_ROOT, commit: str = "HEAD",
) -> tuple[str, dict[str, bytes]]:
    root = root.absolute()
    resolved = _commit(root, commit)
    blobs = _tree_blobs(root, resolved)
    return resolved, _blob_payloads(root, blobs)


def manifest_from_payloads(
    source_commit: str, payloads: dict[str, bytes],
) -> dict[str, Any]:
    inputs = [
        {
            "path": path,
            "sha256": hashlib.sha256(payloads[path]).hexdigest(),
        }
        for path in sorted(payloads)
    ]
    identity = {
        "schema": 1,
        "protocol": PROTOCOL,
        "source_commit": source_commit,
        "entrypoint": ENTRYPOINT,
        "input_policy": INPUT_POLICY,
        "inputs": inputs,
    }
    return {
        **identity,
        "build_sha256": canonical_sha256(identity),
    }


@functools.lru_cache(maxsize=16)
def _cached_manifest(root_reference: str, commit: str) -> dict[str, Any]:
    root = Path(root_reference)
    blobs = _tree_blobs(root, commit)
    return manifest_from_payloads(commit, _blob_payloads(root, blobs))


def build_manifest(
    root: Path = REPO_ROOT, commit: str = "HEAD",
) -> dict[str, Any]:
    root = root.absolute()
    resolved = _commit(root, commit)
    return copy.deepcopy(_cached_manifest(str(root), resolved))


def validate_manifest(
    value: Any, *, root: Path = REPO_ROOT, commit: str = "HEAD",
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrowserFlightRuntimeSourceManifestError(
            "runtime source manifest must be an object",
        )
    expected = build_manifest(root, commit)
    if value != expected:
        raise BrowserFlightRuntimeSourceManifestError(
            "runtime source manifest does not cover the complete committed "
            "production graph",
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="emit the committed browser flight runtime source manifest",
    )
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = build_manifest(REPO_ROOT, args.commit)
    payload = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
