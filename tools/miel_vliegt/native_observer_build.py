#!/usr/bin/env python3
"""Generate and validate the native observer build identity.

The manifest binds natural-transition evidence to one concrete Win32 observer
DLL and to every repository input that shapes that DLL.  It deliberately does
not claim that a local JSON file is an unforgeable attestation; release capture
still needs a trusted runner or signature for that stronger trust boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.native_dispatch_hook_contract import (
        producer_build_sha256,
    )
except ModuleNotFoundError:
    from native_dispatch_hook_contract import producer_build_sha256


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "content/miel_vliegt/native_observer_build.json"
PROTOCOL = "miel-vliegt-native-observer-build"
ARTIFACT_NAME = "native-observer-hook.dll"
TARGET = "i686-w64-mingw32"
CAPTURE_DRIVER_FOUNDATION = {
    "profile": "NATIVE_DISPATCH_DRIVER_V2",
    "profile_sha256":
        "72925be976520350aec44c45861e5f0af1bcaaef0f33fe605f42d6d415c0cd68",
    "scenario_sha256":
        "1435350feab7bfe92840bc8be305f13a6daf539173674e0b1bab8553c7b9b165",
    "initial_user_sha256":
        "7019275a9489a2d078f2cb38425f852dd2c019295e401ba4a58cbd67566555d6",
}
COMPILER_FLAGS = (
    "-std=c11", "-Os", "-s", "-static-libgcc", "-Wall", "-Wextra",
    "-Werror", "-shared", "-I/src",
    f'-DMVDS_PRODUCER_BUILD_SHA256="{producer_build_sha256()}"',
)
INPUT_PATHS = (
    "tools/miel_vliegt/hangover/native_observer_hook.c",
    "tools/miel_vliegt/hangover/native_observation_profiles.generated.h",
    "tools/miel_vliegt/hangover/native_sha256.h",
    "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.h",
    "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.c",
    "tools/miel_vliegt/hangover/native_dispatch_capture_targets.generated.h",
    "tools/miel_vliegt/native_dispatch_capture_target_header.py",
    "tools/miel_vliegt/native_dispatch_capture_job.py",
    "tools/miel_vliegt/native_dispatch_semantic_wire.py",
    "tools/miel_vliegt/native_dispatch_hook_contract.py",
    "tools/miel_vliegt/native_mygghanget_contract.py",
    "tools/miel_vliegt/native_observer_build.py",
    "tools/miel_vliegt/native_observation_profile_contract.py",
    "tools/miel_vliegt/fixtures/native_dispatch_driver/replay.mvo",
    "tools/miel_vliegt/fixtures/native_dispatch_driver/initial-user0.dat.gz.b64",
    "tools/miel_vliegt/native_scene_navigator.py",
    "tools/miel_vliegt/native_trace.py",
    "tools/miel_vliegt/build_native_trace_map.py",
    "content/miel_vliegt/native_scene_probe.json",
    "content/miel_vliegt/native_observation_profiles.json",
    "content/miel_vliegt/scene_semantic_evidence_batches.json",
    "content/miel_vliegt/native_scene_transitions.json",
    "content/miel_vliegt/uds_flight_contracts.json",
    "tools/miel_vliegt/fex_wine/Dockerfile",
    "tools/miel_vliegt/x86_wine/Dockerfile",
)
SHA256 = re.compile(r"[0-9a-f]{64}")
COMPILER_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def build_manifest(
    artifact: Path,
    compiler_version: str,
    root: Path = ROOT,
) -> dict[str, Any]:
    if not artifact.is_file():
        raise ValueError("native observer artifact is unavailable")
    if artifact.name != ARTIFACT_NAME:
        raise ValueError(
            "native observer artifact must use the canonical link basename"
        )
    if COMPILER_VERSION.fullmatch(compiler_version) is None:
        raise ValueError("native observer compiler version is invalid")
    inputs = [
        {"path": relative, "sha256": _sha256((root / relative).read_bytes())}
        for relative in INPUT_PATHS
    ]
    identity = {
        "schema": 1,
        "protocol": PROTOCOL,
        "target": TARGET,
        "compiler_version": compiler_version,
        "compiler_flags": list(COMPILER_FLAGS),
        "artifact": {
            "name": ARTIFACT_NAME,
            "sha256": _sha256(artifact.read_bytes()),
        },
        "capture_driver_foundation": dict(CAPTURE_DRIVER_FOUNDATION),
        "inputs": inputs,
    }
    return {**identity, "build_sha256": _sha256(_canonical(identity))}


def validate_manifest(
    path: Path = MANIFEST_PATH,
    root: Path = ROOT,
    artifact: Path | None = None,
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("native observer build manifest is unavailable") from error
    artifact_record = value.get("artifact") if isinstance(value, dict) else None
    compiler_version = value.get("compiler_version") if isinstance(value, dict) else None
    if not isinstance(artifact_record, dict) \
            or set(artifact_record) != {"name", "sha256"} \
            or artifact_record.get("name") != ARTIFACT_NAME \
            or SHA256.fullmatch(artifact_record.get("sha256", "")) is None \
            or not isinstance(compiler_version, str) \
            or COMPILER_VERSION.fullmatch(compiler_version) is None:
        raise ValueError("native observer build manifest is invalid")
    if artifact is not None:
        if not artifact.is_file() \
                or _sha256(artifact.read_bytes()) != artifact_record["sha256"]:
            raise ValueError("native observer artifact bytes drifted")
        expected = build_manifest(artifact, compiler_version, root)
    else:
        inputs = [
            {"path": relative, "sha256": _sha256((root / relative).read_bytes())}
            for relative in INPUT_PATHS
        ]
        identity = {
            "schema": 1,
            "protocol": PROTOCOL,
            "target": TARGET,
            "compiler_version": compiler_version,
            "compiler_flags": list(COMPILER_FLAGS),
            "artifact": dict(artifact_record),
            "capture_driver_foundation": dict(CAPTURE_DRIVER_FOUNDATION),
            "inputs": inputs,
        }
        expected = {**identity, "build_sha256": _sha256(_canonical(identity))}
    if _canonical(value) != _canonical(expected):
        raise ValueError("native observer build manifest or its inputs drifted")
    return value


def write_manifest_exclusive(path: Path, value: dict[str, Any]) -> None:
    """Create a receipt once; never overwrite evidence from an older build."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
    except FileExistsError as error:
        raise ValueError(f"native observer build output already exists: {path}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--compiler-version")
    parser.add_argument("--output", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        validate_manifest(args.output, artifact=args.artifact)
        print(f"PASS {args.output}")
        return 0
    if args.artifact is None or args.compiler_version is None:
        parser.error("generation requires --artifact and --compiler-version")
    value = build_manifest(args.artifact, args.compiler_version)
    write_manifest_exclusive(args.output, value)
    print(value["build_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
