#!/usr/bin/env python3
"""Generate and validate the browser transition-producer build identity."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "content/miel_vliegt/web_transition_build.json"
PROTOCOL = "miel-web-scene-transition-build"
INPUT_PATHS = (
    "content/miel_vliegt/native_scene_transitions.json",
    "content/miel_vliegt/web_scene_transition_runtime.json",
    "src/flight/runtime/SceneTransitionContract.js",
    "src/flight/runtime/WebSceneTransitionRecorder.js",
    "src/flight/runtime/WebNaturalTransitionCaptureRunner.js",
    "src/flight/engine/scene/SceneDispatchRuntime.js",
    "src/flight/engine/scene/WebSceneDispatchCaptureExecutor.js",
    "src/flight/engine/scene/WebSceneDispatchCandidateBridge.js",
    "tools/miel_vliegt/run_web_natural_transition_capture.cjs",
    "tools/miel_vliegt/web_natural_transition_capture.py",
    "src/index.js",
    "src/scenes/flight_world.js",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def build_manifest(root: Path = ROOT) -> dict[str, Any]:
    inputs = []
    for relative in INPUT_PATHS:
        path = root / relative
        inputs.append({"path": relative, "sha256": _sha256(path.read_bytes())})
    identity = {"schema": 1, "protocol": PROTOCOL, "inputs": inputs}
    return {**identity, "build_sha256": _sha256(_canonical(identity))}


def validate_manifest(
    path: Path = MANIFEST_PATH, root: Path = ROOT,
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("web transition build manifest is unavailable") from error
    expected = build_manifest(root)
    if _canonical(value) != _canonical(expected):
        raise ValueError("web transition build manifest or its inputs drifted")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="generate or validate the web transition build manifest",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        validate_manifest()
        print(f"PASS {MANIFEST_PATH.relative_to(ROOT)}")
        return 0
    value = build_manifest()
    MANIFEST_PATH.write_text(
        json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8",
    )
    print(value["build_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
