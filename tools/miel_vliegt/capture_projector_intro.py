#!/usr/bin/env python3
"""Bind a native Director-projector recording to the extracted intro identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
from pathlib import Path


def validate_media(media: dict[str, object]) -> None:
    """Reject captures that cannot preserve the native 640x480 A/V output."""
    streams = media.get("streams", [])
    if not isinstance(streams, list):
        raise ValueError("native projector capture stream metadata is invalid")
    video = [
        stream for stream in streams
        if isinstance(stream, dict) and stream.get("codec_type") == "video"
    ]
    audio = [
        stream for stream in streams
        if isinstance(stream, dict) and stream.get("codec_type") == "audio"
    ]
    if len(video) != 1 or (video[0].get("width"), video[0].get("height")) != (640, 480):
        raise ValueError("native projector capture must contain one 640x480 video stream")
    if video[0].get("codec_name") not in {"ffv1", "huffyuv", "rawvideo"}:
        raise ValueError("native projector capture video must use a lossless codec")
    if len(audio) != 1 or audio[0].get("codec_name") not in {
            "pcm_s16le", "pcm_s16be", "pcm_s24le", "pcm_s24be", "pcm_f32le", "flac"}:
        raise ValueError("native projector capture must contain one lossless audio stream")
    try:
        duration = float(media["format"]["duration"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("native projector capture has no measurable duration") from error
    if not math.isfinite(duration) or duration <= 1:
        raise ValueError("native projector capture duration is invalid")


def create_receipt(
        manifest_path: Path,
        capture: Path,
        output: Path,
        capture_tool: str) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    intro = manifest["movies"][manifest["intro_index"]]
    movie = manifest_path.parent / intro["payload"]
    if hashlib.sha256(movie.read_bytes()).hexdigest() != intro["sha256"]:
        raise ValueError("rebased intro payload drifted from projector manifest")
    probe = subprocess.run([
        "ffprobe", "-v", "error", "-show_entries",
        "format=duration,size:stream=codec_type,codec_name,width,height",
        "-of", "json", str(capture),
    ], check=True, capture_output=True, text=True)
    media = json.loads(probe.stdout)
    validate_media(media)
    receipt = {
        "schema": 1,
        "capture_method": "native-projector",
        "capture_tool": capture_tool,
        "projector_sha256": manifest["projector"]["sha256"],
        "intro_movie_sha256": intro["sha256"],
        "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
        "media": media,
    }
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="projector extraction manifest")
    parser.add_argument("capture", type=Path, help="lossless native projector recording")
    parser.add_argument("output", type=Path, help="receipt JSON to create")
    parser.add_argument("--capture-tool", required=True, help="native capture environment/tool identity")
    args = parser.parse_args()
    create_receipt(args.manifest, args.capture, args.output, args.capture_tool)


if __name__ == "__main__":
    main()
