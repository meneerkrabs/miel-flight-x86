#!/usr/bin/env python3
"""Render a Director score with pinned LibreShockwave and mux its audio."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any


STREAM_HEADER = struct.Struct("<4sIII")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_exact(stream: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            raise RuntimeError("LibreShockwave exporter ended before its stream header")
        chunks.extend(chunk)
    return bytes(chunks)


def _run_renderer_stream(
    renderer: Path,
    movie: Path,
    video: Path,
    metadata: Path,
    audio_dir: Path,
    fps: int,
    visual_only: bool = False,
    score_frame: int | None = None,
    marker: str | None = None,
) -> dict[str, int]:
    error_log = metadata.with_suffix(".stderr.log")
    with error_log.open("wb") as errors:
        command = [str(renderer), str(movie), str(metadata), str(audio_dir), str(fps)]
        if visual_only:
            command.append("--visual-only")
        if score_frame is not None:
            command.extend(("--score-frame", str(score_frame)))
        if marker is not None:
            command.extend(("--marker", marker))
        exporter = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=errors,
        )
        assert exporter.stdout is not None
        try:
            magic, width, height, stream_fps = STREAM_HEADER.unpack(
                _read_exact(exporter.stdout, STREAM_HEADER.size)
            )
            if magic != b"MDR1" or min(width, height, stream_fps) < 1:
                raise RuntimeError("LibreShockwave exporter returned an invalid stream header")
            ffmpeg = subprocess.Popen(
                [
                    "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                    "-f", "rawvideo", "-pixel_format", "rgba",
                    "-video_size", f"{width}x{height}", "-framerate", str(stream_fps),
                    "-i", "pipe:0", "-an", "-c:v", "libx264", "-preset", "slow",
                    "-crf", "16", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
                    str(video),
                ],
                stdin=subprocess.PIPE,
            )
            assert ffmpeg.stdin is not None
            try:
                shutil.copyfileobj(exporter.stdout, ffmpeg.stdin, length=1024 * 1024)
            except BrokenPipeError as error:
                raise RuntimeError("ffmpeg rejected LibreShockwave raw video") from error
            finally:
                ffmpeg.stdin.close()
            ffmpeg_result = ffmpeg.wait()
            exporter_result = exporter.wait()
        except BaseException:
            exporter.kill()
            exporter.wait()
            raise
    if exporter_result != 0:
        detail = error_log.read_text(encoding="utf-8", errors="replace").strip()
        raise RuntimeError(f"LibreShockwave exporter failed ({exporter_result}): {detail}")
    if ffmpeg_result != 0 or not video.is_file():
        raise RuntimeError(f"ffmpeg raw-video encoding failed ({ffmpeg_result})")
    error_log.unlink(missing_ok=True)
    return {"width": width, "height": height, "fps": stream_fps}


def _audio_segments(events: list[dict[str, Any]], duration_ms: int) -> list[dict[str, Any]]:
    """Turn Director channel commands into non-overlapping playable segments."""
    active: dict[int, dict[str, Any]] = {}
    segments: list[dict[str, Any]] = []

    def close(channel: int, end_ms: int) -> None:
        current = active.pop(channel, None)
        if current is None or end_ms <= current["segment_start_ms"]:
            return
        segments.append({
            **current,
            "duration_ms": end_ms - current["segment_start_ms"],
            "source_offset_ms": current["segment_start_ms"] - current["play_start_ms"],
        })

    for event in events:
        channel = int(event.get("channel", 0))
        time_ms = max(0, min(duration_ms, int(event.get("time_ms", 0))))
        action = event.get("action")
        if action == "play" and event.get("file"):
            close(channel, time_ms)
            active[channel] = {
                "channel": channel,
                "file": event["file"],
                "segment_start_ms": time_ms,
                "play_start_ms": time_ms,
                "volume": int(event.get("volume", 255)),
                "loop_count": max(1, int(event.get("loop_count", 1))),
            }
        elif action == "stop":
            close(channel, time_ms)
        elif action == "volume" and channel in active:
            current = active[channel]
            play_start = current["play_start_ms"]
            source_file = current["file"]
            loop_count = current["loop_count"]
            close(channel, time_ms)
            active[channel] = {
                "channel": channel,
                "file": source_file,
                "segment_start_ms": time_ms,
                "play_start_ms": play_start,
                "volume": int(event.get("volume", 255)),
                "loop_count": loop_count,
            }
    for channel in list(active):
        close(channel, duration_ms)
    return segments


def _mux_audio(video: Path, destination: Path, metadata: dict[str, Any], audio_dir: Path) -> None:
    duration_ms = int(metadata["duration_ms"])
    segments = _audio_segments(metadata.get("audio_events", []), duration_ms)
    if not segments:
        os.replace(video, destination)
        return

    command = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", str(video)]
    filters: list[str] = []
    labels: list[str] = []
    for index, segment in enumerate(segments, start=1):
        source = audio_dir / segment["file"]
        if not source.is_file():
            raise RuntimeError(f"renderer audio event references missing file: {source}")
        command.extend(["-stream_loop", str(segment["loop_count"] - 1), "-i", str(source)])
        label = f"a{index}"
        delay = segment["segment_start_ms"]
        start = segment["source_offset_ms"] / 1000
        length = segment["duration_ms"] / 1000
        volume = max(0, min(255, segment["volume"])) / 255
        filters.append(
            f"[{index}:a]atrim=start={start:.6f}:duration={length:.6f},"
            f"asetpts=PTS-STARTPTS,volume={volume:.8f},adelay={delay}:all=1[{label}]"
        )
        labels.append(f"[{label}]")
    filters.append(f"{''.join(labels)}amix=inputs={len(labels)}:normalize=0:dropout_transition=0[aout]")
    command.extend([
        "-filter_complex", ";".join(filters), "-map", "0:v:0", "-map", "[aout]",
        "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-t", f"{duration_ms / 1000:.6f}",
        "-movflags", "+faststart", str(destination),
    ])
    subprocess.run(command, check=True)


def render_movie(
    movie: Path,
    destination: Path,
    renderer: Path,
    renderer_manifest: Path,
    receipt: Path,
    fps: int = 60,
    expected_movie_sha256: str | None = None,
    visual_only: bool = False,
    score_frame: int | None = None,
    marker: str | None = None,
) -> dict[str, Any]:
    for required in (movie, renderer, renderer_manifest):
        if not required.is_file():
            raise FileNotFoundError(required)
    movie_hash = sha256(movie)
    if expected_movie_sha256 is not None and movie_hash != expected_movie_sha256:
        raise ValueError("Director movie identity does not match its projector manifest")
    pin = json.loads(renderer_manifest.read_text(encoding="utf-8"))
    if pin.get("schema") != 1 or pin.get("integration_mode") != "external-build-tool":
        raise ValueError("invalid LibreShockwave pin manifest")

    destination.parent.mkdir(parents=True, exist_ok=True)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="miel-director-render-") as temporary:
        work = Path(temporary)
        audio_dir = work / "audio"
        metadata_path = work / "render.json"
        video = work / "video.mp4"
        stream = _run_renderer_stream(
            renderer, movie, video, metadata_path, audio_dir, fps,
            visual_only=visual_only,
            score_frame=score_frame,
            marker=marker,
        )
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("script_errors"):
            raise RuntimeError(f"Director scripts failed during render: {metadata['script_errors']}")
        if metadata.get("score_frames", 0) < 1 or metadata.get("output_frames", 0) < 1:
            raise RuntimeError("LibreShockwave produced no renderable score frames")
        if metadata.get("stage") != {"width": stream["width"], "height": stream["height"]}:
            raise RuntimeError("renderer stream and metadata dimensions disagree")
        if visual_only or score_frame is not None or marker is not None:
            os.replace(video, destination)
        else:
            _mux_audio(video, destination, metadata, audio_dir)

    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_streams", "-show_format", "-of", "json", str(destination)],
        check=True, capture_output=True, text=True,
    )
    media = json.loads(probe.stdout)
    result = {
        "schema": 1,
        "render_method": "libreshockwave-score",
        "render_scope": "score-frame" if score_frame is not None or marker is not None else
            ("visual-only" if visual_only else "audio-visual"),
        "movie_sha256": movie_hash,
        "renderer": pin,
        "render": metadata,
        "media": media,
        "asset_sha256": sha256(destination),
    }
    receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("movie", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--renderer", type=Path, default=Path(".venv/bin/miel_director_exporter"))
    parser.add_argument(
        "--renderer-manifest", type=Path,
        default=Path("tools/miel_vliegt/libreshockwave.json"),
    )
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--fps", type=int, default=60)
    parser.add_argument("--expected-movie-sha256")
    parser.add_argument(
        "--visual-only", action="store_true",
        help="render the score without resolving Director sound members",
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "--score-frame", type=int,
        help="render exactly one numbered Director score frame without audio",
    )
    target.add_argument(
        "--marker",
        help="render exactly one named Director marker without audio",
    )
    args = parser.parse_args()
    render_movie(
        args.movie, args.output, args.renderer, args.renderer_manifest, args.receipt,
        args.fps, args.expected_movie_sha256, args.visual_only, args.score_frame, args.marker,
    )


if __name__ == "__main__":
    main()
