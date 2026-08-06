#!/usr/bin/env python3
"""Build evidence that the pinned Director exporter renders the Dutch intro."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .render_director_movie import render_movie
except ImportError:  # Direct script execution.
    from render_director_movie import render_movie


EXPECTED_STAGE = {"width": 640, "height": 480}
EXPECTED_SCORE_FRAMES = 1765
EXPECTED_DURATION_MS = 70600
EXPECTED_PLAY_MS = 40
EXPECTED_STOP_MS = 66560


def verify_render(
    movie: Path,
    renderer: Path,
    renderer_manifest: Path,
    projector_manifest: Path,
    output_dir: Path,
    fps: int = 30,
) -> dict:
    projector = json.loads(projector_manifest.read_text(encoding="utf-8"))
    intro = projector["movies"][projector["intro_index"]]
    if intro["role"] != "intro" or intro["payload"] != movie.name:
        raise ValueError("projector manifest does not identify the requested intro movie")

    output_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = output_dir / "libreshockwave-intro-render.json"
    result = render_movie(
        movie,
        output_dir / "libreshockwave-intro.mp4",
        renderer,
        renderer_manifest,
        receipt_path,
        fps=fps,
        expected_movie_sha256=intro["sha256"],
    )
    render = result["render"]
    if render.get("stage") != EXPECTED_STAGE:
        raise ValueError(f"unexpected Director stage: {render.get('stage')}")
    if render.get("score_frames") != EXPECTED_SCORE_FRAMES:
        raise ValueError(f"unexpected Director score length: {render.get('score_frames')}")
    if render.get("duration_ms") != EXPECTED_DURATION_MS or render.get("tempos") != [25]:
        raise ValueError("Director tempo-derived timing drifted")
    if render.get("script_errors"):
        raise ValueError(f"Director script errors: {render['script_errors']}")

    events = render.get("audio_events", [])
    plays = [event for event in events if event.get("action") == "play"]
    stops = [event for event in events if event.get("action") == "stop" and event.get("channel") == 1]
    if len(plays) != 1 or plays[0].get("channel") != 1 or plays[0].get("time_ms") != EXPECTED_PLAY_MS:
        raise ValueError(f"Director narration start drifted: {plays}")
    if not plays[0].get("file") or plays[0].get("format") != "wav":
        raise ValueError("Director narration was not extracted as playable PCM")
    if not any(event.get("time_ms") == EXPECTED_STOP_MS for event in stops):
        raise ValueError(f"Director narration stop drifted: {stops}")

    streams = result.get("media", {}).get("streams", [])
    stream_types = {stream.get("codec_type") for stream in streams}
    if stream_types != {"video", "audio"}:
        raise ValueError(f"rendered intro must contain video and audio: {stream_types}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--movie",
        type=Path,
        default=Path("content/miel_vliegt/projector-movies/movie-2-intro.dir"),
    )
    parser.add_argument(
        "--projector-manifest",
        type=Path,
        default=Path("content/miel_vliegt/projector-movies/manifest.json"),
    )
    parser.add_argument("--renderer", type=Path, default=Path(".venv/bin/miel_director_exporter"))
    parser.add_argument(
        "--renderer-manifest",
        type=Path,
        default=Path("tools/miel_vliegt/libreshockwave.json"),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fps", type=int, default=30)
    args = parser.parse_args()
    result = verify_render(
        args.movie,
        args.renderer,
        args.renderer_manifest,
        args.projector_manifest,
        args.output_dir,
        args.fps,
    )
    print(json.dumps({
        "status": "PASS",
        "movie_sha256": result["movie_sha256"],
        "asset_sha256": result["asset_sha256"],
        "score_frames": result["render"]["score_frames"],
        "duration_ms": result["render"]["duration_ms"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
