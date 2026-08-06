#!/usr/bin/env python3
"""Export the original Miel Vliegt hangar assets for the Phaser runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import struct
import zlib
from pathlib import Path

try:
    from tools.miel_vliegt.capture_projector_intro import validate_media
    from tools.miel_vliegt.decode_gti import GtiImage, decode_gti
    from tools.miel_vliegt.projector_movies import extract_projector_movies
    from tools.miel_vliegt.render_director_movie import render_movie
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from capture_projector_intro import validate_media
    from decode_gti import GtiImage, decode_gti
    from projector_movies import extract_projector_movies
    from render_director_movie import render_movie


HANGAR_PATH = Path("data/Graphics/Barn")
FRONTEND_PATH = Path("data/Graphics/Frontend")
ICONS_PATH = Path("data/Graphics/Icons")
PROJECTOR_SOUND_PATH = Path("data/Sound/Barn/Projector_loop.wav")
DOOR_SOUND_PATHS = {
    "flight-door-open": Path("data/Sound/Barn/door_open.wav"),
    "flight-door-close": Path("data/Sound/Barn/door_close.wav"),
}
HISTORY_VOICE_PATH = Path("data/Sound/Voices/c")
RADIO_FEEDBACK_PATH = Path("data/Sound/Voices/b/MM010049B.WAV")
INTRO_VIDEO_PATH = Path("data/Video/intro_indeo(320x240).avi")
INTRO_VIDEO_ASSET = "flight-intro.mp4"
INTRO_RENDER_EXPECTATIONS = {
    "stage": {"width": 640, "height": 480},
    "score_frames": 1765,
    "required_streams": ["video", "audio"],
}
INTRO_NATIVE_CONTROL_FLOW = {
    "loader": "0x00406af0",
    "caller": "0x00405030",
    "movie_vtable_slot": "0x0044c6ec",
    "open_failure_result": False,
    "fallback": "abort-movie-mode-and-continue-native-startup",
}
INTRO_SOURCE_AUDITS = [
    {
        "edition": "nl-alt",
        "archive_identifier": "miel-monteur-vliegt-de-wereld-rond",
        "iso_sha256": "5dd277a6a404df9340c4937a8a6f2f46a730cf872775cecc19cd778a8f5cef28",
        "searched": ["iso-files", "installshield-all-groups", "udsp:data,map,sounds"],
        "result": "native-path-absent",
        "note": "UDSP archives are byte-identical to the canonical Dutch ISO",
    },
    {
        "edition": "de",
        "archive_identifier": "Flugzeuge_bauen_Willy_Werkel",
        "iso_sha256": "b35fe7ad6c17da300ef94d2484355593d4f3d7aa1cf21c5c8269f61829f313da",
        "searched": ["iso-files", "preinstalled-tree", "udsp:data,map,sounds"],
        "result": "native-path-absent",
    },
    {
        "edition": "sv",
        "archive_identifier": "byggflygplanmedmullemeck",
        "iso_sha256": "a8418892b4bd5a81d6abf9f510c3a88e3e354510dcc6e13ea414d6924ac4cf69",
        "searched": ["iso-files", "installshield-all-groups", "udsp:data,map"],
        "result": "native-path-absent",
        "excluded_candidate": {
            "path": "System Files (Swedish)/ScanMovie.avi",
            "reason": "480x300 Cinepak Scan.exe movie; not the executable's 320x240 Indeo path",
            "sha256": "d5a568e2ac6adda932707e7ca698acb4d5f3294415a84889533246a68883653a",
        },
    },
]
REQUIRED_BACKGROUNDS = {"hangar_inside", "hangar_outside", "hangar_shelf", "hangar_sky"}
LABELS = {
    "dörr": "door",
    "album": "album",
    "camera": "camera",
    "map": "map",
    "upp": "up",
    "ner": "down",
    "siffra": "number",
}


def _png_chunk(identifier: bytes, payload: bytes) -> bytes:
    body = identifier + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))


def encode_png(image: GtiImage) -> bytes:
    rows = b"".join(
        b"\0" + image.rgba[offset : offset + image.width * 4]
        for offset in range(0, len(image.rgba), image.width * 4)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">2I5B", image.width, image.height, 8, 6, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(rows, 9))
        + _png_chunk(b"IEND", b"")
    )


def parse_hotspots(path: Path) -> dict[str, dict[str, dict[str, int]]]:
    sections: dict[str, dict[str, dict[str, int]]] = {}
    section = None
    for raw_line in path.read_text(encoding="latin-1").splitlines():
        line = raw_line.strip()
        if line.endswith(":") and "=" not in line:
            section = line[:-1].lower()
            sections[section] = {}
            continue
        match = re.match(r"([^:=]+)\s*[:=]\s*(\d+)\s*,\s*(\d+)", line)
        if not match or section is None:
            continue
        label = match.group(1).strip().lower()
        normalized = LABELS.get(label)
        if normalized is None:
            raise ValueError(f"{path}: unknown hotspot label {label!r}")
        sections[section][normalized] = {"x": int(match.group(2)), "y": int(match.group(3))}
    if set(sections) != {"outside", "inside", "shelf"}:
        raise ValueError(f"{path}: incomplete hangar hotspot sections")
    return sections


def export_hangar(source_root: Path, output: Path) -> dict[str, object]:
    source = source_root / HANGAR_PATH
    if not source.is_dir():
        raise ValueError(f"missing extracted hangar directory: {source}")
    output.mkdir(parents=True, exist_ok=True)
    image_dir = output / "miel-vliegt"
    image_dir.mkdir(parents=True, exist_ok=True)

    assets = []
    dimensions = {}
    for path in sorted(source.glob("hangar*.gti")):
        image = decode_gti(path.read_bytes())
        key = path.stem.replace("_", "-")
        destination = image_dir / f"{path.stem}.png"
        destination.write_bytes(encode_png(image))
        assets.append({"type": "image", "key": key, "url": f"assets/miel-vliegt/{destination.name}"})
        dimensions[path.stem] = {"width": image.width, "height": image.height}

    missing = REQUIRED_BACKGROUNDS - set(dimensions)
    if missing:
        raise ValueError(f"missing required hangar images: {', '.join(sorted(missing))}")
    hotspots = parse_hotspots(source / "kordinater.txt")
    audio = {}
    for key, relative_path in DOOR_SOUND_PATHS.items():
        path = source_root / relative_path
        if not path.is_file():
            raise ValueError(f"missing hangar door sound: {path}")
        destination = image_dir / path.name
        destination.write_bytes(path.read_bytes())
        assets.append({"type": "audio", "key": key, "urls": [f"assets/miel-vliegt/{path.name}"]})
        audio[key] = {"source": relative_path.as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    contract = {
        "dimensions": dimensions,
        "compositions": {
            "outside": {
                "layers": [
                    {
                        "key": "hangar-sky",
                        "mode": "tile",
                        "x": 0,
                        "y": 0,
                        "width": dimensions["hangar_outside"]["width"],
                        "height": dimensions["hangar_sky"]["height"],
                    },
                    {"key": "hangar-outside", "mode": "image", "x": 0, "y": 0},
                ]
            }
        },
        "hotspots": hotspots,
        "audio": audio,
    }
    (output / "flight_hangar.json").write_text(
        json.dumps({"flight_hangar": assets}, indent=2) + "\n", encoding="utf-8"
    )
    (output / "flight_hangar_contract.json").write_text(
        json.dumps(contract, indent=2) + "\n", encoding="utf-8"
    )
    return contract


def _frontend_sources(source_root: Path) -> list[tuple[str, Path]]:
    frontend = source_root / FRONTEND_PATH
    icons = source_root / ICONS_PATH
    sources = [
        ("flight-album-bg", frontend / "album_bg.gti"),
        ("flight-name-entry", frontend / "name_entry_window.gti"),
        ("flight-frontend-background", frontend / "background.gti"),
        ("flight-handbook-bg", frontend / "handbook_bg.gti"),
        ("flight-film-bg", frontend / "flightfilm_bg.gti"),
        ("flight-film-fg", frontend / "flightfilm_fg.gti"),
        ("flight-film-grain-tiled", frontend / "grain_tiled.gti"),
        ("flight-history-empty", frontend / "flighthistory_empty.gti"),
        ("flight-film-selector", frontend / "bildbytare.gti"),
        ("flight-map-complete", frontend / "MapPhotos/map_complete.gti"),
        ("flight-icon-exit", icons / "icon_exitarrow_00.gti"),
        ("flight-icon-exit-small", icons / "icon_exitarrowsmall_00.gti"),
        ("flight-icon-left", icons / "icon_arrowleft_00.gti"),
        ("flight-icon-right", icons / "icon_arrowright_00.gti"),
        ("flight-icon-up", icons / "icon_arrowup_00.gti"),
        ("flight-icon-down", icons / "icon_arrowdown_00.gti"),
        ("flight-icon-paste", icons / "icon_pasteplane_00.gti"),
        ("flight-icon-load", icons / "icon_loadplane_00.gti"),
        ("flight-icon-trash", icons / "icon_trash_00.gti"),
        ("flight-icon-print", icons / "icon_print_00.gti"),
        ("flight-icon-export", icons / "icon_export_00.gti"),
        ("flight-icon-import", icons / "icon_import_00.gti"),
        ("flight-album-tab", icons / "flik.gti"),
    ]
    sources.extend(
        (f"flight-handbook-{page:02d}", frontend / f"handbook_{page:02d}.gti")
        for page in range(1, 25)
    )
    sources.extend(
        (f"flight-history-{item:02d}", frontend / f"flighthistory_{item:02d}.gti")
        for item in range(1, 17)
    )
    sources.extend(
        (f"flight-film-grain-{frame:02d}", frontend / f"grain{frame:02d}.gti")
        for frame in range(9)
    )
    return sources


def export_frontend(source_root: Path, output: Path) -> dict[str, object]:
    """Export the three native hangar frontends and their parity manifest."""
    output.mkdir(parents=True, exist_ok=True)
    image_dir = output / "miel-vliegt"
    image_dir.mkdir(parents=True, exist_ok=True)

    assets = []
    images = {}
    for key, path in _frontend_sources(source_root):
        if not path.is_file():
            raise ValueError(f"missing required flight frontend image: {path}")
        raw = path.read_bytes()
        image = decode_gti(raw)
        destination = image_dir / f"{key}.png"
        destination.write_bytes(encode_png(image))
        assets.append({"type": "image", "key": key, "url": f"assets/miel-vliegt/{destination.name}"})
        images[key] = {
            "source": path.relative_to(source_root).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "width": image.width,
            "height": image.height,
        }

    projector_sound = source_root / PROJECTOR_SOUND_PATH
    if not projector_sound.is_file():
        raise ValueError(f"missing projector loop: {projector_sound}")
    sound_raw = projector_sound.read_bytes()
    sound_destination = image_dir / "Projector_loop.wav"
    sound_destination.write_bytes(sound_raw)
    assets.append({
        "type": "audio",
        "key": "flight-projector-loop",
        "urls": [f"assets/miel-vliegt/{sound_destination.name}"],
    })

    history_sequence = []
    history_images = (None, None, 1, 2, 3, None, 4, 5, 5, 6, 7, None, 8, 9, None, 10, 11, 12, 13, 14, 15, 16)
    history_audio = {}
    for number, image_number in zip(range(91, 113), history_images):
        path = source_root / HISTORY_VOICE_PATH / f"MM010{number:03d}C.WAV"
        if not path.is_file():
            raise ValueError(f"missing flight history voice: {path}")
        key = f"flight-history-voice-{number:03d}"
        destination = image_dir / path.name
        raw = path.read_bytes()
        destination.write_bytes(raw)
        assets.append({"type": "audio", "key": key, "urls": [f"assets/miel-vliegt/{path.name}"]})
        history_audio[key] = {"source": path.relative_to(source_root).as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}
        history_sequence.append({"voice": key, "image": image_number})

    radio_path = source_root / RADIO_FEEDBACK_PATH
    if not radio_path.is_file():
        raise ValueError(f"missing hangar radio feedback: {radio_path}")
    radio_raw = radio_path.read_bytes()
    radio_destination = image_dir / radio_path.name
    radio_destination.write_bytes(radio_raw)
    assets.append({"type": "audio", "key": "flight-radio-feedback", "urls": [f"assets/miel-vliegt/{radio_path.name}"]})

    evidence = {}
    for name in (
        "flightfilm_sounds.txt", "layout_flightfilm.txt",
        "layout_score_album_main.txt", "layout_score_album_exportimport.txt",
    ):
        path = source_root / FRONTEND_PATH / name
        if not path.is_file():
            raise ValueError(f"missing native frontend evidence: {path}")
        evidence[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    contract = {
        "schema": 1,
        "handbook_pages": 24,
        "history_items": 16,
        "history_sequence": history_sequence,
        "history_audio": history_audio,
        "images": images,
        "evidence": evidence,
        "projector_loop": {
            "source": PROJECTOR_SOUND_PATH.as_posix(),
            "sha256": hashlib.sha256(sound_raw).hexdigest(),
        },
        "radio_feedback": {
            "bank": "B",
            "line": 49,
            "source": RADIO_FEEDBACK_PATH.as_posix(),
            "sha256": hashlib.sha256(radio_raw).hexdigest(),
        },
    }
    (output / "flight_frontend.json").write_text(
        json.dumps({"flight_frontend": assets}, indent=2) + "\n", encoding="utf-8"
    )
    (output / "flight_frontend_contract.json").write_text(
        json.dumps(contract, indent=2) + "\n", encoding="utf-8"
    )
    return contract


def _find_intro_video(source_root: Path) -> Path | None:
    """Find the executable's intro path without assuming filesystem casing."""
    expected = INTRO_VIDEO_PATH.as_posix().lower()
    matches = [
        path for path in source_root.rglob("*")
        if path.is_file() and path.relative_to(source_root).as_posix().lower() == expected
    ]
    if len(matches) > 1:
        raise ValueError(f"ambiguous native flight intro sources: {matches}")
    return matches[0] if matches else None


def _validate_intro_render_receipt(receipt: dict[str, object]) -> None:
    render = receipt.get("render", {})
    if render.get("stage") != INTRO_RENDER_EXPECTATIONS["stage"]:
        raise ValueError("Director intro render stage drifted from the source score")
    if render.get("score_frames") != INTRO_RENDER_EXPECTATIONS["score_frames"]:
        raise ValueError("Director intro score frame count drifted")
    if render.get("script_errors"):
        raise ValueError("Director intro renderer reported script errors")
    if not any(event.get("action") == "play" for event in render.get("audio_events", [])):
        raise ValueError("Director intro render omitted its score audio")
    stream_types = {
        stream.get("codec_type") for stream in receipt.get("media", {}).get("streams", [])
    }
    if not set(INTRO_RENDER_EXPECTATIONS["required_streams"]).issubset(stream_types):
        raise ValueError("Director intro render is missing required audio/video streams")


def _contract_render_receipt(receipt: dict[str, object]) -> dict[str, object]:
    """Keep source semantics in git, not host/ffmpeg-specific container noise."""
    selected_stream_fields = {
        "video": ("codec_type", "codec_name", "width", "height", "pix_fmt", "r_frame_rate"),
        "audio": ("codec_type", "codec_name", "sample_rate", "channels", "channel_layout"),
    }
    streams = []
    for stream in receipt["media"]["streams"]:
        fields = selected_stream_fields.get(stream.get("codec_type"))
        if fields:
            streams.append({field: stream[field] for field in fields if field in stream})
    return {
        "schema": receipt["schema"],
        "render_method": receipt["render_method"],
        "movie_sha256": receipt["movie_sha256"],
        "renderer": receipt["renderer"],
        "render": receipt["render"],
        "media": {"streams": streams},
    }


def export_intro(
        source_root: Path,
        output: Path,
        projector: Path | None = None,
        capture: Path | None = None,
        capture_receipt: Path | None = None,
        renderer: Path | None = None,
        renderer_manifest: Path | None = None) -> dict[str, object]:
    """Inventory the embedded Director intro and optionally import its capture."""
    if (capture is None) != (capture_receipt is None):
        raise ValueError("--intro-capture and --intro-capture-receipt must be supplied together")
    if (renderer is None) != (renderer_manifest is None):
        raise ValueError("--intro-renderer and --intro-renderer-manifest must be supplied together")
    output.mkdir(parents=True, exist_ok=True)
    source = _find_intro_video(source_root)
    contract: dict[str, object] = {
        "schema": 1,
        "source_kind": "embedded-director-projector",
        "availability": "projector-absent",
        "disposition": "continue-to-hangar",
        "legacy_engine_movie": {
            "path": INTRO_VIDEO_PATH.as_posix(),
            "canonical_audit": {
                "edition": "miel-vliegt-de-wereld-rond-nl",
                "iso_sha256": "693a85370b704e743f56c7d6c39bc89574c1a74129ca351157e5b9514aaa3a60",
                "executable_sha256": "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2",
                "searched": ["iso-files", "installshield-all-groups", "udsp:data,map,sounds"],
                "result": "native-path-absent",
            },
            "native_control_flow": INTRO_NATIVE_CONTROL_FLOW,
            "alternate_edition_audits": INTRO_SOURCE_AUDITS,
        },
    }
    if source is not None:
        contract["legacy_engine_movie"]["asset"] = {
            "source": source.relative_to(source_root).as_posix(),
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        }
    projector_manifest = None
    if projector is not None:
        # Rebased Director sources are parity evidence, never browser assets.
        # Keeping them outside ``miel-vliegt`` prevents Docker from publishing
        # the original movie payloads alongside the generated web media.
        projector_manifest = extract_projector_movies(projector, output / "projector-movies")
        contract.update({
            "availability": "render-pending",
            "projector_source": projector_manifest,
            "render_blocker": (
                "The source-exact Director 8 score is extracted; a native-projector capture "
                "receipt is required because the available ScummVM renderer cannot parse this v800 score."
            ),
        })
    if renderer is not None:
        if projector_manifest is None:
            raise ValueError("Director intro rendering requires --projector")
        intro = projector_manifest["movies"][projector_manifest["intro_index"]]
        movie = output / "projector-movies" / intro["payload"]
        image_dir = output / "miel-vliegt"
        image_dir.mkdir(parents=True, exist_ok=True)
        destination = image_dir / INTRO_VIDEO_ASSET
        render_receipt_path = (
            output / "projector-movies" / "render-oracles" / "libreshockwave" / "receipt.json"
        )
        render_receipt = render_movie(
            movie,
            destination,
            renderer,
            renderer_manifest,
            render_receipt_path,
            expected_movie_sha256=intro["sha256"],
        )
        _validate_intro_render_receipt(render_receipt)
        contract_receipt = _contract_render_receipt(render_receipt)
        receipt_hash = hashlib.sha256(
            json.dumps(contract_receipt, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        contract.pop("render_blocker", None)
        contract.update({
            "availability": "available",
            "disposition": "play-before-hangar",
            "reconstruction": {
                "method": "libreshockwave-score",
                "parity_status": "pending-native-oracle",
                "receipt": contract_receipt,
                "expectations": INTRO_RENDER_EXPECTATIONS,
            },
            "asset": {
                "url": f"assets/miel-vliegt/{INTRO_VIDEO_ASSET}",
                "render_receipt_sha256": receipt_hash,
            },
        })
    if capture is not None:
        if projector_manifest is None:
            raise ValueError("intro capture requires --projector and --intro-capture-receipt")
        receipt = json.loads(capture_receipt.read_text(encoding="utf-8"))
        intro = projector_manifest["movies"][projector_manifest["intro_index"]]
        if receipt.get("schema") != 1 or receipt.get("capture_method") != "native-projector":
            raise ValueError("invalid native projector capture receipt")
        validate_media(receipt.get("media", {}))
        if receipt.get("projector_sha256") != projector_manifest["projector"]["sha256"]:
            raise ValueError("capture receipt projector identity drifted")
        if receipt.get("intro_movie_sha256") != intro["sha256"]:
            raise ValueError("capture receipt intro movie identity drifted")
        capture_sha256 = hashlib.sha256(capture.read_bytes()).hexdigest()
        if receipt.get("capture_sha256") != capture_sha256:
            raise ValueError("native projector capture drifted from its receipt")
        image_dir = output / "miel-vliegt"
        image_dir.mkdir(parents=True, exist_ok=True)
        destination = image_dir / INTRO_VIDEO_ASSET
        subprocess.run([
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
            "-i", str(capture), "-map_metadata", "-1", "-c:v", "libx264",
            "-pix_fmt", "yuv420p", "-c:a", "aac", "-movflags", "+faststart",
            str(destination),
        ], check=True)
        contract.update({
            "availability": "available",
            "disposition": "play-before-hangar",
            "capture": {
                "source_sha256": capture_sha256,
                "receipt": receipt,
            },
            "asset": {
                "url": f"assets/miel-vliegt/{INTRO_VIDEO_ASSET}",
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            },
        })
    (output / "flight_intro_contract.json").write_text(
        json.dumps(contract, indent=2) + "\n", encoding="utf-8"
    )
    return contract


def export_all(
        source_root: Path,
        output: Path,
        projector: Path | None = None,
        capture: Path | None = None,
        capture_receipt: Path | None = None,
        renderer: Path | None = None,
        renderer_manifest: Path | None = None) -> None:
    export_hangar(source_root, output)
    export_frontend(source_root, output)
    export_intro(
        source_root, output, projector, capture, capture_receipt, renderer, renderer_manifest
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="root containing extracted data/")
    parser.add_argument("output", type=Path, help="web assets output directory")
    parser.add_argument("--projector", type=Path, help="original Start_Mulle.exe projector")
    parser.add_argument("--intro-capture", type=Path, help="native execution capture to transcode")
    parser.add_argument("--intro-capture-receipt", type=Path, help="capture provenance receipt")
    parser.add_argument("--intro-renderer", type=Path, help="pinned LibreShockwave exporter")
    parser.add_argument("--intro-renderer-manifest", type=Path, help="LibreShockwave pin manifest")
    args = parser.parse_args()
    export_all(
        args.source, args.output, args.projector, args.intro_capture, args.intro_capture_receipt,
        args.intro_renderer, args.intro_renderer_manifest,
    )


if __name__ == "__main__":
    main()
