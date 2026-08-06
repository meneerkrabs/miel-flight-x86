#!/usr/bin/env python3
"""Differential gate for generated Kaitai parsers and independent oracles."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import difflib
import hashlib
import json
from pathlib import Path, PureWindowsPath
import struct

try:
    from tools.miel_vliegt.extract_udsp import UdspArchive
    from tools.miel_vliegt.kaitai_adapters import parse_cca_kaitai, parse_user_save_kaitai
    from tools.miel_vliegt.parse_cca import parse_cca
    from tools.miel_vliegt.parse_user_save import parse_user_save
except ModuleNotFoundError:  # Direct script execution from the repository root.
    from extract_udsp import UdspArchive
    from kaitai_adapters import parse_cca_kaitai, parse_user_save_kaitai
    from parse_cca import parse_cca
    from parse_user_save import parse_user_save


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "content" / "miel_vliegt" / "kaitai_parser_ratchet.json"
GENERATED_MANIFEST = (
    Path(__file__).resolve().parent
    / "kaitai"
    / "generated"
    / "python"
    / "manifest.json"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ir_sha256(value: object) -> str:
    def json_value(item: object) -> object:
        if isinstance(item, bytes):
            return {"bytes_hex": item.hex()}
        if isinstance(item, dict):
            return {key: json_value(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [json_value(child) for child in item]
        return item

    encoded = json.dumps(
        json_value(asdict(value)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return _sha256(encoded)


def _raw_user_save(username: bytes, chunks: tuple[tuple[bytes, bytes], ...]) -> bytes:
    body = b"USER" + b"NAME" + struct.pack(">I", len(username)) + username
    for chunk_id, payload in chunks:
        body += chunk_id + struct.pack(">I", len(payload)) + payload
    return b"FORM" + struct.pack(">I", len(body)) + body


def _user_fixture_receipt() -> dict[str, object]:
    valid = {
        "name_only": _raw_user_save(b"", ()),
        "source_order": _raw_user_save(
            b"Sander",
            (
                (b"MISS", b"mission-one"),
                (b"INVI", b"propeller\0"),
                (b"PHOT", b"map-state"),
                (b"DIPL", b"diplomas"),
                (b"BARN", b"barn-state"),
                (b"AIRP", b"airplane"),
                (b"AIRA", b"saved-airplane"),
            ),
        ),
        "repeated_chunks": _raw_user_save(
            b"Miel",
            ((b"MISS", b"first"), (b"INVI", b"part"), (b"MISS", b"second")),
        ),
    }
    invalid = {
        "wrong_magic": b"RIFF" + valid["name_only"][4:],
        "wrong_form_size": valid["name_only"][:4]
        + struct.pack(">I", len(valid["name_only"]) - 7)
        + valid["name_only"][8:],
        "unknown_chunk": _raw_user_save(b"Miel", ((b"FUTR", b"x"),)),
        "missing_name": b"FORM\x00\x00\x00\x0dUSERMISS\x00\x00\x00\x01x",
    }

    records = []
    for name, payload in valid.items():
        handwritten = parse_user_save(payload)
        generated = parse_user_save_kaitai(payload)
        if generated != handwritten:
            raise ValueError(f"USER fixture {name}: normalized IR differs")
        records.append(
            {
                "name": name,
                "sha256": _sha256(payload),
                "normalized_ir_sha256": _ir_sha256(generated),
            }
        )
    for name, payload in invalid.items():
        rejected = []
        for parser_name, parser in (
            ("handwritten", parse_user_save),
            ("generated", parse_user_save_kaitai),
        ):
            try:
                parser(payload)
            except (TypeError, ValueError):
                rejected.append(parser_name)
        if rejected != ["handwritten", "generated"]:
            raise ValueError(f"USER malformed fixture {name}: rejection differs: {rejected}")
    return {
        "claim": "SYNTHETIC_DIFFERENTIAL_EXACT",
        "claim_limit": "No original Dutch user*.dat capture is available yet",
        "native_samples": 0,
        "valid_fixtures": records,
        "malformed_fixtures_rejected": sorted(invalid),
    }


def build_ratchet(data_up: Path) -> dict[str, object]:
    archive = UdspArchive(data_up)
    entries = sorted(
        (
            entry
            for entry in archive.files
            if PureWindowsPath(entry.path).suffix.casefold() == ".cca"
        ),
        key=lambda entry: entry.path.casefold(),
    )
    files = []
    total_animations = 0
    total_transforms = 0
    for entry in entries:
        payload = archive.payload(entry)
        handwritten = parse_cca(payload, source=entry.path)
        generated = parse_cca_kaitai(payload, source=entry.path)
        if generated != handwritten:
            raise ValueError(f"{entry.path}: generated and handwritten CCA IR differ")
        ir_hash = _ir_sha256(generated)
        files.append(
            {
                "path": entry.path.replace("\\", "/"),
                "sha256": _sha256(payload),
                "normalized_ir_sha256": ir_hash,
                "animations": generated.animation_count,
                "frames_per_animation": generated.frame_count,
                "transform_records": generated.animation_count * generated.frame_count,
            }
        )
        total_animations += generated.animation_count
        total_transforms += generated.animation_count * generated.frame_count

    return {
        "schema": 1,
        "claim": "GENERATED_VS_INDEPENDENT_DIFFERENTIAL_EXACT",
        "claim_limit": (
            "Binary framing and normalized stored-record IR only; runtime physics, "
            "interpolation, rendering and original save acceptance are separate gates"
        ),
        "toolchain": json.loads(GENERATED_MANIFEST.read_text(encoding="utf-8")),
        "cca": {
            "source": {
                "archive": data_up.name,
                "sha256": _sha256(data_up.read_bytes()),
                "version": f"{archive.header.version_major}.{archive.header.version_minor}",
            },
            "counts": {
                "files": len(files),
                "blueprint_animations": total_animations,
                "transform_records": total_transforms,
            },
            "files": files,
        },
        "user_save": _user_fixture_receipt(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_up", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    encoded = json.dumps(build_ratchet(args.data_up), indent=2) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    encoded.splitlines(keepends=True),
                    fromfile=str(args.output),
                    tofile="fresh Kaitai parity ratchet",
                )
            )
            raise SystemExit(f"Kaitai parser ratchet drifted:\n{diff[:12000]}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
