#!/usr/bin/env python3
"""Verify every exported flight-scene asset against its source contract.

This is a build-artifact differential, not a framebuffer parity claim.  It
closes the gap between the tracked source inventory and the gitignored payload
that is copied into the production image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "content/miel_vliegt/flight_scene_asset_contract.json"
DEFAULT_PACK = ROOT / "content/miel_vliegt/flight_scene_assets.json"
DEFAULT_ASSET_ROOT = ROOT / "content/miel_vliegt/miel-vliegt"
DEFAULT_RECEIPT = ROOT / "content/miel_vliegt/flight_scene_payload_differential.json"
DEFAULT_SCHEMA = ROOT / "tools/miel_vliegt/schemas/flight-scene-payload-differential.schema.json"
PROTOCOL = "miel-vliegt-flight-scene-payload-differential"
CLAIM = "EXACT_EXPORTED_SCENE_PAYLOAD"
CLAIM_LIMIT = [
    "SCENE_COMPOSITION_UNPROVEN",
    "NATIVE_FRAMEBUFFER_PARITY_UNPROVEN",
]
POLICY = {
    "missingFiles": "REJECT",
    "unlistedSceneFiles": "REJECT",
    "imageBytes": "EXACT_OUTPUT_SHA256",
    "imageMetadata": "EXACT_PNG_IHDR",
    "audioBytes": "EXACT_SOURCE_SHA256",
    "audioMetadata": "VALID_RIFF_WAVE",
    "phaserPack": "EXACT_SEMANTIC_MATCH",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class PayloadDifferentialError(ValueError):
    """Raised when the generated private payload is incomplete or stale."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PayloadDifferentialError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise PayloadDifferentialError(f"expected JSON object in {path}")
    return value


def _asset_relative(url: str) -> str:
    prefix = "assets/miel-vliegt/"
    if not isinstance(url, str) or not url.startswith(prefix):
        raise PayloadDifferentialError(f"scene asset URL escapes its payload root: {url!r}")
    relative = url[len(prefix):]
    path = Path(relative)
    if not relative or path.is_absolute() or ".." in path.parts:
        raise PayloadDifferentialError(f"unsafe scene asset URL: {url!r}")
    return path.as_posix()


def _png_metadata(payload: bytes) -> dict[str, int]:
    if len(payload) < 33 or payload[:8] != PNG_SIGNATURE:
        raise PayloadDifferentialError("exported image is not a PNG")
    length = struct.unpack_from(">I", payload, 8)[0]
    if length != 13 or payload[12:16] != b"IHDR":
        raise PayloadDifferentialError("exported PNG has no canonical IHDR")
    width, height, bit_depth, color_type, compression, filtering, interlace = (
        struct.unpack_from(">IIBBBBB", payload, 16)
    )
    if width <= 0 or height <= 0:
        raise PayloadDifferentialError("exported PNG has invalid dimensions")
    return {
        "width": width,
        "height": height,
        "bitDepth": bit_depth,
        "colorType": color_type,
        "compression": compression,
        "filter": filtering,
        "interlace": interlace,
    }


def _wav_metadata(payload: bytes) -> dict[str, int]:
    if len(payload) < 12 or payload[:4] != b"RIFF" or payload[8:12] != b"WAVE":
        raise PayloadDifferentialError("exported audio is not a RIFF/WAVE file")
    declared_size = struct.unpack_from("<I", payload, 4)[0] + 8
    if declared_size > len(payload):
        raise PayloadDifferentialError("exported WAVE file is truncated")
    offset = 12
    fmt: tuple[int, int, int, int, int, int] | None = None
    data_bytes: int | None = None
    while offset + 8 <= len(payload):
        chunk_id = payload[offset:offset + 4]
        size = struct.unpack_from("<I", payload, offset + 4)[0]
        start = offset + 8
        end = start + size
        if end > len(payload):
            raise PayloadDifferentialError("exported WAVE chunk is truncated")
        if chunk_id == b"fmt " and fmt is None:
            if size < 16:
                raise PayloadDifferentialError("exported WAVE fmt chunk is incomplete")
            fmt = struct.unpack_from("<HHIIHH", payload, start)
        elif chunk_id == b"data" and data_bytes is None:
            data_bytes = size
        offset = end + (size & 1)
    if fmt is None or data_bytes is None:
        raise PayloadDifferentialError("exported WAVE lacks fmt or data")
    format_tag, channels, sample_rate, byte_rate, block_align, bits_per_sample = fmt
    return {
        "formatTag": format_tag,
        "channels": channels,
        "sampleRate": sample_rate,
        "byteRate": byte_rate,
        "blockAlign": block_align,
        "bitsPerSample": bits_per_sample,
        "dataBytes": data_bytes,
    }


def _aggregate(rows: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["path"]):
        digest.update(_canonical(row))
        digest.update(b"\n")
    return digest.hexdigest()


def _expected_pack(contract: dict[str, Any]) -> dict[str, list[dict[str, object]]]:
    assets: dict[str, dict[str, object]] = {}
    for row in contract.get("images", []):
        record = {key: row[key] for key in ("type", "key", "url")}
        if record["key"] in assets:
            raise PayloadDifferentialError(f"duplicate asset key: {record['key']}")
        assets[str(record["key"])] = record
    for row in contract.get("audio", []):
        record = {key: row[key] for key in ("type", "key", "urls")}
        if record["key"] in assets:
            raise PayloadDifferentialError(f"duplicate asset key: {record['key']}")
        assets[str(record["key"])] = record

    pack: dict[str, list[dict[str, object]]] = {}
    assigned: set[str] = set()
    for section in contract.get("packSections", []):
        key = section.get("key")
        asset_keys = section.get("assetKeys")
        if not isinstance(key, str) or not key or key in pack \
                or not isinstance(asset_keys, list) \
                or any(not isinstance(asset_key, str) for asset_key in asset_keys):
            raise PayloadDifferentialError("invalid Phaser pack section in source contract")
        duplicate = assigned.intersection(asset_keys)
        missing = set(asset_keys) - set(assets)
        if duplicate or missing:
            raise PayloadDifferentialError(
                f"invalid Phaser pack closure: duplicate={sorted(duplicate)}, "
                f"missing={sorted(missing)}"
            )
        assigned.update(asset_keys)
        pack[key] = [assets[asset_key] for asset_key in asset_keys]
    if assigned != set(assets):
        raise PayloadDifferentialError("Phaser pack omits source-contract assets")
    return pack


def build_receipt(
    contract_path: Path = DEFAULT_CONTRACT,
    pack_path: Path = DEFAULT_PACK,
    asset_root: Path = DEFAULT_ASSET_ROOT,
    schema_path: Path = DEFAULT_SCHEMA,
) -> dict[str, Any]:
    contract = _load_json(contract_path)
    if contract.get("schema") != 1 \
            or contract.get("contract") != "miel-vliegt-flight-scene-assets":
        raise PayloadDifferentialError("unsupported flight scene asset contract")
    images = contract.get("images")
    audio = contract.get("audio")
    counts = contract.get("counts")
    if not isinstance(images, list) or not isinstance(audio, list) \
            or not isinstance(counts, dict) \
            or counts.get("images") != len(images) \
            or counts.get("audioVariants") != len(audio):
        raise PayloadDifferentialError("flight scene asset count algebra drifted")

    image_rows: list[dict[str, Any]] = []
    audio_rows: list[dict[str, Any]] = []
    expected_paths: set[str] = set()
    total_bytes = 0

    for source in images:
        relative = _asset_relative(source.get("url"))
        if relative in expected_paths:
            raise PayloadDifferentialError(f"duplicate exported payload path: {relative}")
        expected_paths.add(relative)
        path = asset_root / relative
        if not path.is_file():
            raise PayloadDifferentialError(f"missing exported scene image: {relative}")
        payload = path.read_bytes()
        digest = _sha256_bytes(payload)
        if digest != source.get("outputSha256"):
            raise PayloadDifferentialError(f"scene image hash drifted: {relative}")
        metadata = _png_metadata(payload)
        if metadata["width"] != source.get("width") \
                or metadata["height"] != source.get("height") \
                or metadata["bitDepth"] != 8 \
                or metadata["colorType"] != 6:
            raise PayloadDifferentialError(f"scene image metadata drifted: {relative}")
        total_bytes += len(payload)
        image_rows.append({
            "path": relative,
            "sha256": digest,
            "bytes": len(payload),
            "metadata": metadata,
        })

    for source in audio:
        urls = source.get("urls")
        if not isinstance(urls, list) or len(urls) != 1:
            raise PayloadDifferentialError(
                f"scene audio must have one canonical URL: {source.get('key')!r}"
            )
        relative = _asset_relative(urls[0])
        if relative in expected_paths:
            raise PayloadDifferentialError(f"duplicate exported payload path: {relative}")
        expected_paths.add(relative)
        path = asset_root / relative
        if not path.is_file():
            raise PayloadDifferentialError(f"missing exported scene audio: {relative}")
        payload = path.read_bytes()
        digest = _sha256_bytes(payload)
        if digest != source.get("sourceSha256"):
            raise PayloadDifferentialError(f"scene audio hash drifted: {relative}")
        metadata = _wav_metadata(payload)
        total_bytes += len(payload)
        audio_rows.append({
            "path": relative,
            "sha256": digest,
            "bytes": len(payload),
            "metadata": metadata,
        })

    scene_root = asset_root / "scenes"
    actual_paths = {
        path.relative_to(asset_root).as_posix()
        for path in scene_root.rglob("*")
        if path.is_file()
    } if scene_root.is_dir() else set()
    missing = expected_paths - actual_paths
    unlisted = actual_paths - expected_paths
    if missing or unlisted:
        raise PayloadDifferentialError(
            f"scene payload closure drifted: missing={sorted(missing)}, "
            f"unlisted={sorted(unlisted)}"
        )

    pack = _load_json(pack_path)
    expected_pack = _expected_pack(contract)
    if pack != expected_pack:
        raise PayloadDifferentialError("Phaser scene pack differs from the source contract")
    pack_assets = sum(len(rows) for rows in pack.values())

    receipt: dict[str, Any] = {
        "schema": 1,
        "protocol": PROTOCOL,
        "claim": CLAIM,
        "claimLimit": CLAIM_LIMIT,
        "inputs": {
            "contract": {
                "path": _display_path(contract_path),
                "sha256": _sha256(contract_path),
                "canonicalSha256": _sha256_bytes(_canonical(contract)),
            },
            "generator": {
                "path": _display_path(Path(__file__)),
                "sha256": _sha256(Path(__file__)),
            },
            "schema": {
                "path": _display_path(schema_path),
                "sha256": _sha256(schema_path),
            },
        },
        "policy": POLICY,
        "classes": {
            "sceneImages": {
                "status": "EXACT",
                "files": len(image_rows),
                "bytes": sum(row["bytes"] for row in image_rows),
                "aggregateSha256": _aggregate(image_rows),
            },
            "sceneAudio": {
                "status": "EXACT",
                "files": len(audio_rows),
                "bytes": sum(row["bytes"] for row in audio_rows),
                "aggregateSha256": _aggregate(audio_rows),
            },
            "phaserPack": {
                "status": "EXACT",
                "sections": len(pack),
                "assets": pack_assets,
                "sha256": _sha256(pack_path),
                "canonicalSha256": _sha256_bytes(_canonical(pack)),
            },
        },
        "summary": {
            "status": "EXACT",
            "files": len(expected_paths),
            "bytes": total_bytes,
            "assetClasses": 3,
            "framebufferParityClaimed": False,
        },
    }
    receipt["subjectSha256"] = _sha256_bytes(_canonical(receipt))
    validate_receipt(receipt)
    return receipt


def validate_schema_guard(schema: dict[str, Any]) -> None:
    properties = schema.get("properties")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" \
            or schema.get("additionalProperties") is not False \
            or not isinstance(properties, dict) \
            or set(schema.get("required", [])) != {
                "schema", "protocol", "claim", "claimLimit", "inputs", "policy",
                "classes", "summary", "subjectSha256",
            }:
        raise PayloadDifferentialError("payload differential schema guard drifted")


def validate_receipt(receipt: dict[str, Any]) -> None:
    if set(receipt) != {
        "schema", "protocol", "claim", "claimLimit", "inputs", "policy",
        "classes", "summary", "subjectSha256",
    } or receipt.get("schema") != 1 \
            or receipt.get("protocol") != PROTOCOL \
            or receipt.get("claim") != CLAIM \
            or receipt.get("claimLimit") != CLAIM_LIMIT:
        raise PayloadDifferentialError("payload differential receipt header drifted")
    inputs = receipt.get("inputs")
    classes = receipt.get("classes")
    summary = receipt.get("summary")
    if not isinstance(inputs, dict) or set(inputs) != {"contract", "generator", "schema"} \
            or receipt.get("policy") != POLICY \
            or not isinstance(classes, dict) \
            or set(classes) != {"sceneImages", "sceneAudio", "phaserPack"} \
            or not isinstance(summary, dict):
        raise PayloadDifferentialError("payload differential receipt shape drifted")
    for name, value in inputs.items():
        expected_keys = (
            {"path", "sha256", "canonicalSha256"}
            if name == "contract" else {"path", "sha256"}
        )
        if not isinstance(value, dict) or set(value) != expected_keys \
                or not isinstance(value.get("path"), str) or not value["path"] \
                or not SHA256.fullmatch(str(value.get("sha256", ""))):
            raise PayloadDifferentialError("payload differential input identity drifted")
    if not SHA256.fullmatch(str(inputs["contract"].get("canonicalSha256", ""))):
        raise PayloadDifferentialError("payload differential contract identity drifted")
    image_class = classes["sceneImages"]
    audio_class = classes["sceneAudio"]
    pack_class = classes["phaserPack"]
    if any(
        not isinstance(row, dict) or row.get("status") != "EXACT"
        for row in classes.values()
    ) \
            or set(image_class) != {"status", "files", "bytes", "aggregateSha256"} \
            or set(audio_class) != {"status", "files", "bytes", "aggregateSha256"} \
            or set(pack_class) != {
                "status", "sections", "assets", "sha256", "canonicalSha256",
            } \
            or any(
                not isinstance(row.get(field), int) or row[field] < 0
                for row in (image_class, audio_class)
                for field in ("files", "bytes")
            ) \
            or any(
                not SHA256.fullmatch(str(row.get("aggregateSha256", "")))
                for row in (image_class, audio_class)
            ) \
            or any(
                not isinstance(pack_class.get(field), int) or pack_class[field] < 0
                for field in ("sections", "assets")
            ) \
            or not SHA256.fullmatch(str(pack_class.get("sha256", ""))) \
            or not SHA256.fullmatch(str(pack_class.get("canonicalSha256", ""))) \
            or set(summary) != {
                "status", "files", "bytes", "assetClasses",
                "framebufferParityClaimed",
            } \
            or summary.get("status") != "EXACT" \
            or summary.get("files") != image_class["files"] + audio_class["files"] \
            or summary.get("bytes") != image_class["bytes"] + audio_class["bytes"] \
            or pack_class["assets"] != summary.get("files") \
            or summary.get("assetClasses") != 3 \
            or summary.get("framebufferParityClaimed") is not False:
        raise PayloadDifferentialError("payload differential cannot claim exact closure")
    subject = receipt.get("subjectSha256")
    unsigned = dict(receipt)
    unsigned.pop("subjectSha256", None)
    if not SHA256.fullmatch(str(subject or "")) \
            or subject != _sha256_bytes(_canonical(unsigned)):
        raise PayloadDifferentialError("payload differential subject hash drifted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--asset-root", type=Path, default=DEFAULT_ASSET_ROOT)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    schema = _load_json(args.schema)
    validate_schema_guard(schema)
    fresh = build_receipt(args.contract, args.pack, args.asset_root, args.schema)
    if args.write:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(fresh, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return 0
    current = _load_json(args.receipt)
    validate_receipt(current)
    if current != fresh:
        raise PayloadDifferentialError(
            "flight scene payload differential receipt drifted; regenerate from the pinned ISO"
        )
    print(json.dumps(fresh["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
