#!/usr/bin/env python3
"""Harvest CCF material bindings and their exact Dutch GTI texture payloads.

The CCF stores texture names without paths or extensions.  For aircraft parts
the native search domain is ``Graphics/Parts/Textures``.  Keeping that domain
explicit prevents a same-named effect texture elsewhere in the game from being
selected accidentally.  Both source bytes and decoded RGBA/PNG bytes are
hashed so extraction, decoding and browser publication can be checked
independently.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from collections import Counter
from pathlib import Path

try:
    from tools.miel_vliegt.decode_gti import decode_gti
    from tools.miel_vliegt.export_web_assets import encode_png
    from tools.miel_vliegt.harvest_ccf_parts import harvest as harvest_parts
except ModuleNotFoundError:  # Direct script execution.
    from decode_gti import decode_gti
    from export_web_assets import encode_png
    from harvest_ccf_parts import harvest as harvest_parts


TEXTURE_ROOT = Path("data/Graphics/Parts/Textures")
ASSET_URL_ROOT = "assets/miel-vliegt/ccf-textures"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _texture_index(source_root: Path) -> dict[str, Path]:
    root = source_root / TEXTURE_ROOT
    if not root.is_dir():
        raise ValueError(f"missing CCF part texture directory: {root}")
    index: dict[str, Path] = {}
    for path in sorted(root.glob("*.gti"), key=lambda item: item.name.lower()):
        key = path.stem.casefold()
        if key in index:
            raise ValueError(f"case-insensitive CCF texture collision: {index[key]} and {path}")
        index[key] = path
    return index


def harvest(source_root: Path, parts_contract: dict[str, object] | None = None) -> dict[str, object]:
    parts_contract = parts_contract or harvest_parts(source_root)
    index = _texture_index(source_root)
    uses = []
    requested_names: dict[str, set[str]] = {}
    for part in parts_contract["parts"]:
        for reference, material in sorted(part["materials"].items(), key=lambda item: int(item[0])):
            texture = material["texture"]
            uses.append(
                {
                    "part_id": part["part_id"],
                    "material_reference": int(reference),
                    "material_name": material["name"],
                    "texture": texture,
                }
            )
            if texture is not None:
                requested_names.setdefault(texture.casefold(), set()).add(texture)

    missing = sorted(key for key in requested_names if key not in index)
    if missing:
        raise ValueError(f"missing CCF material textures: {', '.join(missing)}")

    textures = []
    format_counts: Counter[str] = Counter()
    for key in sorted(requested_names):
        aliases = sorted(requested_names[key])
        if len(aliases) != 1:
            raise ValueError(f"CCF texture uses disagree on case/spelling for {key!r}: {aliases}")
        path = index[key]
        source = path.read_bytes()
        image = decode_gti(source)
        png = encode_png(image)
        alpha = image.rgba[3::4]
        format_counts[image.format_name] += 1
        asset_name = f"{path.stem}.png"
        textures.append(
            {
                "id": key,
                "ccf_name": aliases[0],
                "source": path.relative_to(source_root).as_posix(),
                "source_sha256": _sha256(source),
                "decoded_rgba_sha256": _sha256(image.rgba),
                "png_sha256": _sha256(png),
                "asset_name": asset_name,
                "asset_url": f"{ASSET_URL_ROOT}/{asset_name}",
                "width": image.width,
                "height": image.height,
                "format": image.format_name,
                "mipmap_levels": image.mipmap_levels,
                "alpha": {
                    "minimum": min(alpha),
                    "maximum": max(alpha),
                    "transparent_pixels": sum(value < 255 for value in alpha),
                },
            }
        )

    contract = {
        "schema": 1,
        "search_policy": {
            "domain": TEXTURE_ROOT.as_posix(),
            "key": "casefold(CCF texture name)",
            "fallback_domains": [],
        },
        "counts": {
            "parts": len(parts_contract["parts"]),
            "material_uses": len(uses),
            "textured_material_uses": sum(use["texture"] is not None for use in uses),
            "textureless_material_uses": sum(use["texture"] is None for use in uses),
            "unique_textures": len(textures),
            "formats": dict(sorted(format_counts.items())),
        },
        "checkpoints": {
            "default_airplane_part_6": {
                "part_id": 6,
                "texture": "03_moth",
                "evidence": "CCF material reference plus exact GTI decode",
                "claim": "SOURCE_TEXTURE_EXACT",
            }
        },
        "textures": textures,
        "material_uses": uses,
    }
    expected = {
        "parts": 256,
        "material_uses": 362,
        "textured_material_uses": 355,
        "textureless_material_uses": 7,
        "unique_textures": 122,
        "formats": {"ARGB4444": 2, "RGB565": 120},
    }
    if contract["counts"] != expected:
        raise ValueError(f"CCF material corpus invariants drifted: {contract['counts']} != {expected}")
    return contract


def write_assets(contract: dict[str, object], source_root: Path, asset_root: Path) -> None:
    asset_root.mkdir(parents=True, exist_ok=True)
    expected = set()
    for texture in contract["textures"]:
        source = source_root / texture["source"]
        destination = asset_root / texture["asset_name"]
        payload = encode_png(decode_gti(source.read_bytes()))
        if _sha256(payload) != texture["png_sha256"]:
            raise ValueError(f"PNG encoder drifted for {texture['id']}")
        destination.write_bytes(payload)
        expected.add(destination.name)
    unexpected = sorted(path.name for path in asset_root.glob("*.png") if path.name not in expected)
    if unexpected:
        raise ValueError(f"stale CCF texture assets: {', '.join(unexpected)}")


def check_assets(contract: dict[str, object], asset_root: Path) -> None:
    expected = {texture["asset_name"]: texture["png_sha256"] for texture in contract["textures"]}
    actual = {path.name: _sha256(path.read_bytes()) for path in asset_root.glob("*.png")}
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(name for name in expected.keys() & actual.keys() if expected[name] != actual[name])
        raise ValueError(f"CCF texture assets drifted: missing={missing}, extra={extra}, changed={changed}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--asset-root", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    contract = harvest(args.source)
    encoded = json.dumps(contract, indent=2) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True), encoded.splitlines(keepends=True),
                    fromfile=str(args.output), tofile="fresh CCF material harvest",
                )
            )
            raise SystemExit(f"CCF material parity contract drifted:\n{diff[:12000]}")
        if args.asset_root:
            check_assets(contract, args.asset_root)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        if args.asset_root:
            write_assets(contract, args.source, args.asset_root)


if __name__ == "__main__":
    main()
