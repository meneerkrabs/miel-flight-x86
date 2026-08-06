#!/usr/bin/env python3
"""Decode UDS ``GtIm``/``Imag`` images to PNG."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


IMAGE_HEADER = struct.Struct("<5I")
FORMAT_NAMES = {
    3: "P8",
    4: "AP88",
    5: "RGB565",
    6: "ARGB4444",
    7: "RGB888",
    8: "ARGB8888",
}


@dataclass(frozen=True)
class GtiImage:
    width: int
    height: int
    format: int
    mipmap_levels: int
    rgba: bytes

    @property
    def format_name(self) -> str:
        return FORMAT_NAMES[self.format]


def _expand(value: int, bits: int) -> int:
    maximum = (1 << bits) - 1
    return (value * 255 + maximum // 2) // maximum


def _palette(payload: bytes, entries: int) -> tuple[list[tuple[int, int, int, int]], bytes]:
    size = entries * 4
    if len(payload) < size:
        raise ValueError("truncated GTI palette")
    colors = [(r, g, b, a) for b, g, r, a in struct.iter_unpack("<4B", payload[:size])]
    return colors, payload[size:]


def decode_gti(data: bytes) -> GtiImage:
    if not data.startswith(b"GtIm"):
        raise ValueError("not a GtIm image")
    chunk_offset = data.rfind(b"Imag")
    if chunk_offset < 0 or chunk_offset + 8 + IMAGE_HEADER.size > len(data):
        raise ValueError("missing Imag chunk")
    chunk_size = struct.unpack_from("<I", data, chunk_offset + 4)[0]
    chunk_end = chunk_offset + 8 + chunk_size
    if chunk_end != len(data):
        raise ValueError("Imag chunk does not end at EOF")
    image_format, width, height, palette_entries, mipmap_levels = IMAGE_HEADER.unpack_from(
        data, chunk_offset + 8
    )
    if image_format not in FORMAT_NAMES:
        raise ValueError(f"unsupported GTI format {image_format}")
    if width <= 0 or height <= 0 or mipmap_levels <= 0:
        raise ValueError("invalid GTI dimensions or mipmap count")
    payload = data[chunk_offset + 8 + IMAGE_HEADER.size : chunk_end]
    palette: list[tuple[int, int, int, int]] = []
    if image_format in (3, 4):
        if palette_entries <= 0:
            raise ValueError("paletted GTI has no palette")
        palette, payload = _palette(payload, palette_entries)

    pixel_count = width * height
    rgba = bytearray()
    if image_format == 3:
        base = payload[:pixel_count]
        if len(base) != pixel_count:
            raise ValueError("truncated P8 image")
        for index in base:
            if index >= len(palette):
                raise ValueError(f"palette index {index} is out of range")
            rgba.extend(palette[index])
    elif image_format == 4:
        base = payload[: pixel_count * 2]
        if len(base) != pixel_count * 2:
            raise ValueError("truncated AP88 image")
        for index, alpha in struct.iter_unpack("<BB", base):
            if index >= len(palette):
                raise ValueError(f"palette index {index} is out of range")
            red, green, blue, _ = palette[index]
            rgba.extend((red, green, blue, alpha))
    elif image_format in (5, 6):
        base = payload[: pixel_count * 2]
        if len(base) != pixel_count * 2:
            raise ValueError("truncated 16-bit GTI image")
        for (pixel,) in struct.iter_unpack("<H", base):
            if image_format == 5:
                rgba.extend(
                    (
                        _expand((pixel >> 11) & 0x1F, 5),
                        _expand((pixel >> 5) & 0x3F, 6),
                        _expand(pixel & 0x1F, 5),
                        255,
                    )
                )
            else:
                rgba.extend(
                    (
                        _expand((pixel >> 8) & 0xF, 4),
                        _expand((pixel >> 4) & 0xF, 4),
                        _expand(pixel & 0xF, 4),
                        _expand((pixel >> 12) & 0xF, 4),
                    )
                )
    elif image_format == 7:
        base = payload[: pixel_count * 3]
        if len(base) != pixel_count * 3:
            raise ValueError("truncated RGB888 image")
        for blue, green, red in struct.iter_unpack("<BBB", base):
            rgba.extend((red, green, blue, 255))
    else:
        base = payload[: pixel_count * 4]
        if len(base) != pixel_count * 4:
            raise ValueError("truncated ARGB8888 image")
        for blue, green, red, alpha in struct.iter_unpack("<BBBB", base):
            rgba.extend((red, green, blue, alpha))
    return GtiImage(width, height, image_format, mipmap_levels, bytes(rgba))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    image = decode_gti(args.source.read_bytes())
    try:
        from PIL import Image
    except ImportError as error:
        raise SystemExit("Pillow is required to write PNG output") from error
    args.output.parent.mkdir(parents=True, exist_ok=True)
    Image.frombytes("RGBA", (image.width, image.height), image.rgba).save(args.output)
    print(f"{args.source}: {image.width}x{image.height} {image.format_name} -> {args.output}")


if __name__ == "__main__":
    main()
