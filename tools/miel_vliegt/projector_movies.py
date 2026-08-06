#!/usr/bin/env python3
"""Extract and rebase Director movies embedded in the flight projector."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


DIRECTOR_FORMS = {b"MV93", b"APPL", b"MC95", b"FGDM"}
ROLE_EVIDENCE = {
    "intro": (b"_intro_album_STOR", b"intro_prat_cuepoints"),
    "launcher": (b"introfilm01-jpg.dir",),
    "shell": (b"mainScript",),
}
CANONICAL_PROJECTOR_SHA256 = "c575b54bdc54bcd0486e2f490f9aa05dc6079d2f0cd16162d7c1bd10bb2c2793"
CANONICAL_PROJECTORRAYS_VALIDATION = {
    "commit": "6f9bcebf626b43719abe2affcbbcb041d154d666",
    "result": "all-rebased-movies-decompile",
    "movies": 3,
}


def _u32(data: bytes | bytearray, offset: int, little: bool) -> int:
    return struct.unpack_from("<I" if little else ">I", data, offset)[0]


def _put_u32(data: bytearray, offset: int, value: int, little: bool) -> None:
    struct.pack_into("<I" if little else ">I", data, offset, value)


def _tag(raw: bytes, little: bool) -> bytes:
    return raw[::-1] if little else raw


def _relative_pointer(value: int, base: int, end: int) -> int:
    if base <= value < end:
        return value - base
    if 0 <= value < end - base:
        return value
    raise ValueError(f"Director pointer {value} falls outside embedded movie {base}:{end}")


def rebase_movie(executable: bytes, base: int) -> bytes:
    """Turn an absolute-offset projector movie into a standalone RIFX file."""
    magic = executable[base:base + 4]
    if magic not in (b"RIFX", b"XFIR"):
        raise ValueError(f"no Director header at projector offset {base}")
    little = magic == b"XFIR"
    size = _u32(executable, base + 4, little) + 8
    end = base + size
    if end > len(executable):
        raise ValueError(f"embedded Director movie at {base} is truncated")
    raw = bytearray(executable[base:end])
    if _tag(bytes(raw[8:12]), little) not in DIRECTOR_FORMS:
        raise ValueError(f"unsupported Director form at projector offset {base}")

    mmap = _relative_pointer(_u32(raw, 24, little), base, end)
    _put_u32(raw, 24, mmap, little)
    if mmap + 32 > len(raw) or _tag(bytes(raw[mmap:mmap + 4]), little) != b"mmap":
        raise ValueError(f"embedded Director movie at {base} has no valid mmap")
    count = _u32(raw, mmap + 16, little)
    entries = mmap + 32
    if count > 100000 or entries + count * 20 > len(raw):
        raise ValueError(f"embedded Director movie at {base} has invalid mmap count {count}")
    for index in range(count):
        pointer = entries + index * 20 + 8
        value = _u32(raw, pointer, little)
        if value == 0xFFFFFFFF:
            continue
        _put_u32(raw, pointer, _relative_pointer(value, base, end), little)
    return bytes(raw)


def _role(movie: bytes) -> tuple[str, list[str]]:
    matches = [
        role for role, signatures in ROLE_EVIDENCE.items()
        if all(signature in movie for signature in signatures)
    ]
    if len(matches) != 1:
        return "unknown", []
    role = matches[0]
    return role, [signature.decode("ascii") for signature in ROLE_EVIDENCE[role]]


def extract_projector_movies(projector: Path, output: Path) -> dict[str, object]:
    data = projector.read_bytes()
    projector_sha256 = hashlib.sha256(data).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    movies = []
    for match in re.finditer(b"RIFX|XFIR", data):
        base = match.start()
        little = match.group() == b"XFIR"
        if base + 12 > len(data):
            continue
        size = _u32(data, base + 4, little) + 8
        end = base + size
        if end > len(data) or _tag(data[base + 8:base + 12], little) not in DIRECTOR_FORMS:
            continue
        try:
            movie = rebase_movie(data, base)
        except ValueError:
            continue
        role, evidence = _role(movie)
        destination = output / f"movie-{len(movies)}-{role}.dir"
        destination.write_bytes(movie)
        movies.append({
            "index": len(movies),
            "role": role,
            "offset": base,
            "size": size,
            "sha256": hashlib.sha256(movie).hexdigest(),
            "evidence": evidence,
            "payload": destination.name,
        })
    intro = [movie for movie in movies if movie["role"] == "intro"]
    if len(intro) != 1:
        raise ValueError(f"expected one embedded flight intro, found {len(intro)}")
    if projector_sha256 == CANONICAL_PROJECTOR_SHA256 and len(movies) != 3:
        raise ValueError(f"canonical projector movie inventory drifted: expected 3, found {len(movies)}")
    manifest = {
        "schema": 1,
        "projector": {
            "filename": projector.name,
            "size": len(data),
            "sha256": projector_sha256,
        },
        "movies": movies,
        "intro_index": intro[0]["index"],
        "external_validation": {
            "projectorrays": (
                CANONICAL_PROJECTORRAYS_VALIDATION
                if projector_sha256 == CANONICAL_PROJECTOR_SHA256
                else {"result": "not-recorded-for-this-projector"}
            ),
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projector", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    extract_projector_movies(args.projector, args.output)


if __name__ == "__main__":
    main()
