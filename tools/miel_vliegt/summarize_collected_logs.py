#!/usr/bin/env python3
"""Print bounded diagnostic counts from private Flight logs, never raw lines."""

import json
from itertools import islice
from pathlib import Path
import re
import sys


MAX_FILES = 12
MAX_TAIL = 64 * 1024
MARKERS = {
    name: re.compile(r"\b" + re.escape(name) + r"\b")
    for name in (
        "MVP_INIT", "MVP_DllMain", "MVP_DI", "MVP_DDCREATE", "MVP_DD7",
        "MVP_EXC", "MVO", "MVT", "CreateDevice", "DirectDrawCreate",
    )
}
WINE_ERROR = re.compile(r"\berr:[A-Za-z0-9_]+:")
KNOWN_ERRORS = {
    "E_OUTOFMEMORY": re.compile(r"0x8007000e\b", re.I),
    "REGDB_E_CLASSNOTREG": re.compile(r"0x80040154\b", re.I),
    "RPC_S_SERVER_UNAVAILABLE": re.compile(r"0x800706ba\b", re.I),
}


def role(name: str) -> str:
    lower = name.lower()
    for candidate in ("proxy", "observer", "wine", "game", "orchestration"):
        if candidate in lower:
            return candidate
    return "other"


def summarize(directory: Path) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid diagnostic directory")
    entries = list(islice(directory.iterdir(), MAX_FILES + 1))
    if len(entries) > MAX_FILES:
        raise ValueError("too many diagnostic files")
    files = sorted(
        path for path in entries
        if path.suffix == ".log" and not path.is_symlink() and path.is_file()
    )
    rows = []
    for index, path in enumerate(files[:MAX_FILES], 1):
        size = path.stat().st_size
        with path.open("rb") as stream:
            stream.seek(max(0, size - MAX_TAIL))
            sample = stream.read(MAX_TAIL)
        data = sample.decode("utf-8", errors="replace")
        rows.append({
            "alias": f"log_{index:02d}", "role": role(path.name),
            "size_bytes": size, "tail_bytes": len(sample),
            "markers": {name: len(pattern.findall(data)) for name, pattern in MARKERS.items()
                        if pattern.search(data)},
            "wine_error_count": len(WINE_ERROR.findall(data)),
            "known_error_codes": [name for name, pattern in KNOWN_ERRORS.items()
                                  if pattern.search(data)],
        })
    return {"schema": 1, "protocol": "miel-flight-bounded-log-diagnostics",
            "status": "DIAGNOSTIC_ONLY", "logs": rows}


if __name__ == "__main__":
    try:
        result = summarize(Path(sys.argv[1]))
    except (IndexError, OSError, ValueError):
        result = {"schema": 1, "protocol": "miel-flight-bounded-log-diagnostics",
                  "status": "DIAGNOSTIC_UNAVAILABLE"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
