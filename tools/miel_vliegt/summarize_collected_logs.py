#!/usr/bin/env python3
"""Print bounded diagnostic counts from private Flight logs, never raw lines."""

import json
from collections import Counter
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
DEVICE_LEAVE = re.compile(
    r"^MVP_DD7 sequence=(?P<sequence>\d+) method=IDirect3D7::CreateDevice(?P<rgb>-rgb-retry)? "
    r"phase=leave hr=0x(?P<hr>[0-9a-fA-F]{8})\b"
)
DEVICE_RESULT = re.compile(
    r"^MVP_DD7 sequence=(?P<sequence>\d+) detail=IDirect3D7::CreateDevice(?P<rgb>-rgb)?-result "
    r"device=(?P<device>\S+)"
)
EXCEPTION_CODE = re.compile(r"^MVP_EXC code=0x([0-9a-fA-F]{8})\b")
EXCEPTION_CLASSES = {
    "40010006": "DEBUG_PRINT",
    "c0000005": "ACCESS_VIOLATION",
    "c000001d": "ILLEGAL_INSTRUCTION",
    "c0000094": "INTEGER_DIVIDE_BY_ZERO",
    "e06d7363": "CPP_EXCEPTION",
    "406d1388": "THREAD_NAME",
}


def role(name: str) -> str:
    lower = name.lower()
    for candidate in ("proxy", "observer", "wine", "game", "orchestration"):
        if candidate in lower:
            return candidate
    return "other"


def device_and_exception_outcomes(data: str) -> tuple[list[dict], dict[str, int]]:
    outcomes: list[tuple[int, dict]] = []
    exceptions: Counter[str] = Counter()
    for line in data.splitlines():
        if match := DEVICE_LEAVE.match(line):
            outcomes.append((int(match["sequence"]),
                             {"route": "RGB_RETRY" if match["rgb"] else "HAL",
                              "hresult": "0x" + match["hr"].upper(), "device": "UNKNOWN"}))
        elif match := DEVICE_RESULT.match(line):
            route = "RGB_RETRY" if match["rgb"] else "HAL"
            if (outcomes and outcomes[-1][1]["route"] == route
                    and outcomes[-1][0] + 1 == int(match["sequence"])):
                pointer = match["device"]
                if re.fullmatch(r"(?:0x)?0+|\(nil\)|NULL", pointer, re.I):
                    outcomes[-1][1]["device"] = "NULL"
                elif re.fullmatch(r"(?:0x)?[0-9a-fA-F]{4,16}", pointer):
                    outcomes[-1][1]["device"] = "NONNULL"
        if match := EXCEPTION_CODE.match(line):
            exceptions[EXCEPTION_CLASSES.get(match[1].lower(), "OTHER")] += 1
    return [row for _, row in outcomes[-8:]], dict(sorted(exceptions.items()))


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
        device_outcomes, exception_classes = device_and_exception_outcomes(data)
        rows.append({
            "alias": f"log_{index:02d}", "role": role(path.name),
            "size_bytes": size, "tail_bytes": len(sample),
            "tail_truncated": size > len(sample),
            "device_outcomes": device_outcomes,
            "exception_classes": exception_classes,
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
