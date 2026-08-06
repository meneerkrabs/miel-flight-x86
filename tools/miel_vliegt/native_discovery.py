#!/usr/bin/env python3
"""Validate and summarize non-promotable native flight discovery logs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


CHANNELS = {
    "controls.sample.raw",
    "physics.entry.raw",
    "physics.leave.raw",
    "collision.entry.raw",
    "camera.entry.raw",
    "render.entry.raw",
}
ADDRESS = re.compile(r"^0x[0-9a-f]{8}$")


class DiscoveryError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DiscoveryError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _json(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as error:
        raise DiscoveryError(f"{label}: invalid JSON") from error
    if not isinstance(value, dict):
        raise DiscoveryError(f"{label}: expected an object")
    return value


def parse_log(path: Path, *, require_all: bool = False) -> list[dict[str, Any]]:
    loaded = False
    expected_sequence = 0
    previous_frame = 0
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("MVO "):
            marker = _json(line[4:], f"line {line_number}")
            if marker.get("schema") == 1 \
                    and marker.get("protocol") == "miel-vliegt-native-observer-hook" \
                    and marker.get("status") == "LOADED" \
                    and isinstance(marker.get("thread_id"), int) \
                    and not isinstance(marker.get("thread_id"), bool):
                loaded = True
            continue
        if not line.startswith("MVT "):
            continue
        record = _json(line[4:], f"line {line_number}")
        sequence = record.get("sequence")
        if isinstance(sequence, bool) or sequence != expected_sequence:
            raise DiscoveryError("record sequence is missing or non-contiguous")
        expected_sequence += 1
        if record.get("record") == "behavior":
            records.append(record)
            continue
        if record.get("record") != "discovery" or set(record) != {
            "record", "sequence", "channel", "frame", "values", "diagnostics",
        }:
            raise DiscoveryError("unknown or malformed discovery record")
        channel = record["channel"]
        if channel not in CHANNELS:
            raise DiscoveryError(f"unknown discovery channel: {channel!r}")
        frame = record["frame"]
        if isinstance(frame, bool) or not isinstance(frame, int) or frame < previous_frame:
            raise DiscoveryError("discovery frames must be monotonic non-negative integers")
        previous_frame = frame
        values = record["values"]
        if not isinstance(values, dict) or set(values) != {
            "this_address", "camera_address", "flight_address",
            "snapshot_size", "snapshot_hex",
        }:
            raise DiscoveryError("discovery values have an invalid shape")
        for field in ("this_address", "camera_address", "flight_address"):
            if not isinstance(values[field], str) or not ADDRESS.fullmatch(values[field]):
                raise DiscoveryError(f"invalid discovery pointer: {field}")
        size = values["snapshot_size"]
        snapshot = values["snapshot_hex"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 0x280 \
                or not isinstance(snapshot, str) or len(snapshot) != size * 2 \
                or re.fullmatch(r"[0-9a-f]*", snapshot) is None:
            raise DiscoveryError("discovery snapshot length or encoding is invalid")
        diagnostics = record["diagnostics"]
        if not isinstance(diagnostics, dict) or set(diagnostics) != {"thread_id"} \
                or isinstance(diagnostics["thread_id"], bool) \
                or not isinstance(diagnostics["thread_id"], int):
            raise DiscoveryError("discovery record has no thread identity")
        records.append(record)
    if not loaded:
        raise DiscoveryError("observer log has no LOADED marker")
    discovered = {record["channel"] for record in records if record.get("record") == "discovery"}
    if require_all and discovered != CHANNELS:
        raise DiscoveryError(
            f"discovery channels incomplete: missing {sorted(CHANNELS - discovered)}"
        )
    return records


def summarize(path: Path, *, require_all: bool = False) -> dict[str, Any]:
    records = parse_log(path, require_all=require_all)
    discovery = [row for row in records if row.get("record") == "discovery"]
    counts = Counter(row["channel"] for row in discovery)
    frames = [row["frame"] for row in discovery]
    snapshot_sizes: dict[str, set[int]] = defaultdict(set)
    pointers: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for row in discovery:
        values = row["values"]
        snapshot_sizes[row["channel"]].add(values["snapshot_size"])
        for field in ("this_address", "camera_address", "flight_address"):
            if values[field] != "0x00000000":
                pointers[row["channel"]][field].add(values[field])
    return {
        "schema": 1,
        "protocol": "miel-vliegt-native-discovery-summary",
        "status": "DISCOVERY_ONLY",
        "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "record_count": len(records),
        "first_sequence": records[0]["sequence"] if records else None,
        "last_sequence": records[-1]["sequence"] if records else None,
        "first_frame": min(frames) if frames else None,
        "last_frame": max(frames) if frames else None,
        "channel_counts": dict(sorted(counts.items())),
        "snapshot_sizes": {
            channel: sorted(sizes) for channel, sizes in sorted(snapshot_sizes.items())
        },
        "pointer_cardinality": {
            channel: {field: len(values) for field, values in sorted(fields.items())}
            for channel, fields in sorted(pointers.items())
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--require-all", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = summarize(args.log, require_all=args.require_all)
    rendered = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
