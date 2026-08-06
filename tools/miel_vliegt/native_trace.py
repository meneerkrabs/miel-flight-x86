#!/usr/bin/env python3
"""Prepare, canonicalize, replay and compare Miel Vliegt native traces."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.miel_vliegt.build_native_trace_map import build_map


DEFAULT_MANIFEST = ROOT / "content/miel_vliegt/native_trace_probe.json"
DEFAULT_INDEX = ROOT / "content/miel_vliegt/native_function_index.json"
DEFAULT_TEMPLATE = ROOT / "tools/miel_vliegt/native_trace_windbg.template"
PROTOCOL = "miel-vliegt-native-trace"
VERSION = 1
HEX32 = re.compile(r"^0x[0-9a-fA-F]{8}$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1:
        raise ValueError("unsupported native trace probe schema")
    return manifest


class PeImage:
    """Minimal dependency-free PE32 reader used only for capture preflight."""

    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError(f"{path}: not a PE executable")
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: missing PE signature")
        machine, count = struct.unpack_from("<HH", self.data, pe + 4)
        if machine != 0x14C:
            raise ValueError(f"{path}: native trace probe requires i386 PE")
        optional_size = struct.unpack_from("<H", self.data, pe + 20)[0]
        optional = pe + 24
        if struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise ValueError(f"{path}: native trace probe requires PE32")
        self.image_base = struct.unpack_from("<I", self.data, optional + 28)[0]
        section_offset = optional + optional_size
        self.sections = []
        for index in range(count):
            values = struct.unpack_from("<8sIIIIIIHHI", self.data, section_offset + 40 * index)
            self.sections.append({
                "virtual_address": self.image_base + values[2],
                "virtual_size": values[1],
                "raw_size": values[3],
                "raw_offset": values[4],
            })

    def bytes_at(self, address: int, size: int) -> bytes:
        for section in self.sections:
            delta = address - section["virtual_address"]
            if 0 <= delta and delta + size <= section["raw_size"]:
                offset = section["raw_offset"] + delta
                return self.data[offset:offset + size]
        raise ValueError(f"address 0x{address:08x} is not file-backed")


def verify_probe_inputs(executable: Path, manifest: dict[str, Any], root: Path = ROOT) -> PeImage:
    source = manifest["source"]
    actual_hash = sha256_file(executable)
    if actual_hash != source["executable_sha256"]:
        raise ValueError(f"wrong native executable: {actual_hash}")
    image = PeImage(executable)
    if image.image_base != int(source["image_base"], 16):
        raise ValueError("native executable image base drifted")
    for field, hash_field in (("function_index", "function_index_sha256"), ("function_seeds", "function_seeds_sha256")):
        path = root / source[field]
        if sha256_file(path) != source[hash_field]:
            raise ValueError(f"pinned {field} drifted")
    for probe in manifest["behavior_hooks"]:
        expected = bytes.fromhex(probe["signature"])
        address = int(probe["address"], 16)
        if image.bytes_at(address, len(expected)) != expected:
            raise ValueError(f"probe signature drifted: {probe['id']}")
    for assertion in manifest["static_assertions"]:
        expected = bytes.fromhex(assertion["bytes"])
        address = int(assertion["address"], 16)
        if image.bytes_at(address, len(expected)) != expected:
            raise ValueError(f"static probe assertion drifted: {assertion['id']}")
    return image


def _coverage_selection(coverage_map: dict[str, Any], selector: str) -> tuple[set[str], set[str]]:
    if selector == "all":
        return (
            {item["id"] for item in coverage_map["functions"]},
            {item["id"] for item in coverage_map["basic_blocks"]},
        )
    if selector != "default":
        raise ValueError(f"unknown coverage selector: {selector}")
    function_ids = {"fn_0040e610"}
    block_ids = {
        item["id"] for item in coverage_map["basic_blocks"]
        if item["function_id"] in function_ids
    }
    return function_ids, block_ids


def _printf_coverage(record: str, stable_id: str) -> str:
    channel = "coverage.function" if record == "function" else "coverage.block"
    return (
        f'.printf "MVT {{\\\"record\\\":\\\"coverage\\\",\\\"sequence\\\":%u,'
        f'\\\"channel\\\":\\\"{channel}\\\",\\\"id\\\":\\\"{stable_id}\\\"}}\\n", @$t0; '
        "r @$t0 = @$t0 + 1"
    )


def _windbg_breakpoint(address: int, commands: list[str]) -> str:
    # bp receives one quoted command string. Quotes needed later by .printf and
    # quotes embedded in its JSON format therefore need one additional layer.
    payload = "; ".join(commands).replace('"', '\\"')
    return f'bp {address:08x} "{payload}"'


def prepare_windbg_script(
    executable: Path,
    output: Path,
    log_path: str,
    selector: str = "default",
    manifest_path: Path = DEFAULT_MANIFEST,
    index_path: Path = DEFAULT_INDEX,
) -> dict[str, int]:
    manifest = load_manifest(manifest_path)
    verify_probe_inputs(executable, manifest)
    coverage_map = build_map(index_path)
    function_ids, block_ids = _coverage_selection(coverage_map, selector)
    function_records = {item["id"]: item for item in coverage_map["functions"]}
    block_records = {item["id"]: item for item in coverage_map["basic_blocks"]}
    by_address: dict[int, list[str]] = {}
    for stable_id in sorted(function_ids):
        address = int(function_records[stable_id]["address"], 16)
        by_address.setdefault(address, []).append(_printf_coverage("function", stable_id))
    for stable_id in sorted(block_ids):
        address = int(block_records[stable_id]["start"], 16)
        by_address.setdefault(address, []).append(_printf_coverage("block", stable_id))

    entry_address = 0x0040E610
    leave_address = 0x0040F82F
    entry_commands = [
        '.printf "MVT {\\\"record\\\":\\\"behavior\\\",\\\"sequence\\\":%u,\\\"channel\\\":\\\"flight.step.enter\\\",\\\"values\\\":{\\\"dt_f32_bits\\\":\\\"0x%08x\\\"},\\\"diagnostics\\\":{\\\"this_address\\\":\\\"0x%08x\\\"}}\\n", @$t0, poi(@esp+4), @ecx',
        "r @$t0 = @$t0 + 1",
        *by_address.pop(entry_address, []),
        "gc",
    ]
    leave_commands = [
        '.printf "MVT {\\\"record\\\":\\\"behavior\\\",\\\"sequence\\\":%u,\\\"channel\\\":\\\"flight.step.leave\\\",\\\"values\\\":{}}\\n", @$t0',
        "r @$t0 = @$t0 + 1",
        *by_address.pop(leave_address, []),
        "gc",
    ]
    coverage_lines = []
    for address, commands in sorted(by_address.items()):
        coverage_lines.append(_windbg_breakpoint(address, commands + ["gc"]))
    template = DEFAULT_TEMPLATE.read_text(encoding="utf-8")
    rendered = template.replace("__LOG_PATH__", log_path)
    rendered = rendered.replace("__ENTRY_BREAKPOINT__", _windbg_breakpoint(entry_address, entry_commands))
    rendered = rendered.replace("__LEAVE_BREAKPOINT__", _windbg_breakpoint(leave_address, leave_commands))
    rendered = rendered.replace("$$ __COVERAGE_BREAKPOINTS__", "\n".join(coverage_lines) or "$$ no additional coverage breakpoints")
    output.write_text(rendered, encoding="utf-8")
    return {"functions": len(function_ids), "basic_blocks": len(block_ids), "breakpoints": len(by_address) + 2}


def _normalize_number(value: float, places: int) -> float | int:
    if not math.isfinite(value):
        raise ValueError("trace contains a non-finite number")
    result = round(value, places)
    if result == 0:
        return 0
    return result


def _normalize(value: Any, places: int) -> Any:
    if isinstance(value, dict):
        return {key: _normalize(item, places) for key, item in value.items() if key not in {"diagnostics", "captured_at", "host"}}
    if isinstance(value, list):
        return [_normalize(item, places) for item in value]
    if isinstance(value, float):
        return _normalize_number(value, places)
    return value


def canonicalize_records(records: list[dict[str, Any]], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if not records or records[0].get("record") != "trace_header":
        raise ValueError("trace must start with trace_header")
    if records[-1].get("record") == "trace_footer":
        records = records[:-1]
    places = manifest["canonicalization"]["float_decimal_places"]
    normalized = [_normalize(record, places) for record in records]
    for record in normalized[1:]:
        if record.get("record") == "behavior" and record.get("channel") == "flight.step.enter":
            values = record.get("values", {})
            raw = values.pop("dt_f32_bits", None)
            if raw is not None:
                if not isinstance(raw, str) or not HEX32.fullmatch(raw):
                    raise ValueError("flight.step dt_f32_bits must be 0x + 8 hex digits")
                bits = int(raw, 16)
                values["dt_seconds"] = _normalize_number(struct.unpack("<f", struct.pack("<I", bits))[0], places)
    lines = "".join(canonical_json(record) + "\n" for record in normalized).encode("utf-8")
    normalized.append({
        "record": "trace_footer",
        "event_count": len(normalized) - 1,
        "content_sha256": sha256_bytes(lines),
    })
    validate_trace(normalized)
    return normalized


def validate_trace(records: list[dict[str, Any]]) -> None:
    if len(records) < 2 or records[0].get("record") != "trace_header" or records[-1].get("record") != "trace_footer":
        raise ValueError("trace needs one header and one footer")
    header = records[0]
    if header.get("protocol") != PROTOCOL or header.get("version") != VERSION:
        raise ValueError("unsupported native trace protocol")
    if header.get("capture_kind") not in {"native", "web", "protocol_fixture"}:
        raise ValueError("invalid trace capture_kind")
    source_hash = header.get("source", {}).get("executable_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise ValueError("trace has no pinned executable SHA-256")
    events = records[1:-1]
    for sequence, event in enumerate(events):
        if event.get("sequence") != sequence:
            raise ValueError("trace event sequence is missing or out of order")
        if event.get("record") == "behavior":
            if not isinstance(event.get("channel"), str) or not isinstance(event.get("values"), dict):
                raise ValueError("invalid behavior event")
        elif event.get("record") == "coverage":
            if event.get("channel") not in {"coverage.function", "coverage.block", "coverage.edge"}:
                raise ValueError("invalid coverage channel")
            if not isinstance(event.get("id"), str):
                raise ValueError("coverage event has no stable id")
        else:
            raise ValueError(f"invalid trace record: {event.get('record')!r}")
    footer = records[-1]
    if footer.get("event_count") != len(events):
        raise ValueError("trace footer event count mismatch")
    body = "".join(canonical_json(record) + "\n" for record in records[:-1]).encode("utf-8")
    if footer.get("content_sha256") != sha256_bytes(body):
        raise ValueError("trace footer content hash mismatch")


def read_trace(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid JSON") from error
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: trace record must be an object")
        records.append(value)
    return records


def write_trace(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(canonical_json(record) + "\n" for record in records), encoding="utf-8")


def import_windbg(
    log_path: Path,
    output: Path,
    scenario_id: str,
    description: str,
    input_script_sha256: str,
    manifest_path: Path = DEFAULT_MANIFEST,
    capture_kind: str = "native",
) -> list[dict[str, Any]]:
    manifest = load_manifest(manifest_path)
    events = []
    for line_number, line in enumerate(log_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        marker = line.find("MVT ")
        if marker < 0:
            continue
        try:
            event = json.loads(line[marker + 4:])
        except json.JSONDecodeError as error:
            raise ValueError(f"{log_path}:{line_number}: invalid MVT event") from error
        events.append(event)
    if not events:
        raise ValueError("WinDbg log contains no MVT events")
    if not re.fullmatch(r"[0-9a-f]{64}", input_script_sha256):
        raise ValueError("scenario input script needs a lowercase SHA-256")
    coverage_map = build_map(DEFAULT_INDEX)
    header = {
        "record": "trace_header",
        "protocol": PROTOCOL,
        "version": VERSION,
        "capture_kind": capture_kind,
        "source": {
            "edition": manifest["source"]["edition"],
            "executable_sha256": manifest["source"]["executable_sha256"],
            "probe_manifest_sha256": sha256_file(manifest_path),
            "coverage_map_sha256": sha256_bytes(canonical_json(coverage_map).encode("utf-8")),
        },
        "scenario": {"id": scenario_id, "description": description, "input_script_sha256": input_script_sha256},
    }
    records = canonicalize_records([header, *events], manifest)
    write_trace(output, records)
    return records


def import_web(
    log_path: Path,
    output: Path,
    scenario_id: str,
    description: str,
    input_script_sha256: str,
    runtime_sha256: str,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> list[dict[str, Any]]:
    """Wrap browser probe JSONL in the same canonical trace as native capture."""
    manifest = load_manifest(manifest_path)
    if not re.fullmatch(r"[0-9a-f]{64}", input_script_sha256):
        raise ValueError("scenario input script needs a lowercase SHA-256")
    if not re.fullmatch(r"[0-9a-f]{64}", runtime_sha256):
        raise ValueError("web runtime needs a lowercase SHA-256")
    events = read_trace_events(log_path)
    coverage_map = build_map(DEFAULT_INDEX)
    header = {
        "record": "trace_header",
        "protocol": PROTOCOL,
        "version": VERSION,
        "capture_kind": "web",
        "source": {
            "edition": manifest["source"]["edition"],
            "executable_sha256": manifest["source"]["executable_sha256"],
            "web_runtime_sha256": runtime_sha256,
            "probe_manifest_sha256": sha256_file(manifest_path),
            "coverage_map_sha256": sha256_bytes(canonical_json(coverage_map).encode("utf-8")),
        },
        "scenario": {
            "id": scenario_id,
            "description": description,
            "input_script_sha256": input_script_sha256,
        },
    }
    records = canonicalize_records([header, *events], manifest)
    write_trace(output, records)
    return records


def read_trace_events(path: Path) -> list[dict[str, Any]]:
    events = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid JSON") from error
        if not isinstance(event, dict) or event.get("record") not in {"behavior", "coverage"}:
            raise ValueError(f"{path}:{line_number}: expected a behavior or coverage event")
        # The browser probe repeats protocol metadata so a raw console/event
        # stream remains self-describing. The canonical trace owns it once in
        # the header.
        event.pop("protocol", None)
        event.pop("version", None)
        events.append(event)
    return events


def coverage_report(records: list[dict[str, Any]], coverage_map: dict[str, Any]) -> dict[str, Any]:
    known = {
        "coverage.function": {item["id"] for item in coverage_map["functions"]},
        "coverage.block": {item["id"] for item in coverage_map["basic_blocks"]},
        "coverage.edge": {item["id"] for item in coverage_map["edges"]},
    }
    observed = {channel: set() for channel in known}
    for event in records[1:-1]:
        channel = event.get("channel")
        if channel in observed:
            observed[channel].add(event["id"])
    result = {}
    for channel in known:
        unknown = sorted(observed[channel] - known[channel])
        uncovered = sorted(known[channel] - observed[channel])
        result[channel] = {
            "known": len(known[channel]),
            "observed": len(observed[channel]),
            "unknown_count": len(unknown),
            "unknown": unknown,
            "uncovered_count": len(uncovered),
            "uncovered": uncovered,
        }
    result["unresolved_static_branch_sites"] = {
        "count": len(coverage_map["unresolved_branch_sites"]),
        "ids": [item["id"] for item in coverage_map["unresolved_branch_sites"]],
    }
    return result


def compact_coverage_report(report: dict[str, Any], limit: int = 20) -> dict[str, Any]:
    compact = {}
    for channel in ("coverage.function", "coverage.block", "coverage.edge"):
        item = report[channel]
        compact[channel] = {
            key: value for key, value in item.items() if key not in {"unknown", "uncovered"}
        }
        compact[channel]["unknown_sample"] = item["unknown"][:limit]
        compact[channel]["uncovered_sample"] = item["uncovered"][:limit]
    static = report["unresolved_static_branch_sites"]
    compact["unresolved_static_branch_sites"] = {
        "count": static["count"],
        "id_sample": static["ids"][:limit],
    }
    return compact


def _compare_values(left: Any, right: Any, path: str, tolerances: dict[str, Any], differences: list[str]) -> None:
    if isinstance(left, dict) and isinstance(right, dict):
        if set(left) != set(right):
            differences.append(f"{path}: keys differ")
            return
        for key in sorted(left):
            _compare_values(left[key], right[key], f"{path}.{key}" if path else key, tolerances, differences)
        return
    tolerance = tolerances.get(path, {}).get("absolute")
    if tolerance is not None and isinstance(left, (int, float)) and isinstance(right, (int, float)):
        if abs(left - right) > tolerance:
            differences.append(f"{path}: {left} != {right} (absolute tolerance {tolerance})")
    elif left != right:
        differences.append(f"{path}: {left!r} != {right!r}")


def compare_traces(baseline: list[dict[str, Any]], candidate: list[dict[str, Any]], manifest: dict[str, Any], coverage_map: dict[str, Any]) -> list[str]:
    validate_trace(baseline)
    validate_trace(candidate)
    differences = []
    for field in ("protocol", "version"):
        if baseline[0].get(field) != candidate[0].get(field):
            differences.append(f"header.{field} differs")
    if baseline[0]["source"]["executable_sha256"] != candidate[0]["source"]["executable_sha256"]:
        differences.append("header.source.executable_sha256 differs")
    if baseline[0]["scenario"]["id"] != candidate[0]["scenario"]["id"]:
        differences.append("header.scenario.id differs")
    baseline_behavior = [item for item in baseline[1:-1] if item["record"] == "behavior"]
    candidate_behavior = [item for item in candidate[1:-1] if item["record"] == "behavior"]
    if len(baseline_behavior) != len(candidate_behavior):
        differences.append(f"behavior event count: {len(baseline_behavior)} != {len(candidate_behavior)}")
    tolerances = manifest["comparison"]["field_tolerances"]
    for index, (left, right) in enumerate(zip(baseline_behavior, candidate_behavior)):
        if left["channel"] != right["channel"]:
            differences.append(f"behavior[{index}].channel differs")
            continue
        for field in ("contract_id", "step", "phase"):
            if field in left or field in right:
                if left.get(field) != right.get(field):
                    differences.append(f"behavior[{index}].{field} differs")
        _compare_values(left["values"], right["values"], f"{left['channel']}.values", tolerances, differences)
    baseline_coverage = coverage_report(baseline, coverage_map)
    candidate_coverage = coverage_report(candidate, coverage_map)
    for channel in ("coverage.function", "coverage.block", "coverage.edge"):
        if candidate_coverage[channel]["unknown_count"]:
            differences.append(f"{channel}: {candidate_coverage[channel]['unknown_count']} unknown IDs")
        baseline_ids = {
            event["id"] for event in baseline[1:-1] if event.get("channel") == channel
        }
        candidate_ids = {
            event["id"] for event in candidate[1:-1] if event.get("channel") == channel
        }
        missing = baseline_ids - candidate_ids
        if missing:
            differences.append(f"{channel}: {len(missing)} baseline IDs missing")
    return differences


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare-probe")
    prepare.add_argument("--executable", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--log-path", default="miel-vliegt-native-trace.log")
    prepare.add_argument("--coverage", choices=("default", "all"), default="default")
    importer = sub.add_parser("import-windbg")
    importer.add_argument("--log", type=Path, required=True)
    importer.add_argument("--output", type=Path, required=True)
    importer.add_argument("--scenario", required=True)
    importer.add_argument("--description", required=True)
    importer.add_argument("--input-script-sha256", required=True)
    web_importer = sub.add_parser("import-web")
    web_importer.add_argument("--log", type=Path, required=True)
    web_importer.add_argument("--output", type=Path, required=True)
    web_importer.add_argument("--scenario", required=True)
    web_importer.add_argument("--description", required=True)
    web_importer.add_argument("--input-script-sha256", required=True)
    web_importer.add_argument("--runtime-sha256", required=True)
    replay = sub.add_parser("replay")
    replay.add_argument("trace", type=Path)
    replay.add_argument("--require-native", action="store_true")
    compare = sub.add_parser("compare")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    args = parser.parse_args()

    if args.command == "prepare-probe":
        counts = prepare_windbg_script(args.executable, args.output, args.log_path, args.coverage)
        print("native trace probe prepared: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
        return
    if args.command == "import-windbg":
        records = import_windbg(args.log, args.output, args.scenario, args.description, args.input_script_sha256)
        print(f"native trace imported: events={len(records) - 2} sha256={records[-1]['content_sha256']}")
        return
    if args.command == "import-web":
        records = import_web(
            args.log, args.output, args.scenario, args.description,
            args.input_script_sha256, args.runtime_sha256,
        )
        print(f"web trace imported: events={len(records) - 2} sha256={records[-1]['content_sha256']}")
        return
    coverage_map = build_map(DEFAULT_INDEX)
    if args.command == "replay":
        records = read_trace(args.trace)
        validate_trace(records)
        if args.require_native and records[0]["capture_kind"] != "native":
            raise SystemExit("trace is a protocol fixture, not native evidence")
        report = coverage_report(records, coverage_map)
        print(json.dumps({
            "trace": str(args.trace),
            "capture_kind": records[0]["capture_kind"],
            "events": records[-1]["event_count"],
            "content_sha256": records[-1]["content_sha256"],
            "coverage": compact_coverage_report(report),
        }, indent=2))
        return
    manifest = load_manifest()
    baseline = read_trace(args.baseline)
    candidate = read_trace(args.candidate)
    differences = compare_traces(baseline, candidate, manifest, coverage_map)
    if differences:
        for difference in differences:
            print(difference)
        raise SystemExit(1)
    print("native traces match")


if __name__ == "__main__":
    main()
