#!/usr/bin/env python3
"""Build deterministic native input replays and stable scenario shards.

The replay plan uses a relative monotonic clock.  Tick zero is always
monotonic nanosecond zero, so neither wall-clock time nor host scheduling can
leak into a checked-in plan.  Scenario and plan identities are hashes of
canonical JSON; source identities are hashes of the actual repository files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "miel-vliegt-native-replay"
PLAN_PROTOCOL = "miel-vliegt-native-replay-plan"
RECEIPT_PROTOCOL = "miel-vliegt-native-replay-receipt"
VERSION = 1
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
UINT64_MAX = (1 << 64) - 1


def canonical_json(value: Any) -> str:
    """Return the one canonical JSON representation used for all identities."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=_reject_constant,
        object_pairs_hook=_object_without_duplicate_keys,
    )


def _require_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must contain exactly: {', '.join(sorted(keys))}")
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_int(value: Any, label: str, minimum: int, maximum: int | None = None) -> int:
    if not _is_int(value) or value < minimum or (maximum is not None and value > maximum):
        suffix = f"..{maximum}" if maximum is not None else " or greater"
        raise ValueError(f"{label} must be an integer in {minimum}{suffix}")
    return value


def _source_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("source hash paths must be non-empty POSIX paths")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or pure.parts in {(), (".",)} or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"unsafe source hash path: {relative!r}")
    root = root.resolve()
    candidate = (root / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError(f"source hash path escapes repository root: {relative}") from error
    return candidate


def validate_source_hashes(source_hashes: Any, root: Path = ROOT) -> dict[str, str]:
    """Validate every declared source against disk; missing pins fail closed."""

    if not isinstance(source_hashes, dict) or not source_hashes:
        raise ValueError("scenario must pin at least one source hash")
    normalized: dict[str, str] = {}
    for relative, expected in source_hashes.items():
        if not isinstance(relative, str) or not isinstance(expected, str) or not SHA256.fullmatch(expected):
            raise ValueError("source hashes must map repository paths to lowercase SHA-256 values")
        source = _source_path(root, relative)
        if not source.is_file():
            raise ValueError(f"pinned source is missing: {relative}")
        actual = sha256_file(source)
        if actual != expected:
            raise ValueError(f"pinned source hash drifted: {relative} ({actual})")
        normalized[relative] = expected
    return dict(sorted(normalized.items()))


def _validate_event(event: Any, index: int, start_tick: int, end_tick: int) -> None:
    if not isinstance(event, dict):
        raise ValueError(f"event {index} must be an object")
    kind = event.get("type")
    action = event.get("action")
    if kind == "key":
        _require_exact_keys(event, {"tick", "type", "action", "key"}, f"event {index}")
        if action not in {"down", "up"}:
            raise ValueError(f"event {index} key action must be down or up")
        if not isinstance(event["key"], str) or not event["key"]:
            raise ValueError(f"event {index} key must be a non-empty string")
    elif kind == "mouse":
        common = {"tick", "type", "action", "x", "y"}
        if action == "move":
            _require_exact_keys(event, common, f"event {index}")
        elif action in {"down", "up"}:
            _require_exact_keys(event, common | {"button"}, f"event {index}")
            if event["button"] not in {"left", "middle", "right", "x1", "x2"}:
                raise ValueError(f"event {index} has an invalid mouse button")
        elif action == "wheel":
            _require_exact_keys(event, common | {"delta_x", "delta_y"}, f"event {index}")
            _require_int(event["delta_x"], f"event {index}.delta_x", -2147483648, 2147483647)
            _require_int(event["delta_y"], f"event {index}.delta_y", -2147483648, 2147483647)
        else:
            raise ValueError(f"event {index} has an invalid mouse action")
        _require_int(event["x"], f"event {index}.x", -2147483648, 2147483647)
        _require_int(event["y"], f"event {index}.y", -2147483648, 2147483647)
    else:
        raise ValueError(f"event {index} type must be key or mouse")
    tick = _require_int(event["tick"], f"event {index}.tick", start_tick, end_tick)
    if tick < start_tick or tick > end_tick:
        raise ValueError(f"event {index} tick is outside the replay interval")


def validate_scenario(scenario: Any, root: Path = ROOT) -> dict[str, Any]:
    required = {
        "schema", "protocol", "id", "description", "timing", "seed",
        "source_hashes", "events", "checkpoints",
    }
    scenario = _require_exact_keys(scenario, required, "scenario")
    if scenario["schema"] != VERSION or scenario["protocol"] != PROTOCOL:
        raise ValueError("unsupported native replay scenario")
    if not isinstance(scenario["id"], str) or not IDENTIFIER.fullmatch(scenario["id"]):
        raise ValueError("scenario id must be a stable lowercase identifier")
    if not isinstance(scenario["description"], str) or not scenario["description"].strip():
        raise ValueError("scenario description must be non-empty")
    timing = _require_exact_keys(
        scenario["timing"],
        {"tick_ns", "start_tick", "end_tick", "monotonic_origin_ns"},
        "scenario.timing",
    )
    tick_ns = _require_int(timing["tick_ns"], "scenario.timing.tick_ns", 1, UINT64_MAX)
    start_tick = _require_int(timing["start_tick"], "scenario.timing.start_tick", 0, UINT64_MAX)
    end_tick = _require_int(timing["end_tick"], "scenario.timing.end_tick", start_tick, UINT64_MAX)
    if start_tick != 0 or timing["monotonic_origin_ns"] != 0:
        raise ValueError("native replay timing must use relative tick/monotonic origins of zero")
    if end_tick > UINT64_MAX // tick_ns:
        raise ValueError("native replay monotonic timestamp overflows uint64")
    _require_int(scenario["seed"], "scenario.seed", 0, UINT64_MAX)
    validate_source_hashes(scenario["source_hashes"], root)

    events = scenario["events"]
    if not isinstance(events, list):
        raise ValueError("scenario.events must be an array")
    previous_tick = start_tick
    for index, event in enumerate(events):
        _validate_event(event, index, start_tick, end_tick)
        if event["tick"] < previous_tick:
            raise ValueError("scenario events must be ordered by non-decreasing tick")
        previous_tick = event["tick"]

    checkpoints = scenario["checkpoints"]
    if not isinstance(checkpoints, list) or not checkpoints:
        raise ValueError("scenario must define at least one checkpoint")
    checkpoint_ids: set[str] = set()
    previous_tick = start_tick
    for index, checkpoint in enumerate(checkpoints):
        _require_exact_keys(checkpoint, {"id", "tick"}, f"checkpoint {index}")
        identifier = checkpoint["id"]
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise ValueError(f"checkpoint {index} has an invalid id")
        if identifier in checkpoint_ids:
            raise ValueError(f"duplicate checkpoint id: {identifier}")
        checkpoint_ids.add(identifier)
        tick = _require_int(checkpoint["tick"], f"checkpoint {index}.tick", start_tick, end_tick)
        if tick < previous_tick:
            raise ValueError("scenario checkpoints must be ordered by non-decreasing tick")
        previous_tick = tick
    return scenario


def load_scenario(path: Path, root: Path = ROOT) -> dict[str, Any]:
    scenario = load_json(path)
    return validate_scenario(scenario, root)


def scenario_sha256(scenario: dict[str, Any]) -> str:
    return canonical_sha256(scenario)


def _monotonic_ns(timing: dict[str, int], tick: int) -> int:
    return timing["monotonic_origin_ns"] + (tick - timing["start_tick"]) * timing["tick_ns"]


def build_replay(scenario: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    """Build a canonical, host-clock-independent replay plan."""

    validate_scenario(scenario, root)
    timing = dict(scenario["timing"])
    events = []
    for sequence, source in enumerate(scenario["events"]):
        event = dict(source)
        event["sequence"] = sequence
        event["monotonic_ns"] = _monotonic_ns(timing, event["tick"])
        events.append(event)
    checkpoints = [
        {
            "id": checkpoint["id"],
            "tick": checkpoint["tick"],
            "monotonic_ns": _monotonic_ns(timing, checkpoint["tick"]),
        }
        for checkpoint in scenario["checkpoints"]
    ]
    plan: dict[str, Any] = {
        "schema": VERSION,
        "protocol": PLAN_PROTOCOL,
        "scenario": {"id": scenario["id"], "sha256": scenario_sha256(scenario)},
        "timing": timing,
        "seed": scenario["seed"],
        "source_hashes": dict(sorted(scenario["source_hashes"].items())),
        "events": events,
        "checkpoints": checkpoints,
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    return plan


build_plan = build_replay


def write_canonical_json(path: Path, value: Any) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")


def shard_for(identifier: str, shard_count: int) -> int:
    """Assign an id without depending on discovery order or the scenario set."""

    if not isinstance(identifier, str) or not identifier:
        raise ValueError("shard identifier must be non-empty")
    _require_int(shard_count, "shard_count", 1, UINT64_MAX)
    return int.from_bytes(hashlib.sha256(identifier.encode("utf-8")).digest(), "big") % shard_count


stable_shard = shard_for
assign_shard = shard_for


def build_shard_manifest(
    scenarios: Iterable[dict[str, Any]], shard_count: int, root: Path = ROOT,
) -> dict[str, Any]:
    _require_int(shard_count, "shard_count", 1, UINT64_MAX)
    rows = []
    seen: set[str] = set()
    for scenario in scenarios:
        validate_scenario(scenario, root)
        identifier = scenario["id"]
        if identifier in seen:
            raise ValueError(f"duplicate scenario id: {identifier}")
        seen.add(identifier)
        rows.append({
            "id": identifier,
            "scenario_sha256": scenario_sha256(scenario),
            "shard": shard_for(identifier, shard_count),
        })
    rows.sort(key=lambda row: row["id"])
    manifest: dict[str, Any] = {
        "schema": VERSION,
        "protocol": f"{PROTOCOL}-shards",
        "shard_count": shard_count,
        "assignments": rows,
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest


def scenarios_for_shard(manifest: dict[str, Any], shard_index: int) -> list[str]:
    shard_count = manifest.get("shard_count")
    _require_int(shard_count, "manifest.shard_count", 1, UINT64_MAX)
    _require_int(shard_index, "shard_index", 0, shard_count - 1)
    assignments = manifest.get("assignments")
    if not isinstance(assignments, list):
        raise ValueError("shard manifest assignments must be an array")
    return [row["id"] for row in assignments if row.get("shard") == shard_index]


def validate_receipt(
    receipt: dict[str, Any] | Path,
    scenario: dict[str, Any] | Path,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Validate a completed runner receipt against all replay inputs."""

    if isinstance(receipt, Path):
        receipt = load_json(receipt)
    if isinstance(scenario, Path):
        scenario = load_scenario(scenario, root)
    else:
        validate_scenario(scenario, root)
    required = {
        "schema", "protocol", "status", "runner", "scenario_id",
        "scenario_sha256", "plan_sha256", "source_hashes", "seed",
        "event_count", "completed_tick", "checkpoints",
    }
    receipt = _require_exact_keys(receipt, required, "receipt")
    if receipt["schema"] != VERSION or receipt["protocol"] != RECEIPT_PROTOCOL:
        raise ValueError("unsupported native replay receipt")
    if receipt["status"] != "PASS":
        raise ValueError("native replay receipt did not pass")
    if not isinstance(receipt["runner"], str) or not receipt["runner"].strip():
        raise ValueError("native replay receipt has no runner identity")
    plan = build_replay(scenario, root)
    expected_scalars = {
        "scenario_id": scenario["id"],
        "scenario_sha256": plan["scenario"]["sha256"],
        "plan_sha256": plan["plan_sha256"],
        "source_hashes": plan["source_hashes"],
        "seed": plan["seed"],
        "event_count": len(plan["events"]),
        "completed_tick": plan["timing"]["end_tick"],
    }
    for key, expected in expected_scalars.items():
        if receipt[key] != expected:
            raise ValueError(f"native replay receipt {key} drifted")
    validate_source_hashes(receipt["source_hashes"], root)
    observed = receipt["checkpoints"]
    if not isinstance(observed, list) or len(observed) != len(plan["checkpoints"]):
        raise ValueError("native replay receipt checkpoint count drifted")
    for index, (actual, expected) in enumerate(zip(observed, plan["checkpoints"])):
        _require_exact_keys(actual, {"id", "tick", "monotonic_ns", "state_sha256"}, f"receipt checkpoint {index}")
        if {key: actual[key] for key in ("id", "tick", "monotonic_ns")} != expected:
            raise ValueError(f"native replay receipt checkpoint {index} drifted")
        if not isinstance(actual["state_sha256"], str) or not SHA256.fullmatch(actual["state_sha256"]):
            raise ValueError(f"native replay receipt checkpoint {index} has no state hash")
    return receipt


validate_replay_receipt = validate_receipt


def _load_scenarios(paths: Iterable[Path], root: Path) -> list[dict[str, Any]]:
    return [load_scenario(path, root) for path in paths]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="root used to resolve pinned source paths")
    commands = parser.add_subparsers(dest="command", required=True)

    plan_parser = commands.add_parser("plan", help="write one deterministic replay plan")
    plan_parser.add_argument("scenario", type=Path)
    plan_parser.add_argument("output", type=Path)

    shard_parser = commands.add_parser("shard", help="write stable scenario shard assignments")
    shard_parser.add_argument("scenarios", type=Path, nargs="+")
    shard_parser.add_argument("--count", type=int, required=True)
    shard_parser.add_argument("--index", type=int)
    shard_parser.add_argument("--output", type=Path)

    receipt_parser = commands.add_parser("validate-receipt", help="fail unless a runner receipt matches its scenario")
    receipt_parser.add_argument("scenario", type=Path)
    receipt_parser.add_argument("receipt", type=Path)

    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.command == "plan":
        plan = build_replay(load_scenario(args.scenario, root), root)
        write_canonical_json(args.output, plan)
        return 0
    if args.command == "shard":
        manifest = build_shard_manifest(_load_scenarios(args.scenarios, root), args.count, root)
        if args.index is not None:
            manifest = {
                **manifest,
                "selected_shard": args.index,
                "selected_scenarios": scenarios_for_shard(manifest, args.index),
            }
        rendered = canonical_json(manifest) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    validate_receipt(args.receipt, args.scenario, root)
    print(canonical_json({"scenario": load_scenario(args.scenario, root)["id"], "status": "PASS"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
