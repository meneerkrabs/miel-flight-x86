#!/usr/bin/env python3
"""Validate the machine-readable Miel Vliegt parity ledger and checkpoints.

This gate validates evidence and prevents status regression. It deliberately
does not compare web motion or pixels to the native executable: no native
trajectory or render trace has been captured yet.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.verify_director_render_oracle import (
        validate as validate_director_render_oracle,
    )
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from verify_director_render_oracle import validate as validate_director_render_oracle


ALLOWED_STATUSES = {
    "EQUIVALENT", "PLATFORM_SUBSTITUTION", "MISSING", "DESCOPED"
}
REQUIRED_BY_STATUS = {
    "EQUIVALENT": {"source", "runtime", "verification", "claim"},
    "PLATFORM_SUBSTITUTION": {"source", "replacement", "limitation", "verification"},
    "MISSING": {"source", "gap", "required_evidence"},
    "DESCOPED": {"source", "reason", "boundary"},
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def resolve_pointer(document: Any, pointer: str, label: str) -> Any:
    if not pointer:
        return document
    if not pointer.startswith("/"):
        raise ValueError(f"{label}: invalid JSON pointer #{pointer}")
    value = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            try:
                value = value[int(part)]
            except (ValueError, IndexError) as error:
                raise ValueError(f"{label}: missing JSON pointer segment {part!r}") from error
        elif isinstance(value, dict) and part in value:
            value = value[part]
        else:
            raise ValueError(f"{label}: missing JSON pointer segment {part!r}")
    return value


def validate_reference(root: Path, reference: str, label: str) -> None:
    relative, separator, pointer = reference.partition("#")
    path = root / relative
    if not path.is_file():
        raise ValueError(f"{label}: evidence file does not exist: {relative}")
    if separator:
        resolve_pointer(load_json(path), pointer, label)


def resolve_checkpoint(checkpoints: dict[str, Any], dotted: str, label: str) -> Any:
    value: Any = checkpoints
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            raise ValueError(f"{label}: unknown checkpoint {dotted}")
        value = value[part]
    return value


def validate_checkpoint_values(root: Path, checkpoints: dict[str, Any]) -> None:
    native = load_json(root / "content/miel_vliegt/uds_flight_contracts.json")
    hangar = load_json(root / "content/miel_vliegt/flight_hangar_contract.json")
    frontend = load_json(root / "content/miel_vliegt/flight_frontend_contract.json")
    intro = load_json(root / "content/miel_vliegt/flight_intro_contract.json")
    airplane = load_json(root / "content/miel_vliegt/uds_flight_parts.json")

    airplane_checkpoint = checkpoints["runtime"]["airplane_catalog"]
    for field in ("models", "parts", "vertices", "triangles"):
        if airplane_checkpoint[field] != airplane["counts"][field]:
            raise ValueError(f"runtime.airplane_catalog {field} drifted")
    if airplane_checkpoint["default_airplane"] != airplane["default_airplane"]:
        raise ValueError("runtime.airplane_catalog default airplane drifted")

    runtime = checkpoints["runtime"]["world_contract"]
    if runtime["world"] != native["runtime"]["world"]:
        raise ValueError("runtime.world_contract world/start drifted from harvested native contract")
    if runtime["controls"] != native["runtime"]["controls"]:
        raise ValueError("runtime.world_contract controls drifted from harvested native contract")
    if runtime["maximum_step_seconds"] != native["runtime"]["simulation"]["maximum_step_seconds"]:
        raise ValueError("runtime.world_contract maximum step drifted from harvested native contract")

    mission = checkpoints["runtime"]["mission_catalog"]
    for field in ("mission_declarations", "unique_mission_ids"):
        if mission[field] != native["counts"][field]:
            raise ValueError(f"runtime.mission_catalog {field} drifted from harvested native contract")

    render = checkpoints["render"]["hangar"]
    for view in render["views"]:
        dimensions = hangar["dimensions"].get(view)
        if dimensions != render["stage"]:
            raise ValueError(f"render.hangar {view} dimensions drifted")
    expected_hotspots = {
        "inside_door": hangar["hotspots"]["inside"]["door"],
        "outside_door": hangar["hotspots"]["outside"]["door"],
        "outside_album": hangar["hotspots"]["outside"]["album"],
        "outside_camera": hangar["hotspots"]["outside"]["camera"],
        "outside_map": hangar["hotspots"]["outside"]["map"],
        "shelf_door": hangar["hotspots"]["shelf"]["door"],
    }
    for name, expected in expected_hotspots.items():
        if render["hotspot_checkpoints"][name] != [expected["x"], expected["y"]]:
            raise ValueError(f"render.hangar hotspot {name} drifted")

    frontend_render = checkpoints["render"]["frontends"]
    expected_frontend = {
        "handbook_pages": frontend["handbook_pages"],
        "history_items": frontend["history_items"],
        "history_cues": len(frontend["history_sequence"]),
    }
    for field, expected in expected_frontend.items():
        if frontend_render[field] != expected:
            raise ValueError(f"render.frontends {field} drifted")

    intro_render = checkpoints["render"]["intro"]
    for field in ("source_kind", "availability", "disposition"):
        if intro_render[field] != intro[field]:
            raise ValueError(f"render.intro {field} drifted")

    audio = checkpoints["audio"]
    actual_door_hashes = {
        key: value["sha256"] for key, value in hangar["audio"].items()
    }
    if audio["door_samples"]["identities"] != actual_door_hashes:
        raise ValueError("audio.door_samples identities drifted")
    if audio["history_voice"]["sample_count"] != len(frontend["history_audio"]):
        raise ValueError("audio.history_voice sample count drifted")


def validate(root: Path, ledger_path: Path, checkpoints_path: Path) -> Counter[str]:
    ledger = load_json(ledger_path)
    checkpoints = load_json(checkpoints_path)
    if ledger.get("schema") != 1 or checkpoints.get("schema") != 1:
        raise ValueError("unsupported flight parity schema")
    if set(ledger.get("statuses", [])) != ALLOWED_STATUSES:
        raise ValueError("ledger status vocabulary drifted")
    if checkpoints.get("native_trace_available") is not False:
        raise ValueError("native_trace_available must remain false until a trace artifact is checked in")
    if ledger.get("policy", {}).get("native_trace_available") is not False:
        raise ValueError("ledger must not claim native differential trace coverage")

    records = ledger.get("records")
    if not isinstance(records, list):
        raise ValueError("ledger records must be an array")
    ids = [record.get("id") for record in records]
    if any(not isinstance(record_id, str) or not record_id for record_id in ids):
        raise ValueError("every ledger record needs a non-empty id")
    if len(ids) != len(set(ids)):
        raise ValueError("flight parity ledger contains duplicate ids")
    if ids != sorted(ids):
        raise ValueError("flight parity ledger records must be sorted by id")

    counts: Counter[str] = Counter()
    covered_checkpoints = set()
    native_coverage: dict[str, str] = {}
    for record in records:
        record_id = record["id"]
        status = record.get("status")
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"{record_id}: invalid status {status!r}")
        counts[status] += 1
        missing_fields = REQUIRED_BY_STATUS[status] - record.keys()
        if missing_fields:
            raise ValueError(f"{record_id}: missing {status} fields {sorted(missing_fields)}")
        for field in ("source", "runtime", "verification"):
            if field in record:
                validate_reference(root, record[field], f"{record_id}.{field}")
        if "contract" in record:
            resolve_checkpoint(checkpoints, record["contract"], record_id)
            covered_checkpoints.add(record["contract"])
        if "native_contract" in record:
            native_contract = record["native_contract"]
            if native_contract in native_coverage:
                raise ValueError(
                    f"native contract {native_contract} covered by both "
                    f"{native_coverage[native_contract]} and {record_id}"
                )
            native_coverage[native_contract] = record_id

    floor = ledger["quality_floor"]
    if len(records) < floor["minimum_records"]:
        raise ValueError("flight parity inventory shrank below its reviewed floor")
    if counts["EQUIVALENT"] < floor["minimum_equivalent"]:
        raise ValueError("EQUIVALENT coverage regressed below its reviewed floor")
    for status, key in (
        ("PLATFORM_SUBSTITUTION", "maximum_platform_substitution"),
        ("MISSING", "maximum_missing"),
    ):
        if counts[status] > floor[key]:
            raise ValueError(f"{status} count regressed above its reviewed ceiling")
    missing_ids = {record["id"] for record in records if record["status"] == "MISSING"}
    allowed_missing_ids = set(floor["allowed_missing_ids"])
    if missing_ids != allowed_missing_ids:
        raise ValueError(
            "reviewed MISSING allowlist drifted: "
            f"unreviewed={sorted(missing_ids - allowed_missing_ids)}, "
            f"stale={sorted(allowed_missing_ids - missing_ids)}"
        )

    native = load_json(root / "content/miel_vliegt/uds_flight_contracts.json")
    declared_native = set(native["parity_scope"]["proven"] + native["parity_scope"]["not_yet_parity"])
    if set(native_coverage) != declared_native:
        raise ValueError(
            "native scope coverage mismatch: "
            f"missing={sorted(declared_native - set(native_coverage))}, "
            f"extra={sorted(set(native_coverage) - declared_native)}"
        )
    required_checkpoints = {
        "runtime.airplane_catalog", "runtime.world_contract", "runtime.mission_catalog",
        "render.frontends", "render.hangar",
        "audio.door_samples", "audio.history_voice",
    }
    if not required_checkpoints <= covered_checkpoints:
        raise ValueError(f"uncovered checkpoints: {sorted(required_checkpoints - covered_checkpoints)}")

    validate_checkpoint_values(root, checkpoints)
    render_oracle = load_json(
        root / "content/miel_vliegt/director_intro_render_oracle_contract.json"
    )
    validate_director_render_oracle(
        render_oracle,
        root,
        root / render_oracle["artifact_policy"]["root"],
    )
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--checkpoints", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    ledger = args.ledger or root / "content/miel_vliegt/flight_parity_ledger.json"
    checkpoints = args.checkpoints or root / "content/miel_vliegt/flight_parity_checkpoints.json"
    counts = validate(root, ledger, checkpoints)
    print("flight parity ledger OK: " + ", ".join(
        f"{status}={counts[status]}" for status in sorted(ALLOWED_STATUSES)
    ))


if __name__ == "__main__":
    main()
