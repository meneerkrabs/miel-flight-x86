#!/usr/bin/env python3
"""Cross-check external gameplay hypotheses against harvested first-party data.

The external registry is deliberately non-authoritative.  This resolver may
only report that individual coordinate fields are corroborated by the
original ``data/Missions/*.txt`` declarations.  It never exports parity
evidence and it never upgrades a claim to runtime equivalence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = ROOT / "content/miel_vliegt/external_hypothesis_registry.json"
DEFAULT_SOURCE = ROOT / "content/miel_vliegt/uds_flight_contracts.json"
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/external_hypothesis_resolutions.json"

ACTION_FIELDS = {
    "ADD_MAPEVENT": ("event_id", "asset_id", "mode_flag", "x", "height", "y", "radius"),
    "ADD_MAPEVENTRANDOMPOS": (
        "event_id", "asset_id", "mode_flag", "x", "height", "y", "radius", "placement_radius"
    ),
}


def _split_arguments(value: str) -> list[str]:
    return [part.strip() for part in value.split(",")]


def _integer(value: str) -> int:
    try:
        return int(value, 10)
    except ValueError as error:
        raise ValueError(f"expected integer mission argument, got {value!r}") from error


def harvest_map_actions(source: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for mission_index, mission in enumerate(source.get("missions", [])):
        for action_index, action in enumerate(mission.get("actions", [])):
            command = action.get("command")
            fields = ACTION_FIELDS.get(command)
            if fields is None:
                continue
            arguments = _split_arguments(action.get("arguments", ""))
            if len(arguments) != len(fields):
                raise ValueError(
                    f"{mission.get('source')}:{mission.get('name')} {command} has "
                    f"{len(arguments)} arguments; expected {len(fields)}"
                )
            values: dict[str, Any] = dict(zip(fields, arguments))
            for field in fields[2:]:
                values[field] = _integer(values[field])
            rows.append({
                "mission_id": mission["id"],
                "mission_name": mission["name"],
                "source": mission["source"],
                "source_pointer": f"#/missions/{mission_index}/actions/{action_index}",
                "command": command,
                "values": values,
            })
    return rows


def _point_resolution(point: dict[str, Any], actions: list[dict[str, Any]]) -> dict[str, Any]:
    coordinate_matches = [
        action for action in actions
        if action["values"]["x"] == point.get("x") and action["values"]["y"] == point.get("y")
    ]
    if not coordinate_matches:
        return {
            "item_id": point["item_id"],
            "status": "UNVERIFIED",
            "matched_fields": [],
            "conflicting_fields": [],
            "source_matches": [],
        }

    expected_radius = point.get("placement_radius")
    exact_matches = coordinate_matches
    conflicting_fields: list[str] = []
    if expected_radius is not None:
        exact_matches = [
            action for action in coordinate_matches
            if action["values"].get("placement_radius") == expected_radius
        ]
        if not exact_matches:
            conflicting_fields.append("placement_radius")

    matches = exact_matches or coordinate_matches
    status = "FIRST_PARTY_SOURCE_CORROBORATED" if exact_matches else "PARTIALLY_CORROBORATED"
    matched_fields = ["x", "y"]
    if expected_radius is not None and exact_matches:
        matched_fields.append("placement_radius")
    return {
        "item_id": point["item_id"],
        "status": status,
        "matched_fields": matched_fields,
        "conflicting_fields": conflicting_fields,
        "source_matches": [{
            "mission_id": action["mission_id"],
            "mission_name": action["mission_name"],
            "source": action["source"],
            "source_pointer": action["source_pointer"],
            "command": action["command"],
            "values": action["values"],
        } for action in matches],
    }


def _resolve_erik_yarn(source: dict[str, Any]) -> dict[str, Any] | None:
    """Corroborate issue #2's Eric/yarn sequence from the original mission declaration."""

    for mission_index, mission in enumerate(source.get("missions", [])):
        if mission.get("id") != 36 or mission.get("name") != "erik_needhelp_thread":
            continue
        dependencies = {
            (item.get("state"), item.get("type"), item.get("data"))
            for item in mission.get("dependencies", [])
        }
        actions = {
            (item.get("state"), item.get("command"), item.get("arguments"))
            for item in mission.get("actions", [])
        }
        required_dependencies = {
            ("activate", "mission_notactivated", str(mission_id))
            for mission_id in (601, 602, 603, 604)
        } | {
            ("complete", "map_event", "found_mobilephone_special"),
            ("reward", "arrive", "3"),
        }
        required_actions = {
            ("activate", "ADD_MAPEVENTRANDOMPOS", "found_mobilephone_special, mobiltelefon_erik, 1, 1855, 25, 1441, 25, 1000"),
            ("reward", "PLAY_SCRIPT", "sam_scribbler, erik_getthread"),
            ("reward", "GET_ITEM", "sytrad_atle"),
        }
        if required_dependencies <= dependencies and required_actions <= actions:
            return {
                "id": "issue2.erik.yarn",
                "status": "FIRST_PARTY_SOURCE_CORROBORATED",
                "reason": "original mission 36 encodes four prior Eric missions, a second phone, Sam arrival and yarn reward",
                "point_resolutions": [],
                "source_matches": [{
                    "mission_id": 36,
                    "mission_name": mission["name"],
                    "source": mission["source"],
                    "source_pointer": f"#/missions/{mission_index}",
                }],
            }
    return None


def build_resolutions(registry: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    actions = harvest_map_actions(source)
    resolutions: list[dict[str, Any]] = []
    for hypothesis in registry.get("hypotheses", []):
        claim = hypothesis.get("claim", {})
        if claim.get("kind") != "MISSION_COORDINATES":
            if hypothesis["id"] == "issue2.erik.yarn":
                resolved = _resolve_erik_yarn(source)
                if resolved is not None:
                    resolutions.append(resolved)
                    continue
            resolutions.append({
                "id": hypothesis["id"],
                "status": "UNVERIFIED",
                "reason": "no deterministic first-party resolver for this rule kind",
                "point_resolutions": [],
            })
            continue
        points = [_point_resolution(point, actions) for point in claim.get("points", [])]
        statuses = {point["status"] for point in points}
        if statuses == {"FIRST_PARTY_SOURCE_CORROBORATED"}:
            status = "FIRST_PARTY_SOURCE_CORROBORATED"
        elif "FIRST_PARTY_SOURCE_CORROBORATED" in statuses or "PARTIALLY_CORROBORATED" in statuses:
            status = "PARTIALLY_CORROBORATED"
        else:
            status = "UNVERIFIED"
        resolutions.append({
            "id": hypothesis["id"],
            "status": status,
            "reason": "field-level comparison with harvested original mission declarations",
            "point_resolutions": points,
        })

    counts = {status: 0 for status in (
        "FIRST_PARTY_SOURCE_CORROBORATED", "PARTIALLY_CORROBORATED", "UNVERIFIED"
    )}
    for row in resolutions:
        counts[row["status"]] += 1
    return {
        "schema_version": 1,
        "evidence_policy": {
            "source": "ORIGINAL_UDS_MISSION_DECLARATIONS",
            "corroboration_is_runtime_parity": False,
            "may_satisfy_parity_gate": False,
            "external_claims_remain_hypotheses": True,
        },
        "counts": counts,
        "resolutions": resolutions,
        "parity_evidence_exports": [],
    }


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    source = json.loads(args.source.read_text(encoding="utf-8"))
    expected = canonical_bytes(build_resolutions(registry, source))
    if args.write:
        args.output.write_bytes(expected)
        return
    if not args.output.exists():
        raise SystemExit(f"missing resolution artifact: {args.output}")
    if args.output.read_bytes() != expected:
        raise SystemExit("external hypothesis resolution artifact is stale")
    print("external hypothesis resolutions OK")


if __name__ == "__main__":
    main()
