#!/usr/bin/env python3
"""Generate the edition-specific flight scene-dispatch manifest.

The browser reducer consumes structural UDSP keys, never localized archive
paths.  This generator joins the selected edition's mission declarations,
native location registry and harvested UDSP scripts and fails closed when the
three inventories no longer agree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MISSIONS = ROOT / "content/miel_vliegt/uds_flight_contracts.json"
DEFAULT_LOCATIONS = ROOT / "content/miel_vliegt/native_scene_probe.json"
DEFAULT_UDSP = ROOT / "content/miel_vliegt/uds_scene_scripts.json"
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/scene_dispatch_contract.json"
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:/\\-]+$")
SCRIPT_OPCODES = {
    "PLAY_SCRIPT": "GROUND",
    "PLAY_BARNSCRIPT": "BARN",
    "PLAY_SCRIPTMODEFLY": "FLIGHT",
}
SPECIAL_POLICIES = {
    "grotte_grundlig": "GROTTE_REFUEL",
    "raymond_rajser": "RAYMOND_CHALLENGE",
    "varldsutstallning": "EXHIBITION_SELECTOR",
    "mygghanget": "BESPOKE_NO_UDSP",
}
SPECIAL_ROOTS = {
    "grotte_grundlig": ("refuel",),
    "raymond_rajser": ("challenge_first", "challenge", "mulle_win", "mulle_lose"),
    "varldsutstallning": (
        "judge", "nooneathome_emma", "nooneathome_circus",
        "allfinished_emma", "allfinished_circus", "outro",
    ),
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, schema: int, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError(f"{label} must use schema {schema}")
    return value


def _source(path: Path) -> dict[str, str]:
    try:
        relative = path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError as error:
        raise ValueError(f"source is outside repository root: {path}") from error
    return {"path": relative, "sha256": sha256_file(path)}


def artifact_key(domain_id: str, dispatch_id: str) -> str:
    return f"LOCATION_SCRIPT:{domain_id}/{dispatch_id}"


def _split_arguments(arguments: str) -> list[str]:
    return [part.strip() for part in arguments.split(",") if part.strip()]


def _artifact_ref(artifacts: dict[str, dict[str, Any]], domain_id: str,
                  dispatch_id: str) -> dict[str, Any]:
    key = artifact_key(domain_id, dispatch_id)
    try:
        return dict(artifacts[key])
    except KeyError as error:
        raise ValueError(f"missing UDSP scene artifact: {key}") from error


def build_contract(
    missions: dict[str, Any], locations: dict[str, Any], udsp: dict[str, Any],
    *, sources: dict[str, dict[str, str]], edition: str | None = None,
) -> dict[str, Any]:
    source_edition = locations.get("source", {}).get("edition")
    selected_edition = edition or source_edition
    if not isinstance(selected_edition, str) or not IDENTIFIER.fullmatch(selected_edition):
        raise ValueError("location manifest has no structural edition id")
    if edition is not None and source_edition is not None and edition != source_edition:
        raise ValueError("requested edition differs from location manifest")

    location_rows = locations.get("scenes")
    if not isinstance(location_rows, list) or len(location_rows) != 18:
        raise ValueError("location manifest must contain exactly 18 locations")
    by_id: dict[int, dict[str, Any]] = {}
    by_domain: dict[str, dict[str, Any]] = {}
    for row in location_rows:
        location_id = row.get("location_id")
        domain_id = row.get("id")
        if (not isinstance(location_id, int) or isinstance(location_id, bool) or
                not isinstance(domain_id, str) or not IDENTIFIER.fullmatch(domain_id) or
                not isinstance(row.get("mode"), str)):
            raise ValueError("invalid location identity")
        if location_id in by_id or domain_id in by_domain:
            raise ValueError("duplicate location identity")
        by_id[location_id] = row
        by_domain[domain_id] = row

    mission_rows = missions.get("missions")
    if not isinstance(mission_rows, list):
        raise ValueError("mission contract has no mission declarations")
    locationinfo_ids = {
        int(dependency["data"])
        for mission in mission_rows
        if mission.get("source") == "data/Missions/locationinfo.txt"
        for dependency in mission.get("dependencies", [])
        if dependency.get("type") == "enter_location"
    }
    if locationinfo_ids != set(by_id):
        raise ValueError("mission and native location inventories differ")

    artifact_rows: dict[str, dict[str, Any]] = {}
    for row in udsp.get("scripts", []):
        if row.get("type") != "LOCATION_SCRIPT":
            continue
        domain_id = row.get("domain_id")
        dispatch_id = row.get("dispatch_id")
        digest = row.get("sha256")
        if (not isinstance(domain_id, str) or not IDENTIFIER.fullmatch(domain_id) or
                not isinstance(dispatch_id, str) or not IDENTIFIER.fullmatch(dispatch_id) or
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid harvested location-script identity")
        key = artifact_key(domain_id, dispatch_id)
        if key in artifact_rows:
            raise ValueError(f"duplicate UDSP scene artifact: {key}")
        artifact_rows[key] = {
            "artifactKey": key,
            "type": "LOCATION_SCRIPT",
            "domainId": domain_id,
            "dispatchId": dispatch_id,
            "sha256": digest,
        }

    udsp_domains = {row["domainId"] for row in artifact_rows.values()}
    expected_domains = set(by_domain) - {"mygghanget"}
    if udsp_domains != expected_domains | {"barn"}:
        raise ValueError("UDSP and native location domains differ")

    expected_absences = [
        {
            "domainId": "mygghanget", "dispatchId": None,
            "kind": "LOCATION_SCRIPT_DOMAIN", "reason": "BESPOKE_NATIVE_STATE_MACHINE",
        },
        {
            "domainId": "raymond_rajser", "dispatchId": "allfinished",
            "kind": "LOCATION_SCRIPT", "reason": "SPECIALIZED_CHALLENGE_POLICY",
        },
        {
            "domainId": "varldsutstallning", "dispatchId": "allfinished",
            "kind": "LOCATION_SCRIPT", "reason": "SUFFIXED_EXHIBITION_FINAL_ROOTS",
        },
    ]
    for absence in expected_absences:
        if absence["dispatchId"] is None:
            if absence["domainId"] in udsp_domains:
                raise ValueError("expected absent UDSP domain is present")
        elif artifact_key(absence["domainId"], absence["dispatchId"]) in artifact_rows:
            raise ValueError("expected absent UDSP script is present")

    compiled_locations = []
    for location_id, row in sorted(by_id.items()):
        domain_id = row["id"]
        policy = SPECIAL_POLICIES.get(domain_id, "GENERIC")
        default_root = None
        final_root = None
        if policy in {"GENERIC", "GROTTE_REFUEL"}:
            default_root = _artifact_ref(artifact_rows, domain_id, "nooneathome")
            final_root = _artifact_ref(artifact_rows, domain_id, "allfinished")
        special_roots = [
            _artifact_ref(artifact_rows, domain_id, dispatch_id)
            for dispatch_id in SPECIAL_ROOTS.get(domain_id, ())
        ]
        compiled_locations.append({
            "locationId": location_id,
            "domainId": domain_id,
            "mode": row["mode"],
            "policy": policy,
            "defaultRoot": default_root,
            "finalRoot": final_root,
            "specialRoots": special_roots,
        })

    compiled_actions = []
    for mission in mission_rows:
        mission_key = f'{mission["id"]}:{mission["source"]}'
        for action_index, action in enumerate(mission.get("actions", [])):
            opcode = action.get("command")
            if opcode not in SCRIPT_OPCODES and opcode != "PLAY_OUTRO":
                continue
            phase = action.get("state")
            if phase not in {"activate", "complete", "reward"}:
                raise ValueError("script mission action has invalid phase")
            if opcode == "PLAY_OUTRO":
                if action.get("arguments") != "":
                    raise ValueError("PLAY_OUTRO must not have arguments")
                compiled_actions.append({
                    "missionKey": mission_key,
                    "missionId": mission["id"],
                    "missionPhase": phase,
                    "nativeActionOrdinal": action_index,
                    "opcode": opcode,
                    "route": "LOCATION_POLICY",
                    "domainId": "varldsutstallning",
                    "scriptId": "outro",
                    "artifactKey": artifact_key("varldsutstallning", "outro"),
                })
                continue
            arguments = _split_arguments(action.get("arguments", ""))
            if opcode == "PLAY_BARNSCRIPT":
                if len(arguments) != 1:
                    raise ValueError("PLAY_BARNSCRIPT must have one argument")
                domain_id, script_id = "barn", arguments[0]
            else:
                if len(arguments) != 2:
                    raise ValueError(f"{opcode} must have two arguments")
                domain_id, script_id = arguments
            ref = _artifact_ref(artifact_rows, domain_id, script_id)
            compiled_actions.append({
                "missionKey": mission_key,
                "missionId": mission["id"],
                "missionPhase": phase,
                "nativeActionOrdinal": action_index,
                "opcode": opcode,
                "route": SCRIPT_OPCODES[opcode],
                "domainId": domain_id,
                "scriptId": script_id,
                "artifactKey": ref["artifactKey"],
            })

    return {
        "schema": 1,
        "contract": "miel-vliegt-scene-dispatch",
        "edition": selected_edition,
        "claim": "STATIC_DISPATCH_POLICY_RUNTIME_PARITY_UNPROVEN",
        "sources": sources,
        "routes": {
            "GROUND": {"opcode": "PLAY_SCRIPT", "enqueue": "PREPEND", "start": "LOCATION_SELECTION"},
            "BARN": {"opcode": "PLAY_BARNSCRIPT", "enqueue": "APPEND", "start": "IMMEDIATE_IF_IDLE"},
            "FLIGHT": {"opcode": "PLAY_SCRIPTMODEFLY", "enqueue": "REPLACE", "start": "IMMEDIATE"},
        },
        "expectedAbsences": expected_absences,
        "locations": compiled_locations,
        "artifacts": [artifact_rows[key] for key in sorted(artifact_rows)],
        "missionActions": compiled_actions,
    }


def generate(mission_path: Path, location_path: Path, udsp_path: Path,
             *, edition: str | None = None) -> dict[str, Any]:
    paths = {
        "missions": mission_path,
        "locations": location_path,
        "udsp": udsp_path,
    }
    return build_contract(
        _load(mission_path, 1, "mission contract"),
        _load(location_path, 1, "location manifest"),
        _load(udsp_path, 2, "UDSP scene contract"),
        edition=edition,
        sources={name: _source(path) for name, path in paths.items()},
    )


def render(contract: dict[str, Any]) -> str:
    return json.dumps(contract, ensure_ascii=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--missions", type=Path, default=DEFAULT_MISSIONS)
    parser.add_argument("--locations", type=Path, default=DEFAULT_LOCATIONS)
    parser.add_argument("--udsp", type=Path, default=DEFAULT_UDSP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--edition")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = render(generate(args.missions, args.locations, args.udsp, edition=args.edition))
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != payload:
            raise SystemExit(f"scene dispatch contract drifted: {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
