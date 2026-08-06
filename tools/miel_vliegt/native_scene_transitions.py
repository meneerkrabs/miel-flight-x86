#!/usr/bin/env python3
"""Validate the fail-closed native Miel Vliegt mode-transition contract.

This module consumes checked-in analysis artifacts only.  It never opens or
copies the proprietary executable and never promotes trace-required,
unresolved, or debug-only routes to natural parity evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "content/miel_vliegt/native_scene_transitions.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ADDRESS = re.compile(r"^0x[0-9a-f]{8}$")

CORE_MODES = {
    "login": "mode_login",
    "barn": "mode_barn",
    "flight": "mode_fly",
    "credits": "mode_credits",
}
MANAGER_CONTRACT = {
    "resolve_mode": "0x0041e410",
    "set_mode": "0x0041e450",
    "queue_mode": "0x0041e490",
    "activate_pending": "0x0041e4a0",
    "current_mode_offset": "0x18c",
    "pending_mode_offset": "0x190",
}
REQUIRED_ARTIFACTS = {
    "native_common_location_state_machine",
    "native_function_index",
    "native_code_map",
    "native_scene_probe",
    "uds_flight_contracts",
    "mission_action_contracts",
}
EDGE_REQUIRED_FIELDS = {
    "id", "source", "source_type", "target", "target_type", "trigger",
    "address", "predicate", "evidence_status", "natural", "parity_eligible",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"artifact escapes repository root: {relative}") from error
    return candidate


def expanded_edges(contract: dict[str, Any]) -> list[dict[str, Any]]:
    """Return logical natural candidates without unresolved/debug routes."""
    result = [deepcopy(edge) for edge in contract["edges"]]
    for row in contract["location_edges"]:
        result.extend((deepcopy(row["landing"]), deepcopy(row["departure"])))
    return result


def natural_parity_edges(contract: dict[str, Any]) -> list[dict[str, Any]]:
    """Expose only edges allowed to count as natural parity evidence."""
    allowed = set(contract["policy"]["natural_parity_statuses"])
    return [
        edge for edge in expanded_edges(contract)
        if edge["natural"] and edge["parity_eligible"]
        and edge["evidence_status"] in allowed
    ]


def _validate_modes(contract: dict[str, Any]) -> tuple[set[str], set[int]]:
    policy = contract["policy"]
    modes = contract.get("modes")
    if not isinstance(modes, list) or len(modes) != policy["manager_mode_count"]:
        raise ValueError("manager mode inventory must contain exactly 22 modes")
    ids = [mode.get("id") for mode in modes]
    names = [mode.get("mode") for mode in modes]
    if len(set(ids)) != len(ids) or len(set(names)) != len(names):
        raise ValueError("manager mode inventory contains duplicate identities")

    core = {mode["id"]: mode["mode"] for mode in modes if mode.get("mode_type") == "core"}
    if core != CORE_MODES or len(core) != policy["core_mode_count"]:
        raise ValueError("core manager modes drifted")
    locations = [mode for mode in modes if mode.get("mode_type") == "location"]
    if len(locations) != policy["location_mode_count"]:
        raise ValueError("location manager mode inventory must contain exactly 18 modes")
    location_ids = [mode.get("location_id") for mode in locations]
    if any(not isinstance(value, int) or isinstance(value, bool) for value in location_ids):
        raise ValueError("location mode has no integer location_id")
    if len(set(location_ids)) != len(location_ids):
        raise ValueError("location mode inventory contains duplicate location IDs")

    core_fields = {"id", "mode", "mode_type", "mode_address", "constructor"}
    location_fields = core_fields | {"location_id", "flight_marker_call"}
    for mode in modes:
        expected = core_fields if mode["mode_type"] == "core" else location_fields
        if set(mode) != expected:
            raise ValueError(f"mode fields drifted: {mode.get('id')}")
        if not mode["mode"].startswith("mode_"):
            raise ValueError(f"invalid manager mode name: {mode['mode']}")
        for field in expected & {"mode_address", "constructor", "flight_marker_call"}:
            if not ADDRESS.fullmatch(mode[field]):
                raise ValueError(f"invalid {field}: {mode['id']}")
    return set(names), set(location_ids)


def _validate_edge(edge: dict[str, Any], mode_names: set[str], *, category: str) -> None:
    optional = {
        "alternate_addresses", "reason", "site_role", "commit_address", "owner_address",
    }
    if set(edge) - EDGE_REQUIRED_FIELDS - optional or not EDGE_REQUIRED_FIELDS <= set(edge):
        raise ValueError(f"{category} edge fields drifted: {edge.get('id')}")
    if not ADDRESS.fullmatch(edge["address"]):
        raise ValueError(f"invalid edge address: {edge['id']}")
    for address in edge.get("alternate_addresses", []):
        if not ADDRESS.fullmatch(address):
            raise ValueError(f"invalid alternate edge address: {edge['id']}")
    for field in ("commit_address", "owner_address"):
        if field in edge and not ADDRESS.fullmatch(edge[field]):
            raise ValueError(f"invalid {field}: {edge['id']}")
    if "site_role" in edge and edge["site_role"] not in {"producer", "commit"}:
        raise ValueError(f"invalid site_role: {edge['id']}")
    if edge["source_type"] == "mode" and edge["source"] not in mode_names:
        raise ValueError(f"edge references unknown source mode: {edge['id']}")
    if edge["target_type"] == "mode" and edge["target"] not in mode_names:
        raise ValueError(f"edge references unknown target mode: {edge['id']}")
    if not isinstance(edge["trigger"], str) or not edge["trigger"]:
        raise ValueError(f"edge has no trigger: {edge['id']}")
    if not isinstance(edge["predicate"], str) or not edge["predicate"]:
        raise ValueError(f"edge has no predicate: {edge['id']}")


def _validate_edge_policy(contract: dict[str, Any], mode_names: set[str]) -> None:
    statuses = set(contract["policy"]["evidence_statuses"])
    allowed = set(contract["policy"]["natural_parity_statuses"])
    edges = expanded_edges(contract)
    ids = [edge["id"] for edge in edges]
    if len(ids) != len(set(ids)):
        raise ValueError("natural edge inventory contains duplicate IDs")
    for edge in edges:
        _validate_edge(edge, mode_names, category="natural")
        if edge["evidence_status"] not in statuses - {"UNRESOLVED"}:
            raise ValueError(f"natural edge has invalid evidence status: {edge['id']}")
        if edge["natural"] is not True:
            raise ValueError(f"natural edge is marked nonnatural: {edge['id']}")
        should_count = edge["evidence_status"] in allowed
        if edge["parity_eligible"] is not should_count:
            raise ValueError(f"natural parity policy violated: {edge['id']}")

    trace_required = {
        "mygghanget.barn.state6",
        "mygghanget.barn.offscreen",
        "varldsutstallning.credits",
        "varldsutstallning.barn.callback",
        "varldsutstallning.barn.state5",
    }
    trace_required.update(
        edge["id"] for edge in edges if edge["id"].startswith("location.departure.")
    )
    status_by_id = {edge["id"]: edge["evidence_status"] for edge in edges}
    if any(status_by_id.get(edge_id) != "NATIVE_TRACE_REQUIRED" for edge_id in trace_required):
        raise ValueError("an open native hook was promoted without trace evidence")

    location_names = {
        mode["mode"] for mode in contract["modes"] if mode["mode_type"] == "location"
    }
    rows = contract.get("location_edges", [])
    if len(rows) != 18 or {row.get("location") for row in rows} != location_names:
        raise ValueError("location edge inventory must cover all 18 locations exactly once")
    for row in rows:
        if set(row) != {"location", "landing", "departure"}:
            raise ValueError(f"location edge row fields drifted: {row.get('location')}")
        if row["landing"]["source"] != "mode_fly" or row["landing"]["target"] != row["location"]:
            raise ValueError(f"location landing edge drifted: {row['location']}")
        if row["departure"]["source"] != row["location"] or row["departure"]["target"] != "mode_fly":
            raise ValueError(f"location departure edge drifted: {row['location']}")
        landing = row["landing"]
        departure = row["departure"]
        if (
            landing.get("site_role") != "producer"
            or landing["address"] != "0x00430fa4"
            or landing.get("commit_address") != "0x0042c790"
        ):
            raise ValueError(f"location landing producer/commit roles drifted: {row['location']}")
        if (
            departure.get("site_role") != "commit"
            or departure["address"] != "0x00425c2e"
            or departure.get("alternate_addresses") != [
                "0x00425cb1", "0x00425e90", "0x00425fe5", "0x004262ee",
            ]
            or departure.get("owner_address") != "0x00425ab0"
        ):
            raise ValueError(f"location departure owner/commit roles drifted: {row['location']}")

    unresolved = contract.get("unresolved_edges", [])
    if [edge.get("id") for edge in unresolved] != ["location.barn.generic_return"]:
        raise ValueError("unresolved edge inventory drifted")
    for edge in unresolved:
        _validate_edge(edge, mode_names, category="unresolved")
        if edge["evidence_status"] != "UNRESOLVED" or edge["natural"] or edge["parity_eligible"]:
            raise ValueError(f"unresolved edge escaped fail-closed policy: {edge['id']}")
    debug = contract.get("debug_edges", [])
    if [edge.get("id") for edge in debug] != ["debug.engine_mode"]:
        raise ValueError("debug edge inventory drifted")
    for edge in debug:
        _validate_edge(edge, mode_names, category="debug")
        if edge["evidence_status"] != contract["policy"]["debug_status"] \
                or edge["natural"] or edge["parity_eligible"]:
            raise ValueError(f"debug edge escaped fail-closed policy: {edge['id']}")
    if debug[0]["address"] != "0x0041e22d":
        raise ValueError("engine_mode debug edge address drifted")


def _validate_artifacts(
    contract: dict[str, Any], root: Path, mode_names: set[str], location_ids: set[int]
) -> None:
    source = contract["source"]
    artifacts = source.get("artifacts", {})
    if set(artifacts) != REQUIRED_ARTIFACTS:
        raise ValueError("transition contract artifact pins drifted")
    loaded: dict[str, dict[str, Any]] = {}
    for name, pin in artifacts.items():
        if set(pin) != {"path", "sha256"} or not SHA256.fullmatch(pin.get("sha256", "")):
            raise ValueError(f"invalid artifact pin: {name}")
        path = _artifact_path(root, pin["path"])
        if not path.is_file() or sha256_file(path) != pin["sha256"]:
            raise ValueError(f"pinned artifact drifted: {name}")
        loaded[name] = json.loads(path.read_text(encoding="utf-8"))

    executable_sha = source["executable_sha256"]
    if not SHA256.fullmatch(executable_sha):
        raise ValueError("transition contract has no executable SHA-256")
    for name in ("native_function_index", "native_code_map"):
        if loaded[name].get("source", {}).get("sha256") != executable_sha:
            raise ValueError(f"{name} belongs to another executable")
    probe = loaded["native_scene_probe"]
    if probe.get("source", {}).get("executable_sha256") != executable_sha:
        raise ValueError("native scene probe belongs to another executable")
    common = loaded["native_common_location_state_machine"]
    if common.get("source", {}).get("executable_sha256") != executable_sha:
        raise ValueError("common location state machine belongs to another executable")
    if common.get("policy", {}).get("runtime_parity") != "NATIVE_TRACE_REQUIRED":
        raise ValueError("common location runtime parity was promoted without native traces")
    native_transitions = common.get("transitions", {})
    boundaries = common.get("semantic_boundaries", {})
    if boundaries != {
        "common_location_controller_update": "0x00425ab0",
        "mode_fly": {
            "vtable": "0x0044cf58",
            "tick": "0x0042ca10",
            "render": "0x0042d6d0",
        },
        "invariant": "COMMON_LOCATION_CONTROLLER_IS_NOT_MODE_FLY_LIFECYCLE",
        "all_entries_distinct": True,
        "runtime_parity": "NATIVE_TRACE_REQUIRED",
    }:
        raise ValueError("common location controller was conflated with mode_fly lifecycle")
    graph = common.get("transition_graph", {})
    if [(row.get("source"), row.get("target")) for row in graph.get("update_edges", [])] != [
        (0, 2), (2, 6), (2, 0), (2, 4), (4, 0), (3, 0),
        (5, 4), (5, 0), (6, 5), (7, 5),
    ] or [(row.get("source"), row.get("target"))
          for row in graph.get("setter_reentry_edges", [])] != [(2, 4), (2, 3)] \
            or graph.get("runtime_parity") != "NATIVE_TRACE_REQUIRED":
        raise ValueError("common location static transition graph drifted")
    pending = native_transitions.get("pending_target", {})
    departure = native_transitions.get("flight_departure", {})
    if pending.get("landing_marker_producer") != "0x00430fa4" \
            or pending.get("manager_queue_commit") != "0x0042c790":
        raise ValueError("landing producer/commit evidence differs from native state machine")
    if departure.get("owner_routine") != "0x00425ab0" \
            or departure.get("commit_callsites") != [
                "0x00425c2e", "0x00425cb1", "0x00425e90", "0x00425fe5", "0x004262ee",
            ]:
        raise ValueError("departure owner/commit evidence differs from native state machine")

    contract_locations = {
        (mode["id"], mode["location_id"], mode["mode"], mode["mode_address"], mode["constructor"])
        for mode in contract["modes"] if mode["mode_type"] == "location"
    }
    probe_locations = {
        (scene["id"], scene["location_id"], scene["mode"], scene["mode_address"], scene["constructor"])
        for scene in probe.get("scenes", [])
    }
    if contract_locations != probe_locations:
        raise ValueError("transition modes differ from native scene probe")
    flight_targets = {
        target.get("mode") for target in probe.get("startup_targets", [])
        if target.get("id") == "flight"
    }
    if flight_targets != {"mode_fly"} or "mode_fly" not in mode_names:
        raise ValueError("mode_fly is not preserved as a manager-active mode")

    uds = loaded["uds_flight_contracts"]
    mission_location_ids = {
        int(dependency["data"])
        for mission in uds.get("missions", [])
        if mission.get("source") == "data/Missions/locationinfo.txt"
        for dependency in mission.get("dependencies", [])
        if dependency.get("type") == "enter_location"
    }
    if mission_location_ids != location_ids:
        raise ValueError("location IDs differ from UDS locationinfo evidence")
    final = next((mission for mission in uds.get("missions", []) if mission.get("name") == "mecchifinal"), None)
    if final is None or not any(action.get("command") == "PLAY_OUTRO" for action in final.get("actions", [])):
        raise ValueError("mecchifinal PLAY_OUTRO evidence drifted")
    actions = loaded["mission_action_contracts"].get("actions", [])
    if not any(action.get("opcode") == "PLAY_OUTRO" for action in actions):
        raise ValueError("mission action PLAY_OUTRO contract drifted")

    spans = [
        (int(function["address"], 16), int(function["end"], 16))
        for function in loaded["native_function_index"].get("functions", [])
    ]
    addresses = [
        contract["manager"][key]
        for key in ("resolve_mode", "set_mode", "queue_mode", "activate_pending")
    ]
    addresses += [mode["constructor"] for mode in contract["modes"]]
    addresses += [
        mode["flight_marker_call"] for mode in contract["modes"]
        if mode["mode_type"] == "location"
    ]
    for edge in expanded_edges(contract) + contract["unresolved_edges"] + contract["debug_edges"]:
        addresses.append(edge["address"])
        addresses.extend(edge.get("alternate_addresses", []))
        addresses.extend(edge[field] for field in ("commit_address", "owner_address") if field in edge)
    addresses.extend(hook["address"] for hook in contract["required_native_hooks"])
    for value in addresses:
        address = int(value, 16)
        if not any(start <= address < end for start, end in spans):
            raise ValueError(f"contract address is outside native function index: {value}")


def validate_contract(
    contract: dict[str, Any], *, root: Path = ROOT, verify_artifacts: bool = True
) -> dict[str, Any]:
    if contract.get("schema") != 1:
        raise ValueError("unsupported native scene transition schema")
    policy = contract.get("policy", {})
    if (
        policy.get("manager_mode_count"),
        policy.get("core_mode_count"),
        policy.get("location_mode_count"),
    ) != (22, 4, 18):
        raise ValueError("mode inventory policy drifted")
    if policy.get("evidence_statuses") != ["PROVEN_STATIC", "NATIVE_TRACE_REQUIRED", "UNRESOLVED"]:
        raise ValueError("evidence status policy drifted")
    if policy.get("natural_parity_statuses") != ["PROVEN_STATIC"]:
        raise ValueError("natural parity policy must fail closed")
    if contract.get("manager") != MANAGER_CONTRACT:
        raise ValueError("native manager contract drifted")
    mode_names, location_ids = _validate_modes(contract)
    _validate_edge_policy(contract, mode_names)

    predicates = contract.get("predicates", {})
    for edge in expanded_edges(contract) + contract["unresolved_edges"]:
        if edge["predicate"] not in predicates and edge["id"] != "startup.login":
            raise ValueError(f"edge references unknown predicate: {edge['id']}")
    hooks = {hook.get("id"): hook for hook in contract.get("required_native_hooks", [])}
    if set(hooks) != {"location_departure_state", "generic_return_activator", "outro_callback"}:
        raise ValueError("required native hook inventory drifted")
    if hooks["location_departure_state"].get("address") != "0x00426570" \
            or hooks["generic_return_activator"].get("watch") != "active location +0x487c" \
            or hooks["outro_callback"].get("address") != "0x0043f770":
        raise ValueError("fail-closed native hook addresses drifted")
    if verify_artifacts:
        _validate_artifacts(contract, root, mode_names, location_ids)
    return contract


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    return validate_contract(json.loads(path.read_text(encoding="utf-8")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", nargs="?", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--check", action="store_true", help="validate without emitting data")
    args = parser.parse_args()
    contract = load_contract(args.contract)
    if not args.check:
        print(json.dumps({
            "manager_modes": len(contract["modes"]),
            "natural_candidates": len(expanded_edges(contract)),
            "parity_eligible": len(natural_parity_edges(contract)),
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
