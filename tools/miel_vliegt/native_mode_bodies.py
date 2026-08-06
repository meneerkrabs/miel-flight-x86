#!/usr/bin/env python3
"""Validate the static lifecycle/body map for all 22 native Miel Vliegt modes.

The contract identifies vtable entries that a future BODY observer may record.
It consumes checked-in analysis only, contains no executable bytes and never
turns a static address or constructor name into runtime-parity evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "content/miel_vliegt/native_mode_bodies.json"
EXECUTABLE_SHA256 = "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ADDRESS = re.compile(r"^0x[0-9a-f]{8}$")
PHASES = ("load", "open", "tick", "render", "close", "unload")
LIFECYCLE_SLOTS = {
    "is_open": "0x04",
    "open": "0x08",
    "close": "0x0c",
    "render": "0x10",
    "tick": "0x14",
    "is_loaded": "0x1c",
    "load": "0x20",
    "unload": "0x24",
}
REQUIRED_ARTIFACTS = {
    "native_function_index",
    "native_code_map",
    "native_scene_probe",
    "native_scene_transitions",
    "uds_scene_scripts",
}

# id: (vtable, load, open, tick, render, close, unload)
EXPECTED_BODIES = {
    "login": ("0x0044ce88", "0x00427e00", "0x00427d80", "0x00428880", "0x004283d0", "0x004072e0", "0x004282c0"),
    "barn": ("0x0044caec", "0x004156d0", "0x00416180", "0x004169a0", "0x00416370", "0x00416320", "0x00416000"),
    "flight": ("0x0044cf58", "0x0042be40", "0x0042b9a0", "0x0042ca10", "0x0042d6d0", "0x0042bdc0", "0x0042c400"),
    "credits": ("0x0044cb58", "0x0041b520", "0x0041b4e0", "0x0041b6f0", "0x0041b7c0", "0x0041b510", "0x0041b680"),
    "roy_mccoy": ("0x0044d828", "0x00442650", "0x00425170", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "sam_scribbler": ("0x0044d8b0", "0x00442ce0", "0x00425170", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "ture_tapp": ("0x0044d8f4", "0x00442ff0", "0x004434f0", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "atle_artillerist": ("0x0044d570", "0x0043fdf0", "0x00425170", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "viola_wallmark": ("0x0044da28", "0x00444e30", "0x00425170", "0x004452d0", "0x00445ce0", "0x00445ca0", "0x00445150"),
    "sampo_sanna": ("0x0044d86c", "0x00442910", "0x00440500", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "brejton_bord": ("0x0044d5b4", "0x004400f0", "0x00440500", "0x00440550", "0x00427300", "0x00425520", "0x00440460"),
    "grotte_grundlig": ("0x0044d718", "0x004414e0", "0x004417d0", "0x00440000", "0x00445ce0", "0x00425520", "0x004417b0"),
    "gabriella_gourmet": ("0x0044d6d4", "0x004411f0", "0x00444c20", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "richard_revers": ("0x0044d7e4", "0x00442370", "0x00425170", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "victor_vulcan": ("0x0044d9e4", "0x00444950", "0x00444c20", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "varldsutstallning": ("0x0044d948", "0x00443770", "0x00444090", "0x00440000", "0x004440c0", "0x004440b0", "0x00443c60"),
    "vermont_vrak": ("0x0044d994", "0x00444270", "0x00444580", "0x004445d0", "0x00427300", "0x00425520", "0x004259a0"),
    "fiona_falk": ("0x0044d690", "0x00440c80", "0x00440f60", "0x00440fa0", "0x00427300", "0x00425520", "0x004259a0"),
    "doris_digital": ("0x0044d608", "0x00440680", "0x00425170", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "raymond_rajser": ("0x0044d7a0", "0x00441d00", "0x00425170", "0x00440000", "0x00427300", "0x00425520", "0x00441f70"),
    "ernst_eremit": ("0x0044d64c", "0x00440930", "0x00425170", "0x00440000", "0x00427300", "0x00425520", "0x004259a0"),
    "mygghanget": ("0x0044d75c", "0x004419a0", "0x00441a60", "0x00441b20", "0x00427300", "0x00425520", "0x004259a0"),
}
EXPECTED_PROFILES = {
    "login": "LOGIN",
    "barn": "BARN",
    "flight": "FLIGHT",
    "credits": "CREDITS",
    "varldsutstallning": "EXHIBITION_LOCATION",
    "mygghanget": "MYGGHANGET_LOCATION",
}
EXPECTED_STATE_SCHEMAS = {
    "LOGIN": ["lifecycle", "login_submission"],
    "BARN": ["lifecycle", "barn_airplane"],
    "FLIGHT": ["lifecycle", "flight_terminal"],
    "CREDITS": ["lifecycle", "credits_terminal_unresolved"],
    "GENERIC_LOCATION": ["lifecycle", "location_common"],
    "EXHIBITION_LOCATION": ["lifecycle", "location_common", "exhibition_return"],
    "MYGGHANGET_LOCATION": ["lifecycle", "location_common", "mygghanget_return"],
}
MODE_FIELDS = {
    "id", "mode", "mode_type", "location_id", "constructor", "vtable",
    "loader_function", "lifecycle", "behavior_profile", "state_schema_ids",
    "def_root", "def_file_count", "static_summary", "runtime_body_equivalence",
    "parity_eligible",
}

# Set after canonical review of the complete `modes` array. This digest protects
# prose summaries and evidence boundaries in addition to the address constants.
EXPECTED_MODES_SHA256 = "25c56bf0982c01a351497859b712cd7b31fa8b2853956fa1872a33b78d8f28e5"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _artifact_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"artifact escapes repository root: {relative}") from error
    return path


def shared_lifecycle_entries(modes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for mode in modes:
        for phase in PHASES:
            grouped[(phase, mode["lifecycle"][phase])].append(mode["id"])
    return [
        {"phase": phase, "entry": entry, "modes": ids}
        for (phase, entry), ids in sorted(grouped.items())
        if len(ids) > 1
    ]


def _expanded_transition_edges(transitions: dict[str, Any]) -> list[dict[str, Any]]:
    edges = list(transitions.get("edges", []))
    for row in transitions.get("location_edges", []):
        edges.extend((row["landing"], row["departure"]))
    edges.extend(transitions.get("unresolved_edges", []))
    return edges


def _validate_engine(contract: dict[str, Any]) -> None:
    engine = contract.get("engine", {})
    if engine.get("lifecycle_vtable_slots") != LIFECYCLE_SLOTS:
        raise ValueError("mode lifecycle vtable slots drifted")
    if engine.get("base_state_fields") != {
        "loaded_u8": "0x14",
        "open_u8": "0x15",
    }:
        raise ValueError("mode lifecycle state fields drifted")
    if engine.get("is_open_entry") != "0x00406f70" or engine.get("is_loaded_entry") != "0x00406f80":
        raise ValueError("mode lifecycle predicate entries drifted")
    if engine.get("manager") != {
        "current_mode_offset": "0x18c",
        "pending_mode_offset": "0x190",
        "commit": "0x0041e4a0",
        "render_callback": "0x0041dbc0",
        "close_dispatch_site": "0x0041e4e9",
        "conditional_unload_dispatch_site": "0x0041e50a",
        "unload_skip_mode": "mode_fly",
    }:
        raise ValueError("mode manager lifecycle contract drifted")


def _validate_state_schemas(contract: dict[str, Any]) -> None:
    expected = {
        "lifecycle": {"evidence": "PROVEN_STATIC", "fields": {"loaded_u8": "0x14", "open_u8": "0x15"}},
        "login_submission": {"evidence": "PROVEN_STATIC", "fields": {"editing_u8": "0xd4"}, "terminal_values": {"lookup_blank": -1, "user_table_full": -2}},
        "barn_airplane": {"evidence": "PROVEN_STATIC", "fields": {"airplane_pointer": "0x160", "completion_from_airplane": "0x128"}, "terminal_values": {"complete": 511}},
        "flight_terminal": {"evidence": "PROVEN_STATIC", "fields": {"crash_started_u8": "0x48fd", "crash_return_armed_u8": "0x48fe", "crash_timer_f32": "0x4900", "pending_target": "0x47e4"}, "terminal_values": {"crash_timeout_seconds": 6.0}},
        "location_common": {"evidence": "PROVEN_STATIC", "fields": {"state_u32": "0x8dc", "return_to_barn_u8": "0x487c", "fade_phase_a_u8": "0x487d", "fade_phase_b_u8": "0x487e", "flight_departure_u8": "0x4890"}, "terminal_values": {"offscreen_departure_states": [0, 2, 3, 4, 5], "flight_state": 5, "return_timeout_seconds": 6.0}},
        "exhibition_return": {"evidence": "PROVEN_STATIC", "fields": {"outro_return_u8": "0x48ad"}, "terminal_values": {"barn_state_callback": 5, "outro_channel": 3, "barn_channel": 2}},
        "mygghanget_return": {"evidence": "PARTIAL_STATIC", "fields": {"state_u32": "0x8dc", "flight_departure_u8": "0x4890"}, "terminal_values": {"barn_state_callback": 6, "offscreen_state": 5}},
        "credits_terminal_unresolved": {"evidence": "UNRESOLVED", "fields": {}, "terminal_values": {}},
    }
    if contract.get("state_schemas") != expected:
        raise ValueError("mode state/terminal schemas drifted")


def _validate_capture_contract(contract: dict[str, Any]) -> None:
    expected = {
        "event_kind": "BODY",
        "required_fields": ["mode_id", "object", "vtable", "phase", "entry", "edge", "thread", "tick", "depth"],
        "edges": ["ENTER", "LEAVE"],
        "phases": ["CONSTRUCT", "LOAD", "OPEN", "TICK", "RENDER", "CLOSE", "UNLOAD"],
        "pairing": "Same mode_id/object/vtable/phase/entry/thread/tick/depth; ENTER precedes LEAVE.",
        "identity_rule": "vtable and entry must match the statically reviewed row; constructor observation proves CONSTRUCT only.",
        "promotion_rule": "A lifecycle phase is observed only after a paired original-thread ENTER/LEAVE; static address presence never promotes runtime parity.",
        "mode_fly_unload_rule": "Manager commit statically skips slot +0x24 when the outgoing name equals mode_fly; only an actual paired UNLOAD may claim another route invoked it.",
    }
    if contract.get("body_capture") != expected:
        raise ValueError("BODY capture contract drifted")


def _validate_modes(
    contract: dict[str, Any], transitions: dict[str, Any], probe: dict[str, Any], uds: dict[str, Any]
) -> None:
    modes = contract.get("modes")
    transition_modes = transitions.get("modes", [])
    if not isinstance(modes, list) or len(modes) != 22:
        raise ValueError("mode body inventory must contain exactly 22 modes")
    if [row.get("id") for row in modes] != [row.get("id") for row in transition_modes]:
        raise ValueError("mode body order differs from transition inventory")

    probe_by_id = {row["id"]: row for row in probe.get("scenes", [])}
    uds_by_id = {row["id"]: row for row in uds.get("scenes", [])}
    edges = _expanded_transition_edges(transitions)
    transition_names = {row["id"]: row["mode"] for row in transition_modes}

    for row, transition in zip(modes, transition_modes):
        mode_id = row["id"]
        if set(row) != MODE_FIELDS:
            raise ValueError(f"mode body fields drifted: {mode_id}")
        body = EXPECTED_BODIES.get(mode_id)
        if body is None:
            raise ValueError(f"unreviewed mode body: {mode_id}")
        if row["vtable"] != body[0] or tuple(row["lifecycle"][phase] for phase in PHASES) != body[1:]:
            raise ValueError(f"mode lifecycle addresses drifted: {mode_id}")
        if set(row["lifecycle"]) != set(PHASES):
            raise ValueError(f"mode lifecycle phase set drifted: {mode_id}")
        for key in ("mode", "mode_type", "constructor"):
            if row[key] != transition[key]:
                raise ValueError(f"mode body differs from transition {key}: {mode_id}")
        expected_location = transition.get("location_id")
        if row["location_id"] != expected_location:
            raise ValueError(f"mode body location ID drifted: {mode_id}")

        probe_row = probe_by_id.get(mode_id)
        expected_loader = probe_row["loader"] if probe_row else None
        if row["loader_function"] != expected_loader:
            raise ValueError(f"mode loader function differs from probe: {mode_id}")
        if probe_row and (probe_row["constructor"] != row["constructor"] or probe_row["mode"] != row["mode"]):
            raise ValueError(f"mode constructor identity differs from probe: {mode_id}")

        scene = uds_by_id.get(mode_id)
        expected_root = f"data/Scripts/Locations/{mode_id}" if scene else None
        expected_count = len(scene["script_paths"]) if scene else 0
        if mode_id == "barn":
            scene = uds_by_id.get("barn")
            expected_root = "data/Scripts/Locations/barn"
            expected_count = len(scene["script_paths"]) if scene else 0
        if row["def_root"] != expected_root or row["def_file_count"] != expected_count:
            raise ValueError(f"mode DEF-root linkage drifted: {mode_id}")
        if scene and any(not path.startswith(expected_root + "/") for path in scene["script_paths"]):
            raise ValueError(f"mode DEF scripts escape their root: {mode_id}")

        profile = EXPECTED_PROFILES.get(mode_id, "GENERIC_LOCATION")
        if row["behavior_profile"] != profile or row["state_schema_ids"] != EXPECTED_STATE_SCHEMAS[profile]:
            raise ValueError(f"mode behavior/state profile drifted: {mode_id}")
        if row["runtime_body_equivalence"] != "UNPROVEN" or row["parity_eligible"] is not False:
            raise ValueError(f"mode body escaped fail-closed parity policy: {mode_id}")
        if not isinstance(row["static_summary"], str) or not row["static_summary"]:
            raise ValueError(f"mode body static summary missing: {mode_id}")

        outgoing = [edge for edge in edges if edge.get("source") == transition_names[mode_id]]
        if profile == "GENERIC_LOCATION" and not any(edge["id"] == f"location.departure.{row['mode']}" for edge in outgoing):
            raise ValueError(f"generic location has no departure contract: {mode_id}")

    digest = canonical_sha256(modes)
    if contract.get("reviewed_modes_sha256") != digest or digest != EXPECTED_MODES_SHA256:
        raise ValueError("digest-locked mode body summaries drifted")
    if contract.get("shared_lifecycle_entries") != shared_lifecycle_entries(modes):
        raise ValueError("shared versus mode-specific lifecycle grouping drifted")


def _validate_artifacts(contract: dict[str, Any], root: Path) -> dict[str, Any]:
    source = contract.get("source", {})
    if source.get("executable_sha256") != EXECUTABLE_SHA256:
        raise ValueError("mode body contract belongs to another executable")
    artifacts = source.get("artifacts", {})
    if set(artifacts) != REQUIRED_ARTIFACTS:
        raise ValueError("mode body artifact pins drifted")
    loaded: dict[str, Any] = {}
    for name, pin in artifacts.items():
        if set(pin) != {"path", "sha256"} or not SHA256.fullmatch(pin.get("sha256", "")):
            raise ValueError(f"invalid mode body artifact pin: {name}")
        path = _artifact_path(root, pin["path"])
        if not path.is_file() or sha256_file(path) != pin["sha256"]:
            raise ValueError(f"pinned mode body artifact drifted: {name}")
        loaded[name] = json.loads(path.read_text(encoding="utf-8"))
    for name in ("native_function_index", "native_code_map"):
        if loaded[name].get("source", {}).get("sha256") != EXECUTABLE_SHA256:
            raise ValueError(f"{name} belongs to another executable")
    if loaded["native_scene_probe"].get("source", {}).get("executable_sha256") != EXECUTABLE_SHA256:
        raise ValueError("native scene probe belongs to another executable")
    if loaded["native_scene_transitions"].get("source", {}).get("executable_sha256") != EXECUTABLE_SHA256:
        raise ValueError("native scene transitions belong to another executable")

    index = loaded["native_function_index"]
    spans = [(int(row["address"], 16), int(row["end"], 16)) for row in index.get("functions", [])]
    sections = [
        (int(row["address"], 16), int(row["address"], 16) + row["virtual_size"], row["executable"])
        for row in index.get("sections", [])
    ]
    for mode in contract["modes"]:
        for value in [mode["constructor"], *mode["lifecycle"].values()]:
            address = int(value, 16)
            if not any(start <= address < end for start, end in spans):
                raise ValueError(f"mode body address outside native function index: {mode['id']} {value}")
        vtable = int(mode["vtable"], 16)
        if not any(start <= vtable < end and not executable for start, end, executable in sections):
            raise ValueError(f"mode vtable outside native data sections: {mode['id']}")
    return loaded


def validate_contract(
    contract: dict[str, Any], *, root: Path = ROOT, verify_artifacts: bool = True
) -> dict[str, Any]:
    if contract.get("schema") != 1 or contract.get("claim") != "STATIC_MODE_BODY_MAP_COMPLETE_RUNTIME_UNPROVEN":
        raise ValueError("unsupported native mode body contract")
    if contract.get("policy") != {
        "mode_count": 22,
        "core_mode_count": 4,
        "location_mode_count": 18,
        "runtime_body_equivalence": "UNPROVEN",
        "parity_promotion_requires": "PAIRED_REVIEWED_NATIVE_BODY_TRACE",
    }:
        raise ValueError("mode body fail-closed policy drifted")
    _validate_engine(contract)
    _validate_state_schemas(contract)
    _validate_capture_contract(contract)
    if verify_artifacts:
        loaded = _validate_artifacts(contract, root)
    else:
        source = contract["source"]["artifacts"]
        loaded = {
            name: json.loads(_artifact_path(root, source[name]["path"]).read_text(encoding="utf-8"))
            for name in ("native_scene_transitions", "native_scene_probe", "uds_scene_scripts")
        }
    _validate_modes(
        contract,
        loaded["native_scene_transitions"],
        loaded["native_scene_probe"],
        loaded["uds_scene_scripts"],
    )
    if contract.get("unresolved") != [
        "The original dispatch site that invokes every mode tick/render entry outside the reviewed manager gates.",
        "Credits terminal state fields and the exact shutdown completion predicate.",
        "Mode-specific branches below each lifecycle entry until BODY traces exercise them.",
        "Lifecycle/vtable identities for other language executables until separately fingerprinted.",
    ]:
        raise ValueError("mode body unresolved boundary drifted")
    return contract


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    return validate_contract(json.loads(path.read_text(encoding="utf-8")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", nargs="?", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    contract = load_contract(args.contract)
    if not args.check:
        print(json.dumps({
            "modes": len(contract["modes"]),
            "shared_entries": len(contract["shared_lifecycle_entries"]),
            "body_trace_promoted": sum(row["parity_eligible"] for row in contract["modes"]),
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
