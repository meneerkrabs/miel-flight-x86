#!/usr/bin/env python3
"""Extract the shared native location state machine from a pinned PE32 image.

The extractor intentionally follows instruction shapes and PE pointers instead
of treating addresses from one language edition as source truth.  Addresses in
the emitted receipt are evidence for the supplied executable only; runtime
parity remains a separate native-trace obligation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.native_mygghanget_contract import (
        PeImage, _address, _find_unique, _u32, _window,
    )
except ModuleNotFoundError:  # Direct script execution.
    from native_mygghanget_contract import PeImage, _address, _find_unique, _u32, _window


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/native_common_location_state_machine.json"
DEFAULT_MODE_BODIES = ROOT / "content/miel_vliegt/native_mode_bodies.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hex(value: int) -> str:
    return f"0x{value:08x}"


def _read_u32(image: PeImage, address: int) -> int:
    return _u32(image.data, image.address_to_offset(address))


def _direct_calls(image: PeImage, target: int) -> list[int]:
    calls: list[int] = []
    for section in image.sections:
        if not int(section["flags"]) & 0x20000000:
            continue
        start = int(section["rawOffset"])
        raw = image.data[start:start + int(section["rawSize"])]
        base = int(section["address"])
        for index in range(0, len(raw) - 4):
            if raw[index] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", raw, index + 1)[0]
            if base + index + 5 + displacement == target:
                calls.append(base + index)
    return calls


def _call_target(image: PeImage, callsite: int) -> int:
    offset = image.address_to_offset(callsite)
    if image.data[offset] != 0xE8:
        raise ValueError(f"expected direct call at {_hex(callsite)}")
    return callsite + 5 + struct.unpack_from("<i", image.data, offset + 1)[0]


def _calls_in_range(image: PeImage, start: int, size: int) -> list[int]:
    offset = image.address_to_offset(start)
    raw = image.data[offset:offset + size]
    return [start + index for index in range(len(raw) - 4) if raw[index] == 0xE8]


def _push_immediate_before(image: PeImage, callsite: int, lookback: int = 16) -> int | None:
    offset = image.address_to_offset(callsite)
    for cursor in range(offset - 5, offset - lookback - 1, -1):
        if image.data[cursor] == 0x68:
            return _u32(image.data, cursor + 1)
    return None


def _nearest_owner(callsite: int, entries: list[int], limit: int) -> int:
    candidates = [entry for entry in entries if 0 <= callsite - entry <= limit]
    if not candidates:
        raise ValueError(f"no lifecycle owner for native callsite {_hex(callsite)}")
    return max(candidates)


def _table(image: PeImage, address: int) -> list[str]:
    return [_hex(_read_u32(image, address + index * 4)) for index in range(8)]


def _jump_table(image: PeImage, address: int) -> dict[str, Any]:
    return {
        "address": _hex(address),
        "targets": _table(image, address),
        "receipt": _window(image, image.address_to_offset(address), 32),
    }


def _state_references(image: PeImage) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for section in image.sections:
        if not int(section["flags"]) & 0x20000000:
            continue
        start = int(section["rawOffset"])
        raw = image.data[start:start + int(section["rawSize"])]
        base = int(section["address"])
        for index in range(len(raw) - 9):
            tail = raw[index + 2:index + 6]
            if tail != b"\xdc\x08\x00\x00":
                continue
            opcode = raw[index:index + 2]
            if opcode == b"\x8b\x86":
                refs.append({"address": _hex(base + index), "operation": "read"})
            elif opcode == b"\x89\x86":
                refs.append({"address": _hex(base + index), "operation": "write"})
            elif opcode == b"\x39\xbe":
                refs.append({"address": _hex(base + index), "operation": "compare"})
            elif opcode == b"\x83\xbe" and raw[index + 6] == 6:
                refs.append({
                    "address": _hex(base + index), "operation": "compare_immediate",
                    "value": 6,
                })
    refs.sort(key=lambda row: int(row["address"], 16))
    return refs


def _state_setter_calls(
    image: PeImage, start: int, end: int, jump_targets: list[int], predicates: dict[tuple[int, int], str]
) -> list[dict[str, Any]]:
    """Recover virtual state-setter calls and bind them to their dispatch case."""
    offset = image.address_to_offset(start)
    raw = image.data[offset:image.address_to_offset(end)]
    state_by_target = {target: state for state, target in enumerate(jump_targets)}
    sorted_targets = sorted(state_by_target)
    edges: list[dict[str, Any]] = []
    for index in range(len(raw) - 9):
        if raw[index:index + 2] not in (b"\x8b\x06", b"\x8b\x16"):
            continue
        size = 0
        target_state = -1
        if raw[index + 2] == 0x53 \
                and raw[index + 3:index + 5] == b"\x8b\xce" \
                and raw[index + 5:index + 8] in (b"\xff\x50\x34", b"\xff\x52\x34"):
            size, target_state = 8, 0
        elif raw[index + 2] == 0x6A \
                and raw[index + 4:index + 6] == b"\x8b\xce" \
                and raw[index + 6:index + 9] in (b"\xff\x50\x34", b"\xff\x52\x34"):
            size, target_state = 9, raw[index + 3]
        if not size:
            continue
        site = start + index
        case_targets = [target for target in sorted_targets if target <= site]
        if not case_targets:
            raise ValueError(f"state setter call {_hex(site)} precedes every dispatch case")
        source_state = state_by_target[max(case_targets)]
        predicate = predicates.get((source_state, target_state))
        if predicate is None:
            raise ValueError(
                f"unreviewed state transition {source_state}->{target_state} at {_hex(site)}"
            )
        edges.append({
            "source": source_state,
            "target": target_state,
            "callsite": _hex(site),
            "predicate": predicate,
            "receipt": _window(image, image.address_to_offset(site), size),
            "runtime_parity": "NATIVE_TRACE_REQUIRED",
        })
    return edges


def extract_contract(executable: Path, mode_bodies_path: Path = DEFAULT_MODE_BODIES) -> dict[str, Any]:
    image = PeImage(executable)
    mode_bodies = json.loads(mode_bodies_path.read_text(encoding="utf-8"))
    executable_sha = _sha256(executable)
    if mode_bodies.get("source", {}).get("executable_sha256") != executable_sha:
        raise ValueError("native mode bodies and executable identities differ")

    update_off = _find_unique(
        image, "common location update",
        "81 ec 08 01 00 00 53 55 56 8b f1 57 8b 06 ff 50 04 84 c0 0f 84 ?? ?? ?? ??",
    )
    update = image.offset_to_address(update_off)
    update_dispatch_off = _find_unique(
        image, "common update dispatch",
        "8b 86 dc 08 00 00 8b ac 24 1c 01 00 00 83 f8 07 0f 87 ?? ?? ?? ?? ff 24 85 ?? ?? ?? ??",
    )
    setter_off = _find_unique(
        image, "common location state setter",
        "8b 44 24 04 81 ec 80 00 00 00 83 f8 07 53 55 56 8b f1 57 89 86 dc 08 00 00 0f 87 ?? ?? ?? ?? ff 24 85 ?? ?? ?? ??",
    )
    render_dispatch_off = _find_unique(
        image, "common render dispatch",
        "8b 86 dc 08 00 00 83 f8 07 0f 87 ?? ?? ?? ?? ff 24 85 ?? ?? ?? ?? 8b 46 54 85 c0",
    )
    update_dispatch = image.offset_to_address(update_dispatch_off)
    setter = image.offset_to_address(setter_off)
    render_dispatch = image.offset_to_address(render_dispatch_off)
    update_table = _u32(image.data, update_dispatch_off + 25)
    setter_table = _u32(image.data, setter_off + 34)
    render_table = _u32(image.data, render_dispatch_off + 18)

    flight = next((row for row in mode_bodies["modes"] if row["id"] == "flight"), None)
    if flight is None or flight.get("mode") != "mode_fly":
        raise ValueError("native mode bodies contain no unique mode_fly lifecycle")
    flight_tick = int(flight["lifecycle"]["tick"], 16)
    flight_render = int(flight["lifecycle"]["render"], 16)
    flight_vtable = int(flight["vtable"], 16)
    if _read_u32(image, flight_vtable + 0x14) != flight_tick \
            or _read_u32(image, flight_vtable + 0x10) != flight_render:
        raise ValueError("mode_fly tick/render differ from their PE vtable slots")
    if update in {int(value, 16) for value in flight["lifecycle"].values()}:
        raise ValueError("common location controller was conflated with mode_fly lifecycle")

    locations = [row for row in mode_bodies["modes"] if row["mode_type"] == "location"]
    if len(locations) != 18:
        raise ValueError("native mode body inventory no longer has 18 locations")
    tick_entries = sorted({int(row["lifecycle"]["tick"], 16) for row in locations})
    setter_entries = sorted({_read_u32(image, int(row["vtable"], 16) + 0x34) for row in locations})
    update_calls = _direct_calls(image, update)
    setter_calls = _direct_calls(image, setter)
    tick_calls = {entry: [] for entry in tick_entries}
    for callsite in update_calls:
        tick_calls[_nearest_owner(callsite, tick_entries, 0xA00)].append(callsite)
    setter_reentry = {entry: [] for entry in setter_entries}
    for callsite in setter_calls:
        try:
            owner = _nearest_owner(callsite, setter_entries, 0x400)
        except ValueError:
            continue
        setter_reentry[owner].append(callsite)

    reachability = []
    for row in locations:
        tick = int(row["lifecycle"]["tick"], 16)
        state_setter = _read_u32(image, int(row["vtable"], 16) + 0x34)
        calls = tick_calls[tick]
        if not calls or not (state_setter == setter or setter_reentry[state_setter]):
            raise ValueError(f"location does not reach both common routines: {row['mode']}")
        reachability.append({
            "id": row["id"], "mode": row["mode"], "location_id": row["location_id"],
            "tick_entry": _hex(tick), "update_callsites": [_hex(value) for value in calls],
            "state_setter_entry": _hex(state_setter),
            "common_setter_callsites": (
                [_hex(state_setter)] if state_setter == setter
                else [_hex(value) for value in setter_reentry[state_setter]]
            ),
        })

    update_end = update + 0xA98
    update_raw = image.data[update_off:image.address_to_offset(update_end)]
    immediate_call_groups: dict[tuple[int, int], list[int]] = {}
    for index in range(5, len(update_raw) - 4):
        if update_raw[index] != 0xE8 or update_raw[index - 5] != 0x68:
            continue
        callsite = update + index
        key = (_u32(update_raw, index - 4), _call_target(image, callsite))
        immediate_call_groups.setdefault(key, []).append(callsite)
    departure_groups = [
        (key, sites) for key, sites in immediate_call_groups.items() if len(sites) == 5
    ]
    if len(departure_groups) != 1:
        raise ValueError("common location flight-departure call shape is ambiguous")
    (flight_mode_descriptor, manager_set_mode), flight_departures = departure_groups[0]
    if len(flight_departures) != 5:
        raise ValueError("common location flight-departure inventory drifted")
    set_mode_calls = _direct_calls(image, manager_set_mode)
    barn_candidates = [
        site for site in set_mode_calls
        if update <= site < update_end and site not in flight_departures
        and _push_immediate_before(image, site, 8) is not None
    ]
    if len(barn_candidates) != 1:
        raise ValueError("generic common barn return callsite drifted")
    generic_barn = barn_candidates[0]
    barn_mode_descriptor = _push_immediate_before(image, generic_barn, 8)

    lifecycle_entries = sorted(set(tick_entries + setter_entries))
    specialized_barn: list[int] = []
    for site in set_mode_calls:
        if site == generic_barn or _push_immediate_before(image, site) != barn_mode_descriptor:
            continue
        try:
            _nearest_owner(site, lifecycle_entries, 0x400)
        except ValueError:
            continue
        specialized_barn.append(site)
    if len(specialized_barn) != 3:
        raise ValueError("specialized location barn-return inventory drifted")

    pending_setter_off = _find_unique(
        image, "flight pending-target producer",
        "8b 44 24 04 56 85 c0 8b f1 74 ?? 80 38 00 74 ?? 8b 4e 54 50 c6 86 e4 47 00 00 01 e8 ?? ?? ?? ?? 8b 4e 64 89 86 e0 47 00 00",
    )
    pending_commit_off = _find_unique(
        image, "flight pending-target commit",
        "53 56 8b f1 33 db 8b 4e 64 3b cb 74 05 8b 01 ff 50 0c 39 5e 54 74 ?? 8b 8e e0 47 00 00",
    )
    pending_setter = image.offset_to_address(pending_setter_off)
    pending_commit = image.offset_to_address(pending_commit_off)
    landing_marker_off = _find_unique(
        image, "landing marker producer owner",
        "83 ec 30 56 8b f1 8b 46 0c 85 c0 0f 84 ?? ?? ?? ?? 8b 48 04 85 c9 0f 84 ?? ?? ?? ??",
    )
    producer_calls = _direct_calls(image, pending_setter)
    commit_calls = _direct_calls(image, pending_commit)
    pending_commit_calls = _calls_in_range(image, pending_commit, 116)
    queue_commits = pending_commit_calls[-1:]
    landing_marker = image.offset_to_address(landing_marker_off)
    marker_producers = [site for site in producer_calls if landing_marker <= site < landing_marker + 587]
    crash_producers = [site for site in producer_calls if site not in marker_producers]
    if len(marker_producers) != 1 or len(crash_producers) != 1:
        raise ValueError("flight pending-target producer roles drifted")
    if len(queue_commits) != 1:
        raise ValueError("flight pending-target manager commit drifted")

    raymond = next(row for row in reachability if row["id"] == "raymond_rajser")
    raymond_off = image.address_to_offset(int(raymond["state_setter_entry"], 16))
    raymond_bytes = image.data[raymond_off:raymond_off + 0xC0]
    if b"\x6a\x0b" not in raymond_bytes:
        raise ValueError("Raymond stored state 11 path drifted")
    state11_site = int(raymond["state_setter_entry"], 16) + raymond_bytes.index(b"\x6a\x0b")

    refs = _state_references(image)
    read_addresses = {
        int(row["address"], 16) for row in refs if row["operation"] == "read"
    }
    if len(refs) != 7 \
            or sum(row["operation"] == "write" for row in refs) != 1 \
            or len(read_addresses) != 3 \
            or not {update_dispatch, render_dispatch} <= read_addresses:
        raise ValueError("direct +0x8dc reference inventory drifted")

    update_targets = [_read_u32(image, update_table + index * 4) for index in range(8)]
    setter_targets = [_read_u32(image, setter_table + index * 4) for index in range(8)]
    update_predicates = {
        (0, 2): "actor active(+0x1d0) and actor y passes threshold(+0x1d4)",
        (2, 6): "speed < 0.2 and absolute approach axis > 0.95",
        (2, 0): "actor inactive or actor-height threshold return branch",
        (2, 4): "aircraft x/z crosses a configured location boundary",
        (3, 0): "actor-height plus native margin passes return comparison",
        (4, 0): "actor-height plus native margin passes return comparison",
        (5, 4): "aircraft x/z crosses a configured location boundary",
        (5, 0): "actor inactive or actor-height threshold return branch",
        (6, 5): "common-location scene-root queue(+0x8c8) is drained",
        (7, 5): "fuel aggregate reaches zero after optional handle cleanup",
    }
    setter_predicates = {
        (2, 4): "aircraft x/z crosses a configured location boundary during setter re-entry",
        (2, 3): "manual camera byte(+0x9b0) equals zero during setter re-entry",
    }
    update_edges = _state_setter_calls(
        image, update, update_table - 4, update_targets, update_predicates,
    )
    setter_edges = _state_setter_calls(
        image, setter, setter_table - 4, setter_targets, setter_predicates,
    )
    if [(row["source"], row["target"]) for row in update_edges] != [
        (0, 2), (2, 6), (2, 0), (2, 4), (4, 0), (3, 0),
        (5, 4), (5, 0), (6, 5), (7, 5),
    ]:
        raise ValueError("common location update transition graph drifted")
    if [(row["source"], row["target"]) for row in setter_edges] != [(2, 4), (2, 3)]:
        raise ValueError("common location setter re-entry graph drifted")

    return {
        "schema": 1,
        "contract_id": "miel-vliegt-native-common-location-state-machine-v1",
        "source": {
            "executable_sha256": executable_sha,
            "image_base": _hex(image.image_base),
            "location_identity_input": str(mode_bodies_path.relative_to(ROOT)),
            "location_identity_rule": "same executable SHA-256; identities only, no cyclic artifact pin",
        },
        "policy": {
            "edition_binding": "PE_INSTRUCTION_SHAPES_AND_POINTERS",
            "static_evidence": "PROVEN_STATIC",
            "runtime_parity": "NATIVE_TRACE_REQUIRED",
        },
        "state": {
            "object_offset": "0x8dc", "common_dispatch_domain": {"minimum": 0, "maximum": 7},
            "stored_domain_extension": {
                "value": 11, "owner": "mode_raymondrajser", "push_site": _hex(state11_site),
                "effect": "stored by the common setter; common update/render bounds-skip it",
            },
            "direct_references": refs,
        },
        "semantic_boundaries": {
            "common_location_controller_update": _hex(update),
            "mode_fly": {
                "vtable": _hex(flight_vtable),
                "tick": _hex(flight_tick),
                "render": _hex(flight_render),
            },
            "invariant": "COMMON_LOCATION_CONTROLLER_IS_NOT_MODE_FLY_LIFECYCLE",
            "all_entries_distinct": len({update, flight_tick, flight_render}) == 3,
            "runtime_parity": "NATIVE_TRACE_REQUIRED",
        },
        "routines": {
            "update": {
                "entry": _hex(update),
                "semantic_role": "common_location_controller_update",
                "prologue_receipt": _window(image, update_off, 32),
                "dispatch_receipt": _window(image, update_dispatch_off, 29),
                "jump_table": _jump_table(image, update_table),
            },
            "setter": {
                "entry": _hex(setter), "prologue_receipt": _window(image, setter_off, 32),
                "jump_table": _jump_table(image, setter_table),
                "store_before_bounds_check": True,
            },
            "render": {
                "dispatch_entry": _hex(render_dispatch),
                "dispatch_receipt": _window(image, render_dispatch_off, 21),
                "jump_table": _jump_table(image, render_table),
            },
        },
        "reachability": {"locations": reachability, "location_count": len(reachability)},
        "transition_graph": {
            "update_edges": update_edges,
            "setter_reentry_edges": setter_edges,
            "runtime_parity": "NATIVE_TRACE_REQUIRED",
        },
        "transitions": {
            "flight_departure": {
                "owner_routine": _hex(update),
                "commit_callsites": [_hex(site) for site in flight_departures],
                "manager_set_mode": _hex(manager_set_mode),
                "target_mode_descriptor": _hex(flight_mode_descriptor),
            },
            "barn_returns": {
                "target_mode_descriptor": _hex(barn_mode_descriptor),
                "generic_common_callsite": _hex(generic_barn),
                "specialized_callsites": [_hex(site) for site in specialized_barn],
            },
            "pending_target": {
                "producer_routine": {"entry": _hex(pending_setter), "receipt": _window(image, pending_setter_off, 71)},
                "producer_callsites": [_hex(site) for site in producer_calls],
                "commit_routine": {"entry": _hex(pending_commit), "receipt": _window(image, pending_commit_off, 116)},
                "commit_routine_callsites": [_hex(site) for site in commit_calls],
                "manager_queue_commit": _hex(queue_commits[0]),
                "landing_marker": {
                    "routine": _window(image, landing_marker_off, 587),
                    "producer_callsite": _hex(marker_producers[0]),
                },
                "landing_marker_producer": _hex(marker_producers[0]),
                "crash_producer": _hex(crash_producers[0]),
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--mode-bodies", type=Path, default=DEFAULT_MODE_BODIES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    contract = extract_contract(args.executable, args.mode_bodies)
    encoded = json.dumps(contract, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != encoded:
            raise SystemExit(f"generated contract drifted: {args.output}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
