#!/usr/bin/env python3
"""Validate fail-closed native scene-dispatch observer records.

This diagnostic channel describes native producer/UDSP-root calls only.  It is
deliberately ineligible for BODY and natural-transition parity promotion.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


PREFIX = "MVD "
PROTOCOL = "miel-vliegt-native-scene-dispatch"
HEX32 = re.compile(r"^0x[0-9a-f]{8}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]{1,95}$")
KINDS = {"DISPATCH", "ROOT_START", "ROOT_UPDATE"}
ROUTES = {"GROUND", "BARN", "FLIGHT"}
POLICY_STATUS = {
    "GENERIC": "NOT_SPECIAL",
    "GROTTE_REFUEL": "ROOT_AND_ARM_FLAG_SNAPSHOT",
    "RAYMOND_CHALLENGE": "RESULT_AND_FIRST_VISIT_SNAPSHOT",
    "EXHIBITION_SELECTOR": "OUTRO_FLAG_ONLY_PROJECTED_X_UNRESOLVED",
}
VTABLE_POLICY = {
    "0x0044d718": "GROTTE_REFUEL",
    "0x0044d7a0": "RAYMOND_CHALLENGE",
    "0x0044d948": "EXHIBITION_SELECTOR",
}
TOP_KEYS = {
    "schema", "protocol", "sequence", "evidence_scope",
    "natural_transition_evidence", "body_evidence", "observation_status",
    "call_id", "record_kind", "route", "object", "object_vtable", "root",
    "root_name", "root_name_status", "caller", "thread", "manager_thread",
    "manager_tick", "depth", "dt_f32_bits", "before", "after",
    "special_policy",
}
SNAPSHOT_KEYS = {
    "valid", "queue", "root_complete", "root_running", "root_current",
    "root_next",
}
SPECIAL_KEYS = {"policy", "semantic_status", "before", "after"}


class SceneDispatchTraceError(ValueError):
    """Raised when native scene-dispatch evidence violates its wire contract."""


def _exact_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 0xFFFFFFFF:
        raise SceneDispatchTraceError(f"{label} must be an unsigned 32-bit integer")
    return value


def _hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX32.fullmatch(value):
        raise SceneDispatchTraceError(f"{label} must be lowercase 0x + 8 hex digits")
    return value


def _snapshot(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SNAPSHOT_KEYS:
        raise SceneDispatchTraceError(f"{label} has a non-canonical shape")
    if type(value["valid"]) is not bool:
        raise SceneDispatchTraceError(f"{label}.valid must be boolean")
    queue = value["queue"]
    if not isinstance(queue, list) or len(queue) != 4:
        raise SceneDispatchTraceError(f"{label}.queue must contain four pointers")
    for index, pointer in enumerate(queue):
        _hex32(pointer, f"{label}.queue[{index}]")
    for key in ("root_complete", "root_running"):
        number = _exact_int(value[key], f"{label}.{key}")
        if number not in (0, 1):
            raise SceneDispatchTraceError(f"{label}.{key} must be 0 or 1")
    _hex32(value["root_current"], f"{label}.root_current")
    _hex32(value["root_next"], f"{label}.root_next")
    return value


def validate_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != TOP_KEYS:
        raise SceneDispatchTraceError("scene-dispatch record has a non-canonical shape")
    if value["schema"] != 1 or type(value["schema"]) is not int:
        raise SceneDispatchTraceError("scene-dispatch schema must be integer 1")
    if value["protocol"] != PROTOCOL:
        raise SceneDispatchTraceError("unexpected scene-dispatch protocol")
    if value["evidence_scope"] != "SCENE_DISPATCH_ONLY":
        raise SceneDispatchTraceError("scene-dispatch evidence scope is not isolated")
    if value["natural_transition_evidence"] is not False:
        raise SceneDispatchTraceError("scene-dispatch record claims natural-transition evidence")
    if value["body_evidence"] is not False:
        raise SceneDispatchTraceError("scene-dispatch record claims BODY evidence")
    if value["observation_status"] not in {"OBSERVED", "UNRESOLVED"}:
        raise SceneDispatchTraceError("invalid observation status")
    for key in ("sequence", "call_id", "thread", "manager_tick", "depth"):
        _exact_int(value[key], key)
    if type(value["manager_thread"]) is not bool:
        raise SceneDispatchTraceError("manager_thread must be boolean")
    for key in ("object", "object_vtable", "root", "caller", "dt_f32_bits"):
        _hex32(value[key], key)

    kind = value["record_kind"]
    route = value["route"]
    if kind not in KINDS:
        raise SceneDispatchTraceError("invalid record kind")
    if kind == "DISPATCH":
        if route not in ROUTES:
            raise SceneDispatchTraceError("dispatch record has no authoritative route")
    elif route is not None:
        raise SceneDispatchTraceError("UDSP root lifecycle record must have null route")

    name = value["root_name"]
    name_status = value["root_name_status"]
    if name_status == "RESOLVED":
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name):
            raise SceneDispatchTraceError("resolved root name is not structural")
    elif name_status == "UNRESOLVED":
        if name is not None:
            raise SceneDispatchTraceError("unresolved root name must be null")
    else:
        raise SceneDispatchTraceError("invalid root-name status")

    before = _snapshot(value["before"], "before")
    after = _snapshot(value["after"], "after")
    observed = before["valid"] and after["valid"]
    if (value["observation_status"] == "OBSERVED") != observed:
        raise SceneDispatchTraceError("observation status disagrees with snapshots")

    special = value["special_policy"]
    if not isinstance(special, dict) or set(special) != SPECIAL_KEYS:
        raise SceneDispatchTraceError("special-policy snapshot has a non-canonical shape")
    policy = special["policy"]
    if policy not in POLICY_STATUS or special["semantic_status"] != POLICY_STATUS[policy]:
        raise SceneDispatchTraceError("special-policy status is not fail-closed")
    expected_policy = VTABLE_POLICY.get(value["object_vtable"], "GENERIC")
    if policy != expected_policy:
        raise SceneDispatchTraceError("special policy disagrees with the pinned vtable")
    for phase in ("before", "after"):
        fields = special[phase]
        if not isinstance(fields, list) or len(fields) != 2:
            raise SceneDispatchTraceError(f"special_policy.{phase} must contain two values")
        for index, field in enumerate(fields):
            _hex32(field, f"special_policy.{phase}[{index}]")

    if observed and kind == "DISPATCH":
        root = value["root"]
        before_queue, after_queue = before["queue"], after["queue"]
        if route == "GROUND":
            if after_queue[1] == "0x00000000" or after_queue[1] == before_queue[1]:
                raise SceneDispatchTraceError("GROUND prepend did not publish a new tail node")
        elif route == "BARN":
            if after_queue[1] != root:
                raise SceneDispatchTraceError("BARN append did not make root the queue tail")
            expected_head = root if before_queue[0] == "0x00000000" else before_queue[0]
            if after_queue[0] != expected_head:
                raise SceneDispatchTraceError("BARN append changed the queue head incorrectly")
        elif after_queue[0] != root:
            raise SceneDispatchTraceError("FLIGHT replace did not install the requested root")
    if observed and kind == "ROOT_START" and after["root_running"] != 1:
        raise SceneDispatchTraceError("authoritative UDSP start did not arm the root")
    return value


def load_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith(PREFIX):
            continue
        try:
            candidate = json.loads(line[len(PREFIX):])
        except json.JSONDecodeError as error:
            raise SceneDispatchTraceError(f"line {line_number}: invalid MVD JSON") from error
        if isinstance(candidate, dict) and candidate.get("protocol") == PROTOCOL:
            try:
                records.append(validate_record(candidate))
            except SceneDispatchTraceError as error:
                raise SceneDispatchTraceError(f"line {line_number}: {error}") from error
    if not records:
        raise SceneDispatchTraceError("no native scene-dispatch records found")
    for expected, record in enumerate(records):
        if record["sequence"] != expected or record["call_id"] != expected:
            raise SceneDispatchTraceError("scene-dispatch sequence/call IDs are not contiguous")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    records = load_records(args.trace)
    observed = sum(record["observation_status"] == "OBSERVED" for record in records)
    print(json.dumps({
        "protocol": PROTOCOL,
        "records": len(records),
        "observed": observed,
        "unresolved": len(records) - observed,
        "parity_eligible": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
