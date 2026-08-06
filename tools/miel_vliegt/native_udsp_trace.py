#!/usr/bin/env python3
"""Fail-closed validation for native UDSP command lifecycle records."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


PROTOCOL = "miel-vliegt-native-udsp-command"
CHANNEL = "MVU "
DISPATCHER = "0x0043c580"
PHASES = ("BEFORE", "AFTER")
AFTER_OUTCOMES = ("STARTED", "ACTIVE", "COMPLETE")
FIELDS = frozenset({
    "schema", "protocol", "sequence", "evidence_scope",
    "natural_transition_evidence", "call_id", "phase", "thread", "tick",
    "depth", "dispatcher", "parser_case", "handler_case", "composite",
    "node", "opcode_id", "opcode_name", "dt_f32_bits", "complete",
    "started", "modifier", "timer_f32_bits", "context", "next",
    "callback", "payload", "parent_complete", "parent_current", "advanced",
    "outcome",
})
_ADDRESS = re.compile(r"^0x[0-9a-f]{8}$")
_CONTRACT = (
    Path(__file__).resolve().parents[2]
    / "content/miel_vliegt/native_udsp_scene_commands.json"
)


class UdspTraceError(ValueError):
    pass


def _load_observed_commands(
    contract_path: Path = _CONTRACT,
) -> dict[int, dict[str, str]]:
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UdspTraceError(f"cannot load UDSP command contract: {error}") from error
    if not isinstance(contract, dict) or contract.get("schema") != 1 \
            or contract.get("claim") != "STATIC_CONTROL_FLOW_COMPLETE_SEMANTICS_PARTIAL":
        raise UdspTraceError("invalid edition UDSP command contract")
    commands = contract.get("commands")
    policy = contract.get("policy")
    if not isinstance(commands, list) or not isinstance(policy, dict):
        raise UdspTraceError("invalid edition UDSP command contract")
    registered_count = policy.get("registered_command_count")
    if type(registered_count) is not int or registered_count <= 0 \
            or registered_count != len(commands):
        raise UdspTraceError("observed opcode inventory differs from edition contract")
    observed: dict[int, dict[str, str]] = {}
    registered: set[int] = set()
    unobserved = []
    names: set[str] = set()
    for command in commands:
        if not isinstance(command, dict):
            raise UdspTraceError("invalid observed opcode registry")
        opcode_id = command.get("id")
        name = command.get("name")
        if type(opcode_id) is not int or opcode_id <= 0 or opcode_id in registered \
                or not isinstance(name, str) or not name or name in names:
            raise UdspTraceError("invalid observed opcode registry")
        registered.add(opcode_id)
        names.add(name)
        observation = command.get("def_observation", {})
        occurrences = observation.get("occurrences")
        evidence = observation.get("evidence")
        if type(occurrences) is not int or occurrences < 0:
            raise UdspTraceError("invalid observed opcode registry")
        if occurrences == 0:
            if evidence != "NOT_OBSERVED_IN_PINNED_DEF":
                raise UdspTraceError("observed opcode inventory differs from edition contract")
            unobserved.append(opcode_id)
            continue
        if evidence != "OBSERVED_DEF":
            raise UdspTraceError("observed opcode inventory differs from edition contract")
        parser_case = command.get("parser_case_address")
        handler_case = command.get("handler_case_address")
        if not isinstance(parser_case, str) or not _ADDRESS.fullmatch(parser_case) \
                or not isinstance(handler_case, str) or not _ADDRESS.fullmatch(handler_case):
            raise UdspTraceError("invalid observed opcode registry")
        observed[opcode_id] = {
            "name": name,
            "parser_case": parser_case,
            "handler_case": handler_case,
        }
    if registered != set(range(1, registered_count + 1)) \
            or policy.get("observed_def_command_count") != len(observed) \
            or policy.get("unobserved_registered_ids") != unobserved \
            or policy.get("semantic_equivalence_status") != "UNPROVEN":
        raise UdspTraceError("observed opcode inventory differs from edition contract")
    return observed


OBSERVED_COMMANDS = _load_observed_commands()


def parse_records(lines) -> list[dict]:
    records = []
    for line_number, line in enumerate(lines, 1):
        if not line.startswith(CHANNEL):
            continue
        try:
            value = json.loads(line[len(CHANNEL):])
        except json.JSONDecodeError as error:
            raise UdspTraceError(
                f"line {line_number}: invalid JSON: {error.msg}"
            ) from error
        if not isinstance(value, dict):
            raise UdspTraceError(f"line {line_number}: record is not an object")
        records.append(value)
    return records


def _address(record: dict, field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise UdspTraceError(f"{field} is not a canonical address")
    return value


def _bool(record: dict, field: str) -> bool:
    value = record.get(field)
    if type(value) is not bool:
        raise UdspTraceError(f"{field} is not boolean")
    return value


def _uint(record: dict, field: str) -> int:
    value = record.get(field)
    if type(value) is not int or value < 0 or value > 0xFFFFFFFF:
        raise UdspTraceError(f"{field} is not a uint32")
    return value


def _validate_record(record: dict, expected_sequence: int) -> None:
    if frozenset(record) != FIELDS:
        raise UdspTraceError("record fields do not match the UDSP schema")
    if record.get("schema") != 1 or record.get("protocol") != PROTOCOL:
        raise UdspTraceError("record does not use the UDSP protocol")
    if record.get("sequence") != expected_sequence:
        raise UdspTraceError("UDSP sequence is not contiguous")
    if (
        record.get("evidence_scope") != "UDSP_ONLY"
        or record.get("natural_transition_evidence") is not False
    ):
        raise UdspTraceError("record violates the UDSP-only evidence boundary")
    phase = record.get("phase")
    if phase not in PHASES:
        raise UdspTraceError("unknown UDSP phase")
    opcode_id = _uint(record, "opcode_id")
    command = OBSERVED_COMMANDS.get(opcode_id)
    if command is None:
        raise UdspTraceError(f"unobserved opcode {opcode_id}")
    if record.get("opcode_name") != command["name"]:
        raise UdspTraceError("opcode name does not match pinned classifier")
    if record.get("parser_case") != command["parser_case"]:
        raise UdspTraceError("parser case does not match pinned classifier")
    if record.get("handler_case") != command["handler_case"]:
        raise UdspTraceError("handler case does not match pinned classifier")
    if record.get("dispatcher") != DISPATCHER:
        raise UdspTraceError("dispatcher does not match pinned classifier")
    for field in (
        "composite", "node", "dt_f32_bits", "timer_f32_bits", "context",
        "next", "callback", "parent_current",
    ):
        _address(record, field)
    payload = record.get("payload")
    if not isinstance(payload, list) or len(payload) != 5:
        raise UdspTraceError("payload must contain five fields")
    for value in payload:
        if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
            raise UdspTraceError("payload contains a non-canonical field")
    for field in ("sequence", "call_id", "thread", "tick", "depth", "modifier"):
        _uint(record, field)
    if record["depth"] >= 64:
        raise UdspTraceError("UDSP depth exceeds the native observer bound")
    for field in ("complete", "started", "parent_complete", "advanced"):
        _bool(record, field)
    outcome = record.get("outcome")
    if phase == "BEFORE":
        if outcome != "PENDING" or record["advanced"]:
            raise UdspTraceError("BEFORE record has an invalid outcome")
    elif outcome not in AFTER_OUTCOMES:
        raise UdspTraceError("AFTER record has an invalid outcome")
    elif (outcome == "COMPLETE") != record["complete"]:
        raise UdspTraceError("AFTER outcome disagrees with completion state")


def validate_records(records: list[dict]) -> dict:
    if not records:
        raise UdspTraceError("UDSP trace is empty")
    stacks: dict[int, list[tuple]] = {}
    observed = []
    call_ids = set()
    thread_ids = set()
    for sequence, record in enumerate(records):
        _validate_record(record, sequence)
        thread = record["thread"]
        thread_ids.add(thread)
        if len(thread_ids) > 8:
            raise UdspTraceError("UDSP trace exceeds the native thread bound")
        stack = stacks.setdefault(thread, [])
        identity = (
            record["call_id"], record["node"], record["composite"],
            record["opcode_id"], record["opcode_name"], thread,
            record["tick"], record["depth"], record["dt_f32_bits"],
            record["parser_case"], record["handler_case"],
        )
        if record["phase"] == "BEFORE":
            if record["depth"] != len(stack):
                raise UdspTraceError("BEFORE depth does not match nesting")
            if record["call_id"] in call_ids:
                raise UdspTraceError("BEFORE call_id is reused")
            call_ids.add(record["call_id"])
            stack.append(identity)
            if record["opcode_id"] not in observed:
                observed.append(record["opcode_id"])
            continue
        if not stack:
            raise UdspTraceError("AFTER record is unpaired")
        expected = stack.pop()
        if identity != expected:
            raise UdspTraceError("AFTER record does not pair with BEFORE")
    if any(stacks.values()):
        raise UdspTraceError("UDSP trace contains an unpaired BEFORE record")
    return {
        "status": "PASS",
        "pair_count": len(records) // 2,
        "observed_opcode_ids": observed,
        "natural_transition_evidence": False,
        "parity_eligible": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the fail-closed native UDSP lifecycle channel",
    )
    parser.add_argument("trace", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.trace.open(encoding="utf-8") as trace_file:
            result = validate_records(parse_records(trace_file))
    except (OSError, UdspTraceError) as error:
        print(f"UDSP trace validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
