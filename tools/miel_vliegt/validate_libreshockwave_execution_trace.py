#!/usr/bin/env python3
"""Validate the exact, deliberately non-promotional LibreShockwave trace."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


PROTOCOL = "LIBRESHOCKWAVE_RAW_EXECUTION_TRACE_V1"
SCENARIO_PROTOCOL = "LIBRESHOCKWAVE_HANDLER_SCENARIO_V1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROVENANCE_PATHS = {
    "trace_exporter": "tools/miel_vliegt/director_trace_exporter/TraceExporter.cpp",
    "trace_cmake": "tools/miel_vliegt/director_trace_exporter/CMakeLists.txt",
    "trace_build_wrapper": "tools/miel_vliegt/build_libreshockwave_trace.sh",
    "trace_schema": (
        "tools/miel_vliegt/director_trace_exporter/"
        "execution_trace_record.schema.json"
    ),
    "libreshockwave_patch": (
        "tools/miel_vliegt/patches/libreshockwave-director8-score.patch"
    ),
    "toolchain_manifest": "tools/miel_vliegt/libreshockwave.json",
}
EVENT_KINDS = {
    "runtime_boundary",
    "handler_enter",
    "handler_exit",
    "instruction",
    "script_error",
    "audio",
    "scenario_state",
    "scenario_effects",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class TraceValidationError(ValueError):
    """Raised when a trace is not an exact V1 record stream."""


def _fail(record_index: int, message: str) -> None:
    raise TraceValidationError(f"record {record_index}: {message}")


def _exact_keys(
    record: dict[str, Any], expected: set[str], record_index: int, where: str
) -> None:
    actual = set(record)
    if actual != expected:
        _fail(
            record_index,
            f"{where} keys differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}",
        )


def _integer(
    value: Any, record_index: int, name: str, minimum: int | None = None
) -> int:
    if type(value) is not int:
        _fail(record_index, f"{name} must be an integer")
    if minimum is not None and value < minimum:
        _fail(record_index, f"{name} must be >= {minimum}")
    return value


def _string(value: Any, record_index: int, name: str, nonempty=False) -> str:
    if not isinstance(value, str):
        _fail(record_index, f"{name} must be a string")
    if nonempty and not value:
        _fail(record_index, f"{name} must not be empty")
    return value


def _boolean(value: Any, record_index: int, name: str) -> bool:
    if type(value) is not bool:
        _fail(record_index, f"{name} must be a boolean")
    return value


def _object(value: Any, record_index: int, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(record_index, f"{name} must be an object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_handler(
    value: Any,
    record_index: int,
    name: str = "handler",
    *,
    scenario: bool = False,
) -> dict[str, Any]:
    handler = _object(value, record_index, name)
    expected = {"script_id", "script_display_name", "name"}
    if scenario:
        expected.add("handler_bytecode_offset")
    _exact_keys(
        handler,
        expected,
        record_index,
        name,
    )
    _integer(handler["script_id"], record_index, f"{name}.script_id")
    _string(
        handler["script_display_name"],
        record_index,
        f"{name}.script_display_name",
    )
    _string(handler["name"], record_index, f"{name}.name", nonempty=True)
    if scenario:
        _integer(
            handler["handler_bytecode_offset"],
            record_index,
            f"{name}.handler_bytecode_offset",
            0,
        )
    return handler


def _validate_datum(
    value: Any, record_index: int, name: str
) -> dict[str, Any]:
    datum = _object(value, record_index, name)
    _exact_keys(datum, {"type", "value"}, record_index, name)
    _string(datum["type"], record_index, f"{name}.type", nonempty=True)
    _string(datum["value"], record_index, f"{name}.value")
    return datum


def _validate_named_datums(
    value: Any, record_index: int, name: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(record_index, f"{name} must be an array")
    names: list[str] = []
    for index, entry_value in enumerate(value):
        entry = _object(entry_value, record_index, f"{name}[{index}]")
        _exact_keys(
            entry,
            {"name", "datum"},
            record_index,
            f"{name}[{index}]",
        )
        names.append(
            _string(
                entry["name"],
                record_index,
                f"{name}[{index}].name",
                nonempty=True,
            )
        )
        _validate_datum(
            entry["datum"], record_index, f"{name}[{index}].datum"
        )
    if len(names) != len(set(names)):
        _fail(record_index, f"{name} contains duplicate names")
    return value


def _validate_scenario_header(
    value: Any, record_index: int
) -> dict[str, Any]:
    scenario = _object(value, record_index, "scenario")
    _exact_keys(
        scenario, {"selector", "inputs"}, record_index, "scenario"
    )
    selector = _object(scenario["selector"], record_index, "selector")
    _exact_keys(
        selector,
        {"script_chunk_id", "handler_bytecode_offset", "handler_name"},
        record_index,
        "selector",
    )
    _integer(
        selector["script_chunk_id"],
        record_index,
        "selector.script_chunk_id",
        0,
    )
    _integer(
        selector["handler_bytecode_offset"],
        record_index,
        "selector.handler_bytecode_offset",
        0,
    )
    _string(
        selector["handler_name"],
        record_index,
        "selector.handler_name",
        nonempty=True,
    )
    inputs = _object(scenario["inputs"], record_index, "inputs")
    _exact_keys(
        inputs,
        {"fixture_id", "random_seed", "time_ms", "globals", "arguments"},
        record_index,
        "inputs",
    )
    _string(
        inputs["fixture_id"],
        record_index,
        "inputs.fixture_id",
        nonempty=True,
    )
    _integer(inputs["random_seed"], record_index, "inputs.random_seed")
    _integer(inputs["time_ms"], record_index, "inputs.time_ms")
    _validate_named_datums(inputs["globals"], record_index, "inputs.globals")
    if not isinstance(inputs["arguments"], list):
        _fail(record_index, "inputs.arguments must be an array")
    for index, argument in enumerate(inputs["arguments"]):
        _validate_datum(
            argument, record_index, f"inputs.arguments[{index}]"
        )
    return scenario


def _validate_header(
    record: dict[str, Any],
    record_index: int,
    repository_root: Path,
    movie_path: Path | None,
) -> str:
    protocol = record.get("protocol")
    scenario_mode = protocol == SCENARIO_PROTOCOL
    _exact_keys(
        record,
        {
            "sequence",
            "kind",
            "protocol",
            "closure_authority",
            "movie",
            "toolchain",
            "provenance",
        }
        | ({"scenario"} if scenario_mode else set()),
        record_index,
        "header",
    )
    if record["sequence"] != -1 or record["kind"] != "header":
        _fail(record_index, "header must have sequence -1 and kind header")
    if protocol not in {PROTOCOL, SCENARIO_PROTOCOL}:
        _fail(record_index, "unsupported protocol")
    if _boolean(
        record["closure_authority"], record_index, "closure_authority"
    ):
        _fail(record_index, "raw trace must never claim closure authority")
    if scenario_mode:
        _validate_scenario_header(record["scenario"], record_index)

    movie = _object(record["movie"], record_index, "movie")
    _exact_keys(
        movie, {"name", "byte_length", "sha256"}, record_index, "movie"
    )
    _string(movie["name"], record_index, "movie.name", nonempty=True)
    _integer(movie["byte_length"], record_index, "movie.byte_length", 1)
    if not SHA256_RE.fullmatch(_string(movie["sha256"], record_index, "movie.sha256")):
        _fail(record_index, "movie.sha256 must be lowercase SHA-256")
    if movie_path is not None:
        if movie["name"] != movie_path.name:
            _fail(record_index, "movie.name does not match supplied movie")
        if movie["byte_length"] != movie_path.stat().st_size:
            _fail(record_index, "movie.byte_length does not match supplied movie")
        if movie["sha256"] != _sha256(movie_path):
            _fail(record_index, "movie.sha256 does not match supplied movie")

    toolchain = _object(record["toolchain"], record_index, "toolchain")
    _exact_keys(
        toolchain, {"libreshockwave_commit"}, record_index, "toolchain"
    )
    commit = _string(
        toolchain["libreshockwave_commit"],
        record_index,
        "toolchain.libreshockwave_commit",
    )
    if not COMMIT_RE.fullmatch(commit):
        _fail(record_index, "LibreShockwave commit must be a full Git SHA")

    provenance = _object(record["provenance"], record_index, "provenance")
    _exact_keys(
        provenance, set(PROVENANCE_PATHS), record_index, "provenance"
    )
    for name, expected_path in PROVENANCE_PATHS.items():
        entry = _object(provenance[name], record_index, f"provenance.{name}")
        _exact_keys(
            entry, {"path", "sha256"}, record_index, f"provenance.{name}"
        )
        if entry["path"] != expected_path:
            _fail(record_index, f"provenance.{name}.path is not canonical")
        digest = _string(
            entry["sha256"], record_index, f"provenance.{name}.sha256"
        )
        if not SHA256_RE.fullmatch(digest):
            _fail(record_index, f"provenance.{name}.sha256 is malformed")
        source = repository_root / expected_path
        if not source.is_file():
            _fail(record_index, f"provenance source missing: {expected_path}")
        if digest != _sha256(source):
            _fail(record_index, f"provenance hash mismatch: {expected_path}")
    manifest = json.loads(
        (repository_root / PROVENANCE_PATHS["toolchain_manifest"]).read_text(
            encoding="utf-8"
        )
    )
    if commit != manifest.get("commit"):
        _fail(
            record_index,
            "LibreShockwave commit disagrees with the pinned toolchain manifest",
        )
    return protocol


def _validate_event_base(
    record: dict[str, Any], record_index: int, sequence: int
) -> None:
    if record["sequence"] != sequence:
        _fail(record_index, f"expected sequence {sequence}")
    _integer(record["frame"], record_index, "frame", 0)
    _integer(record["call_depth"], record_index, "call_depth", 0)


def _validate_event(
    record: dict[str, Any],
    record_index: int,
    sequence: int,
    stack: list[dict[str, Any]],
    *,
    scenario: bool = False,
) -> None:
    kind = record.get("kind")
    common = {"sequence", "kind", "frame", "call_depth"}
    expected_by_kind = {
        "runtime_boundary": common
        | {"operation", "phase", "frame_before", "frame_after"},
        "handler_enter": common | {"handler"},
        "handler_exit": common | {"handler", "return_value"},
        "instruction": common | {"handler", "instruction"},
        "script_error": common | {"message", "detail"},
        "audio": common | {"audio"},
    }
    if kind not in expected_by_kind:
        _fail(record_index, f"unknown event kind {kind!r}")
    _exact_keys(record, expected_by_kind[kind], record_index, kind)
    _validate_event_base(record, record_index, sequence)

    if kind == "runtime_boundary":
        if record["call_depth"] != len(stack):
            _fail(record_index, "runtime_boundary call_depth disagrees with stack")
        if record["operation"] not in {
            "play",
            "go_to_frame",
            "step_frame",
            "tick",
            "shutdown",
        }:
            _fail(record_index, "unknown runtime operation")
        if record["phase"] not in {"before", "after"}:
            _fail(record_index, "unknown runtime phase")
        _integer(record["frame_before"], record_index, "frame_before", 0)
        _integer(record["frame_after"], record_index, "frame_after", 0)
    elif kind == "handler_enter":
        handler = _validate_handler(
            record["handler"], record_index, scenario=scenario
        )
        if record["call_depth"] != len(stack) + 1:
            _fail(record_index, "handler_enter call_depth disagrees with stack")
        stack.append(handler)
    elif kind == "handler_exit":
        handler = _validate_handler(
            record["handler"], record_index, scenario=scenario
        )
        if scenario:
            _validate_datum(
                record["return_value"], record_index, "return_value"
            )
        else:
            _string(record["return_value"], record_index, "return_value")
        if not stack or handler != stack[-1]:
            _fail(record_index, "handler_exit does not match active handler")
        if record["call_depth"] != len(stack):
            _fail(record_index, "handler_exit call_depth disagrees with stack")
        stack.pop()
    elif kind == "instruction":
        handler = _validate_handler(
            record["handler"], record_index, scenario=scenario
        )
        if not stack or handler != stack[-1]:
            _fail(record_index, "instruction does not name active handler")
        if record["call_depth"] != len(stack):
            _fail(record_index, "instruction call_depth disagrees with stack")
        instruction = _object(
            record["instruction"], record_index, "instruction"
        )
        _exact_keys(
            instruction,
            {
                "bytecode_index",
                "offset",
                "opcode",
                "argument",
                "annotation",
                "stack_size",
            },
            record_index,
            "instruction",
        )
        _integer(
            instruction["bytecode_index"],
            record_index,
            "instruction.bytecode_index",
            0,
        )
        _integer(instruction["offset"], record_index, "instruction.offset", 0)
        _string(
            instruction["opcode"],
            record_index,
            "instruction.opcode",
            nonempty=True,
        )
        _integer(
            instruction["argument"], record_index, "instruction.argument"
        )
        _string(
            instruction["annotation"],
            record_index,
            "instruction.annotation",
        )
        _integer(
            instruction["stack_size"],
            record_index,
            "instruction.stack_size",
            0,
        )
    elif kind == "script_error":
        if record["call_depth"] != len(stack):
            _fail(record_index, "script_error call_depth disagrees with stack")
        _string(record["message"], record_index, "message")
        _string(record["detail"], record_index, "detail")
    elif kind == "audio":
        if record["call_depth"] != len(stack):
            _fail(record_index, "audio call_depth disagrees with stack")
        audio = _object(record["audio"], record_index, "audio")
        _exact_keys(
            audio,
            {
                "action",
                "channel",
                "loop_count",
                "volume",
                "format",
                "byte_length",
            },
            record_index,
            "audio",
        )
        _string(audio["action"], record_index, "audio.action", nonempty=True)
        _integer(audio["channel"], record_index, "audio.channel")
        _integer(audio["loop_count"], record_index, "audio.loop_count")
        _integer(audio["volume"], record_index, "audio.volume")
        _string(audio["format"], record_index, "audio.format")
        _integer(audio["byte_length"], record_index, "audio.byte_length", 0)


def _validate_scenario_action(
    value: Any, record_index: int, name: str
) -> dict[str, Any]:
    action = _object(value, record_index, name)
    _exact_keys(
        action,
        {
            "handler",
            "instruction_offset",
            "opcode",
            "argument",
            "annotation",
        },
        record_index,
        name,
    )
    _validate_handler(
        action["handler"],
        record_index,
        f"{name}.handler",
        scenario=True,
    )
    _integer(
        action["instruction_offset"],
        record_index,
        f"{name}.instruction_offset",
        0,
    )
    _string(action["opcode"], record_index, f"{name}.opcode", nonempty=True)
    _integer(action["argument"], record_index, f"{name}.argument")
    _string(action["annotation"], record_index, f"{name}.annotation")
    return action


def _validate_scenario_event(
    record: dict[str, Any], record_index: int, sequence: int
) -> None:
    if record.get("sequence") != sequence:
        _fail(record_index, f"expected sequence {sequence}")
    kind = record.get("kind")
    if kind == "scenario_state":
        _exact_keys(
            record,
            {
                "sequence",
                "kind",
                "phase",
                "frame",
                "random_seed",
                "globals",
            },
            record_index,
            kind,
        )
        if record["phase"] not in {"before", "after"}:
            _fail(record_index, "scenario_state phase must be before or after")
        _integer(record["frame"], record_index, "frame", 0)
        _integer(record["random_seed"], record_index, "random_seed")
        globals_value = _validate_named_datums(
            record["globals"], record_index, "globals"
        )
        names = [entry["name"] for entry in globals_value]
        if names != sorted(names):
            _fail(record_index, "scenario_state globals must be sorted")
        return
    if kind != "scenario_effects":
        _fail(record_index, f"unknown scenario event kind {kind!r}")
    _exact_keys(
        record,
        {"sequence", "kind", "audio", "go", "actions"},
        record_index,
        kind,
    )
    if not isinstance(record["audio"], list):
        _fail(record_index, "audio must be an array")
    for index, audio_value in enumerate(record["audio"]):
        audio = _object(audio_value, record_index, f"audio[{index}]")
        _exact_keys(
            audio,
            {
                "action",
                "channel",
                "loop_count",
                "volume",
                "format",
                "byte_length",
            },
            record_index,
            f"audio[{index}]",
        )
        _string(
            audio["action"],
            record_index,
            f"audio[{index}].action",
            nonempty=True,
        )
        _integer(audio["channel"], record_index, f"audio[{index}].channel")
        _integer(
            audio["loop_count"],
            record_index,
            f"audio[{index}].loop_count",
        )
        _integer(audio["volume"], record_index, f"audio[{index}].volume")
        _string(audio["format"], record_index, f"audio[{index}].format")
        _integer(
            audio["byte_length"],
            record_index,
            f"audio[{index}].byte_length",
            0,
        )
    go = _object(record["go"], record_index, "go")
    _exact_keys(
        go,
        {"frame_before", "frame_after", "actions"},
        record_index,
        "go",
    )
    _integer(go["frame_before"], record_index, "go.frame_before", 0)
    _integer(go["frame_after"], record_index, "go.frame_after", 0)
    if not isinstance(go["actions"], list):
        _fail(record_index, "go.actions must be an array")
    for index, action_value in enumerate(go["actions"]):
        action = _object(
            action_value, record_index, f"go.actions[{index}]"
        )
        _exact_keys(
            action,
            {"handler", "instruction_offset", "annotation"},
            record_index,
            f"go.actions[{index}]",
        )
        _validate_handler(
            action["handler"],
            record_index,
            f"go.actions[{index}].handler",
            scenario=True,
        )
        _integer(
            action["instruction_offset"],
            record_index,
            f"go.actions[{index}].instruction_offset",
            0,
        )
        annotation = _string(
            action["annotation"],
            record_index,
            f"go.actions[{index}].annotation",
        )
        if annotation != "<go()>":
            _fail(record_index, "go action lacks the exact VM go annotation")
    if not isinstance(record["actions"], list):
        _fail(record_index, "actions must be an array")
    for index, action in enumerate(record["actions"]):
        _validate_scenario_action(action, record_index, f"actions[{index}]")


def _validate_scenario_records(
    records: list[dict[str, Any]], header: dict[str, Any]
) -> None:
    if len(records) < 7:
        _fail(len(records) - 1, "handler scenario stream is incomplete")
    if records[-1].get("kind") != "scenario_summary":
        _fail(len(records) - 1, "last record must be scenario_summary")

    stack: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    instructions: list[dict[str, Any]] = []
    cursor = 1

    before = records[cursor]
    if before.get("kind") != "scenario_state" or before.get("phase") != "before":
        _fail(cursor, "first scenario record must be before state")
    _validate_scenario_event(before, cursor, cursor - 1)
    counts["scenario_state"] += 1
    cursor += 1

    if records[cursor].get("kind") != "handler_enter":
        _fail(cursor, "before state must be followed by handler_enter")
    top_handler = records[cursor].get("handler")
    top_return: dict[str, Any] | None = None
    saw_top_exit = False
    while cursor < len(records) - 1:
        record = records[cursor]
        kind = record.get("kind")
        if kind == "script_error":
            _fail(cursor, "script_error invalidates handler scenario")
        if kind not in {"handler_enter", "handler_exit", "instruction"}:
            _fail(
                cursor,
                "handler invocation may contain only handler and instruction "
                "events",
            )
        if kind == "handler_exit" and record.get("call_depth") == 1:
            top_return = record.get("return_value")
            saw_top_exit = True
        _validate_event(
            record, cursor, cursor - 1, stack, scenario=True
        )
        if kind == "instruction":
            instructions.append(record)
        counts[kind] += 1
        cursor += 1
        if saw_top_exit and not stack:
            break
    if not saw_top_exit or stack:
        _fail(cursor, "top-level handler invocation is incomplete")

    if cursor >= len(records) - 1:
        _fail(cursor, "handler_exit must be followed by after state")
    after = records[cursor]
    if after.get("kind") != "scenario_state" or after.get("phase") != "after":
        _fail(cursor, "handler_exit must be followed by after state")
    _validate_scenario_event(after, cursor, cursor - 1)
    counts["scenario_state"] += 1
    cursor += 1

    if cursor >= len(records) - 1 or records[cursor].get("kind") != "scenario_effects":
        _fail(cursor, "after state must be followed by scenario_effects")
    effects = records[cursor]
    _validate_scenario_event(effects, cursor, cursor - 1)
    counts["scenario_effects"] += 1
    cursor += 1
    if cursor != len(records) - 1:
        _fail(cursor, "scenario_effects must be followed immediately by summary")

    inputs = header["scenario"]["inputs"]
    if before["random_seed"] != inputs["random_seed"]:
        _fail(1, "before random seed disagrees with scenario input")
    if before["globals"] != sorted(
        inputs["globals"], key=lambda entry: entry["name"]
    ):
        _fail(1, "before globals disagree with scenario inputs")
    if effects["go"]["frame_before"] != before["frame"]:
        _fail(len(records) - 2, "go.frame_before disagrees with before state")
    if effects["go"]["frame_after"] != after["frame"]:
        _fail(len(records) - 2, "go.frame_after disagrees with after state")

    actual_actions = [
        {
            "handler": instruction["handler"],
            "instruction_offset": instruction["instruction"]["offset"],
            "opcode": instruction["instruction"]["opcode"],
            "argument": instruction["instruction"]["argument"],
            "annotation": instruction["instruction"]["annotation"],
        }
        for instruction in instructions
    ]
    if effects["actions"] != actual_actions:
        _fail(len(records) - 2, "actions disagree with instruction events")
    go_actions = [
        {
            "handler": action["handler"],
            "instruction_offset": action["instruction_offset"],
            "annotation": action["annotation"],
        }
        for action in actual_actions
        if action["opcode"] == "extCall"
        and action["annotation"] == "<go()>"
    ]
    if effects["go"]["actions"] != go_actions:
        _fail(len(records) - 2, "go actions disagree with instruction events")

    summary_index = len(records) - 1
    summary = records[-1]
    _exact_keys(
        summary,
        {
            "sequence",
            "kind",
            "event_count",
            "counts",
            "handler_event_count",
            "matched_handler",
            "return_value",
            "effect_counts",
            "closure_authority",
        },
        summary_index,
        "scenario_summary",
    )
    expected_count = len(records) - 2
    if _integer(summary["sequence"], summary_index, "sequence", 0) != expected_count:
        _fail(summary_index, "scenario_summary.sequence disagrees with stream")
    if _integer(
        summary["event_count"], summary_index, "event_count", 0
    ) != expected_count:
        _fail(summary_index, "scenario_summary.event_count disagrees with stream")
    embedded_counts = _object(summary["counts"], summary_index, "counts")
    for kind, count in embedded_counts.items():
        _integer(count, summary_index, f"counts.{kind}", 0)
    actual_counts = {kind: value for kind, value in sorted(counts.items())}
    if embedded_counts != actual_counts:
        _fail(summary_index, "scenario_summary.counts disagrees with stream")
    if _integer(
        summary["handler_event_count"],
        summary_index,
        "handler_event_count",
        1,
    ) != counts["handler_enter"]:
        _fail(summary_index, "handler_event_count disagrees with handler events")
    matched_handler = _validate_handler(
        summary["matched_handler"],
        summary_index,
        "matched_handler",
        scenario=True,
    )
    _validate_datum(summary["return_value"], summary_index, "return_value")
    if summary["return_value"] != top_return:
        _fail(
            summary_index,
            "summary return_value disagrees with top-level handler_exit",
        )
    effect_counts = _object(
        summary["effect_counts"], summary_index, "effect_counts"
    )
    _exact_keys(
        effect_counts,
        {"audio", "go", "actions"},
        summary_index,
        "effect_counts",
    )
    expected_effect_counts = {
        "audio": len(effects["audio"]),
        "go": len(go_actions),
        "actions": len(actual_actions),
    }
    if effect_counts != expected_effect_counts:
        _fail(summary_index, "effect_counts disagrees with observed effects")
    if _boolean(
        summary["closure_authority"], summary_index, "closure_authority"
    ):
        _fail(summary_index, "handler scenario must never claim closure authority")

    selector = header["scenario"]["selector"]
    if counts["handler_enter"] < 1:
        _fail(summary_index, "scenario did not execute a handler")
    if matched_handler != top_handler:
        _fail(summary_index, "matched_handler disagrees with runtime event")
    if top_handler["script_id"] != selector["script_chunk_id"]:
        _fail(summary_index, "executed script does not match selector")
    if top_handler["name"] != selector["handler_name"]:
        _fail(summary_index, "executed handler name does not match selector")
    if (
        top_handler["handler_bytecode_offset"]
        != selector["handler_bytecode_offset"]
    ):
        _fail(summary_index, "executed handler offset does not match selector")
    top_instructions = [
        record
        for record in records[1:-1]
        if record.get("kind") == "instruction"
        and record["handler"] == top_handler
    ]
    if not top_instructions or top_instructions[0]["instruction"]["offset"] != 0:
        _fail(summary_index, "selected handler did not execute from offset zero")


def validate_records(
    records: list[dict[str, Any]],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    movie_path: Path | None = None,
) -> None:
    if len(records) < 2:
        raise TraceValidationError("trace needs a header and summary")
    if not all(isinstance(record, dict) for record in records):
        raise TraceValidationError("every NDJSON line must be an object")
    protocol = _validate_header(records[0], 0, repository_root, movie_path)
    if protocol == SCENARIO_PROTOCOL:
        _validate_scenario_records(records, records[0])
        return
    if records[-1].get("kind") != "summary":
        _fail(len(records) - 1, "last record must be summary")

    stack: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for sequence, record in enumerate(records[1:-1]):
        _validate_event(record, sequence + 1, sequence, stack)
        counts[record["kind"]] += 1
    if stack:
        _fail(len(records) - 1, "summary reached with active handlers")

    summary_index = len(records) - 1
    summary = records[-1]
    _exact_keys(
        summary,
        {
            "sequence",
            "kind",
            "target_score_frame",
            "frame_any_handler_observed",
            "event_count",
            "counts",
            "closure_authority",
        },
        summary_index,
        "summary",
    )
    expected_count = len(records) - 2
    if _integer(summary["sequence"], summary_index, "sequence", 0) != expected_count:
        _fail(summary_index, "summary.sequence disagrees with event stream")
    if (
        _integer(summary["event_count"], summary_index, "event_count", 0)
        != expected_count
    ):
        _fail(summary_index, "summary.event_count disagrees with event stream")
    _integer(
        summary["target_score_frame"],
        summary_index,
        "target_score_frame",
        0,
    )
    observed = _boolean(
        summary["frame_any_handler_observed"],
        summary_index,
        "frame_any_handler_observed",
    )
    target_frame = summary["target_score_frame"]
    actual_observed = any(
        record["kind"] == "handler_enter" and record["frame"] == target_frame
        for record in records[1:-1]
    )
    if observed != actual_observed:
        _fail(
            summary_index,
            "frame_any_handler_observed disagrees with handler_enter events",
        )
    if _boolean(
        summary["closure_authority"], summary_index, "closure_authority"
    ):
        _fail(summary_index, "raw trace must never claim closure authority")
    embedded_counts = _object(summary["counts"], summary_index, "counts")
    if set(embedded_counts) - EVENT_KINDS:
        _fail(summary_index, "summary.counts has unknown event kinds")
    for kind, count in embedded_counts.items():
        _integer(count, summary_index, f"counts.{kind}", 0)
    actual_counts = {kind: value for kind, value in sorted(counts.items())}
    if embedded_counts != actual_counts:
        _fail(summary_index, "summary.counts disagrees with event stream")


def read_records(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_bytes().decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise TraceValidationError(f"trace is not valid UTF-8: {error}") from error
    records = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            raise TraceValidationError(f"line {line_number}: blank line")
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise TraceValidationError(
                f"line {line_number}: invalid JSON: {error.msg}"
            ) from error
    return records


def validate_trace(
    trace_path: Path,
    *,
    movie_path: Path | None = None,
    repository_root: Path = REPOSITORY_ROOT,
) -> list[dict[str, Any]]:
    records = read_records(trace_path)
    validate_records(
        records, repository_root=repository_root, movie_path=movie_path
    )
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--movie", type=Path)
    arguments = parser.parse_args()
    try:
        records = validate_trace(arguments.trace, movie_path=arguments.movie)
    except (OSError, TraceValidationError) as error:
        parser.error(str(error))
    print(f"validated {len(records)} records: {arguments.trace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
