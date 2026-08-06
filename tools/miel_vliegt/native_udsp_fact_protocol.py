#!/usr/bin/env python3
"""Validate pointer-free v2 facts emitted by the native UDSP observer.

The raw stream contains only values available at the pinned native hook
boundaries plus observer-owned monotone handles. Source normalization, source
hashes, graph semantics and command names are derived from static contracts
after validation; they are never trusted as native facts.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


PROTOCOL = "miel-vliegt-native-udsp-hook-facts-v2"
VALIDATED_PROTOCOL = "miel-vliegt-native-udsp-hook-facts-validated-v2"
PRODUCER = "NATIVE_UDSP_HOOK"
SUPPORT_STATUS = "VALIDATED_HOOK_FACTS_NOT_PARITY_EVIDENCE"

_ROOT = Path(__file__).resolve().parents[2]
_EXECUTABLE_PATH = _ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json"
_COMMANDS_PATH = _ROOT / "content/miel_vliegt/native_udsp_scene_commands.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POINTER_VALUE = re.compile(r"^0[xX][0-9a-fA-F]{8,16}$")
_HEX_BYTES = re.compile(r"^(?:[0-9a-f]{2})+$")
_F32_BITS = re.compile(r"^[0-9a-f]{8}$")
_MAX_HANDLE = 0x000FFFFF
_MAX_SITE_ID = 0x0000FFFF
_MAX_SOURCE_PATH_BYTES = 4096

_SEMANTIC_KEYS = {
    "artifactkey", "scriptkey", "index", "indices", "opcode",
    "opcodename", "ancestry", "parentpath", "variant", "outcome",
    "parity", "executablecommandindex", "sourcecommandindex",
    "modifier", "modifiername",
}
_POINTER_KEYS = {
    "address", "pointer", "ptr", "object", "vtable", "caller",
    "context", "nodepointer", "rootpointer", "callbackaddress",
}

_DOCUMENT_FIELDS = {"schema", "protocol", "producer", "records"}
_FIELDS = {
    "THREAD_ATTACH": {"sequence", "event", "threadHandle"},
    "PARSE_BEGIN": {
        "sequence", "event", "threadHandle", "parseHandle",
        "sourcePathBytesHex", "causeCallHandle", "causeDispatchHandle",
    },
    "GRAPH_NODE_COMPOSITE": {
        "sequence", "event", "threadHandle", "parseHandle", "nodeHandle",
        "parentHandle", "childOrdinal", "nodeType", "repeat",
    },
    "GRAPH_NODE_COMMAND": {
        "sequence", "event", "threadHandle", "parseHandle", "nodeHandle",
        "parentHandle", "childOrdinal", "nodeType", "commandId",
        "modifierId",
    },
    "PARSE_END": {
        "sequence", "event", "threadHandle", "parseHandle", "success",
        "returnedNodeHandle", "graphCount",
    },
    "ROOT_START_BEGIN": {
        "sequence", "event", "threadHandle", "rootHandle", "parseHandle",
        "rootNodeHandle", "causeCallHandle", "causeDispatchHandle",
        "runningBefore", "completeBefore",
    },
    "ROOT_START_END": {
        "sequence", "event", "threadHandle", "rootHandle", "parseHandle",
        "rootNodeHandle", "runningAfter", "completeAfter",
    },
    "COMPOSITE_RESET_BEGIN": {
        "sequence", "event", "threadHandle", "resetHandle", "rootHandle",
        "nodeHandle", "contextKind", "contextHandle", "dispatchHandle",
        "completeBefore", "currentNodeHandleBefore",
    },
    "COMPOSITE_RESET_END": {
        "sequence", "event", "threadHandle", "resetHandle", "rootHandle",
        "nodeHandle", "completeAfter", "currentNodeHandleAfter",
    },
    "ROOT_UPDATE_BEGIN": {
        "sequence", "event", "threadHandle", "callHandle", "rootHandle",
        "updateOrdinal", "deltaF32Bits", "runningBefore", "completeBefore",
    },
    "ROOT_UPDATE_END": {
        "sequence", "event", "threadHandle", "callHandle", "rootHandle",
        "runningAfter", "completeAfter",
    },
    "DISPATCH_BEGIN": {
        "sequence", "event", "threadHandle", "callHandle",
        "dispatchHandle", "rootHandle", "nodeHandle", "commandId",
        "deltaF32Bits", "completeBefore", "startedBefore",
    },
    "DISPATCH_END": {
        "sequence", "event", "threadHandle", "callHandle",
        "dispatchHandle", "rootHandle", "nodeHandle", "commandId",
        "completeAfter", "startedAfter", "exitSiteCode",
    },
    "RNG_DRAW": {
        "sequence", "event", "threadHandle", "callHandle",
        "dispatchHandle", "rootHandle", "nodeHandle", "drawOrdinal",
        "rawRandU15",
    },
    "CALLBACK_ARM": {
        "sequence", "event", "threadHandle", "armHandle", "parseHandle",
        "nodeHandle", "rootHandle", "callHandle", "dispatchHandle",
        "modifierId",
    },
    "CALLBACK": {
        "sequence", "event", "threadHandle", "armHandle", "parseHandle",
        "nodeHandle", "rootHandle", "callHandle", "dispatchHandle",
        "callbackCode", "completeBefore", "completeAfter", "returnU32",
    },
    "HOOK_FAILURE": {
        "sequence", "event", "threadHandle", "hookCode", "errorCode",
    },
}


class NativeUdspFactError(ValueError):
    """Raised when a native hook fact stream is not structurally exact."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_int(value: Any) -> bool:
    return type(value) is int


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if not _is_int(value) or value < minimum or value > _MAX_HANDLE:
        raise NativeUdspFactError(f"{label} is not a bounded integer")
    return value


def _require_handle(value: Any, label: str) -> int:
    return _require_int(value, label, minimum=1)


def _require_u32(value: Any, label: str, *, minimum: int = 0) -> int:
    if not _is_int(value) or value < minimum or value > 0xFFFFFFFF:
        raise NativeUdspFactError(f"{label} is not u32")
    return value


def _require_site(value: Any, label: str) -> int:
    if not _is_int(value) or value < 1 or value > _MAX_SITE_ID:
        raise NativeUdspFactError(f"{label} is not an internal site id")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise NativeUdspFactError(f"{label} is not boolean")
    return value


def _require_f32_bits(value: Any, label: str) -> str:
    # Every 32-bit IEEE-754 pattern is observable at the ABI, including NaNs
    # and infinities. The structural protocol must not reinterpret it.
    if not isinstance(value, str) or not _F32_BITS.fullmatch(value):
        raise NativeUdspFactError(f"{label} is not canonical float32 bits")
    return value


def _derive_source_path(value: Any) -> str:
    if not isinstance(value, str) or not _HEX_BYTES.fullmatch(value) \
            or len(value) // 2 > _MAX_SOURCE_PATH_BYTES:
        raise NativeUdspFactError("native parser sourcePathBytesHex is invalid")
    try:
        raw = bytes.fromhex(value)
        text = raw.decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise NativeUdspFactError(
            "native parser source path is not pinned-corpus ASCII"
        ) from exc
    if not text or "\x00" in text \
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise NativeUdspFactError("native parser source path bytes are invalid")
    normalized = text.replace("\\", "/")
    if normalized.startswith("/") or "//" in normalized \
            or any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise NativeUdspFactError("native parser source path is invalid")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or path.suffix.lower() != ".def":
        raise NativeUdspFactError("native parser source path is invalid")
    return str(path)


def _reject_untrusted_labels(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise NativeUdspFactError(f"non-string fact key at {path}")
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            if normalized in _SEMANTIC_KEYS or normalized.endswith("index") \
                    or "parity" in normalized:
                raise NativeUdspFactError(f"semantic label is forbidden at {path}.{key}")
            if normalized in _POINTER_KEYS \
                    or normalized.endswith(("address", "pointer", "ptr")):
                raise NativeUdspFactError(f"pointer-shaped key at {path}.{key}")
            _reject_untrusted_labels(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_untrusted_labels(child, f"{path}[{index}]")
        return
    if isinstance(value, str) and _POINTER_VALUE.fullmatch(value):
        raise NativeUdspFactError(f"pointer-shaped value at {path}")
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise NativeUdspFactError(f"non-JSON fact value at {path}")


def _load_contracts() -> tuple[dict[str, Any], dict[str, Any]]:
    executable = json.loads(_EXECUTABLE_PATH.read_bytes())
    commands = json.loads(_COMMANDS_PATH.read_bytes())
    if executable.get("schema") != 1 \
            or executable.get("contract") != "miel-vliegt-executable-udsp-scene-scripts":
        raise NativeUdspFactError("pinned executable UDSP contract is invalid")
    if commands.get("schema") != 1 or not isinstance(commands.get("commands"), list):
        raise NativeUdspFactError("pinned native command contract is invalid")
    source = executable.get("sources", {}).get("nativeCommands", {})
    if source.get("path") != "content/miel_vliegt/native_udsp_scene_commands.json" \
            or source.get("sha256") != _sha256(_COMMANDS_PATH):
        raise NativeUdspFactError("pinned native command contract hash differs")
    return executable, commands


def _script_table(executable: dict[str, Any]) -> dict[str, dict[str, Any]]:
    scripts = executable.get("scripts")
    if not isinstance(scripts, list):
        raise NativeUdspFactError("pinned executable scripts are missing")
    result = {}
    for script in scripts:
        if not isinstance(script, dict) or not isinstance(script.get("path"), str):
            raise NativeUdspFactError("pinned executable script is invalid")
        path = script["path"]
        if path in result or not _SHA256.fullmatch(str(script.get("sourceSha256", ""))):
            raise NativeUdspFactError(f"pinned executable script is invalid: {path}")
        result[path] = script
    return result


def _command_ids(commands: dict[str, Any]) -> set[int]:
    result = set()
    for row in commands["commands"]:
        command_id = row.get("id") if isinstance(row, dict) else None
        if not _is_int(command_id) or command_id in result:
            raise NativeUdspFactError("pinned native command ids are invalid")
        result.add(command_id)
    return result


def _modifier_ids(commands: dict[str, Any]) -> dict[str, int]:
    modifiers = commands.get("engine", {}).get("modifiers")
    if not isinstance(modifiers, dict) or not modifiers:
        raise NativeUdspFactError("pinned native modifier ids are missing")
    result = {}
    seen = set()
    for name, modifier_id in modifiers.items():
        if not isinstance(name, str) or not name or not _is_int(modifier_id) \
                or modifier_id < 0 or modifier_id in seen:
            raise NativeUdspFactError("pinned native modifier ids are invalid")
        result[name] = modifier_id
        seen.add(modifier_id)
    if "NONE" not in result or "WAIT_RANDOM" not in result:
        raise NativeUdspFactError("required pinned native modifiers are missing")
    return result


def _command_id(commands: dict[str, Any], name: str) -> int:
    rows = [row for row in commands["commands"] if row.get("name") == name]
    if len(rows) != 1 or not _is_int(rows[0].get("id")):
        raise NativeUdspFactError(f"pinned native command is missing: {name}")
    return rows[0]["id"]


def _expected_graph(
    script: dict[str, Any], modifier_ids: dict[str, int],
) -> dict[tuple[int, ...], dict[str, Any]]:
    commands = script.get("commands")
    structure = script.get("structure")
    if not isinstance(commands, list) or not isinstance(structure, dict):
        raise NativeUdspFactError("pinned executable graph is invalid")
    by_index = {row.get("executableCommandIndex"): row for row in commands}
    if set(by_index) != set(range(len(commands))):
        raise NativeUdspFactError("pinned executable command indices are invalid")
    result = {}

    def visit(node: dict[str, Any], path: tuple[int, ...]) -> None:
        if "command" in node:
            if set(node) != {"command", "sourceCommand"}:
                raise NativeUdspFactError("pinned command leaf is invalid")
            command = by_index.get(node["command"])
            if command is None or command.get("sourceCommandIndex") != node["sourceCommand"]:
                raise NativeUdspFactError("pinned command leaf binding differs")
            modifier_name = command.get("modifier") or "NONE"
            if modifier_name not in modifier_ids:
                raise NativeUdspFactError("pinned command modifier is unknown")
            result[path] = {
                "nodeType": 6, "commandId": command.get("nativeOpcode"),
                "modifierId": modifier_ids[modifier_name],
                "executableCommandIndex": node["command"],
            }
            return
        if set(node) != {"node", "repeat", "children"} \
                or type(node["repeat"]) is not bool \
                or not isinstance(node["children"], list):
            raise NativeUdspFactError("pinned composite node is invalid")
        result[path] = {"nodeType": 4, "repeat": node["repeat"]}
        for ordinal, child in enumerate(node["children"]):
            if not isinstance(child, dict):
                raise NativeUdspFactError("pinned graph child is invalid")
            visit(child, path + (ordinal,))

    visit(structure, ())
    return result


def _record_fields(record: dict[str, Any]) -> set[str]:
    event = record.get("event")
    if event == "GRAPH_NODE":
        node_type = record.get("nodeType")
        if node_type not in {4, 6}:
            raise NativeUdspFactError("GRAPH_NODE nodeType is invalid")
        suffix = "COMPOSITE" if node_type == 4 else "COMMAND"
        return _FIELDS[f"GRAPH_NODE_{suffix}"]
    fields = _FIELDS.get(event)
    if fields is None:
        raise NativeUdspFactError(f"unknown native fact event: {event!r}")
    return fields


class _Validator:
    def __init__(self, executable: dict[str, Any], commands: dict[str, Any]):
        self.scripts = _script_table(executable)
        self.command_ids = _command_ids(commands)
        self.modifier_ids = _modifier_ids(commands)
        self.wait_random_modifier_id = self.modifier_ids["WAIT_RANDOM"]
        self.callback_modifier_ids = {
            self.modifier_ids[name]
            for name in ("LOOP_TIMES", "LOOP_RANDOMTIMES", "WAIT")
        }
        self.script_command_id = _command_id(commands, "PLAY_CHARACTER_SCRIPT")
        self.animation_command_id = _command_id(commands, "PLAY_CHARACTER_ANIMATION")
        self.wait_command_id = _command_id(commands, "WAIT")
        self.rng_command_ids = {
            _command_id(commands, "PLAY_CHARACTER_SOUND_RANDOM"),
            _command_id(commands, "PLAY_MULLEBARNSOUND"),
            self.wait_command_id,
        }
        self.handles: dict[int, str] = {}
        self.next_handle = 1
        self.threads: dict[int, dict[str, Any]] = {}
        self.parses: dict[int, dict[str, Any]] = {}
        self.nodes: dict[int, dict[str, Any]] = {}
        self.roots: dict[int, dict[str, Any]] = {}
        self.calls: dict[int, dict[str, Any]] = {}
        self.dispatches: dict[int, dict[str, Any]] = {}
        self.resets: dict[int, dict[str, Any]] = {}
        self.arms: dict[int, dict[str, Any]] = {}
        self.bindings: list[dict[str, Any]] = []
        self.event_counts: dict[str, int] = {}
        self.command_coverage: set[int] = set()
        self.raw_rng_draws = 0
        self.failure_observed = False

        # Pointer-free observer site codes. A non-zero code is emitted only
        # from one reviewed native immediate-complete branch that returns
        # without writing node+0x50 (started).
        self.no_start_exit_sites = {
            _command_id(commands, "PLAY_CHARACTER_SCRIPT"): 1,
            _command_id(commands, "PLAY_CHARACTER_ANIMATION"): 2,
            _command_id(commands, "POSITION_CHARACTER"): 3,
        }

    def allocate(self, handle: Any, kind: str) -> int:
        if not _is_int(handle) or handle < 1:
            raise NativeUdspFactError(f"{kind} handle is not a positive integer")
        if handle in self.handles:
            raise NativeUdspFactError(f"duplicate integer handle: {handle}")
        if handle != self.next_handle or handle > _MAX_HANDLE:
            raise NativeUdspFactError(
                f"{kind} handle is not the next contiguous observer id "
                f"({self.next_handle})"
            )
        self.handles[handle] = kind
        self.next_handle += 1
        return handle

    def require(self, handle: Any, kind: str) -> int:
        handle = _require_handle(handle, f"{kind} handle")
        if self.handles.get(handle) != kind:
            raise NativeUdspFactError(f"unknown {kind} handle: {handle}")
        return handle

    def thread_attach(self, record: dict[str, Any]) -> None:
        handle = self.allocate(record["threadHandle"], "thread")
        self.threads[handle] = {
            "parseStack": [], "rootStart": None, "openCall": None,
            "dispatch": None, "resetStack": [], "observedEvents": 0,
        }

    def observe_thread_event(self, record: dict[str, Any]) -> None:
        if record["event"] == "THREAD_ATTACH":
            return
        thread = self.thread(record)
        thread["observedEvents"] += 1

    def thread(self, record: dict[str, Any]) -> dict[str, Any]:
        return self.threads[self.require(record["threadHandle"], "thread")]

    def enforce_lifecycle_barrier(self, record: dict[str, Any]) -> None:
        """Enforce the exact next event of each synchronous native frame."""
        thread_handle = record.get("threadHandle")
        if not _is_int(thread_handle) or thread_handle not in self.threads:
            return
        thread = self.threads[thread_handle]
        event = record.get("event")
        # Observer failure is an out-of-band terminal record. It is accepted
        # through any open frame only so hook_failure/finish can invalidate the
        # entire document; it never becomes positive lifecycle evidence.
        if event == "HOOK_FAILURE":
            return

        call_handle = thread["openCall"]
        if call_handle is not None:
            call = self.calls[call_handle]
            if not call["runningBefore"]:
                if event == "ROOT_UPDATE_END" \
                        and record.get("callHandle") == call_handle \
                        and record.get("rootHandle") == call["rootHandle"]:
                    return
                raise NativeUdspFactError(
                    "stopped root update permits only its exact ROOT_UPDATE_END"
                )

        reset_stack = thread["resetStack"]
        if reset_stack:
            if event == "COMPOSITE_RESET_BEGIN":
                # reset_begin validates the exact next composite child.
                return
            if event == "COMPOSITE_RESET_END" \
                    and record.get("resetHandle") == reset_stack[-1]:
                return
            raise NativeUdspFactError(
                "open composite reset permits only exact recursive reset events"
            )

        parse_stack = thread["parseStack"]
        if parse_stack:
            if event in {"GRAPH_NODE", "PARSE_END"} \
                    and record.get("parseHandle") == parse_stack[-1]:
                return
            raise NativeUdspFactError(
                "open parser permits only its exact graph and return events"
            )

        root_start_handle = thread["rootStart"]
        if root_start_handle is not None:
            root = self.roots[root_start_handle]
            if root["startResetState"] == "PENDING" \
                    and event == "COMPOSITE_RESET_BEGIN":
                return
            if root["startResetState"] == "COMPLETE" \
                    and event == "ROOT_START_END" \
                    and record.get("rootHandle") == root_start_handle:
                return
            raise NativeUdspFactError(
                "open root start permits only its exact reset and return events"
            )

        if call_handle is not None and thread["dispatch"] is None:
            call = self.calls[call_handle]
            expected = call["schedulerExpected"]
            allowed_event = {
                "DISPATCH": "DISPATCH_BEGIN",
                "RESET": "COMPOSITE_RESET_BEGIN",
            }.get(expected[0]) if expected is not None else None
            if allowed_event is not None and event == allowed_event:
                return
            if call["schedulerFinished"] \
                    and event == "ROOT_UPDATE_END" \
                    and record.get("callHandle") == call_handle \
                    and record.get("rootHandle") == call["rootHandle"]:
                return
            raise NativeUdspFactError(
                "root update event differs from the native scheduler lifecycle"
            )

    def _exact_dispatch_context(
        self, record: dict[str, Any], label: str,
    ) -> tuple[int, int] | None:
        thread = self.thread(record)
        call_handle = record["causeCallHandle"]
        dispatch_handle = record["causeDispatchHandle"]
        active_dispatch = thread["dispatch"]
        if active_dispatch is None:
            if call_handle is not None or dispatch_handle is not None:
                raise NativeUdspFactError(f"{label} cause is not active")
            return None
        active_call = thread["openCall"]
        if call_handle != active_call or dispatch_handle != active_dispatch:
            raise NativeUdspFactError(f"{label} cause differs from active dispatch")
        self.require(call_handle, "call")
        dispatch = self.dispatches[self.require(dispatch_handle, "dispatch")]
        if dispatch["callHandle"] != call_handle \
                or dispatch["commandId"] != self.script_command_id:
            raise NativeUdspFactError(
                f"{label} cause is not a PLAY_CHARACTER_SCRIPT dispatch"
            )
        return call_handle, dispatch_handle

    @staticmethod
    def _require_stored_cause(
        thread: dict[str, Any], cause: tuple[int, int] | None, label: str,
    ) -> None:
        if cause is None:
            if thread["dispatch"] is not None:
                raise NativeUdspFactError(f"{label} acquired an unrelated dispatch")
            return
        if thread["openCall"] != cause[0] or thread["dispatch"] != cause[1]:
            raise NativeUdspFactError(f"{label} cause is no longer active")

    def parse_begin(self, record: dict[str, Any]) -> None:
        thread = self.thread(record)
        if thread["openCall"] is not None \
                and not self.calls[thread["openCall"]]["runningBefore"]:
            raise NativeUdspFactError(
                "stopped root update contains a parse side event"
            )
        if thread["dispatch"] is not None or thread["openCall"] is not None \
                or record["causeCallHandle"] is not None \
                or record["causeDispatchHandle"] is not None:
            raise NativeUdspFactError(
                "native parser is not callable from a UDSP dispatch"
            )
        handle = self.allocate(record["parseHandle"], "parse")
        path = _derive_source_path(record["sourcePathBytesHex"])
        script = self.scripts.get(path)
        if script is None:
            raise NativeUdspFactError(f"native parser source path is not pinned: {path}")
        cause = None
        expected_graph = _expected_graph(script, self.modifier_ids)
        self.parses[handle] = {
            "threadHandle": record["threadHandle"], "path": path,
            "script": script, "nodes": [], "ended": False,
            "success": None, "cause": cause, "returnedNodeHandle": None,
            "nativeRunning": False, "nativeComplete": False,
            "latestRoot": None,
            "expectedGraph": expected_graph,
            "expectedOrder": tuple(expected_graph),
        }
        thread["parseStack"].append(handle)

    def _active_parse(self, record: dict[str, Any]) -> dict[str, Any]:
        thread = self.thread(record)
        parse_handle = self.require(record["parseHandle"], "parse")
        if not thread["parseStack"] or thread["parseStack"][-1] != parse_handle:
            raise NativeUdspFactError("parse event is outside its parser call")
        parse = self.parses[parse_handle]
        if parse["ended"]:
            raise NativeUdspFactError("parse event follows PARSE_END")
        self._require_stored_cause(thread, parse["cause"], "parse")
        return parse

    def graph_node(self, record: dict[str, Any]) -> None:
        parse = self._active_parse(record)
        parent_handle = record["parentHandle"]
        ordinal = _require_int(record["childOrdinal"], "graph child ordinal")
        if parent_handle is None:
            if parse["nodes"] or ordinal != 0:
                raise NativeUdspFactError("graph root is duplicated or has a bad ordinal")
            path: tuple[int, ...] = ()
        else:
            parent_handle = self.require(parent_handle, "node")
            parent = self.nodes[parent_handle]
            if parent["parseHandle"] != record["parseHandle"]:
                raise NativeUdspFactError("graph edge crosses parser instances")
            if parent["nodeType"] != 4:
                raise NativeUdspFactError("graph command node cannot have children")
            siblings = [
                node for node in parse["nodes"]
                if node["parentHandle"] == parent_handle
            ]
            if ordinal != len(siblings):
                raise NativeUdspFactError("graph child ordinal is not contiguous")
            path = parent["path"] + (ordinal,)
        expected_index = len(parse["nodes"])
        if expected_index >= len(parse["expectedOrder"]) \
                or path != parse["expectedOrder"][expected_index]:
            raise NativeUdspFactError(
                "native parsed graph order differs from source token order"
            )
        node_handle = self.allocate(record["nodeHandle"], "node")
        node = {
            "parseHandle": record["parseHandle"], "nodeHandle": node_handle,
            "parentHandle": parent_handle, "childOrdinal": ordinal,
            "nodeType": record["nodeType"], "path": path,
            "complete": False, "started": False,
            "currentNodeHandle": None, "latestArmHandle": None,
        }
        if record["nodeType"] == 4:
            node["repeat"] = _require_bool(record["repeat"], "graph repeat")
        else:
            command_id = _require_int(record["commandId"], "native command id", minimum=1)
            if command_id not in self.command_ids:
                raise NativeUdspFactError(f"unknown native command id: {command_id}")
            modifier_id = _require_int(record["modifierId"], "native modifier id")
            if modifier_id not in self.modifier_ids.values():
                raise NativeUdspFactError(f"unknown native modifier id: {modifier_id}")
            node["commandId"] = command_id
            node["modifierId"] = modifier_id
        self.nodes[node_handle] = node
        parse["nodes"].append(node)

    def parse_end(self, record: dict[str, Any]) -> None:
        parse = self._active_parse(record)
        parse_handle = record["parseHandle"]
        success = _require_bool(record["success"], "parser success")
        graph_count = _require_int(record["graphCount"], "observed graph count")
        returned = record["returnedNodeHandle"]
        if not success:
            if returned is not None or graph_count != 0 or parse["nodes"]:
                raise NativeUdspFactError("failed parser return contains a graph")
            graph_sha = None
        else:
            returned = self.require(returned, "node")
            if graph_count != len(parse["nodes"]):
                raise NativeUdspFactError("observed graph count differs")
            if not parse["nodes"] or returned != parse["nodes"][0]["nodeHandle"] \
                    or parse["nodes"][0]["path"] != ():
                raise NativeUdspFactError("parser returned node is not the observed graph root")
            expected = parse["expectedGraph"]
            actual = {node["path"]: node for node in parse["nodes"]}
            if set(actual) != set(expected):
                raise NativeUdspFactError("native parsed graph has missing or extra nodes")
            for path, expected_node in expected.items():
                node = actual[path]
                if node["nodeType"] != expected_node["nodeType"]:
                    raise NativeUdspFactError("native parsed graph node type differs")
                if node["nodeType"] == 4:
                    if node["repeat"] != expected_node["repeat"]:
                        raise NativeUdspFactError("native parsed graph repeat flag differs")
                else:
                    if node["commandId"] != expected_node["commandId"]:
                        raise NativeUdspFactError("native parsed graph command id differs")
                    if node["modifierId"] != expected_node["modifierId"]:
                        raise NativeUdspFactError("native parsed graph modifier id differs")
                node["expected"] = expected_node
            graph_sha = _json_sha256({
                "/".join(map(str, path)): expected[path]
                for path in sorted(expected)
            })
        parse["ended"] = True
        parse["success"] = success
        parse["returnedNodeHandle"] = returned
        thread = self.thread(record)
        thread["parseStack"].pop()
        self.bindings.append({
            "parseHandle": parse_handle, "sourcePath": parse["path"],
            "sourceSha256": parse["script"]["sourceSha256"],
            "parseSucceeded": success, "graphSha256": graph_sha,
            "graphNodeCount": graph_count,
        })

    def _root(self, value: Any) -> dict[str, Any]:
        return self.roots[self.require(value, "root")]

    def root_start_begin(self, record: dict[str, Any]) -> None:
        thread = self.thread(record)
        if thread["openCall"] is not None \
                and not self.calls[thread["openCall"]]["runningBefore"]:
            raise NativeUdspFactError(
                "stopped root update contains a root-start side event"
            )
        if thread["rootStart"] is not None or thread["resetStack"]:
            raise NativeUdspFactError("nested root start is invalid")
        parse_handle = self.require(record["parseHandle"], "parse")
        parse = self.parses[parse_handle]
        if not parse["ended"]:
            raise NativeUdspFactError("root starts before its parse is complete")
        if not parse["success"]:
            raise NativeUdspFactError("root starts from a failed parse")
        root_node = self.require(record["rootNodeHandle"], "node")
        if root_node != parse["returnedNodeHandle"]:
            raise NativeUdspFactError("root node differs from parser return")
        cause = self._exact_dispatch_context(record, "root start")
        if cause is not None:
            dispatch = self.dispatches[cause[1]]
            if dispatch["startedBefore"]:
                raise NativeUdspFactError(
                    "started PLAY_CHARACTER_SCRIPT cannot start another root"
                )
            if dispatch["rootStartCount"] != 0:
                raise NativeUdspFactError(
                    "PLAY_CHARACTER_SCRIPT dispatch started multiple roots"
                )
            dispatch["rootStartCount"] += 1
        running_before = _require_bool(record["runningBefore"], "root running before start")
        complete_before = _require_bool(record["completeBefore"], "root complete before start")
        if running_before != parse["nativeRunning"]:
            raise NativeUdspFactError("root running state differs before start")
        if complete_before != parse["nativeComplete"]:
            raise NativeUdspFactError("root completion state differs before start")
        root_handle = self.allocate(record["rootHandle"], "root")
        self.roots[root_handle] = {
            "parseHandle": parse_handle, "rootNodeHandle": root_node,
            "cause": cause, "nextUpdateOrdinal": 0, "startOpen": True,
            "startResetState": "PENDING",
        }
        parse["latestRoot"] = root_handle
        thread["rootStart"] = root_handle

    def root_start_end(self, record: dict[str, Any]) -> None:
        thread = self.thread(record)
        root_handle = self.require(record["rootHandle"], "root")
        if thread["rootStart"] != root_handle or thread["resetStack"]:
            raise NativeUdspFactError("root start end is outside its start")
        root = self.roots[root_handle]
        if record["parseHandle"] != root["parseHandle"] \
                or record["rootNodeHandle"] != root["rootNodeHandle"]:
            raise NativeUdspFactError("root start end identity differs")
        self._require_stored_cause(thread, root["cause"], "root start")
        if root["startResetState"] != "COMPLETE":
            raise NativeUdspFactError("root start has no exact recursive root reset")
        running = _require_bool(record["runningAfter"], "root running after start")
        complete = _require_bool(record["completeAfter"], "root complete after start")
        if not running or complete:
            raise NativeUdspFactError("root start post-state differs from native contract")
        parse = self.parses[root["parseHandle"]]
        parse["nativeRunning"] = running
        parse["nativeComplete"] = complete
        root["startOpen"] = False
        thread["rootStart"] = None

    def _node_for_root(
        self, root: dict[str, Any], value: Any, node_type: int | None = None,
    ) -> dict[str, Any]:
        node = self.nodes[self.require(value, "node")]
        if node["parseHandle"] != root["parseHandle"]:
            raise NativeUdspFactError("runtime node does not belong to root parse")
        if node_type is not None and node["nodeType"] != node_type:
            raise NativeUdspFactError(f"runtime node is not type {node_type}")
        return node

    def _current_node(
        self, root: dict[str, Any], composite: dict[str, Any], value: Any,
        label: str,
    ) -> int | None:
        if value is None:
            return None
        handle = self.require(value, "node")
        node = self._node_for_root(root, handle)
        if node["parentHandle"] != composite["nodeHandle"]:
            raise NativeUdspFactError(f"{label} is not a direct composite child")
        return handle

    def _children(self, node: dict[str, Any]) -> list[dict[str, Any]]:
        return sorted(
            (
                child for child in self.parses[node["parseHandle"]]["nodes"]
                if child["parentHandle"] == node["nodeHandle"]
            ),
            key=lambda child: child["childOrdinal"],
        )

    def _scheduler_update_composite(self, node: dict[str, Any]):
        """Drive the native 0x0043c580 composite scheduler as a coroutine."""
        node["complete"] = True
        current_handle = node["currentNodeHandle"]
        if current_handle is None:
            return
        current = self.nodes[current_handle]
        if current["nodeType"] == 6:
            yield ("DISPATCH", current_handle)
            if current["complete"]:
                siblings = self._children(node)
                next_ordinal = current["childOrdinal"] + 1
                node["currentNodeHandle"] = (
                    siblings[next_ordinal]["nodeHandle"]
                    if next_ordinal < len(siblings) else None
                )
                if node["currentNodeHandle"] is not None:
                    node["complete"] = False
            else:
                node["complete"] = False
            return

        cursor = current
        while cursor is not None and cursor["nodeType"] == 4:
            yield from self._scheduler_update_composite(cursor)
            if not cursor["complete"]:
                node["complete"] = False
            elif cursor["repeat"]:
                node["complete"] = False
                yield ("RESET", cursor["nodeHandle"])
            siblings = self._children(node)
            next_ordinal = cursor["childOrdinal"] + 1
            cursor = (
                siblings[next_ordinal] if next_ordinal < len(siblings) else None
            )
        if node["complete"]:
            node["currentNodeHandle"] = (
                cursor["nodeHandle"] if cursor is not None else None
            )
            if cursor is not None:
                node["complete"] = False

    def _root_update_scheduler(self, root: dict[str, Any]):
        root_node = self.nodes[root["rootNodeHandle"]]
        yield from self._scheduler_update_composite(root_node)
        if root_node["complete"]:
            if root_node["repeat"]:
                yield ("RESET", root_node["nodeHandle"])
                return True, False
            return False, True
        return True, False

    @staticmethod
    def _advance_scheduler(call: dict[str, Any]) -> None:
        try:
            call["schedulerExpected"] = next(call["scheduler"])
        except StopIteration as stopped:
            call["schedulerExpected"] = None
            call["schedulerFinished"] = True
            call["schedulerResult"] = stopped.value

    def reset_begin(self, record: dict[str, Any]) -> None:
        thread = self.thread(record)
        root_handle = self.require(record["rootHandle"], "root")
        root = self.roots[root_handle]
        node = self._node_for_root(root, record["nodeHandle"], 4)
        context_kind = record["contextKind"]
        dispatch_handle = record["dispatchHandle"]
        parent_reset = (
            self.resets[thread["resetStack"][-1]]
            if thread["resetStack"] else None
        )
        if context_kind == "ROOT_START":
            if thread["rootStart"] != root_handle \
                    or record["contextHandle"] != root_handle \
                    or dispatch_handle is not None:
                raise NativeUdspFactError("reset root-start context differs")
            if parent_reset is None:
                if node["nodeHandle"] != root["rootNodeHandle"] \
                        or root["startResetState"] != "PENDING":
                    raise NativeUdspFactError(
                        "root start must contain exactly one root reset tree"
                    )
                root["startResetState"] = "OPEN"
        elif context_kind == "ROOT_UPDATE":
            call_handle = thread["openCall"]
            if call_handle is None or record["contextHandle"] != call_handle:
                raise NativeUdspFactError("reset update context differs")
            call = self.calls[call_handle]
            if call["rootHandle"] != root_handle:
                raise NativeUdspFactError("reset update root differs")
            if dispatch_handle != thread["dispatch"]:
                raise NativeUdspFactError("reset dispatch context differs")
            if dispatch_handle is not None:
                self.require(dispatch_handle, "dispatch")
            if parent_reset is None:
                if not call["runningBefore"]:
                    raise NativeUdspFactError(
                        "stopped root update contains a reset side event"
                    )
                expected = call["schedulerExpected"]
                if expected != ("RESET", node["nodeHandle"]):
                    raise NativeUdspFactError(
                        "root update reset is not scheduler-authorized"
                    )
                if not node["complete"] or node["currentNodeHandle"] is not None:
                    raise NativeUdspFactError(
                        "repeat reset prestate is not complete at end-of-children"
                    )
        else:
            raise NativeUdspFactError("reset context kind is invalid")
        if parent_reset is not None:
            for field in (
                "rootHandle", "contextKind", "contextHandle", "dispatchHandle",
            ):
                if record[field] != parent_reset[field]:
                    raise NativeUdspFactError(
                        f"nested reset {field} differs from its parent reset"
                    )
            expected = parent_reset["expectedCompositeChildren"]
            index = parent_reset["nextCompositeChild"]
            if index >= len(expected) or node["nodeHandle"] != expected[index]:
                raise NativeUdspFactError(
                    "recursive composite reset order differs from native traversal"
                )
            parent_reset["nextCompositeChild"] += 1
        complete_before = _require_bool(
            record["completeBefore"], "reset completion before",
        )
        if complete_before != node["complete"]:
            raise NativeUdspFactError("reset completion prestate differs")
        current_before = self._current_node(
            root, node, record["currentNodeHandleBefore"], "reset current before",
        )
        if current_before != node["currentNodeHandle"]:
            raise NativeUdspFactError("reset current prestate differs")
        reset_handle = self.allocate(record["resetHandle"], "reset")
        composite_children = [
            child["nodeHandle"] for child in self._children(node)
            if child["nodeType"] == 4
        ]
        self.resets[reset_handle] = {
            "threadHandle": record["threadHandle"], "rootHandle": root_handle,
            "nodeHandle": node["nodeHandle"], "contextKind": context_kind,
            "contextHandle": record["contextHandle"],
            "dispatchHandle": dispatch_handle,
            "expectedCompositeChildren": composite_children,
            "nextCompositeChild": 0,
            "schedulerMatched": (
                context_kind == "ROOT_UPDATE" and parent_reset is None
            ),
        }
        thread["resetStack"].append(reset_handle)

    def reset_end(self, record: dict[str, Any]) -> None:
        thread = self.thread(record)
        reset_handle = self.require(record["resetHandle"], "reset")
        if not thread["resetStack"] or thread["resetStack"][-1] != reset_handle:
            raise NativeUdspFactError("reset end is outside its reset")
        reset = self.resets[reset_handle]
        for field in ("rootHandle", "nodeHandle"):
            if record[field] != reset[field]:
                raise NativeUdspFactError(f"reset end {field} differs")
        root = self.roots[reset["rootHandle"]]
        node = self._node_for_root(root, reset["nodeHandle"], 4)
        if reset["nextCompositeChild"] != len(reset["expectedCompositeChildren"]):
            raise NativeUdspFactError(
                "recursive composite reset tree is incomplete"
            )
        complete = _require_bool(record["completeAfter"], "reset completion after")
        if complete:
            raise NativeUdspFactError("composite reset did not clear completion")
        current_after = self._current_node(
            root, node, record["currentNodeHandleAfter"], "reset current after",
        )
        children = self._children(node)
        expected_current = children[0]["nodeHandle"] if children else None
        if current_after != expected_current:
            raise NativeUdspFactError(
                "reset current after is not the first native child"
            )
        node["complete"] = complete
        node["currentNodeHandle"] = current_after
        # Command Reset at 0x0043c480 clears only the started byte. Command
        # completion is deliberately retained by the native implementation.
        for child in children:
            if child["nodeType"] == 6:
                child["started"] = False
        if node["nodeHandle"] == root["rootNodeHandle"]:
            self.parses[root["parseHandle"]]["nativeComplete"] = complete
        thread["resetStack"].pop()
        if reset["contextKind"] == "ROOT_START" \
                and node["nodeHandle"] == root["rootNodeHandle"]:
            root["startResetState"] = "COMPLETE"
        if reset["schedulerMatched"]:
            call = self.calls[reset["contextHandle"]]
            self._advance_scheduler(call)

    def update_begin(self, record: dict[str, Any]) -> None:
        thread = self.thread(record)
        if thread["openCall"] is not None or thread["rootStart"] is not None \
                or thread["resetStack"]:
            raise NativeUdspFactError("nested root update is invalid")
        root_handle = self.require(record["rootHandle"], "root")
        root = self.roots[root_handle]
        parse = self.parses[root["parseHandle"]]
        if parse["latestRoot"] != root_handle or root["startOpen"]:
            raise NativeUdspFactError("root update does not use latest completed generation")
        running = _require_bool(record["runningBefore"], "root running before update")
        complete = _require_bool(record["completeBefore"], "root complete before update")
        if running != parse["nativeRunning"]:
            raise NativeUdspFactError("root running state differs before update")
        if complete != parse["nativeComplete"]:
            raise NativeUdspFactError("root completion state differs before update")
        if running == complete:
            raise NativeUdspFactError(
                "root running/completion prestate violates native invariant"
            )
        ordinal = _require_int(record["updateOrdinal"], "root update ordinal")
        if ordinal != root["nextUpdateOrdinal"]:
            raise NativeUdspFactError("root update ordinal is not contiguous")
        _require_f32_bits(record["deltaF32Bits"], "update delta")
        call_handle = self.allocate(record["callHandle"], "call")
        root["nextUpdateOrdinal"] += 1
        self.calls[call_handle] = {
            "threadHandle": record["threadHandle"], "rootHandle": root_handle,
            "deltaF32Bits": record["deltaF32Bits"],
            "runningBefore": running, "completeBefore": complete,
            "scheduler": None, "schedulerExpected": None,
            "schedulerFinished": not running, "schedulerResult": (
                (running, complete) if not running else None
            ),
        }
        call = self.calls[call_handle]
        if running:
            call["scheduler"] = self._root_update_scheduler(root)
            self._advance_scheduler(call)
        thread["openCall"] = call_handle

    def _active_call(self, record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        thread = self.thread(record)
        call_handle = self.require(record["callHandle"], "call")
        if thread["openCall"] != call_handle:
            raise NativeUdspFactError("event is outside its root update")
        call = self.calls[call_handle]
        if record["rootHandle"] != call["rootHandle"]:
            raise NativeUdspFactError("event root differs from its root update")
        return thread, call

    def update_end(self, record: dict[str, Any]) -> None:
        thread, call = self._active_call(record)
        if thread["dispatch"] is not None or thread["resetStack"]:
            raise NativeUdspFactError("root update ends with an open nested call")
        running = _require_bool(record["runningAfter"], "root running after update")
        complete = _require_bool(record["completeAfter"], "root complete after update")
        if running == complete:
            raise NativeUdspFactError(
                "root running/completion post-state violates native invariant"
            )
        if not call["runningBefore"] \
                and (running != call["runningBefore"]
                     or complete != call["completeBefore"]):
            raise NativeUdspFactError("stopped root update is not a native no-op")
        if not call["schedulerFinished"]:
            raise NativeUdspFactError(
                "root update ended before its native scheduler events"
            )
        if call["schedulerResult"] != (running, complete):
            raise NativeUdspFactError(
                "root update post-state differs from native scheduler"
            )
        root = self.roots[call["rootHandle"]]
        parse = self.parses[root["parseHandle"]]
        parse["nativeRunning"] = running
        parse["nativeComplete"] = complete
        self.nodes[root["rootNodeHandle"]]["complete"] = complete
        thread["openCall"] = None

    def dispatch_begin(self, record: dict[str, Any]) -> None:
        thread, call = self._active_call(record)
        if not call["runningBefore"]:
            raise NativeUdspFactError(
                "stopped root update contains a dispatch side event"
            )
        if thread["dispatch"] is not None or thread["resetStack"]:
            raise NativeUdspFactError("nested command dispatch is invalid")
        root = self.roots[call["rootHandle"]]
        node = self._node_for_root(root, record["nodeHandle"], 6)
        command_id = _require_int(record["commandId"], "dispatch command id", minimum=1)
        if command_id != node["commandId"]:
            raise NativeUdspFactError("dispatch command does not match graph node")
        delta_bits = _require_f32_bits(record["deltaF32Bits"], "dispatch delta")
        if delta_bits != call["deltaF32Bits"]:
            raise NativeUdspFactError("dispatch delta differs from root update")
        complete_before = _require_bool(
            record["completeBefore"], "dispatch completion before",
        )
        started_before = _require_bool(
            record["startedBefore"], "dispatch started before",
        )
        if complete_before != node["complete"]:
            raise NativeUdspFactError("dispatch completion prestate differs")
        if started_before != node["started"]:
            raise NativeUdspFactError("dispatch started prestate differs")
        dispatch_handle = self.allocate(record["dispatchHandle"], "dispatch")
        self.dispatches[dispatch_handle] = {
            "threadHandle": record["threadHandle"],
            "callHandle": record["callHandle"], "rootHandle": record["rootHandle"],
            "nodeHandle": record["nodeHandle"], "commandId": command_id,
            "rng": 0,
            "rngExpected": int(
                not started_before and (
                    command_id in self.rng_command_ids and (
                        command_id != self.wait_command_id or
                        node["modifierId"] == self.wait_random_modifier_id
                    )
                )
            ),
            "armHandle": None,
            "startedBefore": started_before,
            "rootStartCount": 0,
            "schedulerMatched": False,
        }
        expected = call["schedulerExpected"]
        if expected != ("DISPATCH", node["nodeHandle"]):
            raise NativeUdspFactError(
                "dispatch node differs from native scheduler order"
            )
        self.dispatches[dispatch_handle]["schedulerMatched"] = True
        thread["dispatch"] = dispatch_handle
        self.command_coverage.add(command_id)

    def _active_dispatch(
        self, record: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        thread, _ = self._active_call(record)
        dispatch_handle = self.require(record["dispatchHandle"], "dispatch")
        if thread["dispatch"] != dispatch_handle:
            raise NativeUdspFactError("event is outside its dispatch")
        dispatch = self.dispatches[dispatch_handle]
        for field in ("callHandle", "rootHandle", "nodeHandle"):
            if record[field] != dispatch[field]:
                raise NativeUdspFactError(f"dispatch event {field} differs")
        node = self.nodes[dispatch["nodeHandle"]]
        return thread, dispatch, node

    def dispatch_end(self, record: dict[str, Any]) -> None:
        thread, dispatch, node = self._active_dispatch(record)
        if thread["resetStack"]:
            raise NativeUdspFactError("dispatch ends with an open reset")
        command_id = _require_int(record["commandId"], "dispatch end command id", minimum=1)
        if command_id != dispatch["commandId"]:
            raise NativeUdspFactError("dispatch end command differs")
        if dispatch["rng"] != dispatch["rngExpected"]:
            raise NativeUdspFactError(
                "dispatch RNG draw count differs from the native start branch"
            )
        complete_after = _require_bool(
            record["completeAfter"], "dispatch completion after",
        )
        node["complete"] = complete_after
        started_after = _require_bool(
            record["startedAfter"], "dispatch started after",
        )
        exit_site = _require_u32(record["exitSiteCode"], "dispatch exit site code")
        if dispatch["startedBefore"] and not started_after:
            raise NativeUdspFactError(
                "started dispatch cleared the native started latch"
            )
        if started_after:
            if exit_site != 0:
                raise NativeUdspFactError(
                    "started dispatch claimed a no-start exit site"
                )
        else:
            expected_site = self.no_start_exit_sites.get(dispatch["commandId"])
            if exit_site != expected_site or not complete_after \
                    or dispatch["armHandle"] is not None \
                    or dispatch["rootStartCount"] != 0:
                raise NativeUdspFactError(
                    "dispatch no-start exit is not an exact native immediate-complete branch"
                )
        node["started"] = started_after
        thread["dispatch"] = None
        if dispatch["schedulerMatched"]:
            self._advance_scheduler(self.calls[dispatch["callHandle"]])

    def rng_draw(self, record: dict[str, Any]) -> None:
        _, dispatch, node = self._active_dispatch(record)
        command_id = dispatch["commandId"]
        if command_id not in self.rng_command_ids:
            raise NativeUdspFactError("RNG draw command is invalid")
        if command_id == self.wait_command_id \
                and node["modifierId"] != self.wait_random_modifier_id:
            raise NativeUdspFactError("WAIT RNG draw belongs to a non-random command")
        ordinal = _require_int(record["drawOrdinal"], "RNG draw ordinal")
        if ordinal != dispatch["rng"]:
            raise NativeUdspFactError("RNG draw ordinal is not contiguous")
        if dispatch["rng"] >= dispatch["rngExpected"]:
            raise NativeUdspFactError(
                "RNG draw is outside the native initial start branch"
            )
        raw_rand = record["rawRandU15"]
        if not _is_int(raw_rand) or raw_rand < 0 or raw_rand > 32767:
            raise NativeUdspFactError("raw rand value is not native u15")
        dispatch["rng"] += 1
        self.raw_rng_draws += 1

    def callback_arm(self, record: dict[str, Any]) -> None:
        thread, dispatch, node = self._active_dispatch(record)
        if dispatch["commandId"] != self.animation_command_id:
            raise NativeUdspFactError("callback arm is not an animation dispatch")
        if dispatch["armHandle"] is not None:
                raise NativeUdspFactError("animation dispatch published multiple callback arms")
        if dispatch["startedBefore"]:
            raise NativeUdspFactError(
                "started animation dispatch cannot publish a callback arm"
            )
        modifier_id = _require_int(record["modifierId"], "callback arm modifier id")
        if modifier_id != node["modifierId"]:
            raise NativeUdspFactError("callback arm modifier differs from graph node")
        if modifier_id not in self.callback_modifier_ids:
            raise NativeUdspFactError("callback arm modifier is not native-eligible")
        parse_handle = self.require(record["parseHandle"], "parse")
        root = self.roots[self.require(record["rootHandle"], "root")]
        if parse_handle != node["parseHandle"] \
                or root["parseHandle"] != parse_handle:
            raise NativeUdspFactError("callback arm parse/root identity differs")
        arm_handle = self.allocate(record["armHandle"], "arm")
        previous = node["latestArmHandle"]
        if previous is not None:
            self.arms[previous]["superseded"] = True
        arm = {
            "threadHandle": record["threadHandle"],
            "parseHandle": parse_handle, "nodeHandle": node["nodeHandle"],
            "rootHandle": record["rootHandle"],
            "callHandle": record["callHandle"],
            "dispatchHandle": record["dispatchHandle"],
            "modifierId": modifier_id,
            "superseded": False,
        }
        self.arms[arm_handle] = arm
        node["latestArmHandle"] = arm_handle
        dispatch["armHandle"] = arm_handle

    def callback(self, record: dict[str, Any]) -> None:
        thread = self.thread(record)
        arm_handle = self.require(record["armHandle"], "arm")
        arm = self.arms[arm_handle]
        parse_handle = self.require(record["parseHandle"], "parse")
        parse = self.parses[parse_handle]
        node = self.nodes[self.require(record["nodeHandle"], "node")]
        if node["parseHandle"] != parse_handle \
                or node["nodeType"] != 6 \
                or node["commandId"] != self.animation_command_id:
            raise NativeUdspFactError("callback node is not a parsed animation command")
        for field in ("parseHandle", "nodeHandle", "rootHandle"):
            if record[field] != arm[field]:
                raise NativeUdspFactError(f"callback {field} differs from its arm")
        expected_root = arm["rootHandle"]
        self.require(expected_root, "root")
        if node["latestArmHandle"] != arm_handle or arm["superseded"]:
            raise NativeUdspFactError("callback arm is no longer current")
        if record["callHandle"] != thread["openCall"]:
            raise NativeUdspFactError("callback call context differs")
        if thread["openCall"] is not None \
                and not self.calls[thread["openCall"]]["runningBefore"]:
            raise NativeUdspFactError(
                "stopped root update contains a callback side event"
            )
        if record["dispatchHandle"] != thread["dispatch"]:
            raise NativeUdspFactError("callback dispatch context differs")
        if thread["openCall"] is not None:
            call = self.calls[self.require(thread["openCall"], "call")]
            if call["rootHandle"] != expected_root:
                raise NativeUdspFactError("callback active call belongs to another root")
        if thread["dispatch"] is not None:
            self.require(thread["dispatch"], "dispatch")
        arm_thread = self.threads[arm["threadHandle"]]
        if record["threadHandle"] == arm["threadHandle"] \
                and arm_thread["dispatch"] == arm["dispatchHandle"]:
            raise NativeUdspFactError(
                "callback cannot synchronously re-enter its arming dispatch"
            )
        code = _require_u32(record["callbackCode"], "callback code")
        before = _require_bool(record["completeBefore"], "callback completion before")
        after = _require_bool(record["completeAfter"], "callback completion after")
        if before != node["complete"]:
            raise NativeUdspFactError("callback completion before differs")
        if _require_u32(record["returnU32"], "callback return value") != 1:
            raise NativeUdspFactError("callback return value differs from native ABI")
        if code == 1:
            if not after:
                raise NativeUdspFactError("completion callback did not set completion")
        elif after != before:
            raise NativeUdspFactError("non-completion callback changed completion")
        node["complete"] = after

    def hook_failure(self, record: dict[str, Any], is_last: bool) -> None:
        self.thread(record)
        if not is_last:
            raise NativeUdspFactError("HOOK_FAILURE must be terminal")
        _require_site(record["hookCode"], "failure hook code")
        _require_u32(record["errorCode"], "failure error code", minimum=1)
        self.failure_observed = True

    def finish(self) -> dict[str, Any]:
        if self.failure_observed:
            raise NativeUdspFactError("terminal HOOK_FAILURE invalidates native proof")
        for thread in self.threads.values():
            if thread["observedEvents"] == 0:
                raise NativeUdspFactError(
                    "observer thread handle has no native fact events"
                )
            if thread["parseStack"]:
                raise NativeUdspFactError("native fact stream has a missing PARSE_END")
            if thread["rootStart"] is not None:
                raise NativeUdspFactError("native fact stream has a missing ROOT_START_END")
            if thread["resetStack"]:
                raise NativeUdspFactError("native fact stream has a missing COMPOSITE_RESET_END")
            if thread["dispatch"] is not None:
                raise NativeUdspFactError("native fact stream has a missing DISPATCH_END")
            if thread["openCall"] is not None:
                raise NativeUdspFactError("native fact stream has a missing ROOT_UPDATE_END")
        if any(not parse["ended"] for parse in self.parses.values()):
            raise NativeUdspFactError("native fact stream has a missing PARSE_END")
        if not self.parses:
            raise NativeUdspFactError("native fact stream contains no parse")
        counts = {event: count for event, count in self.event_counts.items() if count}
        successful = sum(1 for parse in self.parses.values() if parse["success"])
        return {
            "schema": 2,
            "protocol": VALIDATED_PROTOCOL,
            "supportStatus": SUPPORT_STATUS,
            "bindings": sorted(self.bindings, key=lambda row: row["parseHandle"]),
            "capabilities": {
                "observerThreadHandleCount": len(self.threads),
                "parseGraph": successful == len(self.parses),
                "rootStartLifecycle": bool(counts.get("ROOT_START_BEGIN"))
                    and counts.get("ROOT_START_BEGIN") == counts.get("ROOT_START_END"),
                "updateLifecycle": bool(counts.get("ROOT_UPDATE_BEGIN"))
                    and counts.get("ROOT_UPDATE_BEGIN") == counts.get("ROOT_UPDATE_END"),
                "compositeResetLifecycle": bool(counts.get("COMPOSITE_RESET_BEGIN"))
                    and counts.get("COMPOSITE_RESET_BEGIN")
                    == counts.get("COMPOSITE_RESET_END"),
                "dispatchLifecycle": bool(counts.get("DISPATCH_BEGIN"))
                    and counts.get("DISPATCH_BEGIN") == counts.get("DISPATCH_END"),
                "rng": {
                    "supported": False,
                    "status": "VALIDATED_RAW_DRAWS_SEED_AND_GLOBAL_ORDER_UNPROVEN",
                    "structuralRawDrawCount": self.raw_rng_draws,
                },
                "callback": bool(counts.get("CALLBACK")),
                "effects": {
                    "supported": False,
                    "status": "UNSUPPORTED_NO_NATIVE_EFFECT_ABI",
                },
                "hookFailureObserved": False,
                "coveredCommandIds": sorted(self.command_coverage),
            },
            "eventCounts": counts,
        }

def validate_native_udsp_facts(document: dict[str, Any]) -> dict[str, Any]:
    """Validate a raw native hook document and derive non-parity facts."""

    _reject_untrusted_labels(document)
    if not isinstance(document, dict) or set(document) != _DOCUMENT_FIELDS:
        raise NativeUdspFactError("native fact document has an invalid shape")
    if not _is_int(document.get("schema")) or document.get("schema") != 2 \
            or document.get("protocol") != PROTOCOL \
            or document.get("producer") != PRODUCER:
        raise NativeUdspFactError("native fact document identity is invalid")
    records = document.get("records")
    if not isinstance(records, list) or not records:
        raise NativeUdspFactError("native fact records are empty")
    executable, commands = _load_contracts()
    validator = _Validator(executable, commands)
    handlers = {
        "THREAD_ATTACH": validator.thread_attach,
        "PARSE_BEGIN": validator.parse_begin,
        "GRAPH_NODE": validator.graph_node,
        "PARSE_END": validator.parse_end,
        "ROOT_START_BEGIN": validator.root_start_begin,
        "ROOT_START_END": validator.root_start_end,
        "COMPOSITE_RESET_BEGIN": validator.reset_begin,
        "COMPOSITE_RESET_END": validator.reset_end,
        "ROOT_UPDATE_BEGIN": validator.update_begin,
        "ROOT_UPDATE_END": validator.update_end,
        "DISPATCH_BEGIN": validator.dispatch_begin,
        "DISPATCH_END": validator.dispatch_end,
        "RNG_DRAW": validator.rng_draw,
        "CALLBACK_ARM": validator.callback_arm,
        "CALLBACK": validator.callback,
    }
    for sequence, record in enumerate(records):
        if not isinstance(record, dict):
            raise NativeUdspFactError(f"native fact record {sequence} is not an object")
        expected_fields = _record_fields(record)
        if set(record) != expected_fields:
            raise NativeUdspFactError(f"{record.get('event')} record shape is invalid")
        if not _is_int(record["sequence"]) or record["sequence"] != sequence:
            raise NativeUdspFactError("native fact sequence is not contiguous")
        validator.enforce_lifecycle_barrier(record)
        validator.observe_thread_event(record)
        event = record["event"]
        validator.event_counts[event] = validator.event_counts.get(event, 0) + 1
        if event == "HOOK_FAILURE":
            validator.hook_failure(record, sequence == len(records) - 1)
        else:
            handlers[event](record)
    return validator.finish()


__all__ = [
    "NativeUdspFactError", "PRODUCER", "PROTOCOL", "SUPPORT_STATUS",
    "VALIDATED_PROTOCOL", "validate_native_udsp_facts",
]
