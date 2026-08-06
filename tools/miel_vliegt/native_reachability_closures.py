#!/usr/bin/env python3
"""Build fail-closed native reachability closure inventories.

The direct call graph is not enough to call a native function unreachable.
This module inventories the four additional inbound-path classes used by the
completion validator:

* loader roots (entry point, PE exports and TLS callbacks);
* callback-shaped literal code pointers in executable bytes;
* vtable/data-shaped literal code pointers in non-executable bytes;
* every unresolved indirect call and branch site from the native index.

The literal pointer scans intentionally over-approximate: every byte offset is
tested and any value inside a recovered function span is retained.  False
positives only make the unreachable set smaller.  Computed targets do not get
silently treated as literals; they remain explicit indirect-target gaps.
Register-indirect calls are resolved only when conservative CFG dataflow finds
an exact reaching definition loaded from a pinned PE import cell. Disconnected
CFG components start with an empty state because recovered function spans can
contain multiple native entry points. Direct x86 switch tables are recovered
only for the exact ``jmp [index*4+absolute_table]`` form when an unsigned bound
check guards the table and every table entry is a decoded basic-block start in
the same recovered function. EBP-parameter indirect calls are resolved only
when every direct xref supplies the parameter as an exact internal function
literal, optionally through an EBP-preserving exception funclet.

Every indirect site also receives a hash-bound structural classification.
Classification is inventory evidence only: it never resolves a target or
removes an OPEN path. Assigned-vtable tail transfers use the same must-CFG,
table-completeness and pinned-byte proof as assigned-vtable calls.
"""

from __future__ import annotations

import argparse
import bisect
import difflib
import hashlib
import importlib.metadata
import json
import re
import struct
from collections import deque
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CODE_MAP = "content/miel_vliegt/native_code_map.json"
FUNCTION_INDEX = "content/miel_vliegt/native_function_index.json"
SCHEMA_CONTRACT = "tools/miel_vliegt/native_reachability_closure_schema.json"
PROTOCOL = "miel-vliegt-native-reachability-closure-review"
SCHEMA = 2
SHA256_LENGTH = 64
PINNED_CAPSTONE_VERSION = "5.0.9"
OUTPUTS = {
    "roots": "content/miel_vliegt/native_reachability_roots.json",
    "callbacks": "content/miel_vliegt/native_reachability_callbacks.json",
    "vtables": "content/miel_vliegt/native_reachability_vtables.json",
    "indirectTargets": "content/miel_vliegt/native_reachability_indirect_targets.json",
}


class NativeReachabilityClosureError(ValueError):
    """Raised when a reachability inventory is incomplete or drifted."""


def _native_dependencies() -> tuple[Any, Any, Any, int]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, Cs
        from capstone.x86 import X86_OP_MEM
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    if importlib.metadata.version("capstone") != PINNED_CAPSTONE_VERSION:
        raise NativeReachabilityClosureError(
            f"native closure generation requires Capstone {PINNED_CAPSTONE_VERSION}"
        )
    try:
        from tools.miel_vliegt.analyze_native import PeImage
    except ModuleNotFoundError:  # Direct script execution.
        from analyze_native import PeImage
    return PeImage, Cs, (CS_ARCH_X86, CS_MODE_32), X86_OP_MEM


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise NativeReachabilityClosureError(f"{path}: expected a JSON object")
    return value


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SHA256_LENGTH \
        and all(character in "0123456789abcdef" for character in value)


def _function_rows(
    code_map: dict[str, Any], function_index: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[tuple[int, int, str, str]],
]:
    if code_map.get("schema") != 1 or function_index.get("schema") != 1:
        raise NativeReachabilityClosureError("native graph/index schema differs")
    if code_map.get("source") != function_index.get("source"):
        raise NativeReachabilityClosureError("native graph/index source identity differs")
    code_functions = code_map.get("functions")
    indexed_functions = function_index.get("functions")
    if not isinstance(code_functions, list) or not isinstance(indexed_functions, list):
        raise NativeReachabilityClosureError("native function inventory is unavailable")
    code_by_id = {}
    index_by_id = {}
    spans = []
    indexed_by_address = {
        row.get("address"): row for row in indexed_functions if isinstance(row, dict)
    }
    for row in code_functions:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise NativeReachabilityClosureError("native code-map row is malformed")
        identifier = row["id"]
        indexed = indexed_by_address.get(row.get("address"))
        if identifier in code_by_id or not isinstance(indexed, dict) \
                or indexed.get("sha256") != row.get("sha256") \
                or indexed.get("end") != row.get("end"):
            raise NativeReachabilityClosureError(
                f"{identifier}: code-map/index identity differs"
            )
        start = int(row["address"], 16)
        end = int(row["end"], 16)
        if not start < end:
            raise NativeReachabilityClosureError(
                f"{identifier}: native function span differs"
            )
        code_by_id[identifier] = row
        index_by_id[identifier] = indexed
        spans.append((start, end, identifier, row["address"]))
    spans.sort()
    if len(code_by_id) != len(indexed_functions):
        raise NativeReachabilityClosureError("native function inventory is not total")
    return code_by_id, index_by_id, spans


def _span_owner(
    address: int, spans: list[tuple[int, int, str, str]],
) -> tuple[str, str, int] | None:
    low = 0
    high = len(spans)
    while low < high:
        middle = (low + high) // 2
        if spans[middle][0] <= address:
            low = middle + 1
        else:
            high = middle
    if low:
        start, end, identifier, formatted = spans[low - 1]
        if start <= address < end:
            return identifier, formatted, address - start
    return None


def _candidate_membership(
    code_map: dict[str, Any],
) -> tuple[str, set[str], list[dict[str, str]]]:
    members = [
        {
            "functionId": row["id"],
            "nativeFunctionSha256": row["sha256"],
        }
        for row in sorted(code_map.get("functions", []), key=lambda item: item["id"])
        if row.get("entrypoint_reachable") is False
        and row.get("has_unresolved_direct_calls") is False
        and row.get("has_unresolved_indirect_calls") is False
    ]
    if not members:
        raise NativeReachabilityClosureError(
            "unreachable candidate membership is unavailable"
        )
    return (
        sha256_json(members),
        {row["functionId"] for row in members},
        members,
    )


def _direct_root_proof(
    code_map: dict[str, Any], candidate_members: list[dict[str, str]],
) -> str:
    return sha256_json({
        "entrypoint": code_map["source"]["entrypoint"],
        "candidateMembers": candidate_members,
        "reachableFunctions": sorted(
            row["id"] for row in code_map["functions"]
            if row["entrypoint_reachable"]
        ),
        "directCallEdges": sorted(
            f"{row['id']}->{target}"
            for row in code_map["functions"] for target in row["calls"]
        ),
    })


def _direct_reachable(
    roots: set[str], code_by_id: dict[str, dict[str, Any]],
) -> set[str]:
    reached = set(roots)
    queue = deque(sorted(roots))
    while queue:
        identifier = queue.popleft()
        row = code_by_id.get(identifier)
        if row is None:
            raise NativeReachabilityClosureError(
                f"reachability root is not a recovered function: {identifier}"
            )
        calls = row.get("calls")
        if not isinstance(calls, list):
            raise NativeReachabilityClosureError(
                f"{identifier}: direct calls are unavailable"
            )
        for target in calls:
            if target not in code_by_id:
                raise NativeReachabilityClosureError(
                    f"{identifier}: direct target is unavailable: {target}"
                )
            if target not in reached:
                reached.add(target)
                queue.append(target)
    return reached


def _pe_root_entries(
    image: PeImage, spans: list[tuple[int, int, str, str]],
) -> tuple[list[str], set[str], list[str], dict[str, Any]]:
    sites = [f"pe-entrypoint:0x{image.entrypoint:08x}"]
    entry_owner = _span_owner(image.entrypoint, spans)
    if entry_owner is None:
        raise NativeReachabilityClosureError("PE entrypoint is outside recovered code")
    targets = {entry_owner[0]}
    unresolved = []
    evidence: dict[str, Any] = {
        "entrypoint": f"0x{image.entrypoint:08x}",
        "exports": [],
        "tlsCallbacks": [],
        "peDirectories": [
            {"index": index, "rva": f"0x{rva:08x}", "size": size}
            for index, (rva, size) in enumerate(image._directories)
        ],
    }

    if len(image._directories) > 0 and image._directories[0][0]:
        export_rva, export_size = image._directories[0]
        try:
            export_va = image.image_base + export_rva
            values = struct.unpack(
                "<IIHHIIIIIII", image.bytes_at(export_va, 40)
            )
            number_of_functions = values[6]
            functions_rva = values[8]
            for ordinal in range(number_of_functions):
                target_rva = struct.unpack(
                    "<I",
                    image.bytes_at(
                        image.image_base + functions_rva + ordinal * 4, 4
                    ),
                )[0]
                if not target_rva:
                    continue
                if export_rva <= target_rva < export_rva + export_size:
                    continue
                target = image.image_base + target_rva
                owner = _span_owner(target, spans)
                site = f"pe-export:{ordinal}:0x{target:08x}"
                sites.append(site)
                evidence["exports"].append(site)
                if owner is None:
                    unresolved.append(site)
                else:
                    targets.add(owner[0])
        except (ValueError, struct.error) as error:
            unresolved.append(f"pe-export-directory:{type(error).__name__}")

    if len(image._directories) > 9 and image._directories[9][0]:
        tls_rva, _ = image._directories[9]
        try:
            tls_va = image.image_base + tls_rva
            callbacks_va = struct.unpack("<IIIIII", image.bytes_at(tls_va, 24))[3]
            if callbacks_va:
                for index in range(4096):
                    target = struct.unpack(
                        "<I", image.bytes_at(callbacks_va + index * 4, 4)
                    )[0]
                    if not target:
                        break
                    owner = _span_owner(target, spans)
                    site = f"pe-tls-callback:{index}:0x{target:08x}"
                    sites.append(site)
                    evidence["tlsCallbacks"].append(site)
                    if owner is None:
                        unresolved.append(site)
                    else:
                        targets.add(owner[0])
                else:
                    unresolved.append("pe-tls-callbacks:unterminated")
        except (ValueError, struct.error) as error:
            unresolved.append(f"pe-tls-directory:{type(error).__name__}")
    return sorted(sites), targets, sorted(unresolved), evidence


def _literal_pointer_sites(
    image: PeImage, spans: list[tuple[int, int, str, str]], *,
    executable: bool,
) -> tuple[list[str], set[str], dict[str, Any]]:
    sites = []
    targets = set()
    scanned_bytes = 0
    by_section: dict[str, int] = {}
    for section in image.sections:
        if section.executable is not executable:
            continue
        raw = image.data[
            section.raw_offset:section.raw_offset + section.raw_size
        ]
        scanned_bytes += len(raw)
        matches = 0
        for offset in range(max(0, len(raw) - 3)):
            target = struct.unpack_from("<I", raw, offset)[0]
            owner = _span_owner(target, spans)
            if owner is None:
                continue
            identifier, function_address, function_offset = owner
            site_address = section.virtual_address + offset
            sites.append(
                f"literal:{section.name}:0x{site_address:08x}:"
                f"0x{target:08x}->{identifier}+0x{function_offset:x}"
            )
            targets.add(identifier)
            matches += 1
        by_section[section.name] = matches
    return sorted(sites), targets, {
        "scanStrideBytes": 1,
        "scannedRawBytes": scanned_bytes,
        "includesSectionRawPadding": True,
        "targetRule": "any little-endian PE32 value inside a recovered function span",
        "matchesBySection": dict(sorted(by_section.items())),
        "literalSiteCount": len(sites),
    }


def _cross_function_branch_sites(
    index_by_id: dict[str, dict[str, Any]],
    spans: list[tuple[int, int, str, str]],
) -> tuple[list[str], set[str], dict[str, Any]]:
    sites = []
    targets = set()
    kinds: dict[str, int] = {}
    for source_id, row in sorted(index_by_id.items()):
        for item in row.get("branch_sites", []):
            target_address = item.get("target")
            if not isinstance(target_address, str):
                continue
            owner = _span_owner(int(target_address, 16), spans)
            if owner is None or owner[0] == source_id:
                continue
            target_id, _, target_offset = owner
            kind = item.get("kind")
            sites.append(
                f"direct-branch:{item['address']}:{kind}:{source_id}"
                f"->{target_id}+0x{target_offset:x}"
            )
            targets.add(target_id)
            kinds[kind] = kinds.get(kind, 0) + 1
    return sorted(sites), targets, {
        "crossFunctionDirectBranchSiteCount": len(sites),
        "crossFunctionDirectBranchTargetCount": len(targets),
        "crossFunctionDirectBranchKinds": dict(sorted(kinds.items())),
        "reason": (
            "native_code_map calls exclude direct cross-function jmp/tail edges; "
            "the branch-site index supplies those inbound paths explicitly"
        ),
    }


def _instruction_map(image: PeImage) -> dict[int, Any]:
    _, decoder_type, decoder_mode, _ = _native_dependencies()
    decoder = decoder_type(*decoder_mode)
    decoder.detail = True
    decoder.skipdata = True
    instructions = {}
    for section in image.sections:
        if not section.executable:
            continue
        raw = image.data[
            section.raw_offset:section.raw_offset + section.raw_size
        ]
        for instruction in decoder.disasm(raw, section.virtual_address):
            if instruction.id:
                instructions[instruction.address] = instruction
    return instructions


_INDIRECT_SITE_CLASSIFICATIONS = {
    "ABSOLUTE_MEMORY_BRANCH",
    "ADJUSTED_VPTR",
    "CFG_CARRIED_MEMORY_BRANCH",
    "CFG_CARRIED_MEMORY_TARGET",
    "INDEXED_MEMORY_BRANCH",
    "LOCAL_DEFINED_MEMORY_BRANCH",
    "LOCAL_DEFINED_MEMORY_TARGET",
    "REGISTER_BRANCH",
    "REGISTER_TARGET",
    "TAIL_VPTR",
    "UNDECODED",
    "CANONICAL_VPTR",
}


def _memory_operand_identity(
    instruction: Any, memory: Any,
) -> dict[str, Any]:
    return {
        "base": _register_family(instruction, memory.base),
        "index": _register_family(instruction, memory.index),
        "scale": memory.scale,
        "displacement": memory.disp,
    }


def _indirect_site_classification(
    row: dict[str, Any], address: int, site: str,
    instructions: dict[int, Any], *, transfer_kind: str,
    ordered_addresses: list[int] | None = None,
) -> dict[str, Any]:
    """Classify one indirect transfer without making a target claim."""
    try:
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    instruction = instructions.get(address)
    if instruction is None or len(instruction.operands) != 1:
        return {
            "site": site,
            "transferKind": transfer_kind,
            "classification": "UNDECODED",
            "instructionAddress": f"0x{address:08x}",
            "instructionMnemonic": None,
            "instructionSha256": None,
            "operand": None,
            "nearestBaseDefinition": None,
        }
    operand = instruction.operands[0]
    common = {
        "site": site,
        "transferKind": transfer_kind,
        "instructionAddress": f"0x{address:08x}",
        "instructionMnemonic": instruction.mnemonic,
        "instructionSha256": _instruction_sha256(instruction),
    }
    if operand.type == X86_OP_REG:
        return {
            **common,
            "classification": (
                "REGISTER_TARGET"
                if transfer_kind == "call" else "REGISTER_BRANCH"
            ),
            "operand": {
                "kind": "register",
                "register": _register_family(instruction, operand.reg),
            },
            "nearestBaseDefinition": None,
        }
    if operand.type != X86_OP_MEM:
        return {
            **common,
            "classification": "UNDECODED",
            "operand": {"kind": "other"},
            "nearestBaseDefinition": None,
        }
    memory_identity = _memory_operand_identity(instruction, operand.mem)
    operand_identity = {"kind": "memory", **memory_identity}
    base = memory_identity["base"]
    if transfer_kind == "branch" and base is None:
        classification = (
            "INDEXED_MEMORY_BRANCH"
            if memory_identity["index"] is not None
            else "ABSOLUTE_MEMORY_BRANCH"
        )
        return {
            **common,
            "classification": classification,
            "operand": operand_identity,
            "nearestBaseDefinition": None,
        }

    block = next(
        (
            (int(candidate["start"], 16), int(candidate["end"], 16))
            for candidate in row.get("basic_blocks", [])
            if int(candidate["start"], 16)
            <= address < int(candidate["end"], 16)
        ),
        None,
    )
    definition = None
    if base is not None and block is not None:
        if ordered_addresses is None:
            ordered_addresses = sorted(instructions)
        first = bisect.bisect_left(ordered_addresses, block[0])
        last = bisect.bisect_left(ordered_addresses, address)
        prior = [
            instructions[candidate_address]
            for candidate_address in ordered_addresses[first:last]
        ]
        for candidate in reversed(prior):
            try:
                _read, written = candidate.regs_access()
            except Exception:
                break
            if base in {
                family
                for register in written
                if (family := _register_family(
                    candidate, register,
                )) is not None
            }:
                definition = candidate
                break
    definition_identity = None
    exact_memory_load = False
    source_memory = None
    if definition is not None:
        source_kind = "other"
        if definition.mnemonic == "mov" \
                and len(definition.operands) == 2:
            destination, source = definition.operands
            if destination.type == X86_OP_REG \
                    and _register_family(
                        definition, destination.reg,
                    ) == base:
                if source.type == X86_OP_MEM:
                    source_kind = "memory"
                    source_memory = _memory_operand_identity(
                        definition, source.mem,
                    )
                    exact_memory_load = True
                elif source.type == X86_OP_REG:
                    source_kind = "register"
                elif source.type == X86_OP_IMM:
                    source_kind = "immediate"
        definition_identity = {
            "address": f"0x{definition.address:08x}",
            "mnemonic": definition.mnemonic,
            "instructionSha256": _instruction_sha256(definition),
            "sourceKind": source_kind,
            "sourceMemory": source_memory,
        }
    if exact_memory_load:
        canonical = source_memory == {
            "base": source_memory["base"],
            "index": None,
            "scale": 1,
            "displacement": 0,
        } and source_memory["base"] is not None
        if transfer_kind == "call":
            classification = (
                "CANONICAL_VPTR" if canonical else "ADJUSTED_VPTR"
            )
        else:
            classification = (
                "TAIL_VPTR" if canonical
                else "LOCAL_DEFINED_MEMORY_BRANCH"
            )
    elif definition is None:
        classification = (
            "CFG_CARRIED_MEMORY_TARGET"
            if transfer_kind == "call"
            else "CFG_CARRIED_MEMORY_BRANCH"
        )
    else:
        classification = (
            "LOCAL_DEFINED_MEMORY_TARGET"
            if transfer_kind == "call"
            else "LOCAL_DEFINED_MEMORY_BRANCH"
        )
    return {
        **common,
        "classification": classification,
        "operand": operand_identity,
        "nearestBaseDefinition": definition_identity,
    }


def _exact_switch_recoveries(
    image: PeImage, row: dict[str, Any], instructions: dict[int, Any],
) -> dict[int, dict[str, Any]]:
    """Recover exact, locally bounded x86 jump tables.

    This deliberately rejects byte-remap tables, register-computed bases and
    cross-function targets.  The accepted shape has one mechanical proof:

    * the jump operand is ``[index*4 + absolute_table]``;
    * the immediately preceding instruction is ``ja``/``jae`` whose fallthrough
      is the jump;
    * the most recent EFLAGS writer in that conditional block is
      ``cmp index, immediate``;
    * the compared index is not written before the jump;
    * the default and every table entry are decoded basic-block starts inside
      this recovered function.
    """
    try:
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error

    function_start = int(row["address"], 16)
    function_end = int(row["end"], 16)
    block_spans = [
        (int(block["start"], 16), int(block["end"], 16))
        for block in row.get("basic_blocks", [])
    ]
    block_starts = {start for start, _end in block_spans}
    function_instructions = [
        instructions[address]
        for address in sorted(instructions)
        if function_start <= address < function_end
    ]
    position = {
        instruction.address: index
        for index, instruction in enumerate(function_instructions)
    }
    conditional_sites = {
        int(branch["address"], 16): branch
        for branch in row.get("branch_sites", [])
        if isinstance(branch, dict)
        and branch.get("kind") == "direct_conditional"
        and isinstance(branch.get("address"), str)
        and isinstance(branch.get("target"), str)
    }
    recoveries = {}
    for branch in row.get("branch_sites", []):
        if branch.get("kind") != "unresolved_switch_or_indirect_jump" \
                or not isinstance(branch.get("address"), str):
            continue
        branch_address = int(branch["address"], 16)
        jump = instructions.get(branch_address)
        if jump is None or jump.mnemonic != "jmp" \
                or len(jump.operands) != 1 \
                or jump.operands[0].type != X86_OP_MEM:
            continue
        memory = jump.operands[0].mem
        if memory.base or not memory.index or memory.scale != 4:
            continue
        jump_position = position.get(branch_address)
        if jump_position is None or jump_position == 0:
            continue
        conditional = function_instructions[jump_position - 1]
        conditional_site = conditional_sites.get(conditional.address)
        if conditional.mnemonic not in {"ja", "jae"} \
                or conditional_site is None \
                or len(conditional.operands) != 1 \
                or conditional.operands[0].type != X86_OP_IMM \
                or conditional.address + conditional.size != branch_address:
            continue
        default_target = conditional.operands[0].imm & 0xFFFFFFFF
        if int(conditional_site["target"], 16) != default_target \
                or default_target not in instructions \
                or default_target not in block_starts \
                or not function_start <= default_target < function_end:
            continue
        conditional_block = next(
            (
                (start, end) for start, end in block_spans
                if start <= conditional.address < end
            ),
            None,
        )
        if conditional_block is None:
            continue
        prior = [
            instruction for instruction in function_instructions
            if conditional_block[0] <= instruction.address < conditional.address
        ]
        comparison = next(
            (
                instruction for instruction in reversed(prior)
                if instruction.eflags
            ),
            None,
        )
        index_family = _register_family(jump, memory.index)
        if index_family is None \
                or comparison is None or comparison.mnemonic != "cmp" \
                or len(comparison.operands) != 2 \
                or comparison.operands[0].type != X86_OP_REG \
                or comparison.operands[1].type != X86_OP_IMM \
                or _register_family(
                    comparison, comparison.operands[0].reg,
                ) != index_family:
            continue
        index_changed = False
        for instruction in function_instructions[
            position[comparison.address] + 1:jump_position
        ]:
            try:
                _read, written = instruction.regs_access()
            except Exception:
                index_changed = True
                break
            if index_family in {
                family for register in written
                if (family := _register_family(
                    instruction, register,
                )) is not None
            }:
                index_changed = True
                break
        if index_changed:
            continue
        bound = comparison.operands[1].imm
        if bound < 0:
            continue
        entry_count = bound + (1 if conditional.mnemonic == "ja" else 0)
        if not 1 <= entry_count <= 4096:
            continue
        table_address = memory.disp & 0xFFFFFFFF
        try:
            table_bytes = image.bytes_at(table_address, entry_count * 4)
            entries = list(struct.unpack(
                f"<{entry_count}I", table_bytes,
            ))
        except (ValueError, struct.error):
            continue
        if any(
            target not in instructions
            or target not in block_starts
            or not function_start <= target < function_end
            for target in entries
        ):
            continue
        recoveries[branch_address] = {
            "branchAddress": f"0x{branch_address:08x}",
            "boundBranchMnemonic": conditional.mnemonic,
            "comparisonAddress": f"0x{comparison.address:08x}",
            "defaultBranchAddress": f"0x{conditional.address:08x}",
            "defaultTargetAddress": f"0x{default_target:08x}",
            "indexRegister": index_family,
            "inclusiveUpperBound": (
                bound if conditional.mnemonic == "ja" else bound - 1
            ),
            "tableAddress": f"0x{table_address:08x}",
            "tableEntryCount": entry_count,
            "tableEntries": [
                f"0x{target:08x}" for target in entries
            ],
            "tableSha256": hashlib.sha256(table_bytes).hexdigest(),
        }
    return recoveries


def _exact_remapped_switch_recoveries(
    image: PeImage, row: dict[str, Any], instructions: dict[int, Any],
) -> dict[int, dict[str, Any]]:
    """Recover bounded byte-remap jump tables emitted for sparse switches."""
    try:
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error

    function_start = int(row["address"], 16)
    function_end = int(row["end"], 16)
    function_instructions = [
        instructions[address]
        for address in sorted(instructions)
        if function_start <= address < function_end
    ]
    position = {
        instruction.address: index
        for index, instruction in enumerate(function_instructions)
    }
    block_starts = {
        int(block["start"], 16)
        for block in row.get("basic_blocks", [])
    }
    conditional_sites = {
        int(branch["address"], 16): branch
        for branch in row.get("branch_sites", [])
        if isinstance(branch, dict)
        and branch.get("kind") == "direct_conditional"
        and isinstance(branch.get("address"), str)
        and isinstance(branch.get("target"), str)
    }
    recoveries = {}
    for branch in row.get("branch_sites", []):
        if branch.get("kind") != "unresolved_switch_or_indirect_jump" \
                or not isinstance(branch.get("address"), str):
            continue
        branch_address = int(branch["address"], 16)
        jump = instructions.get(branch_address)
        if jump is None or jump.mnemonic != "jmp" \
                or len(jump.operands) != 1 \
                or jump.operands[0].type != X86_OP_MEM:
            continue
        jump_memory = jump.operands[0].mem
        if jump_memory.base or not jump_memory.index \
                or jump_memory.scale != 4:
            continue
        jump_index_family = _register_family(jump, jump_memory.index)
        jump_position = position.get(branch_address)
        if jump_index_family is None or jump_position is None:
            continue
        prior = function_instructions[max(0, jump_position - 16):jump_position]
        remap_load = next(
            (
                instruction for instruction in reversed(prior)
                if instruction.mnemonic == "mov"
                and len(instruction.operands) == 2
                and instruction.operands[0].type == X86_OP_REG
                and instruction.operands[1].type == X86_OP_MEM
                and _register_family(
                    instruction, instruction.operands[0].reg,
                ) == jump_index_family
            ),
            None,
        )
        if remap_load is None:
            continue
        remap_memory = remap_load.operands[1].mem
        source_register = remap_memory.base or remap_memory.index
        source_family = _register_family(remap_load, source_register)
        if source_family is None \
                or bool(remap_memory.base) == bool(remap_memory.index) \
                or remap_memory.scale not in {0, 1}:
            continue
        conditional = next(
            (
                instruction for instruction in reversed(prior)
                if instruction.address < remap_load.address
                and instruction.address in conditional_sites
                and instruction.mnemonic in {"ja", "jae"}
                and len(instruction.operands) == 1
                and instruction.operands[0].type == X86_OP_IMM
            ),
            None,
        )
        if conditional is None:
            continue
        conditional_site = conditional_sites[conditional.address]
        conditional_position = position[conditional.address]
        comparison = next(
            (
                instruction
                for instruction in reversed(
                    function_instructions[
                        max(0, conditional_position - 8):conditional_position
                    ]
                )
                if instruction.mnemonic == "cmp"
                and len(instruction.operands) == 2
                and instruction.operands[0].type == X86_OP_REG
                and instruction.operands[1].type == X86_OP_IMM
                and _register_family(
                    instruction, instruction.operands[0].reg,
                ) == source_family
            ),
            None,
        )
        if comparison is None:
            continue
        default_target = conditional.operands[0].imm & 0xFFFFFFFF
        if int(conditional_site["target"], 16) != default_target \
                or default_target not in block_starts:
            continue
        source_changed = False
        for instruction in function_instructions[
            position[comparison.address] + 1:position[remap_load.address]
        ]:
            try:
                _read, written = instruction.regs_access()
            except Exception:
                source_changed = True
                break
            if source_family in {
                family for register in written
                if (family := _register_family(
                    instruction, register,
                )) is not None
            }:
                source_changed = True
                break
        if source_changed:
            continue
        bound = comparison.operands[1].imm
        if bound < 0:
            continue
        remap_entry_count = bound + (
            1 if conditional.mnemonic == "ja" else 0
        )
        if not 1 <= remap_entry_count <= 4096:
            continue
        remap_address = remap_memory.disp & 0xFFFFFFFF
        try:
            remap_bytes = image.bytes_at(remap_address, remap_entry_count)
        except ValueError:
            continue
        table_entry_count = max(remap_bytes) + 1
        if not 1 <= table_entry_count <= 256:
            continue
        table_address = jump_memory.disp & 0xFFFFFFFF
        try:
            table_bytes = image.bytes_at(
                table_address, table_entry_count * 4,
            )
            table_entries = list(struct.unpack(
                f"<{table_entry_count}I", table_bytes,
            ))
        except (ValueError, struct.error):
            continue
        if set(remap_bytes) != set(range(table_entry_count)) \
                or any(
                    target not in instructions
                    or target not in block_starts
                    or not function_start <= target < function_end
                    for target in table_entries
                ):
            continue
        recoveries[branch_address] = {
            "branchAddress": f"0x{branch_address:08x}",
            "boundBranchMnemonic": conditional.mnemonic,
            "comparisonAddress": f"0x{comparison.address:08x}",
            "defaultBranchAddress": f"0x{conditional.address:08x}",
            "defaultTargetAddress": f"0x{default_target:08x}",
            "sourceIndexRegister": source_family,
            "remapIndexRegister": jump_index_family,
            "inclusiveUpperBound": (
                bound if conditional.mnemonic == "ja" else bound - 1
            ),
            "remapAddress": f"0x{remap_address:08x}",
            "remapEntryCount": remap_entry_count,
            "remapSha256": hashlib.sha256(remap_bytes).hexdigest(),
            "remapValues": list(remap_bytes),
            "tableAddress": f"0x{table_address:08x}",
            "tableEntryCount": table_entry_count,
            "tableEntries": [
                f"0x{target:08x}" for target in table_entries
            ],
            "tableSha256": hashlib.sha256(table_bytes).hexdigest(),
        }
    return recoveries


_REGISTER_FAMILIES = {
    "eax": "eax", "ax": "eax", "al": "eax", "ah": "eax",
    "ebx": "ebx", "bx": "ebx", "bl": "ebx", "bh": "ebx",
    "ecx": "ecx", "cx": "ecx", "cl": "ecx", "ch": "ecx",
    "edx": "edx", "dx": "edx", "dl": "edx", "dh": "edx",
    "esi": "esi", "si": "esi",
    "edi": "edi", "di": "edi",
    "ebp": "ebp", "bp": "ebp",
    "esp": "esp", "sp": "esp",
}
_VOLATILE_REGISTER_FAMILIES = frozenset({"eax", "ecx", "edx"})


def _register_family(instruction: Any, register: int) -> str | None:
    try:
        return _REGISTER_FAMILIES.get(instruction.reg_name(register))
    except Exception:
        return None


def _join_register_states(
    states: list[dict[str, tuple[tuple[str, ...], str]]],
) -> dict[str, tuple[tuple[str, ...], str]]:
    if not states:
        return {}
    joined = {}
    for register, value in states[0].items():
        symbol = value[1]
        incoming = [state.get(register) for state in states]
        if any(item is None or item[1] != symbol for item in incoming):
            continue
        definitions = tuple(sorted({
            definition
            for item in incoming
            for definition in item[0]
        }))
        joined[register] = (definitions, symbol)
    return joined


def _register_dataflow_roots(
    predecessors: dict[int, set[int]], entry: int,
    external_roots: set[int],
) -> set[int]:
    """Return every entry that must start without inherited register facts."""
    return {
        entry,
        *external_roots,
        *(
            start for start, sources in predecessors.items()
            if not sources
        ),
    }


def _transfer_register_import_state(
    state: dict[str, tuple[tuple[str, ...], str]],
    block_instructions: list[Any],
    imports: dict[int, str], *, collect: bool,
) -> tuple[
    dict[str, tuple[tuple[str, ...], str]],
    dict[int, tuple[tuple[str, ...], str]],
]:
    try:
        from capstone.x86 import X86_OP_MEM, X86_OP_REG
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    current = dict(state)
    resolved = {}
    for instruction in block_instructions:
        operands = instruction.operands
        if instruction.mnemonic == "call" and operands \
                and operands[0].type == X86_OP_REG:
            family = _register_family(instruction, operands[0].reg)
            if collect and family in current:
                resolved[instruction.address] = current[family]

        try:
            _, written = instruction.regs_access()
        except Exception:
            written = ()
        written_families = {
            family for register in written
            if (family := _register_family(instruction, register)) is not None
        }
        assignment_family = None
        assignment_value = None
        if instruction.mnemonic == "mov" and len(operands) == 2 \
                and operands[0].type == X86_OP_REG:
            assignment_family = _register_family(
                instruction, operands[0].reg,
            )
            source = operands[1]
            if assignment_family is not None \
                    and source.type == X86_OP_MEM \
                    and source.mem.base == 0 and source.mem.index == 0:
                import_address = source.mem.disp & 0xFFFFFFFF
                symbol = imports.get(import_address)
                if symbol is not None:
                    assignment_value = (
                        (f"0x{instruction.address:08x}",), symbol,
                    )
            elif assignment_family is not None and source.type == X86_OP_REG:
                source_family = _register_family(instruction, source.reg)
                assignment_value = current.get(source_family)
        for family in written_families:
            current.pop(family, None)
        if assignment_family is not None and assignment_value is not None:
            current[assignment_family] = assignment_value
        if instruction.mnemonic == "call":
            for family in _VOLATILE_REGISTER_FAMILIES:
                current.pop(family, None)
    return current, resolved


def _resolved_register_import_calls(
    image: PeImage, row: dict[str, Any], instructions: dict[int, Any],
    imports: dict[int, str], external_entry_addresses: set[int],
) -> dict[int, tuple[tuple[str, ...], str]]:
    """Resolve import-valued registers with a conservative CFG dataflow."""
    blocks = [
        (int(block["start"], 16), int(block["end"], 16))
        for block in row.get("basic_blocks", [])
    ]
    if not blocks:
        return {}
    blocks.sort()
    function_start = int(row["address"], 16)
    function_end = int(row["end"], 16)
    function_addresses = [
        address for address in sorted(instructions)
        if function_start <= address < function_end
    ]
    block_by_address = {}
    instructions_by_block = {start: [] for start, _ in blocks}
    block_index = 0
    for address in function_addresses:
        while block_index + 1 < len(blocks) \
                and address >= blocks[block_index][1]:
            block_index += 1
        start, end = blocks[block_index]
        if start <= address < end:
            block_by_address[address] = start
            instructions_by_block[start].append(instructions[address])
    successors = {start: set() for start, _ in blocks}
    block_starts = set(successors)
    branch_by_address = {
        int(branch["address"], 16): branch
        for branch in row.get("branch_sites", [])
        if isinstance(branch, dict) and isinstance(branch.get("address"), str)
    }
    switch_recoveries = _exact_switch_recoveries(image, row, instructions)
    for index, (start, _end) in enumerate(blocks):
        block_instructions = instructions_by_block[start]
        if not block_instructions:
            continue
        last = block_instructions[-1]
        branch = branch_by_address.get(last.address)
        next_block = blocks[index + 1][0] if index + 1 < len(blocks) else None
        if branch is not None and isinstance(branch.get("target"), str):
            target_block = block_by_address.get(int(branch["target"], 16))
            if target_block in block_starts:
                successors[start].add(target_block)
            if branch.get("kind") == "direct_conditional" \
                    and next_block is not None:
                successors[start].add(next_block)
        elif branch is not None \
                and branch.get("kind") == "unresolved_switch_or_indirect_jump":
            recovery = switch_recoveries.get(last.address)
            if recovery is not None:
                successors[start].update(
                    block_by_address[int(target, 16)]
                    for target in recovery["tableEntries"]
                )
        elif last.mnemonic not in {"ret", "retf", "jmp"} \
                and next_block is not None:
            successors[start].add(next_block)
    predecessors = {start: set() for start, _ in blocks}
    for source, targets in successors.items():
        for target in targets:
            predecessors[target].add(source)

    entry = blocks[0][0]
    external_roots = {
        block_by_address[address]
        for address in external_entry_addresses
        if address in block_by_address
    }
    dataflow_roots = _register_dataflow_roots(
        predecessors, entry, external_roots,
    )
    incoming: dict[
        int, dict[str, tuple[tuple[str, ...], str]] | None
    ] = {
        start: None for start, _ in blocks
    }
    outgoing: dict[
        int, dict[str, tuple[tuple[str, ...], str]] | None
    ] = {
        start: None for start, _ in blocks
    }
    changed = True
    while changed:
        changed = False
        for start, _end in blocks:
            if start in dataflow_roots:
                next_incoming = {}
            else:
                reachable = [
                    outgoing[source]
                    for source in sorted(predecessors[start])
                    if outgoing[source] is not None
                ]
                if not reachable:
                    continue
                next_incoming = _join_register_states(reachable)
            next_outgoing, _ = _transfer_register_import_state(
                next_incoming, instructions_by_block[start], imports,
                collect=False,
            )
            if incoming[start] != next_incoming \
                    or outgoing[start] != next_outgoing:
                incoming[start] = next_incoming
                outgoing[start] = next_outgoing
                changed = True

    resolved = {}
    for start, _end in blocks:
        if incoming[start] is None:
            continue
        _, block_resolved = _transfer_register_import_state(
            incoming[start], instructions_by_block[start], imports,
            collect=True,
        )
        resolved.update(block_resolved)
    return resolved


def _instruction_sha256(instruction: Any) -> str:
    return hashlib.sha256(bytes(instruction.bytes)).hexdigest()


def _direct_call_xrefs(
    index_by_id: dict[str, dict[str, Any]], instructions: dict[int, Any],
) -> tuple[
    dict[str, list[tuple[str, Any]]],
    dict[str, list[Any]],
]:
    """Inventory direct calls to exact recovered entry points."""
    try:
        from capstone.x86 import X86_OP_IMM
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    entry_ids = {
        int(row["address"], 16): identifier
        for identifier, row in index_by_id.items()
    }
    function_instructions = {}
    xrefs = {identifier: [] for identifier in index_by_id}
    for identifier, row in sorted(index_by_id.items()):
        start = int(row["address"], 16)
        end = int(row["end"], 16)
        decoded = [
            instructions[address]
            for address in sorted(instructions)
            if start <= address < end
        ]
        function_instructions[identifier] = decoded
        for instruction in decoded:
            if instruction.mnemonic != "call" \
                    or len(instruction.operands) != 1 \
                    or instruction.operands[0].type != X86_OP_IMM:
                continue
            target = instruction.operands[0].imm & 0xFFFFFFFF
            target_id = entry_ids.get(target)
            if target_id is not None:
                xrefs[target_id].append((identifier, instruction))
    return xrefs, function_instructions


def _owns_ebp_frame(instructions: list[Any]) -> bool:
    """Accept only the exact conventional ``push ebp; mov ebp, esp`` prologue."""
    try:
        from capstone.x86 import X86_OP_REG
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    if len(instructions) < 2:
        return False
    push, move = instructions[:2]
    return (
        push.mnemonic == "push"
        and len(push.operands) == 1
        and push.operands[0].type == X86_OP_REG
        and _register_family(push, push.operands[0].reg) == "ebp"
        and move.mnemonic == "mov"
        and len(move.operands) == 2
        and all(operand.type == X86_OP_REG for operand in move.operands)
        and _register_family(move, move.operands[0].reg) == "ebp"
        and _register_family(move, move.operands[1].reg) == "esp"
    )


def _ebp_parameter_index(instruction: Any, operand: Any) -> int | None:
    try:
        from capstone.x86 import X86_OP_MEM
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    if operand.type != X86_OP_MEM or operand.mem.index \
            or _register_family(instruction, operand.mem.base) != "ebp":
        return None
    displacement = operand.mem.disp
    if displacement < 8 or (displacement - 8) % 4:
        return None
    return (displacement - 8) // 4


def _stack_argument_expression(
    caller_id: str, call: Any, parameter_index: int,
    index_by_id: dict[str, dict[str, Any]],
    function_instructions: dict[str, list[Any]],
) -> dict[str, Any] | None:
    """Recover one cdecl/stdcall argument from contiguous push setup."""
    try:
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    row = index_by_id[caller_id]
    block_start = next(
        (
            int(block["start"], 16)
            for block in row.get("basic_blocks", [])
            if int(block["start"], 16) <= call.address
            < int(block["end"], 16)
        ),
        None,
    )
    if block_start is None:
        return None
    prior = [
        instruction
        for instruction in function_instructions[caller_id]
        if block_start <= instruction.address < call.address
    ]
    pushes_seen = 0
    for instruction in reversed(prior):
        if instruction.mnemonic == "push" and len(instruction.operands) == 1:
            if pushes_seen != parameter_index:
                pushes_seen += 1
                continue
            operand = instruction.operands[0]
            common = {
                "sourceFunctionId": caller_id,
                "callAddress": f"0x{call.address:08x}",
                "callInstructionSha256": _instruction_sha256(call),
                "argumentPushAddress": f"0x{instruction.address:08x}",
                "argumentInstructionSha256": _instruction_sha256(instruction),
                "parameterIndex": parameter_index,
            }
            if operand.type == X86_OP_IMM:
                return {
                    **common,
                    "expression": "INTERNAL_FUNCTION_LITERAL",
                    "value": f"0x{operand.imm & 0xFFFFFFFF:08x}",
                }
            forwarded_index = _ebp_parameter_index(instruction, operand)
            if operand.type == X86_OP_MEM and forwarded_index is not None:
                return {
                    **common,
                    "expression": "CALLER_EBP_PARAMETER",
                    "forwardedParameterIndex": forwarded_index,
                }
            return None
        if instruction.mnemonic in {
            "call", "jmp", "ret", "retf", "leave", "pop",
        }:
            return None
        try:
            _read, written = instruction.regs_access()
        except Exception:
            return None
        if any(
            _register_family(instruction, register) == "esp"
            for register in written
        ):
            return None
    return None


def _exact_stack_parameter_call_recoveries(
    image: PeImage, index_by_id: dict[str, dict[str, Any]],
    instructions: dict[int, Any],
    spans: list[tuple[int, int, str, str]],
) -> dict[int, dict[str, Any]]:
    """Resolve exact internal targets passed through EBP stack parameters.

    A site closes only when every direct caller can be reduced to internal
    function-entry literals. A prologueless helper may inherit EBP from all of
    its direct callers, which covers compiler-generated exception funclets
    without assigning them semantic names.
    """
    try:
        from capstone.x86 import X86_OP_MEM
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    xrefs, function_instructions = _direct_call_xrefs(
        index_by_id, instructions,
    )
    _root_sites, loader_root_ids, _root_gaps, _root_evidence = (
        _pe_root_entries(image, spans)
    )
    direct_branch_targets: dict[int, int] = {}
    for row in index_by_id.values():
        for branch in row.get("branch_sites", []):
            if isinstance(branch, dict) \
                    and isinstance(branch.get("target"), str):
                target = int(branch["target"], 16)
                direct_branch_targets[target] = (
                    direct_branch_targets.get(target, 0) + 1
                )

    def absolute_pointer_site_count(address: int) -> int:
        needle = struct.pack("<I", address)
        count = 0
        for section in image.sections:
            raw = image.data[
                section.raw_offset:section.raw_offset + section.raw_size
            ]
            count += sum(
                raw[offset:offset + 4] == needle
                for offset in range(max(0, len(raw) - 3))
            )
        return count
    def resolve_frame_parameter(
        identifier: str, parameter_index: int,
        active: frozenset[tuple[str, int]],
    ) -> list[dict[str, Any]] | None:
        key = (identifier, parameter_index)
        if key in active:
            return None
        next_active = active | {key}
        decoded = function_instructions[identifier]
        callers = xrefs.get(identifier, [])
        if not callers:
            return None
        proofs = []
        if _owns_ebp_frame(decoded):
            for caller_id, call in callers:
                expression = _stack_argument_expression(
                    caller_id, call, parameter_index,
                    index_by_id, function_instructions,
                )
                if expression is None:
                    return None
                if expression["expression"] == "INTERNAL_FUNCTION_LITERAL":
                    address = int(expression["value"], 16)
                    owner = _span_owner(address, spans)
                    if owner is None or address not in instructions:
                        return None
                    proofs.append({
                        "targetAddress": expression["value"],
                        "targetFunctionId": owner[0],
                        "targetFunctionOffset": f"0x{owner[2]:x}",
                        "frameRoute": [identifier],
                        "steps": [expression],
                    })
                    continue
                nested = resolve_frame_parameter(
                    caller_id, expression["forwardedParameterIndex"],
                    next_active,
                )
                if nested is None:
                    return None
                for proof in nested:
                    proofs.append({
                        **proof,
                        "frameRoute": [identifier, *proof["frameRoute"]],
                        "steps": [expression, *proof["steps"]],
                    })
            return proofs

        for instruction in decoded:
            try:
                _read, written = instruction.regs_access()
            except Exception:
                return None
            if any(
                _register_family(instruction, register) == "ebp"
                for register in written
            ):
                return None
        for caller_id, call in callers:
            nested = resolve_frame_parameter(
                caller_id, parameter_index, next_active,
            )
            if nested is None:
                return None
            inherited_step = {
                "sourceFunctionId": caller_id,
                "callAddress": f"0x{call.address:08x}",
                "callInstructionSha256": _instruction_sha256(call),
                "expression": "INHERITED_EBP_FRAME",
                "frameFunctionId": identifier,
                "parameterIndex": parameter_index,
            }
            for proof in nested:
                proofs.append({
                    **proof,
                    "frameRoute": [identifier, *proof["frameRoute"]],
                    "steps": [inherited_step, *proof["steps"]],
                })
        return proofs

    recoveries = {}
    for identifier, row in sorted(index_by_id.items()):
        for item in row.get("unresolved_indirect_calls", []):
            address = int(item["address"], 16)
            instruction = instructions.get(address)
            if instruction is None or item.get("kind") != "memory" \
                    or instruction.mnemonic != "call" \
                    or len(instruction.operands) != 1 \
                    or instruction.operands[0].type != X86_OP_MEM:
                continue
            parameter_index = _ebp_parameter_index(
                instruction, instruction.operands[0],
            )
            if parameter_index is None:
                continue
            proofs = resolve_frame_parameter(
                identifier, parameter_index, frozenset(),
            )
            if not proofs:
                continue
            function_entry = int(row["address"], 16)
            pointer_site_count = absolute_pointer_site_count(function_entry)
            branch_xref_count = direct_branch_targets.get(function_entry, 0)
            is_loader_root = identifier in loader_root_ids
            if pointer_site_count or branch_xref_count or is_loader_root:
                continue
            proofs.sort(key=lambda proof: (
                proof["targetFunctionId"],
                proof["targetAddress"],
                sha256_json(proof),
            ))
            target_ids = sorted({
                proof["targetFunctionId"] for proof in proofs
            })
            target_addresses = sorted({
                proof["targetAddress"] for proof in proofs
            })
            recoveries[address] = {
                "functionId": identifier,
                "callAddress": f"0x{address:08x}",
                "callInstructionSha256": _instruction_sha256(instruction),
                "operandBase": "ebp",
                "operandDisplacement": (
                    instruction.operands[0].mem.disp
                ),
                "parameterIndex": parameter_index,
                "entryInboundProof": {
                    "directCallXrefCount": len(xrefs[identifier]),
                    "absolutePointerSiteCount": pointer_site_count,
                    "directBranchXrefCount": branch_xref_count,
                    "isLoaderRoot": is_loader_root,
                },
                "targetAddresses": target_addresses,
                "targetFunctionIds": target_ids,
                "xrefProofs": proofs,
                "proofSha256": sha256_json(proofs),
            }
    return recoveries


def _exact_assigned_vtables(
    image: PeImage, instructions: dict[int, Any],
    spans: list[tuple[int, int, str, str]],
) -> dict[int, dict[str, Any]]:
    """Recover code-pointer tables whose starts are written as immediates."""
    try:
        from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    assignments: dict[int, list[str]] = {}
    for instruction in instructions.values():
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2 \
                or instruction.operands[0].type != X86_OP_MEM \
                or instruction.operands[1].type != X86_OP_IMM:
            continue
        table_address = instruction.operands[1].imm & 0xFFFFFFFF
        section = next(
            (
                section for section in image.sections
                if not section.executable
                and section.virtual_address <= table_address
                < section.virtual_address + section.raw_size
            ),
            None,
        )
        if section is None:
            continue
        try:
            first_target = struct.unpack(
                "<I", image.bytes_at(table_address, 4)
            )[0]
        except (ValueError, struct.error):
            continue
        if _span_owner(first_target, spans) is None:
            continue
        assignments.setdefault(table_address, []).append(
            f"0x{instruction.address:08x}"
        )
    starts = sorted(assignments)
    tables = {}
    for table_address in starts:
        targets = []
        for slot in range(256):
            address = table_address + slot * 4
            try:
                target = struct.unpack("<I", image.bytes_at(address, 4))[0]
            except (ValueError, struct.error):
                break
            owner = _span_owner(target, spans)
            if owner is None:
                break
            targets.append({
                "address": f"0x{target:08x}",
                "functionId": owner[0],
                "functionOffset": f"0x{owner[2]:x}",
            })
        if not targets:
            continue
        identity = {
            "tableAddress": f"0x{table_address:08x}",
            "assignmentSites": sorted(set(assignments[table_address])),
            "entries": targets,
        }
        tables[table_address] = {
            **identity,
            "tableSha256": hashlib.sha256(
                image.bytes_at(table_address, len(targets) * 4)
            ).hexdigest(),
            "identitySha256": sha256_json(identity),
        }
    return tables


def _resolved_this_vptr_calls(
    image: PeImage, row: dict[str, Any], instructions: dict[int, Any],
    external_entry_addresses: set[int],
    *, transfer_mnemonics: frozenset[str] = frozenset({"call"}),
) -> dict[int, dict[str, Any]]:
    """Find virtual transfers whose vptr is loaded from the entry ``this``."""
    try:
        from capstone.x86 import X86_OP_MEM, X86_OP_REG
    except ModuleNotFoundError as error:
        raise NativeReachabilityClosureError(
            "native closure generation requires pinned Capstone"
        ) from error
    blocks = [
        (int(block["start"], 16), int(block["end"], 16))
        for block in row.get("basic_blocks", [])
    ]
    if not blocks:
        return {}
    blocks.sort()
    function_start = int(row["address"], 16)
    function_end = int(row["end"], 16)
    function_addresses = [
        address for address in sorted(instructions)
        if function_start <= address < function_end
    ]
    block_by_address = {}
    instructions_by_block = {start: [] for start, _ in blocks}
    block_index = 0
    for address in function_addresses:
        while block_index + 1 < len(blocks) \
                and address >= blocks[block_index][1]:
            block_index += 1
        start, end = blocks[block_index]
        if start <= address < end:
            block_by_address[address] = start
            instructions_by_block[start].append(instructions[address])
    successors = {start: set() for start, _ in blocks}
    block_starts = set(successors)
    branch_by_address = {
        int(branch["address"], 16): branch
        for branch in row.get("branch_sites", [])
        if isinstance(branch, dict) and isinstance(branch.get("address"), str)
    }
    switch_recoveries = _exact_switch_recoveries(image, row, instructions)
    remapped_switches = _exact_remapped_switch_recoveries(
        image, row, instructions,
    )
    for index, (start, _end) in enumerate(blocks):
        decoded = instructions_by_block[start]
        if not decoded:
            continue
        last = decoded[-1]
        branch = branch_by_address.get(last.address)
        next_block = blocks[index + 1][0] if index + 1 < len(blocks) else None
        if branch is not None and isinstance(branch.get("target"), str):
            target_block = block_by_address.get(int(branch["target"], 16))
            if target_block in block_starts:
                successors[start].add(target_block)
            if branch.get("kind") == "direct_conditional" \
                    and next_block is not None:
                successors[start].add(next_block)
        elif branch is not None \
                and branch.get("kind") == "unresolved_switch_or_indirect_jump":
            recovery = switch_recoveries.get(last.address) \
                or remapped_switches.get(last.address)
            if recovery is not None:
                successors[start].update(
                    block_by_address[int(target, 16)]
                    for target in recovery["tableEntries"]
                )
        elif last.mnemonic not in {"ret", "retf", "jmp"} \
                and next_block is not None:
            successors[start].add(next_block)
    predecessors = {start: set() for start, _ in blocks}
    for source, targets in successors.items():
        for target in targets:
            predecessors[target].add(source)
    entry = blocks[0][0]
    external_roots = {
        block_by_address[address]
        for address in external_entry_addresses
        if address in block_by_address
    }
    roots = _register_dataflow_roots(predecessors, entry, external_roots)

    def join(states: list[dict[str, Any]]) -> dict[str, Any]:
        if not states:
            return {"aliases": frozenset(), "vptrs": {}}
        aliases = frozenset.intersection(*(
            state["aliases"] for state in states
        ))
        vptrs = {}
        for register, value in states[0]["vptrs"].items():
            offset = value[0]
            incoming = [state["vptrs"].get(register) for state in states]
            if any(item is None or item[0] != offset for item in incoming):
                continue
            definitions = tuple(sorted({
                definition
                for item in incoming
                for definition in item[1]
            }))
            vptrs[register] = (offset, definitions)
        return {"aliases": aliases, "vptrs": vptrs}

    def transfer(
        state: dict[str, Any], decoded: list[Any], *, collect: bool,
    ) -> tuple[dict[str, Any], dict[int, dict[str, Any]]]:
        aliases = set(state["aliases"])
        vptrs = dict(state["vptrs"])
        resolved = {}
        for instruction in decoded:
            operands = instruction.operands
            if instruction.mnemonic in transfer_mnemonics \
                    and len(operands) == 1 \
                    and operands[0].type == X86_OP_MEM:
                memory = operands[0].mem
                base = _register_family(instruction, memory.base)
                if collect and base in vptrs and not memory.index \
                        and memory.disp >= 0 and memory.disp % 4 == 0:
                    resolved[instruction.address] = {
                        "vptrOffset": vptrs[base][0],
                        "vptrLoadDefinitions": list(vptrs[base][1]),
                        "slotIndex": memory.disp // 4,
                    }
            try:
                _read, written = instruction.regs_access()
            except Exception:
                written = ()
            written_families = {
                family for register in written
                if (family := _register_family(
                    instruction, register,
                )) is not None
            }
            assignment_family = None
            assignment_alias = False
            assignment_vptr = None
            if instruction.mnemonic == "mov" and len(operands) == 2 \
                    and operands[0].type == X86_OP_REG:
                assignment_family = _register_family(
                    instruction, operands[0].reg,
                )
                source = operands[1]
                if source.type == X86_OP_REG:
                    source_family = _register_family(
                        instruction, source.reg,
                    )
                    assignment_alias = source_family in aliases
                    assignment_vptr = vptrs.get(source_family)
                elif source.type == X86_OP_MEM and not source.mem.index:
                    source_family = _register_family(
                        instruction, source.mem.base,
                    )
                    if source_family in aliases:
                        assignment_vptr = (
                            source.mem.disp,
                            (f"0x{instruction.address:08x}",),
                        )
            for family in written_families:
                aliases.discard(family)
                vptrs.pop(family, None)
            if assignment_family is not None:
                if assignment_alias:
                    aliases.add(assignment_family)
                if assignment_vptr is not None:
                    vptrs[assignment_family] = assignment_vptr
            if instruction.mnemonic == "call":
                for family in _VOLATILE_REGISTER_FAMILIES:
                    aliases.discard(family)
                    vptrs.pop(family, None)
        return {
            "aliases": frozenset(aliases),
            "vptrs": vptrs,
        }, resolved

    incoming = {start: None for start, _ in blocks}
    outgoing = {start: None for start, _ in blocks}
    changed = True
    while changed:
        changed = False
        for start, _end in blocks:
            if start == entry:
                next_incoming = {
                    "aliases": frozenset({"ecx"}),
                    "vptrs": {},
                }
            elif start in roots:
                next_incoming = {
                    "aliases": frozenset(),
                    "vptrs": {},
                }
            else:
                reachable = [
                    outgoing[source]
                    for source in sorted(predecessors[start])
                    if outgoing[source] is not None
                ]
                if not reachable:
                    continue
                next_incoming = join(reachable)
            next_outgoing, _ = transfer(
                next_incoming, instructions_by_block[start], collect=False,
            )
            if incoming[start] != next_incoming \
                    or outgoing[start] != next_outgoing:
                incoming[start] = next_incoming
                outgoing[start] = next_outgoing
                changed = True
    resolved = {}
    for start, _end in blocks:
        if incoming[start] is None:
            continue
        _outgoing, block_resolved = transfer(
            incoming[start], instructions_by_block[start], collect=True,
        )
        resolved.update(block_resolved)
    return resolved


def _exact_assigned_vtable_call_recoveries(
    image: PeImage, index_by_id: dict[str, dict[str, Any]],
    instructions: dict[int, Any], spans: list[tuple[int, int, str, str]],
    external_entry_addresses: set[int],
    *, transfer_mnemonics: frozenset[str] = frozenset({"call"}),
    address_field: str = "callAddress",
) -> dict[int, dict[str, Any]]:
    """Resolve ``this``-vptr slots against all assigned pinned-PE tables."""
    tables = _exact_assigned_vtables(image, instructions, spans)
    nonexec_occurrences: dict[int, set[int]] = {}
    for section in image.sections:
        if section.executable:
            continue
        raw = image.data[
            section.raw_offset:section.raw_offset + section.raw_size
        ]
        for offset in range(0, max(0, len(raw) - 3), 4):
            value = struct.unpack_from("<I", raw, offset)[0]
            if _span_owner(value, spans) is not None:
                nonexec_occurrences.setdefault(value, set()).add(
                    section.virtual_address + offset
                )
    tables_by_entry: dict[int, list[int]] = {}
    for table_address, table in tables.items():
        for entry in table["entries"]:
            tables_by_entry.setdefault(
                int(entry["address"], 16), []
            ).append(table_address)
    recoveries = {}
    for identifier, row in sorted(index_by_id.items()):
        function_entry = int(row["address"], 16)
        candidate_tables = sorted(set(tables_by_entry.get(
            function_entry, []
        )))
        if not candidate_tables:
            continue
        covered_cells = {
            table_address + slot * 4
            for table_address in candidate_tables
            for slot, entry in enumerate(tables[table_address]["entries"])
            if int(entry["address"], 16) == function_entry
        }
        if nonexec_occurrences.get(function_entry, set()) - covered_cells:
            continue
        sites = _resolved_this_vptr_calls(
            image, row, instructions, external_entry_addresses,
            transfer_mnemonics=transfer_mnemonics,
        )
        for address, site in sites.items():
            slot = site["slotIndex"]
            if site["vptrOffset"] != 0 or any(
                slot >= len(tables[table_address]["entries"])
                for table_address in candidate_tables
            ):
                continue
            entries = [
                tables[table_address]["entries"][slot]
                for table_address in candidate_tables
            ]
            target_addresses = sorted({
                entry["address"] for entry in entries
            })
            target_ids = sorted({
                entry["functionId"] for entry in entries
            })
            evidence_tables = [
                {
                    "tableAddress": tables[table_address]["tableAddress"],
                    "assignmentSites": tables[
                        table_address
                    ]["assignmentSites"],
                    "tableSha256": tables[table_address]["tableSha256"],
                    "identitySha256": tables[
                        table_address
                    ]["identitySha256"],
                    "slotTarget": tables[table_address]["entries"][slot],
                }
                for table_address in candidate_tables
            ]
            identity = {
                "functionId": identifier,
                address_field: f"0x{address:08x}",
                **site,
                "candidateTables": evidence_tables,
                "targetAddresses": target_addresses,
                "targetFunctionIds": target_ids,
            }
            recoveries[address] = {
                **identity,
                "proofSha256": sha256_json(identity),
            }
    return recoveries


def _exact_assigned_vtable_branch_recoveries(
    image: PeImage, index_by_id: dict[str, dict[str, Any]],
    instructions: dict[int, Any], spans: list[tuple[int, int, str, str]],
    external_entry_addresses: set[int],
) -> dict[int, dict[str, Any]]:
    """Resolve exact tail-vtable branches with the call proof unchanged."""
    return _exact_assigned_vtable_call_recoveries(
        image, index_by_id, instructions, spans, external_entry_addresses,
        transfer_mnemonics=frozenset({"jmp"}),
        address_field="branchAddress",
    )


def _indirect_inventory(
    image: PeImage, index_by_id: dict[str, dict[str, Any]],
    literal_targets: set[str],
) -> tuple[list[str], set[str], list[str], dict[str, Any]]:
    _, _, _, memory_operand = _native_dependencies()
    instructions = _instruction_map(image)
    imports = image.imports()
    sites = []
    unresolved = []
    external_import_calls = []
    merged_external_import_calls = []
    external_import_branches = []
    resolved_internal_branches = []
    resolved_remapped_internal_branches = []
    resolved_stack_parameter_calls = []
    resolved_assigned_vtable_calls = []
    resolved_assigned_vtable_branches = []
    site_classifications = []
    resolved_internal_target_ids = set()
    call_kinds: dict[str, int] = {}
    branch_kinds: dict[str, int] = {}
    external_entry_addresses = {
        int(item["target"], 16)
        for source_id, source in index_by_id.items()
        for item in source.get("branch_sites", [])
        if isinstance(item, dict)
        and isinstance(item.get("target"), str)
        and (owner := next(
            (
                target_id for target_id, target in index_by_id.items()
                if int(target["address"], 16)
                <= int(item["target"], 16)
                < int(target["end"], 16)
            ),
            None,
        )) is not None
        and owner != source_id
    }
    spans = sorted(
        (
            int(row["address"], 16), int(row["end"], 16),
            identifier, row["address"],
        )
        for identifier, row in index_by_id.items()
    )
    stack_parameter_calls = _exact_stack_parameter_call_recoveries(
        image, index_by_id, instructions, spans,
    )
    assigned_vtable_calls = _exact_assigned_vtable_call_recoveries(
        image, index_by_id, instructions, spans, external_entry_addresses,
    )
    assigned_vtable_branches = _exact_assigned_vtable_branch_recoveries(
        image, index_by_id, instructions, spans, external_entry_addresses,
    )
    ordered_instruction_addresses = sorted(instructions)

    for identifier, row in sorted(index_by_id.items()):
        switch_recoveries = _exact_switch_recoveries(
            image, row, instructions,
        )
        remapped_switch_recoveries = _exact_remapped_switch_recoveries(
            image, row, instructions,
        )
        register_import_calls = _resolved_register_import_calls(
            image, row, instructions, imports, external_entry_addresses,
        )
        for item in row.get("unresolved_indirect_calls", []):
            address = item.get("address")
            kind = item.get("kind")
            site = f"indirect-call:{address}:{kind}:{identifier}"
            sites.append(site)
            site_classifications.append(_indirect_site_classification(
                row, int(address, 16), site, instructions,
                transfer_kind="call",
                ordered_addresses=ordered_instruction_addresses,
            ))
            call_kinds[kind] = call_kinds.get(kind, 0) + 1
            instruction = instructions.get(int(address, 16))
            resolved = None
            if instruction is not None and kind == "register":
                resolved = register_import_calls.get(instruction.address)
            parameter_recovery = stack_parameter_calls.get(int(address, 16))
            vtable_recovery = assigned_vtable_calls.get(int(address, 16))
            if resolved is None and parameter_recovery is None \
                    and vtable_recovery is None:
                unresolved.append(site)
            elif resolved is not None:
                definitions, symbol = resolved
                if len(definitions) == 1:
                    external_import_calls.append({
                        "site": site,
                        "definition": definitions[0],
                        "symbol": symbol,
                    })
                else:
                    merged_external_import_calls.append({
                        "site": site,
                        "definitions": list(definitions),
                        "symbol": symbol,
                    })
            else:
                if parameter_recovery is not None:
                    resolved_internal_target_ids.update(
                        parameter_recovery["targetFunctionIds"]
                    )
                    resolved_stack_parameter_calls.append({
                        "site": site,
                        **parameter_recovery,
                    })
                else:
                    resolved_internal_target_ids.update(
                        vtable_recovery["targetFunctionIds"]
                    )
                    resolved_assigned_vtable_calls.append({
                        "site": site,
                        **vtable_recovery,
                    })

        for item in row.get("branch_sites", []):
            if item.get("kind") != "unresolved_switch_or_indirect_jump":
                continue
            address = item.get("address")
            instruction = instructions.get(int(address, 16))
            shape = "undecoded"
            import_symbol = None
            if instruction is not None and instruction.operands:
                operand = instruction.operands[0]
                if operand.type == memory_operand:
                    base = bool(operand.mem.base)
                    index = bool(operand.mem.index)
                    displacement = operand.mem.disp & 0xFFFFFFFF
                    shape = (
                        f"memory-base-{int(base)}-index-{int(index)}"
                        f"-disp-0x{displacement:08x}"
                    )
                    if not base and not index:
                        import_symbol = imports.get(displacement)
                else:
                    shape = "register"
            site = f"indirect-branch:{address}:{shape}:{identifier}"
            sites.append(site)
            site_classifications.append(_indirect_site_classification(
                row, int(address, 16), site, instructions,
                transfer_kind="branch",
                ordered_addresses=ordered_instruction_addresses,
            ))
            branch_kinds[shape] = branch_kinds.get(shape, 0) + 1
            switch_recovery = switch_recoveries.get(int(address, 16))
            remapped_switch_recovery = remapped_switch_recoveries.get(
                int(address, 16)
            )
            vtable_recovery = assigned_vtable_branches.get(
                int(address, 16)
            )
            if switch_recovery is not None:
                resolved_internal_target_ids.add(identifier)
                resolved_internal_branches.append({
                    "site": site,
                    "functionId": identifier,
                    **switch_recovery,
                })
            elif remapped_switch_recovery is not None:
                resolved_internal_target_ids.add(identifier)
                resolved_remapped_internal_branches.append({
                    "site": site,
                    "functionId": identifier,
                    **remapped_switch_recovery,
                })
            elif vtable_recovery is not None:
                resolved_internal_target_ids.update(
                    vtable_recovery["targetFunctionIds"]
                )
                resolved_assigned_vtable_branches.append({
                    "site": site,
                    **vtable_recovery,
                })
            elif import_symbol is None:
                unresolved.append(site)
            else:
                external_import_branches.append({
                    "site": site,
                    "symbol": import_symbol,
                })
    return (
        sorted(sites),
        set(literal_targets) | resolved_internal_target_ids,
        sorted(unresolved),
        {
        "indirectSiteClassifications": sorted(
            site_classifications, key=lambda row: row["site"],
        ),
        "indirectSiteClassificationCount": len(site_classifications),
        "indirectSiteClassificationKinds": dict(sorted(
            (
                classification,
                sum(
                    row["classification"] == classification
                    for row in site_classifications
                ),
            )
            for classification in _INDIRECT_SITE_CLASSIFICATIONS
            if any(
                row["classification"] == classification
                for row in site_classifications
            )
        )),
        "indirectSiteClassifierSha256": sha256_json(sorted(
            site_classifications, key=lambda row: row["site"],
        )),
        "indirectSiteClassificationPolicy": (
            "nearest same-basic-block base-register definitions classify "
            "transfer shape only; classifications never add target IDs or "
            "remove unresolved paths"
        ),
        "unresolvedCallKinds": dict(sorted(call_kinds.items())),
        "branchShapes": dict(sorted(branch_kinds.items())),
        "resolvedExternalImportCalls": external_import_calls,
        "resolvedExternalImportCallCount": len(external_import_calls),
        "resolvedMergedExternalImportCalls": sorted(
            merged_external_import_calls, key=lambda row: row["site"],
        ),
        "resolvedMergedExternalImportCallCount": len(
            merged_external_import_calls
        ),
        "registerImportResolutionPolicy": (
            "forward CFG dataflow retains only one identical import symbol "
            "across all predecessors and unions its exact reaching definitions; "
            "every disconnected CFG component starts with an empty state; "
            "the reaching definition must be an exact mov from an absolute "
            "pinned-PE import cell and calls invalidate volatile registers"
        ),
        "resolvedStackParameterCalls": sorted(
            resolved_stack_parameter_calls, key=lambda row: row["site"],
        ),
        "resolvedStackParameterCallCount": len(
            resolved_stack_parameter_calls
        ),
        "stackParameterResolutionPolicy": (
            "only call [ebp+positive-aligned-argument-offset] is accepted; "
            "every exact direct xref must provide an internal function-entry "
            "literal through contiguous push setup, optionally through a "
            "prologueless helper that never writes EBP"
        ),
        "resolvedAssignedVtableCalls": sorted(
            resolved_assigned_vtable_calls, key=lambda row: row["site"],
        ),
        "resolvedAssignedVtableCallCount": len(
            resolved_assigned_vtable_calls
        ),
        "assignedVtableResolutionPolicy": (
            "entry ECX aliases are propagated by a must-CFG dataflow; only "
            "vptr loads at offset zero and aligned memory-call slots qualify. "
            "Candidate tables must begin at pinned-PE addresses written as "
            "immediates; each table conservatively continues through contiguous "
            "internal code pointers, even across possible adjacent tables. "
            "Candidates must cover every aligned non-executable occurrence of "
            "the current function entry and provide the requested slot"
        ),
        "resolvedAssignedVtableBranches": sorted(
            resolved_assigned_vtable_branches, key=lambda row: row["site"],
        ),
        "resolvedAssignedVtableBranchCount": len(
            resolved_assigned_vtable_branches
        ),
        "assignedVtableBranchResolutionPolicy": (
            "tail jmp resolution uses the identical entry-ECX must-alias, "
            "assigned-table completeness and aligned slot proof as calls; "
            "field and adjusted-this receivers remain unresolved"
        ),
        "resolvedExternalImportBranches": sorted(
            external_import_branches, key=lambda row: row["site"],
        ),
        "resolvedExternalImportBranchCount": len(external_import_branches),
        "resolvedInternalBranches": sorted(
            resolved_internal_branches, key=lambda row: row["site"],
        ),
        "resolvedInternalBranchCount": len(resolved_internal_branches),
        "resolvedRemappedInternalBranches": sorted(
            resolved_remapped_internal_branches,
            key=lambda row: row["site"],
        ),
        "resolvedRemappedInternalBranchCount": len(
            resolved_remapped_internal_branches
        ),
        "unresolvedBranchCount": len([
            path for path in unresolved
            if path.startswith("indirect-branch:")
        ]),
        "exactSwitchResolutionPolicy": (
            "only jmp [index*4+absolute_table] guarded by an unsigned "
            "cmp/ja or cmp/jae bound is accepted; the default and every "
            "ordered table entry must be exact decoded basic-block starts "
            "inside the same recovered function"
        ),
        "exactRemappedSwitchResolutionPolicy": (
            "only jmp [remapIndex*4+absolute_table] fed by one byte load "
            "from an absolute remap table is accepted; the source index must "
            "retain an unsigned cmp/ja or cmp/jae bound, remap values must "
            "form a dense zero-based target index set, and every target must "
            "be an exact decoded basic-block start in the same function"
        ),
        "possibleInternalTargetPolicy": (
            "conservative union of every literal internal target observed in "
            "executable and non-executable PE bytes"
        ),
        },
    )


def _review(
    *, closure: str, status: str, executable_sha256: str,
    code_map_sha256: str, function_index_sha256: str,
    candidate_membership_sha256: str,
    sites: list[str], target_ids: set[str], unresolved: list[str],
    evidence: dict[str, Any], generator_sha256: str,
) -> dict[str, Any]:
    targets = sorted(target_ids)
    inventory_identity = {
        "closure": closure,
        "sites": sites,
        "targetFunctionIds": targets,
    }
    inventory = {
        "sites": sites,
        "targetFunctionIds": targets,
        "inventorySha256": sha256_json(inventory_identity),
    }
    value = {
        "schema": SCHEMA,
        "protocol": PROTOCOL,
        "reviewStatus": status,
        "closure": closure,
        "executableSha256": executable_sha256,
        "codeMapSha256": code_map_sha256,
        "candidateMembershipSha256": candidate_membership_sha256,
        "functionIndexSha256": function_index_sha256,
        "generatorSha256": generator_sha256,
        "inventory": inventory,
        "evidence": evidence,
        "unresolvedPaths": unresolved,
    }
    return {**value, "reviewSha256": sha256_json(value)}


def build_reviews(
    executable: Path, *, root: Path = ROOT,
) -> dict[str, dict[str, Any]]:
    code_path = root / CODE_MAP
    index_path = root / FUNCTION_INDEX
    code_map = load_json(code_path)
    function_index = load_json(index_path)
    code_by_id, index_by_id, spans = _function_rows(code_map, function_index)
    membership_sha, candidate_ids, candidate_members = _candidate_membership(
        code_map
    )
    pe_image, _, _, _ = _native_dependencies()
    image = pe_image(executable)
    executable_sha = sha256_file(executable)
    if executable_sha != code_map.get("source", {}).get("sha256") \
            or executable_sha != function_index.get("source", {}).get("sha256"):
        raise NativeReachabilityClosureError(
            "native executable differs from the code map/function index"
        )
    generator_sha = sha256_file(Path(__file__))
    shared = {
        "executable_sha256": executable_sha,
        "code_map_sha256": sha256_file(code_path),
        "function_index_sha256": sha256_file(index_path),
        "candidate_membership_sha256": membership_sha,
        "generator_sha256": generator_sha,
    }

    root_sites, root_targets, root_unresolved, root_evidence = _pe_root_entries(
        image, spans
    )
    root_reachable = _direct_reachable(root_targets, code_by_id)
    root_evidence.update({
        "immediateRootFunctionIds": sorted(root_targets),
        "directReachableFunctionCount": len(root_reachable),
        "directRootProofSha256": _direct_root_proof(
            code_map, candidate_members,
        ),
        "candidateIntersection": sorted(candidate_ids & root_reachable),
    })

    callback_sites, callback_targets, callback_evidence = _literal_pointer_sites(
        image, spans, executable=True,
    )
    branch_sites, branch_targets, branch_evidence = _cross_function_branch_sites(
        index_by_id, spans,
    )
    callback_sites = sorted(callback_sites + branch_sites)
    callback_targets |= branch_targets
    callback_reachable = _direct_reachable(callback_targets, code_by_id)
    callback_evidence.update({
        "scope": (
            "all literal internal code pointers in executable section bytes plus "
            "all direct cross-function branch xrefs omitted by the call-only graph"
        ),
        "branchXrefs": branch_evidence,
        "directClosureFunctionCount": len(callback_reachable),
        "candidateDirectClosureIntersection": sorted(
            candidate_ids & callback_reachable
        ),
        "computedTargetsDelegatedTo": "indirectTargets",
    })

    vtable_sites, vtable_targets, vtable_evidence = _literal_pointer_sites(
        image, spans, executable=False,
    )
    vtable_reachable = _direct_reachable(vtable_targets, code_by_id)
    vtable_evidence.update({
        "scope": (
            "all literal internal code pointers in non-executable section bytes; "
            "a conservative superset of vtables, callback cells and static handlers"
        ),
        "directClosureFunctionCount": len(vtable_reachable),
        "candidateDirectClosureIntersection": sorted(
            candidate_ids & vtable_reachable
        ),
        "computedTargetsDelegatedTo": "indirectTargets",
    })

    indirect_sites, indirect_targets, indirect_unresolved, indirect_evidence = (
        _indirect_inventory(
            image, index_by_id, callback_targets | vtable_targets,
        )
    )
    indirect_reachable = _direct_reachable(indirect_targets, code_by_id)
    indirect_evidence.update({
        "siteCount": len(indirect_sites),
        "unresolvedPathCount": len(indirect_unresolved),
        "possibleInternalTargetCount": len(indirect_targets),
        "possibleInternalDirectClosureFunctionCount": len(indirect_reachable),
        "candidatePossibleClosureIntersection": sorted(
            candidate_ids & indirect_reachable
        ),
        "remainingCandidateFunctionsIfAllPossibleLiteralTargetsReachable": sorted(
            candidate_ids - indirect_reachable
        ),
    })

    return {
        "roots": _review(
            closure="roots",
            status="CLOSED" if not root_unresolved else "OPEN",
            sites=root_sites,
            target_ids=root_reachable,
            unresolved=root_unresolved,
            evidence=root_evidence,
            **shared,
        ),
        "callbacks": _review(
            closure="callbacks",
            status="CLOSED",
            sites=callback_sites,
            target_ids=callback_targets,
            unresolved=[],
            evidence=callback_evidence,
            **shared,
        ),
        "vtables": _review(
            closure="vtables",
            status="CLOSED",
            sites=vtable_sites,
            target_ids=vtable_targets,
            unresolved=[],
            evidence=vtable_evidence,
            **shared,
        ),
        "indirectTargets": _review(
            closure="indirectTargets",
            status="OPEN" if indirect_unresolved else "CLOSED",
            sites=indirect_sites,
            target_ids=indirect_targets,
            unresolved=indirect_unresolved,
            evidence=indirect_evidence,
            **shared,
        ),
    }


def validate_review(
    review: dict[str, Any], *, closure: str, root: Path = ROOT,
) -> dict[str, Any]:
    fields = {
        "schema", "protocol", "reviewStatus", "closure",
        "executableSha256", "codeMapSha256", "candidateMembershipSha256",
        "functionIndexSha256", "generatorSha256",
        "inventory", "evidence", "unresolvedPaths", "reviewSha256",
    }
    schema_contract = load_json(root / SCHEMA_CONTRACT)
    if schema_contract.get("additionalProperties") is not False \
            or set(schema_contract.get("required", [])) != fields \
            or schema_contract.get("properties", {}).get(
                "schema", {}
            ).get("const") != SCHEMA \
            or schema_contract.get("properties", {}).get(
                "protocol", {}
            ).get("const") != PROTOCOL:
        raise NativeReachabilityClosureError(
            "native reachability closure JSON schema differs"
        )
    if not isinstance(review, dict) or set(review) != fields \
            or review.get("schema") != SCHEMA \
            or review.get("protocol") != PROTOCOL \
            or review.get("closure") != closure \
            or review.get("reviewStatus") not in {"CLOSED", "OPEN"}:
        raise NativeReachabilityClosureError(
            f"{closure}: closure review identity differs"
        )
    for field in (
        "executableSha256", "codeMapSha256", "candidateMembershipSha256",
        "functionIndexSha256", "generatorSha256",
        "reviewSha256",
    ):
        if not _is_sha256(review.get(field)):
            raise NativeReachabilityClosureError(
                f"{closure}: {field} is not a SHA-256"
            )
    code_path = root / CODE_MAP
    index_path = root / FUNCTION_INDEX
    if review["codeMapSha256"] != sha256_file(code_path) \
            or review["functionIndexSha256"] != sha256_file(index_path) \
            or review["generatorSha256"] != sha256_file(Path(__file__)):
        raise NativeReachabilityClosureError(
            f"{closure}: closure source hash differs"
        )
    code_map = load_json(code_path)
    membership_sha, _, _ = _candidate_membership(code_map)
    if review["executableSha256"] != code_map.get("source", {}).get("sha256") \
            or review["candidateMembershipSha256"] != membership_sha:
        raise NativeReachabilityClosureError(
            f"{closure}: executable/candidate identity differs"
        )
    inventory = review.get("inventory")
    if not isinstance(inventory, dict) or set(inventory) != {
        "sites", "targetFunctionIds", "inventorySha256",
    }:
        raise NativeReachabilityClosureError(
            f"{closure}: closure inventory differs"
        )
    sites = inventory["sites"]
    targets = inventory["targetFunctionIds"]
    if not isinstance(sites, list) or sites != sorted(set(sites)) \
            or not isinstance(targets, list) or targets != sorted(set(targets)):
        raise NativeReachabilityClosureError(
            f"{closure}: closure inventory is not canonical"
        )
    code_ids = {
        row.get("id") for row in code_map.get("functions", [])
        if isinstance(row, dict)
    }
    if any(not isinstance(site, str) or not site for site in sites) \
            or not set(targets).issubset(code_ids):
        raise NativeReachabilityClosureError(
            f"{closure}: closure sites/targets differ"
        )
    inventory_identity = {
        "closure": closure,
        "sites": sites,
        "targetFunctionIds": targets,
    }
    if inventory.get("inventorySha256") != sha256_json(inventory_identity):
        raise NativeReachabilityClosureError(
            f"{closure}: closure inventory hash differs"
        )
    unresolved = review.get("unresolvedPaths")
    if not isinstance(unresolved, list) or unresolved != sorted(set(unresolved)) \
            or any(not isinstance(path, str) or not path for path in unresolved):
        raise NativeReachabilityClosureError(
            f"{closure}: unresolved paths differ"
        )
    if (review["reviewStatus"] == "CLOSED") != (unresolved == []):
        raise NativeReachabilityClosureError(
            f"{closure}: review status does not match unresolved paths"
        )
    if not isinstance(review.get("evidence"), dict):
        raise NativeReachabilityClosureError(
            f"{closure}: mechanical evidence differs"
        )
    unhashed = dict(review)
    review_sha = unhashed.pop("reviewSha256")
    if review_sha != sha256_json(unhashed):
        raise NativeReachabilityClosureError(
            f"{closure}: closure review hash differs"
        )
    if closure == "roots":
        rows = {
            row["id"]: row for row in code_map["functions"]
        }
        entrypoint = code_map["source"]["entrypoint"]
        entry_id = f"fn_{int(entrypoint, 16):08x}"
        expected = _direct_reachable({entry_id}, rows)
        evidence = review["evidence"]
        if sites != [f"pe-entrypoint:{entrypoint}"] \
                or set(targets) != expected \
                or evidence.get("exports") != [] \
                or evidence.get("tlsCallbacks") != []:
            raise NativeReachabilityClosureError(
                "roots: current PE root closure differs from the direct graph"
            )
    elif closure == "callbacks":
        function_index = load_json(index_path)
        _, index_by_id, spans = _function_rows(code_map, function_index)
        branch_sites, branch_targets, branch_evidence = (
            _cross_function_branch_sites(index_by_id, spans)
        )
        if not set(branch_sites).issubset(sites) \
                or not branch_targets.issubset(set(targets)) \
                or review["evidence"].get("branchXrefs") != branch_evidence:
            raise NativeReachabilityClosureError(
                "callbacks: direct cross-function branch inventory differs"
            )
    elif closure == "indirectTargets":
        function_index = load_json(index_path)
        index_by_identifier = {
            f"fn_{int(row['address'], 16):08x}": row
            for row in function_index.get("functions", [])
        }
        expected_call_sites = set()
        expected_branch_addresses = set()
        for row in function_index.get("functions", []):
            if not isinstance(row, dict):
                raise NativeReachabilityClosureError(
                    "indirectTargets: function index row differs"
                )
            identifier = f"fn_{int(row['address'], 16):08x}"
            for item in row.get("unresolved_indirect_calls", []):
                expected_call_sites.add(
                    f"indirect-call:{item['address']}:{item['kind']}:{identifier}"
                )
            for item in row.get("branch_sites", []):
                if item.get("kind") == "unresolved_switch_or_indirect_jump":
                    expected_branch_addresses.add((item["address"], identifier))
        actual_call_sites = {
            site for site in sites if site.startswith("indirect-call:")
        }
        actual_branches = {
            (parts[1], parts[-1])
            for site in sites if site.startswith("indirect-branch:")
            for parts in [site.split(":")]
        }
        if actual_call_sites != expected_call_sites \
                or actual_branches != expected_branch_addresses:
            raise NativeReachabilityClosureError(
                "indirectTargets: indexed indirect site inventory differs"
            )
        evidence = review["evidence"]
        classifications = evidence.get("indirectSiteClassifications")
        classification_fields = {
            "site", "transferKind", "classification",
            "instructionAddress", "instructionMnemonic",
            "instructionSha256", "operand", "nearestBaseDefinition",
        }
        if not isinstance(classifications, list) \
                or classifications != sorted(
                    classifications, key=lambda row: row.get("site", ""),
                ) \
                or any(
                    not isinstance(row, dict)
                    or set(row) != classification_fields
                    for row in classifications
                ) \
                or {row["site"] for row in classifications} != set(sites) \
                or len(classifications) != len(sites) \
                or evidence.get("indirectSiteClassificationCount") \
                    != len(classifications) \
                or evidence.get("indirectSiteClassifierSha256") \
                    != sha256_json(classifications):
            raise NativeReachabilityClosureError(
                "indirectTargets: indirect-site classifier differs"
            )
        classification_kinds: dict[str, int] = {}
        for row in classifications:
            site = row["site"]
            transfer_kind = row["transferKind"]
            classification = row["classification"]
            operand = row["operand"]
            definition = row["nearestBaseDefinition"]
            address = site.split(":")[1]
            if classification not in _INDIRECT_SITE_CLASSIFICATIONS \
                    or transfer_kind not in {"call", "branch"} \
                    or site.startswith("indirect-call:") \
                        != (transfer_kind == "call") \
                    or row["instructionAddress"] != address \
                    or row["instructionMnemonic"] \
                        not in {None, transfer_kind, "jmp"} \
                    or (
                        (row["instructionMnemonic"] is None)
                        != (row["instructionSha256"] is None)
                    ) \
                    or row["instructionSha256"] is not None \
                        and not _is_sha256(row["instructionSha256"]):
                raise NativeReachabilityClosureError(
                    "indirectTargets: indirect-site classification row differs"
                )
            if operand is not None:
                if not isinstance(operand, dict) \
                        or operand.get("kind") not in {
                            "memory", "other", "register",
                        }:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: classified operand differs"
                    )
                if operand["kind"] == "memory" and set(operand) != {
                    "kind", "base", "index", "scale", "displacement",
                }:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: classified memory differs"
                    )
                if operand["kind"] == "register" and set(operand) != {
                    "kind", "register",
                }:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: classified register differs"
                    )
            if definition is not None:
                if not isinstance(definition, dict) or set(definition) != {
                    "address", "mnemonic", "instructionSha256",
                    "sourceKind", "sourceMemory",
                } or not re.fullmatch(
                    r"0x[0-9a-f]{8}", definition["address"],
                ) or not isinstance(definition["mnemonic"], str) \
                        or not _is_sha256(
                            definition["instructionSha256"]
                        ) \
                        or definition["sourceKind"] not in {
                            "immediate", "memory", "other", "register",
                        }:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: classified definition differs"
                    )
                source_memory = definition["sourceMemory"]
                if definition["sourceKind"] == "memory":
                    if not isinstance(source_memory, dict) \
                            or set(source_memory) != {
                                "base", "index", "scale", "displacement",
                            }:
                        raise NativeReachabilityClosureError(
                            "indirectTargets: classified source differs"
                        )
                elif source_memory is not None:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: non-memory source has memory"
                    )
            canonical_source = (
                isinstance(definition, dict)
                and definition["sourceKind"] == "memory"
                and isinstance(definition["sourceMemory"], dict)
                and definition["sourceMemory"]["base"] is not None
                and definition["sourceMemory"]["index"] is None
                and definition["sourceMemory"]["scale"] == 1
                and definition["sourceMemory"]["displacement"] == 0
            )
            classification_valid = {
                "REGISTER_TARGET": (
                    transfer_kind == "call"
                    and operand is not None
                    and operand["kind"] == "register"
                ),
                "REGISTER_BRANCH": (
                    transfer_kind == "branch"
                    and operand is not None
                    and operand["kind"] == "register"
                ),
                "CANONICAL_VPTR": (
                    transfer_kind == "call" and canonical_source
                ),
                "ADJUSTED_VPTR": (
                    transfer_kind == "call"
                    and isinstance(definition, dict)
                    and definition["sourceKind"] == "memory"
                    and not canonical_source
                ),
                "TAIL_VPTR": (
                    transfer_kind == "branch" and canonical_source
                ),
                "ABSOLUTE_MEMORY_BRANCH": (
                    transfer_kind == "branch"
                    and operand is not None
                    and operand["kind"] == "memory"
                    and operand["base"] is None
                    and operand["index"] is None
                ),
                "INDEXED_MEMORY_BRANCH": (
                    transfer_kind == "branch"
                    and operand is not None
                    and operand["kind"] == "memory"
                    and operand["base"] is None
                    and operand["index"] is not None
                ),
                "CFG_CARRIED_MEMORY_TARGET": (
                    transfer_kind == "call" and definition is None
                    and operand is not None
                    and operand["kind"] == "memory"
                ),
                "CFG_CARRIED_MEMORY_BRANCH": (
                    transfer_kind == "branch" and definition is None
                    and operand is not None
                    and operand["kind"] == "memory"
                    and operand["base"] is not None
                ),
                "LOCAL_DEFINED_MEMORY_TARGET": (
                    transfer_kind == "call"
                    and definition is not None
                    and not (
                        definition["sourceKind"] == "memory"
                    )
                ),
                "LOCAL_DEFINED_MEMORY_BRANCH": (
                    transfer_kind == "branch"
                    and definition is not None
                    and not canonical_source
                ),
                "UNDECODED": (
                    operand is None
                    or operand.get("kind") == "other"
                ),
            }.get(classification, False)
            if not classification_valid:
                raise NativeReachabilityClosureError(
                    "indirectTargets: classification contradicts evidence"
                )
            classification_kinds[classification] = (
                classification_kinds.get(classification, 0) + 1
            )
        if evidence.get("indirectSiteClassificationKinds") \
                != dict(sorted(classification_kinds.items())) \
                or evidence.get("indirectSiteClassificationPolicy") != (
                    "nearest same-basic-block base-register definitions "
                    "classify transfer shape only; classifications never add "
                    "target IDs or remove unresolved paths"
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: classifier summary differs"
            )
        resolved_calls = evidence.get("resolvedExternalImportCalls")
        if not isinstance(resolved_calls, list) \
                or resolved_calls != sorted(
                    resolved_calls, key=lambda row: row.get("site", "")
                ) \
                or any(
                    not isinstance(row, dict)
                    or set(row) != {"site", "definition", "symbol"}
                    or row["site"] not in expected_call_sites
                    or not isinstance(row["definition"], str)
                    or not isinstance(row["symbol"], str)
                    for row in resolved_calls
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved import-call evidence differs"
            )
        resolved_call_sites = {row["site"] for row in resolved_calls}
        if len(resolved_call_sites) != len(resolved_calls) \
                or evidence.get("resolvedExternalImportCallCount") \
                    != len(resolved_calls):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved import-call count differs"
            )
        merged_calls = evidence.get("resolvedMergedExternalImportCalls")
        if not isinstance(merged_calls, list) \
                or merged_calls != sorted(
                    merged_calls, key=lambda row: row.get("site", ""),
                ) \
                or any(
                    not isinstance(row, dict)
                    or set(row) != {"site", "definitions", "symbol"}
                    or row["site"] not in expected_call_sites
                    or not isinstance(row["symbol"], str)
                    or not isinstance(row["definitions"], list)
                    or len(row["definitions"]) < 2
                    or row["definitions"] != sorted(set(row["definitions"]))
                    for row in merged_calls
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: merged import-call evidence differs"
            )
        merged_call_sites = set()
        for row in merged_calls:
            identifier = row["site"].split(":")[-1]
            indexed = index_by_identifier.get(identifier)
            if indexed is None or row["site"] in resolved_call_sites \
                    or row["site"] in merged_call_sites \
                    or any(
                        not re.fullmatch(r"0x[0-9a-f]{8}", definition)
                        or not int(indexed["address"], 16)
                        <= int(definition, 16)
                        < int(indexed["end"], 16)
                        for definition in row["definitions"]
                    ):
                raise NativeReachabilityClosureError(
                    "indirectTargets: merged import-call row differs"
                )
            merged_call_sites.add(row["site"])
        if evidence.get("resolvedMergedExternalImportCallCount") \
                != len(merged_calls):
            raise NativeReachabilityClosureError(
                "indirectTargets: merged import-call count differs"
            )
        resolved_parameter_calls = evidence.get(
            "resolvedStackParameterCalls"
        )
        parameter_fields = {
            "site", "functionId", "callAddress", "callInstructionSha256",
            "operandBase", "operandDisplacement", "parameterIndex",
            "entryInboundProof",
            "targetAddresses", "targetFunctionIds", "xrefProofs",
            "proofSha256",
        }
        if not isinstance(resolved_parameter_calls, list) \
                or resolved_parameter_calls != sorted(
                    resolved_parameter_calls,
                    key=lambda row: row.get("site", ""),
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved stack-parameter calls differ"
            )
        resolved_parameter_sites = set()
        for row in resolved_parameter_calls:
            if not isinstance(row, dict) or set(row) != parameter_fields \
                    or row["site"] not in expected_call_sites \
                    or row["site"] in resolved_parameter_sites \
                    or row["site"] in resolved_call_sites \
                    or row["site"] in merged_call_sites \
                    or row["functionId"] != row["site"].split(":")[-1] \
                    or row["callAddress"] != row["site"].split(":")[1] \
                    or row["operandBase"] != "ebp" \
                    or not isinstance(row["operandDisplacement"], int) \
                    or row["operandDisplacement"] < 8 \
                    or (row["operandDisplacement"] - 8) % 4 \
                    or row["parameterIndex"] \
                        != (row["operandDisplacement"] - 8) // 4 \
                    or not isinstance(row["entryInboundProof"], dict) \
                    or set(row["entryInboundProof"]) != {
                        "directCallXrefCount", "absolutePointerSiteCount",
                        "directBranchXrefCount", "isLoaderRoot",
                    } \
                    or not isinstance(
                        row["entryInboundProof"]["directCallXrefCount"], int,
                    ) \
                    or row["entryInboundProof"]["directCallXrefCount"] < 1 \
                    or row["entryInboundProof"]["absolutePointerSiteCount"] != 0 \
                    or row["entryInboundProof"]["directBranchXrefCount"] != 0 \
                    or row["entryInboundProof"]["isLoaderRoot"] is not False \
                    or not _is_sha256(row["callInstructionSha256"]) \
                    or not _is_sha256(row["proofSha256"]) \
                    or row["proofSha256"] != sha256_json(row["xrefProofs"]) \
                    or not isinstance(row["xrefProofs"], list) \
                    or not row["xrefProofs"] \
                    or not isinstance(row["targetAddresses"], list) \
                    or row["targetAddresses"] \
                        != sorted(set(row["targetAddresses"])) \
                    or not isinstance(row["targetFunctionIds"], list) \
                    or row["targetFunctionIds"] \
                        != sorted(set(row["targetFunctionIds"])) \
                    or not set(row["targetFunctionIds"]).issubset(targets):
                raise NativeReachabilityClosureError(
                    "indirectTargets: resolved stack-parameter row differs"
                )
            proof_targets = set()
            proof_addresses = set()
            for proof in row["xrefProofs"]:
                if not isinstance(proof, dict) \
                        or set(proof) != {
                            "targetAddress", "targetFunctionId",
                            "targetFunctionOffset", "frameRoute", "steps",
                        } \
                        or proof["targetFunctionId"] \
                            not in row["targetFunctionIds"] \
                        or proof["targetAddress"] \
                            not in row["targetAddresses"] \
                        or not re.fullmatch(
                            r"0x[0-9a-f]+", proof["targetFunctionOffset"],
                        ) \
                        or not isinstance(proof["frameRoute"], list) \
                        or not proof["frameRoute"] \
                        or any(
                            function_id not in index_by_identifier
                            for function_id in proof["frameRoute"]
                        ) \
                        or not isinstance(proof["steps"], list) \
                        or not proof["steps"]:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: stack-parameter proof differs"
                    )
                proof_targets.add(proof["targetFunctionId"])
                proof_addresses.add(proof["targetAddress"])
            if proof_targets != set(row["targetFunctionIds"]) \
                    or proof_addresses != set(row["targetAddresses"]):
                raise NativeReachabilityClosureError(
                    "indirectTargets: stack-parameter targets differ"
                )
            resolved_parameter_sites.add(row["site"])
        if evidence.get("resolvedStackParameterCallCount") \
                != len(resolved_parameter_calls):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved stack-parameter count differs"
            )
        vtable_calls = evidence.get("resolvedAssignedVtableCalls")
        vtable_fields = {
            "site", "functionId", "callAddress", "vptrOffset",
            "vptrLoadDefinitions", "slotIndex", "candidateTables",
            "targetAddresses", "targetFunctionIds", "proofSha256",
        }
        if not isinstance(vtable_calls, list) \
                or vtable_calls != sorted(
                    vtable_calls, key=lambda row: row.get("site", ""),
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: assigned-vtable calls differ"
            )
        resolved_vtable_sites = set()
        for row in vtable_calls:
            if not isinstance(row, dict) or set(row) != vtable_fields \
                    or row["site"] not in expected_call_sites \
                    or row["site"] in resolved_call_sites \
                    or row["site"] in merged_call_sites \
                    or row["site"] in resolved_parameter_sites \
                    or row["site"] in resolved_vtable_sites \
                    or row["functionId"] != row["site"].split(":")[-1] \
                    or row["callAddress"] != row["site"].split(":")[1] \
                    or row["vptrOffset"] != 0 \
                    or not isinstance(row["slotIndex"], int) \
                    or row["slotIndex"] < 0 \
                    or not isinstance(row["vptrLoadDefinitions"], list) \
                    or not row["vptrLoadDefinitions"] \
                    or row["vptrLoadDefinitions"] \
                        != sorted(set(row["vptrLoadDefinitions"])) \
                    or not isinstance(row["candidateTables"], list) \
                    or not row["candidateTables"] \
                    or not isinstance(row["targetAddresses"], list) \
                    or row["targetAddresses"] \
                        != sorted(set(row["targetAddresses"])) \
                    or not isinstance(row["targetFunctionIds"], list) \
                    or row["targetFunctionIds"] \
                        != sorted(set(row["targetFunctionIds"])) \
                    or not set(row["targetFunctionIds"]).issubset(targets) \
                    or not _is_sha256(row["proofSha256"]) \
                    or row["proofSha256"] != sha256_json({
                        key: value for key, value in row.items()
                        if key not in {"site", "proofSha256"}
                    }):
                raise NativeReachabilityClosureError(
                    "indirectTargets: assigned-vtable row differs"
                )
            indexed = index_by_identifier[row["functionId"]]
            if any(
                not re.fullmatch(r"0x[0-9a-f]{8}", definition)
                or not int(indexed["address"], 16)
                <= int(definition, 16) < int(indexed["end"], 16)
                for definition in row["vptrLoadDefinitions"]
            ):
                raise NativeReachabilityClosureError(
                    "indirectTargets: assigned-vtable load differs"
                )
            table_targets = []
            table_addresses = []
            for table in row["candidateTables"]:
                if not isinstance(table, dict) or set(table) != {
                    "tableAddress", "assignmentSites", "tableSha256",
                    "identitySha256", "slotTarget",
                } or not re.fullmatch(
                    r"0x[0-9a-f]{8}", table["tableAddress"],
                ) or not isinstance(table["assignmentSites"], list) \
                        or not table["assignmentSites"] \
                        or table["assignmentSites"] \
                            != sorted(set(table["assignmentSites"])) \
                        or not _is_sha256(table["tableSha256"]) \
                        or not _is_sha256(table["identitySha256"]) \
                        or not isinstance(table["slotTarget"], dict) \
                        or set(table["slotTarget"]) != {
                            "address", "functionId", "functionOffset",
                        } \
                        or table["slotTarget"]["functionId"] \
                            not in row["targetFunctionIds"]:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: assigned-vtable table differs"
                    )
                table_addresses.append(table["tableAddress"])
                table_targets.append(table["slotTarget"])
            if table_addresses != sorted(set(table_addresses)) \
                    or sorted({
                        target["address"] for target in table_targets
                    }) != row["targetAddresses"] \
                    or sorted({
                        target["functionId"] for target in table_targets
                    }) != row["targetFunctionIds"]:
                raise NativeReachabilityClosureError(
                    "indirectTargets: assigned-vtable targets differ"
                )
            resolved_vtable_sites.add(row["site"])
        if evidence.get("resolvedAssignedVtableCallCount") \
                != len(vtable_calls):
            raise NativeReachabilityClosureError(
                "indirectTargets: assigned-vtable count differs"
            )
        unresolved_call_sites = {
            site for site in unresolved if site.startswith("indirect-call:")
        }
        if unresolved_call_sites != expected_call_sites - (
            resolved_call_sites
            | merged_call_sites
            | resolved_parameter_sites
            | resolved_vtable_sites
        ):
            raise NativeReachabilityClosureError(
                "indirectTargets: unresolved indexed calls were declared closed"
            )
        actual_branch_sites = {
            site for site in sites if site.startswith("indirect-branch:")
        }
        resolved_external_branches = evidence.get(
            "resolvedExternalImportBranches"
        )
        if not isinstance(resolved_external_branches, list) \
                or resolved_external_branches != sorted(
                    resolved_external_branches,
                    key=lambda row: row.get("site", ""),
                ) \
                or any(
                    not isinstance(row, dict)
                    or set(row) != {"site", "symbol"}
                    or row["site"] not in actual_branch_sites
                    or not isinstance(row["symbol"], str)
                    for row in resolved_external_branches
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved import-branch evidence differs"
            )
        resolved_external_branch_sites = {
            row["site"] for row in resolved_external_branches
        }
        if len(resolved_external_branch_sites) \
                != len(resolved_external_branches) \
                or evidence.get("resolvedExternalImportBranchCount") \
                    != len(resolved_external_branches):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved import-branch count differs"
            )
        resolved_internal_branches = evidence.get(
            "resolvedInternalBranches"
        )
        internal_fields = {
            "site", "functionId", "branchAddress",
            "boundBranchMnemonic", "comparisonAddress",
            "defaultBranchAddress", "defaultTargetAddress",
            "indexRegister", "inclusiveUpperBound", "tableAddress",
            "tableEntryCount", "tableEntries", "tableSha256",
        }
        if not isinstance(resolved_internal_branches, list) \
                or resolved_internal_branches != sorted(
                    resolved_internal_branches,
                    key=lambda row: row.get("site", ""),
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved internal-branch evidence differs"
            )
        resolved_internal_branch_sites = set()
        for row in resolved_internal_branches:
            if not isinstance(row, dict) or set(row) != internal_fields \
                    or row["site"] not in actual_branch_sites \
                    or row["site"] in resolved_internal_branch_sites \
                    or row["boundBranchMnemonic"] not in {"ja", "jae"} \
                    or row["branchAddress"] != row["site"].split(":")[1] \
                    or not isinstance(row["indexRegister"], str) \
                    or row["indexRegister"] not in _REGISTER_FAMILIES.values() \
                    or not isinstance(row["inclusiveUpperBound"], int) \
                    or row["inclusiveUpperBound"] < 0 \
                    or not isinstance(row["tableEntryCount"], int) \
                    or row["tableEntryCount"] \
                        != row["inclusiveUpperBound"] + 1 \
                    or not isinstance(row["tableEntries"], list) \
                    or len(row["tableEntries"]) != row["tableEntryCount"] \
                    or not _is_sha256(row["tableSha256"]):
                raise NativeReachabilityClosureError(
                    "indirectTargets: resolved internal-branch row differs"
                )
            indexed = index_by_identifier.get(row["functionId"])
            if indexed is None:
                raise NativeReachabilityClosureError(
                    "indirectTargets: resolved internal function differs"
                )
            function_start = int(indexed["address"], 16)
            function_end = int(indexed["end"], 16)
            block_starts = {
                int(block["start"], 16)
                for block in indexed.get("basic_blocks", [])
            }
            addresses = [
                row["branchAddress"], row["comparisonAddress"],
                row["defaultBranchAddress"], row["defaultTargetAddress"],
                *row["tableEntries"],
            ]
            if any(
                not isinstance(address, str)
                or not address.startswith("0x")
                or not function_start <= int(address, 16) < function_end
                for address in addresses
            ) or int(row["defaultTargetAddress"], 16) not in block_starts \
                    or any(
                        int(address, 16) not in block_starts
                        for address in row["tableEntries"]
                    ):
                raise NativeReachabilityClosureError(
                    "indirectTargets: switch target escaped its function"
                )
            resolved_internal_branch_sites.add(row["site"])
        if evidence.get("resolvedInternalBranchCount") \
                != len(resolved_internal_branches):
            raise NativeReachabilityClosureError(
                "indirectTargets: resolved internal-branch count differs"
            )
        remapped_branches = evidence.get(
            "resolvedRemappedInternalBranches"
        )
        remapped_fields = {
            "site", "functionId", "branchAddress",
            "boundBranchMnemonic", "comparisonAddress",
            "defaultBranchAddress", "defaultTargetAddress",
            "sourceIndexRegister", "remapIndexRegister",
            "inclusiveUpperBound", "remapAddress", "remapEntryCount",
            "remapSha256", "remapValues", "tableAddress",
            "tableEntryCount", "tableEntries", "tableSha256",
        }
        if not isinstance(remapped_branches, list) \
                or remapped_branches != sorted(
                    remapped_branches, key=lambda row: row.get("site", ""),
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: remapped internal branches differ"
            )
        resolved_remapped_sites = set()
        for row in remapped_branches:
            indexed = index_by_identifier.get(row.get("functionId"))
            if not isinstance(row, dict) or set(row) != remapped_fields \
                    or indexed is None \
                    or row["site"] not in actual_branch_sites \
                    or row["site"] in resolved_remapped_sites \
                    or row["site"] in resolved_internal_branch_sites \
                    or row["branchAddress"] != row["site"].split(":")[1] \
                    or row["boundBranchMnemonic"] not in {"ja", "jae"} \
                    or row["sourceIndexRegister"] \
                        not in _REGISTER_FAMILIES.values() \
                    or row["remapIndexRegister"] \
                        not in _REGISTER_FAMILIES.values() \
                    or not isinstance(row["inclusiveUpperBound"], int) \
                    or row["inclusiveUpperBound"] < 0 \
                    or row["remapEntryCount"] \
                        != row["inclusiveUpperBound"] + 1 \
                    or not isinstance(row["remapValues"], list) \
                    or len(row["remapValues"]) != row["remapEntryCount"] \
                    or any(
                        not isinstance(value, int) or not 0 <= value <= 255
                        for value in row["remapValues"]
                    ) \
                    or row["tableEntryCount"] \
                        != max(row["remapValues"]) + 1 \
                    or set(row["remapValues"]) \
                        != set(range(row["tableEntryCount"])) \
                    or not isinstance(row["tableEntries"], list) \
                    or len(row["tableEntries"]) != row["tableEntryCount"] \
                    or not _is_sha256(row["remapSha256"]) \
                    or not _is_sha256(row["tableSha256"]):
                raise NativeReachabilityClosureError(
                    "indirectTargets: remapped internal branch row differs"
                )
            function_start = int(indexed["address"], 16)
            function_end = int(indexed["end"], 16)
            block_starts = {
                int(block["start"], 16)
                for block in indexed.get("basic_blocks", [])
            }
            code_addresses = [
                row["branchAddress"], row["comparisonAddress"],
                row["defaultBranchAddress"], row["defaultTargetAddress"],
                *row["tableEntries"],
            ]
            if any(
                not isinstance(address, str)
                or not address.startswith("0x")
                or not function_start <= int(address, 16) < function_end
                for address in code_addresses
            ) or int(row["defaultTargetAddress"], 16) not in block_starts \
                    or any(
                        int(address, 16) not in block_starts
                        for address in row["tableEntries"]
                    ):
                raise NativeReachabilityClosureError(
                    "indirectTargets: remapped switch target escaped"
                )
            resolved_remapped_sites.add(row["site"])
        if evidence.get("resolvedRemappedInternalBranchCount") \
                != len(remapped_branches):
            raise NativeReachabilityClosureError(
                "indirectTargets: remapped internal branch count differs"
            )
        vtable_branches = evidence.get("resolvedAssignedVtableBranches")
        vtable_branch_fields = {
            "site", "functionId", "branchAddress", "vptrOffset",
            "vptrLoadDefinitions", "slotIndex", "candidateTables",
            "targetAddresses", "targetFunctionIds", "proofSha256",
        }
        if not isinstance(vtable_branches, list) \
                or vtable_branches != sorted(
                    vtable_branches, key=lambda row: row.get("site", ""),
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: assigned-vtable branches differ"
            )
        resolved_vtable_branch_sites = set()
        for row in vtable_branches:
            indexed = index_by_identifier.get(row.get("functionId"))
            if not isinstance(row, dict) \
                    or set(row) != vtable_branch_fields \
                    or indexed is None \
                    or row["site"] not in actual_branch_sites \
                    or row["site"] in resolved_external_branch_sites \
                    or row["site"] in resolved_internal_branch_sites \
                    or row["site"] in resolved_remapped_sites \
                    or row["site"] in resolved_vtable_branch_sites \
                    or row["functionId"] != row["site"].split(":")[-1] \
                    or row["branchAddress"] != row["site"].split(":")[1] \
                    or row["vptrOffset"] != 0 \
                    or not isinstance(row["slotIndex"], int) \
                    or row["slotIndex"] < 0 \
                    or not isinstance(row["vptrLoadDefinitions"], list) \
                    or not row["vptrLoadDefinitions"] \
                    or row["vptrLoadDefinitions"] \
                        != sorted(set(row["vptrLoadDefinitions"])) \
                    or not isinstance(row["candidateTables"], list) \
                    or not row["candidateTables"] \
                    or not isinstance(row["targetAddresses"], list) \
                    or row["targetAddresses"] \
                        != sorted(set(row["targetAddresses"])) \
                    or not isinstance(row["targetFunctionIds"], list) \
                    or row["targetFunctionIds"] \
                        != sorted(set(row["targetFunctionIds"])) \
                    or not set(row["targetFunctionIds"]).issubset(targets) \
                    or not _is_sha256(row["proofSha256"]) \
                    or row["proofSha256"] != sha256_json({
                        key: value for key, value in row.items()
                        if key not in {"site", "proofSha256"}
                    }):
                raise NativeReachabilityClosureError(
                    "indirectTargets: assigned-vtable branch row differs"
                )
            if any(
                not re.fullmatch(r"0x[0-9a-f]{8}", definition)
                or not int(indexed["address"], 16)
                <= int(definition, 16) < int(indexed["end"], 16)
                for definition in row["vptrLoadDefinitions"]
            ):
                raise NativeReachabilityClosureError(
                    "indirectTargets: assigned-vtable branch load differs"
                )
            table_targets = []
            table_addresses = []
            for table in row["candidateTables"]:
                if not isinstance(table, dict) or set(table) != {
                    "tableAddress", "assignmentSites", "tableSha256",
                    "identitySha256", "slotTarget",
                } or not re.fullmatch(
                    r"0x[0-9a-f]{8}", table["tableAddress"],
                ) or not isinstance(table["assignmentSites"], list) \
                        or not table["assignmentSites"] \
                        or table["assignmentSites"] \
                            != sorted(set(table["assignmentSites"])) \
                        or not _is_sha256(table["tableSha256"]) \
                        or not _is_sha256(table["identitySha256"]) \
                        or not isinstance(table["slotTarget"], dict) \
                        or set(table["slotTarget"]) != {
                            "address", "functionId", "functionOffset",
                        } \
                        or table["slotTarget"]["functionId"] \
                            not in row["targetFunctionIds"]:
                    raise NativeReachabilityClosureError(
                        "indirectTargets: assigned-vtable branch table differs"
                    )
                table_addresses.append(table["tableAddress"])
                table_targets.append(table["slotTarget"])
            if table_addresses != sorted(set(table_addresses)) \
                    or sorted({
                        target["address"] for target in table_targets
                    }) != row["targetAddresses"] \
                    or sorted({
                        target["functionId"] for target in table_targets
                    }) != row["targetFunctionIds"]:
                raise NativeReachabilityClosureError(
                    "indirectTargets: assigned-vtable branch targets differ"
                )
            resolved_vtable_branch_sites.add(row["site"])
        if evidence.get("resolvedAssignedVtableBranchCount") \
                != len(vtable_branches) \
                or evidence.get("assignedVtableBranchResolutionPolicy") != (
                    "tail jmp resolution uses the identical entry-ECX "
                    "must-alias, assigned-table completeness and aligned slot "
                    "proof as calls; field and adjusted-this receivers remain "
                    "unresolved"
                ):
            raise NativeReachabilityClosureError(
                "indirectTargets: assigned-vtable branch count differs"
            )
        resolved_branch_sites = (
            resolved_external_branch_sites
            | resolved_internal_branch_sites
            | resolved_remapped_sites
            | resolved_vtable_branch_sites
        )
        if (
            resolved_external_branch_sites & resolved_internal_branch_sites
            or resolved_external_branch_sites & resolved_remapped_sites
            or resolved_external_branch_sites & resolved_vtable_branch_sites
            or resolved_internal_branch_sites & resolved_remapped_sites
            or resolved_internal_branch_sites & resolved_vtable_branch_sites
            or resolved_remapped_sites & resolved_vtable_branch_sites
        ):
            raise NativeReachabilityClosureError(
                "indirectTargets: branch has conflicting resolution classes"
            )
        unresolved_branch_sites = {
            site for site in unresolved
            if site.startswith("indirect-branch:")
        }
        if unresolved_branch_sites \
                != actual_branch_sites - resolved_branch_sites:
            raise NativeReachabilityClosureError(
                "indirectTargets: unresolved indexed branches differ"
            )
        if evidence.get("unresolvedBranchCount") \
                != len(unresolved_branch_sites):
            raise NativeReachabilityClosureError(
                "indirectTargets: unresolved branch count differs"
            )
        if evidence.get("siteCount") != len(sites) \
                or evidence.get("unresolvedPathCount") != len(unresolved):
            raise NativeReachabilityClosureError(
                "indirectTargets: evidence counts differ"
            )
    return review


def validate_all(
    reviews: dict[str, dict[str, Any]], *, root: Path = ROOT,
) -> dict[str, dict[str, Any]]:
    if set(reviews) != set(OUTPUTS):
        raise NativeReachabilityClosureError("closure review set is incomplete")
    return {
        name: validate_review(reviews[name], closure=name, root=root)
        for name in OUTPUTS
    }


def _encoded(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--executable", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.validate:
        reviews = {
            name: load_json(root / relative)
            for name, relative in OUTPUTS.items()
        }
        validate_all(reviews, root=root)
        print(
            "native reachability closures valid: "
            + ", ".join(
                f"{name}={reviews[name]['reviewStatus']}"
                for name in OUTPUTS
            )
        )
        return 0
    if args.executable is None:
        raise SystemExit("--executable is required unless --validate is used")
    reviews = build_reviews(args.executable.resolve(), root=root)
    for name, relative in OUTPUTS.items():
        output = root / relative
        encoded = _encoded(reviews[name])
        if args.check:
            current = output.read_text(encoding="utf-8") \
                if output.is_file() else ""
            if current != encoded:
                diff = "".join(difflib.unified_diff(
                    current.splitlines(keepends=True),
                    encoded.splitlines(keepends=True),
                    fromfile=str(output),
                    tofile=f"fresh {name} closure",
                ))
                raise SystemExit(f"{name} closure drifted:\n{diff}")
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(encoded, encoding="utf-8")
    print(
        "native reachability closures generated: "
        + ", ".join(
            f"{name}={reviews[name]['reviewStatus']}"
            f"({len(reviews[name]['unresolvedPaths'])} gaps)"
            for name in OUTPUTS
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
