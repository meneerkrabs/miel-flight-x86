#!/usr/bin/env python3
"""Build a reproducible function/callgraph index for the native flight executable."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)


class PeImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.image_base, self.entrypoint, self.sections, self._directories = self._headers()

    def _headers(self):
        if self.data[:2] != b"MZ":
            raise ValueError(f"{self.path}: missing MZ header")
        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise ValueError(f"{self.path}: missing PE header")
        coff = pe_offset + 4
        machine, section_count, _, _, _, optional_size, _ = struct.unpack_from(
            "<HHIIIHH", self.data, coff
        )
        if machine != 0x14C:
            raise ValueError(f"{self.path}: expected i386 PE, got machine {machine:#x}")
        optional = coff + 20
        if struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise ValueError(f"{self.path}: expected PE32 optional header")
        image_base = struct.unpack_from("<I", self.data, optional + 28)[0]
        entrypoint = image_base + struct.unpack_from("<I", self.data, optional + 16)[0]
        directory_count = min(struct.unpack_from("<I", self.data, optional + 92)[0], 16)
        directories = [
            struct.unpack_from("<II", self.data, optional + 96 + index * 8)
            for index in range(directory_count)
        ]
        section_offset = optional + optional_size
        sections = []
        for index in range(section_count):
            offset = section_offset + index * 40
            name, virtual_size, virtual_address, raw_size, raw_offset, _, _, _, _, flags = (
                struct.unpack_from("<8sIIIIIIHHI", self.data, offset)
            )
            sections.append(Section(
                name.rstrip(b"\0").decode("ascii"),
                image_base + virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                flags,
            ))
        return image_base, entrypoint, tuple(sections), directories

    def address_to_offset(self, address: int) -> int:
        for section in self.sections:
            delta = address - section.virtual_address
            if 0 <= delta < section.raw_size:
                return section.raw_offset + delta
        raise ValueError(f"address {address:#x} is not file-backed")

    def bytes_at(self, address: int, size: int) -> bytes:
        offset = self.address_to_offset(address)
        return self.data[offset:offset + size]

    def cstring(self, address: int) -> str:
        offset = self.address_to_offset(address)
        end = self.data.find(b"\0", offset)
        if end < 0:
            raise ValueError(f"unterminated string at {address:#x}")
        return self.data[offset:end].decode("latin-1")

    def imports(self) -> dict[int, str]:
        if len(self._directories) < 2 or not self._directories[1][0]:
            return {}
        descriptor = self.image_base + self._directories[1][0]
        imports = {}
        while True:
            offset = self.address_to_offset(descriptor)
            original, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", self.data, offset)
            if not any((original, name_rva, first_thunk)):
                break
            dll = self.cstring(self.image_base + name_rva)
            lookup = self.image_base + (original or first_thunk)
            iat = self.image_base + first_thunk
            index = 0
            while True:
                value = struct.unpack_from("<I", self.data, self.address_to_offset(lookup + index * 4))[0]
                if not value:
                    break
                if value & 0x80000000:
                    symbol = f"ordinal_{value & 0xffff}"
                else:
                    symbol = self.cstring(self.image_base + value + 2)
                imports[iat + index * 4] = f"{dll}!{symbol}"
                index += 1
            descriptor += 20
        return imports

    def strings(self, minimum: int = 5) -> dict[int, str]:
        strings = {}
        for section in self.sections:
            if section.executable:
                continue
            data = self.data[section.raw_offset:section.raw_offset + section.raw_size]
            start = None
            for index, value in enumerate(data + b"\0"):
                printable = value in (9, 10, 13) or 32 <= value < 127
                if printable and start is None:
                    start = index
                if not printable and start is not None:
                    if index - start >= minimum:
                        strings[section.virtual_address + start] = data[start:index].decode("ascii")
                    start = None
        return strings


def _padding_starts(code: bytes, base: int) -> set[int]:
    starts = {base}
    index = 0
    while index < len(code):
        if code[index] not in (0x90, 0xCC):
            index += 1
            continue
        end = index + 1
        while end < len(code) and code[end] in (0x90, 0xCC):
            end += 1
        if end - index >= 4 and end < len(code):
            starts.add(base + end)
        index = end
    return starts


def analyze(image: PeImage, seeds: dict[str, object]) -> dict[str, object]:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    imports = image.imports()
    strings = image.strings()
    seed_by_address = {int(item["address"], 16): item for item in seeds["functions"]}
    for address, seed in seed_by_address.items():
        # De seeds dragen alleen hash+lengte; de bytes zelf komen uit de
        # lokale executable, zodat de publieke repo geen code herdistribueert.
        actual = image.bytes_at(address, seed["signature_length"])
        if hashlib.sha256(actual).hexdigest() != seed["signature_sha256"]:
            raise ValueError(f"native function signature drifted: {seed['name']} at {address:#x}")
    contract_evidence = []
    function_names = {item["name"] for item in seeds["functions"]}
    for contract in seeds.get("contracts", []):
        if contract["function"] not in function_names:
            raise ValueError(f"native contract names unknown function: {contract['function']}")
        address = int(contract["address"], 16)
        actual = image.bytes_at(address, contract["bytes_length"])
        if hashlib.sha256(actual).hexdigest() != contract["bytes_sha256"]:
            raise ValueError(f"native contract drifted: {contract['id']} at {address:#x}")
        contract_evidence.append({
            "id": contract["id"],
            "function": contract["function"],
            "address": f"0x{address:08x}",
            "sha256": contract["bytes_sha256"],
            "decoded": contract["decoded"],
        })

    instructions = {}
    starts = {image.entrypoint, *seed_by_address}
    section_ends = {}
    for section in image.sections:
        if not section.executable:
            continue
        code = image.data[section.raw_offset:section.raw_offset + section.raw_size]
        section_ends[section.virtual_address] = section.virtual_address + len(code)
        starts.update(_padding_starts(code, section.virtual_address))
        for instruction in md.disasm(code, section.virtual_address):
            instructions[instruction.address] = instruction
            if instruction.mnemonic == "call" and instruction.operands:
                operand = instruction.operands[0]
                if operand.type == X86_OP_IMM:
                    starts.add(operand.imm)

    executable_ranges = [
        (section.virtual_address, section.virtual_address + section.raw_size)
        for section in image.sections if section.executable
    ]
    starts = sorted(
        address for address in starts
        if address in instructions and any(begin <= address < end for begin, end in executable_ranges)
    )
    functions = []
    total_basic_blocks = 0
    total_conditional_branches = 0
    total_indirect_branches = 0
    total_decoded_bytes = 0
    total_skipdata_bytes = 0
    for index, start in enumerate(starts):
        containing_end = next(end for begin, end in executable_ranges if begin <= start < end)
        later = starts[index + 1] if index + 1 < len(starts) else containing_end
        end = min(later, containing_end)
        calls = set()
        import_calls = set()
        unresolved_indirect_calls = []
        unresolved_direct_calls = []
        branch_sites = []
        string_refs = {}
        data_refs = set()
        function_instructions = [
            instructions[address]
            for address in sorted(address for address in instructions if start <= address < end)
        ]
        block_starts = {start}
        for instruction in function_instructions:
            try:
                operands = instruction.operands
            except CsError:
                operands = ()
            try:
                is_jump = instruction.group(CS_GRP_JUMP)
                is_return = instruction.group(CS_GRP_RET)
            except CsError:
                is_jump = is_return = False
            next_address = instruction.address + instruction.size
            if is_jump:
                operand = operands[0] if operands else None
                target = (
                    operand.imm & 0xFFFFFFFF
                    if operand is not None and operand.type == X86_OP_IMM else None
                )
                conditional = instruction.mnemonic != "jmp"
                if target is not None:
                    kind = "direct_conditional" if conditional else "direct_unconditional"
                    branch_sites.append({
                        "address": f"0x{instruction.address:08x}",
                        "kind": kind,
                        "target": f"0x{target:08x}",
                    })
                    if start <= target < end:
                        block_starts.add(target)
                else:
                    branch_sites.append({
                        "address": f"0x{instruction.address:08x}",
                        "kind": "unresolved_switch_or_indirect_jump",
                    })
                if next_address < end:
                    block_starts.add(next_address)
            elif is_return and next_address < end:
                block_starts.add(next_address)
            if instruction.mnemonic == "call" and operands:
                operand = operands[0]
                if operand.type == X86_OP_IMM:
                    target = operand.imm & 0xFFFFFFFF
                    if target not in starts:
                        unresolved_direct_calls.append({
                            "address": f"0x{instruction.address:08x}",
                            "target": f"0x{target:08x}",
                        })
                elif operand.type == X86_OP_REG:
                    unresolved_indirect_calls.append({
                        "address": f"0x{instruction.address:08x}",
                        "kind": "register",
                    })
                elif operand.type == X86_OP_MEM:
                    target = operand.mem.disp & 0xFFFFFFFF
                    is_absolute = operand.mem.base == 0 and operand.mem.index == 0
                    if not (is_absolute and target in imports):
                        unresolved_indirect_calls.append({
                            "address": f"0x{instruction.address:08x}",
                            "kind": "memory",
                        })
            for operand in operands:
                if operand.type == X86_OP_IMM:
                    target = operand.imm
                    if instruction.mnemonic == "call" and target in starts:
                        calls.add(target)
                    if target in strings:
                        string_refs[target] = strings[target]
                elif operand.type == X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
                    target = operand.mem.disp & 0xFFFFFFFF
                    if instruction.mnemonic in ("call", "jmp") and target in imports:
                        import_calls.add(imports[target])
                    if target in strings:
                        string_refs[target] = strings[target]
                    elif image.image_base <= target < image.image_base + 0x1000000:
                        data_refs.add(target)
        sorted_block_starts = sorted(block_starts)
        basic_blocks = []
        for block_index, block_start in enumerate(sorted_block_starts):
            block_end = sorted_block_starts[block_index + 1] if block_index + 1 < len(sorted_block_starts) else end
            block_instructions = [
                instruction for instruction in function_instructions
                if block_start <= instruction.address < block_end
            ]
            decoded_bytes = sum(
                instruction.size for instruction in block_instructions if instruction.id != 0
            )
            skipdata_bytes = sum(
                instruction.size for instruction in block_instructions if instruction.id == 0
            )
            basic_blocks.append({
                "id": f"bb_{block_start:08x}",
                "start": f"0x{block_start:08x}",
                "end": f"0x{block_end:08x}",
                "size": block_end - block_start,
                "instruction_count": len(block_instructions),
                "decoded_instruction_bytes": decoded_bytes,
                "unknown_skipdata_bytes": skipdata_bytes,
            })
        decoded_bytes = sum(
            instruction.size for instruction in function_instructions if instruction.id != 0
        )
        skipdata_bytes = sum(
            instruction.size for instruction in function_instructions if instruction.id == 0
        )
        instruction_covered_bytes = decoded_bytes + skipdata_bytes
        uncovered_bytes = max(0, end - start - instruction_covered_bytes)
        total_basic_blocks += len(basic_blocks)
        total_conditional_branches += sum(
            site["kind"] == "direct_conditional" for site in branch_sites
        )
        total_indirect_branches += sum(
            site["kind"] == "unresolved_switch_or_indirect_jump" for site in branch_sites
        )
        total_decoded_bytes += decoded_bytes
        total_skipdata_bytes += skipdata_bytes
        raw = image.bytes_at(start, end - start)
        seed = seed_by_address.get(start)
        functions.append({
            "address": f"0x{start:08x}",
            "end": f"0x{end:08x}",
            "size": end - start,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "name": seed["name"] if seed else None,
            "module": seed["module"] if seed else None,
            "calls": [f"0x{target:08x}" for target in sorted(calls)],
            "imports": sorted(import_calls),
            "strings": [
                {"address": f"0x{address:08x}", "value": value}
                for address, value in sorted(string_refs.items())
            ],
            "data_references": [f"0x{address:08x}" for address in sorted(data_refs)],
            "unresolved_indirect_calls": unresolved_indirect_calls,
            "unresolved_direct_calls": unresolved_direct_calls,
            "branch_sites": branch_sites,
            "basic_blocks": basic_blocks,
            "analysis_coverage": {
                "function_span_bytes": end - start,
                "decoded_instruction_bytes": decoded_bytes,
                "unknown_skipdata_bytes": skipdata_bytes,
                "uncovered_bytes": uncovered_bytes,
            },
        })
    executable_bytes = sum(
        section.raw_size for section in image.sections if section.executable
    )
    function_span_bytes = sum(function["size"] for function in functions)
    return {
        "schema": 1,
        "source": {
            "sha256": hashlib.sha256(image.data).hexdigest(),
            "image_base": f"0x{image.image_base:08x}",
            "entrypoint": f"0x{image.entrypoint:08x}",
        },
        "counts": {
            "sections": len(image.sections),
            "imports": len(imports),
            "strings": len(strings),
            "functions": len(functions),
            "named_functions": len(seed_by_address),
            "basic_blocks": total_basic_blocks,
            "direct_conditional_branches": total_conditional_branches,
            "unresolved_indirect_branches": total_indirect_branches,
            "executable_bytes": executable_bytes,
            "function_span_bytes": function_span_bytes,
            "decoded_instruction_bytes": total_decoded_bytes,
            "unknown_skipdata_bytes": total_skipdata_bytes,
            "uncovered_executable_bytes": max(0, executable_bytes - function_span_bytes),
        },
        "sections": [
            {
                "name": section.name,
                "address": f"0x{section.virtual_address:08x}",
                "virtual_size": section.virtual_size,
                "raw_size": section.raw_size,
                "executable": section.executable,
            }
            for section in image.sections
        ],
        "imports": [
            {"address": f"0x{address:08x}", "symbol": symbol}
            for address, symbol in sorted(imports.items())
        ],
        "contracts": contract_evidence,
        "functions": functions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--seeds", type=Path,
        default=Path(__file__).resolve().parents[2] / "content/miel_vliegt/native_function_seeds.json",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    seeds = json.loads(args.seeds.read_text(encoding="utf-8"))
    result = analyze(PeImage(args.executable), seeds)
    if result["source"]["sha256"] != seeds["image_sha256"]:
        raise SystemExit("native executable identity does not match function seeds")
    encoded = json.dumps(result, separators=(",", ":")) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            raise SystemExit("native function index drifted; regenerate only from the pinned executable")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
