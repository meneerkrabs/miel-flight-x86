#!/usr/bin/env python3
"""Execute the original EXE aggregation path through the pinned first-party DLLs."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_PROT_ALL, Uc, UcError, __version__ as unicorn_version
from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_FPCW

try:
    from tools.miel_vliegt.pe32_micro_loader import (
        LoadedPe32, highlow_relocation_count, link_imports, map_pe32,
    )
    from tools.miel_vliegt.x86_micro_oracle import ROOT, SENTINEL, STACK, STACK_SIZE, X86MicroOracle, load_json, sha256_file, validate_contract as validate_air_contract
except ModuleNotFoundError:
    from pe32_micro_loader import LoadedPe32, highlow_relocation_count, link_imports, map_pe32
    from x86_micro_oracle import ROOT, SENTINEL, STACK, STACK_SIZE, X86MicroOracle, load_json, sha256_file, validate_contract as validate_air_contract


CONTRACT = ROOT / "content/miel_vliegt/first_party_dll_contract.json"
OBJECT = 0x75000000
TREE = 0x75100000
TRAPS = 0x75200000
PAGE = 0x1000
CC_BASE = 0x10000000
UDS_BASE = 0x10200000


class FirstPartyOracleError(RuntimeError):
    pass


def _module(contract: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in contract["modules"] if item["name"].lower() == name.lower())


def validate_contract(root: Path = ROOT) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = load_json(root / CONTRACT.relative_to(ROOT))
    identity = load_json(root / "content/miel_vliegt/source_identity.json")
    if contract.get("schema") != 1 or contract.get("policy") != {
        "cc_base": "0x10000000", "udspack_base": "0x10200000",
        "relocations": ["ABSOLUTE", "HIGHLOW"], "forwarded_exports": "FAIL",
        "unresolved_imports": "TRAP", "dllmain": "DO_NOT_EXECUTE_FOR_AGGREGATION",
    }:
        raise ValueError("unsupported or weakened first-party DLL contract")
    if {item["name"] for item in contract.get("modules", [])} != {"Cc.dll", "UdsPack.dll"}:
        raise ValueError("first-party DLL contract module set drifted")
    module_fields = {
        "name", "sha256", "preferred_base", "mapped_base", "size_of_image",
        "exports", "imports", "highlow_relocations",
    }
    if any(set(item) != module_fields for item in contract["modules"]):
        raise ValueError("first-party DLL contract module fields drifted")
    for key, name in (("cc_dll", "Cc.dll"), ("udspack_dll", "UdsPack.dll")):
        if identity[key]["sha256"] != _module(contract, name)["sha256"]:
            raise ValueError(f"{name}: source identity and loader contract disagree")
    return contract, identity


def _patch_executable_imports(
    machine: Uc, oracle: X86MicroOracle,
    providers: dict[str, LoadedPe32], traps: dict[str, int],
) -> None:
    for iat, symbol in oracle.image.imports().items():
        dll, _, name = symbol.partition("!")
        provider = providers.get(dll.lower())
        target = provider.exports.get(name) if provider is not None else None
        machine.mem_write(iat, struct.pack("<I", target or traps[symbol]))


def _encode_chain(machine: Uc, part_ids: list[int], parts: dict[int, dict[str, Any]]) -> int:
    machine.mem_write(TREE, b"\0" * 0x40000)
    node_base, property_base, link_base = TREE, TREE + 0x10000, TREE + 0x20000
    for index, part_id in enumerate(part_ids):
        node = node_base + index * 0x200
        prop = property_base + index * 0x40
        part = parts[part_id]
        machine.mem_write(node + 0x120, struct.pack("<I", prop))
        machine.mem_write(prop + 4, struct.pack(
            "<9I", part["component_type"], part["part_id"], *part["fields"],
        ))
        if index + 1 < len(part_ids):
            link = link_base + index * 0x20
            machine.mem_write(node + 4, struct.pack("<I", link))
            machine.mem_write(link + 0x10, struct.pack("<I", node_base + (index + 1) * 0x200))
    return node_base if part_ids else 0


def _machine(
    executable: Path, cc_path: Path, uds_path: Path, contract: dict[str, Any], identity: dict[str, Any]
) -> tuple[Uc, X86MicroOracle, LoadedPe32, LoadedPe32, dict[int, str]]:
    air_contract, air_identity, index = validate_air_contract()
    oracle = X86MicroOracle(executable, air_contract, air_identity, index)
    machine = oracle._machine()
    cc_row, uds_row = _module(contract, "Cc.dll"), _module(contract, "UdsPack.dll")
    cc = map_pe32(machine, cc_path, CC_BASE, cc_row["sha256"])
    uds = map_pe32(machine, uds_path, UDS_BASE, uds_row["sha256"])
    if cc.image.image_base != int(cc_row["preferred_base"], 16) \
            or uds.image.image_base != int(uds_row["preferred_base"], 16) \
            or cc.base != int(cc_row["mapped_base"], 16) \
            or uds.base != int(uds_row["mapped_base"], 16) \
            or cc.size != cc_row["size_of_image"] or uds.size != uds_row["size_of_image"] \
            or len(cc.exports) != cc_row["exports"] or len(cc.imports) != cc_row["imports"] \
            or len(uds.exports) != uds_row["exports"] or len(uds.imports) != uds_row["imports"] \
            or cc.relocation_count != cc_row["highlow_relocations"] \
            or highlow_relocation_count(cc.image) != cc_row["highlow_relocations"] \
            or highlow_relocation_count(uds.image) != uds_row["highlow_relocations"] \
            or uds.relocation_count != uds_row["highlow_relocations"]:
        raise ValueError("first-party DLL structural contract drifted")
    machine.mem_map(TRAPS, 0x10000, UC_PROT_ALL)
    symbols = sorted(set(oracle.image.imports().values()) | set(cc.imports.values()) | set(uds.imports.values()))
    trap_by_symbol = {symbol: TRAPS + index * 16 for index, symbol in enumerate(symbols)}
    trap_by_address = {address: symbol for symbol, address in trap_by_symbol.items()}
    link_imports(machine, uds, {}, trap_by_symbol)
    link_imports(machine, cc, {"udspack.dll": uds}, trap_by_symbol)
    _patch_executable_imports(
        machine, oracle, {"cc.dll": cc, "udspack.dll": uds}, trap_by_symbol,
    )
    machine.mem_map(OBJECT, PAGE, UC_PROT_ALL)
    machine.mem_map(TREE, 0x40000, UC_PROT_ALL)
    return machine, oracle, cc, uds, trap_by_address


def execute_scenario(
    scenario: str, executable: Path, cc_path: Path, uds_path: Path,
    contract: dict[str, Any], identity: dict[str, Any],
) -> dict[str, Any]:
    machine, oracle, cc, uds, trap_symbols = _machine(
        executable, cc_path, uds_path, contract, identity
    )
    machine.mem_write(OBJECT, b"\0" * PAGE)
    parts_contract = load_json(ROOT / "content/miel_vliegt/uds_flight_part_components.json")
    parts = {item["part_id"]: item for item in parts_contract["parts"]}
    barn = load_json(ROOT / "content/miel_vliegt/uds_barn_contracts.json")
    if scenario == "reset":
        entry, stack_args = 0x0040FA30, []
        exe_ranges = [(0x0040FA30, 0x0040FBB0)]
    elif scenario == "aggregate-null":
        entry, stack_args = 0x0040FBB0, [0, 0, 0]
        exe_ranges = [
            (0x0040F8F0, 0x0040F940), (0x0040FA30, 0x0040FBB0),
            (0x0040FBB0, 0x0040FE30), (0x0040FE30, 0x004102D0),
        ]
    elif scenario == "aggregate-default":
        root = _encode_chain(machine, [item["part_id"] for item in barn["default_airplane"]], parts)
        entry, stack_args = 0x0040FBB0, [root, 0, 0]
        exe_ranges = [
            (0x0040F8F0, 0x0040F940), (0x0040FA30, 0x0040FBB0),
            (0x0040FBB0, 0x0040FE30), (0x0040FE30, 0x004102D0),
        ]
    else:
        raise ValueError(f"unknown first-party scenario {scenario}")
    stack_pointer = STACK + STACK_SIZE - 0x100
    machine.mem_write(stack_pointer, struct.pack(f"<{1 + len(stack_args)}I", SENTINEL, *stack_args))
    machine.reg_write(UC_X86_REG_ESP, stack_pointer)
    machine.reg_write(UC_X86_REG_ECX, OBJECT)
    machine.reg_write(UC_X86_REG_FPCW, 0x027F)
    trace: list[int] = []
    writes: set[tuple[str, int, int]] = set()
    violations: list[str] = []

    def inside(address: int, size: int, base: int, length: int) -> bool:
        return base <= address and address + size <= base + length

    def on_code(uc: Uc, address: int, size: int, _: object) -> None:
        if address in trap_symbols:
            violations.append(f"unresolved platform import reached: {trap_symbols[address]}")
            uc.emu_stop()
        elif any(begin <= address < end for begin, end in exe_ranges) \
                or any(begin <= address < end for begin, end in cc.executable_ranges):
            trace.append(address)
        else:
            violations.append(f"unexpected code at {address:#x}")
            uc.emu_stop()

    def on_read(uc: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
        allowed = inside(address, size, oracle.image.image_base, 0x200000) \
            or inside(address, size, cc.base, cc.size) \
            or inside(address, size, uds.base, uds.size) \
            or inside(address, size, STACK, STACK_SIZE) \
            or inside(address, size, OBJECT, PAGE) \
            or inside(address, size, TREE, 0x40000)
        if not allowed:
            violations.append(f"unexpected read at {address:#x} size {size}")
            uc.emu_stop()

    def on_write(uc: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
        if inside(address, size, STACK, STACK_SIZE):
            writes.add(("stack", address - STACK, size))
        elif inside(address, size, OBJECT, 0x200):
            writes.add(("aircraft", address - OBJECT, size))
        else:
            violations.append(f"unexpected write at {address:#x} size {size}")
            uc.emu_stop()

    def on_invalid(uc: Uc, access: int, address: int, size: int, value: int, _: object) -> bool:
        violations.append(f"invalid memory access {access} at {address:#x} size {size} value {value}")
        uc.emu_stop()
        return False

    machine.hook_add(UC_HOOK_CODE, on_code)
    machine.hook_add(UC_HOOK_MEM_READ, on_read)
    machine.hook_add(UC_HOOK_MEM_WRITE, on_write)
    machine.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
    try:
        machine.emu_start(entry, SENTINEL, count=200000)
    except UcError as error:
        raise FirstPartyOracleError(f"{scenario}: {error}") from error
    expected_esp = stack_pointer + 4 + len(stack_args) * 4
    if violations:
        raise FirstPartyOracleError(f"{scenario}: {violations[0]}")
    if machine.reg_read(UC_X86_REG_EIP) != SENTINEL \
            or machine.reg_read(UC_X86_REG_ESP) != expected_esp:
        raise FirstPartyOracleError(f"{scenario}: incomplete execution or unbalanced stack")
    object_bytes = bytes(machine.mem_read(OBJECT, 0x200))
    return {
        "id": scenario,
        "instruction_count": len(trace),
        "first_party_instruction_count": sum(CC_BASE <= address < CC_BASE + cc.size for address in trace),
        "trace_sha256": hashlib.sha256(b"".join(struct.pack("<I", address) for address in trace)).hexdigest(),
        "aircraft_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "component_mask": struct.unpack_from("<I", object_bytes, 0x128)[0],
        "counted_parts": struct.unpack_from("<i", object_bytes, 0x12C)[0],
        "field6_bits": struct.unpack_from("<I", object_bytes, 0x130)[0],
        "mass_like_bits": struct.unpack_from("<I", object_bytes, 0x15C)[0],
        "write_set_sha256": hashlib.sha256(json.dumps(sorted(writes), separators=(",", ":")).encode()).hexdigest(),
        "platform_import_transcript": [],
    }


def build_receipt(executable: Path, cc_dll: Path, udspack_dll: Path) -> dict[str, Any]:
    contract, identity = validate_contract()
    scenarios = [
        execute_scenario(name, executable, cc_dll, udspack_dll, contract, identity)
        for name in ("reset", "aggregate-null", "aggregate-default")
    ]
    return {
        "schema": 1,
        "protocol": "miel-vliegt-x86-first-party-oracle",
        "evidence_class": "FIRST_PARTY_EXECUTION",
        "equivalence_claimed": False,
        "executable_sha256": identity["executable"]["sha256"],
        "cc_dll_sha256": identity["cc_dll"]["sha256"],
        "udspack_dll_sha256": identity["udspack_dll"]["sha256"],
        "contract_sha256": sha256_file(CONTRACT),
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "scenarios": scenarios,
    }


def verify_artifact(path: Path) -> dict[str, Any]:
    contract, identity = validate_contract()
    receipt = load_json(path)
    if receipt.get("schema") != 1 or receipt.get("protocol") != "miel-vliegt-x86-first-party-oracle" \
            or receipt.get("evidence_class") != "FIRST_PARTY_EXECUTION" \
            or receipt.get("equivalence_claimed") is not False \
            or receipt.get("executable_sha256") != identity["executable"]["sha256"] \
            or receipt.get("cc_dll_sha256") != identity["cc_dll"]["sha256"] \
            or receipt.get("udspack_dll_sha256") != identity["udspack_dll"]["sha256"] \
            or receipt.get("contract_sha256") != sha256_file(CONTRACT) \
            or receipt.get("emulator") != {"name": "unicorn", "version": unicorn_version}:
        raise ValueError("first-party oracle receipt provenance drifted")
    scenarios = receipt.get("scenarios")
    if not isinstance(scenarios, list) or [item.get("id") for item in scenarios] != [
        "reset", "aggregate-null", "aggregate-default"
    ]:
        raise ValueError("first-party oracle scenario coverage drifted")
    for item in scenarios:
        if item.get("instruction_count", 0) <= 0 or item.get("first_party_instruction_count", 0) <= 0 \
                or item.get("platform_import_transcript") != []:
            raise ValueError("first-party oracle did not execute a closed original DLL path")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    verify = sub.add_parser("verify")
    artifact = sub.add_parser("verify-artifact")
    for command in (capture, verify):
        command.add_argument("--executable", type=Path, required=True)
        command.add_argument("--cc-dll", type=Path, required=True)
        command.add_argument("--udspack-dll", type=Path, required=True)
    capture.add_argument("--output", type=Path, default=ROOT / "content/miel_vliegt/x86_first_party_aggregation.json")
    verify.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_first_party_aggregation.json")
    artifact.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_first_party_aggregation.json")
    args = parser.parse_args()
    if args.command == "capture":
        receipt = build_receipt(args.executable.resolve(), args.cc_dll.resolve(), args.udspack_dll.resolve())
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    elif args.command == "verify":
        expected = verify_artifact(args.artifact.resolve())
        actual = build_receipt(args.executable.resolve(), args.cc_dll.resolve(), args.udspack_dll.resolve())
        if actual != expected:
            raise SystemExit("first-party aggregation receipt drifted")
    else:
        verify_artifact(args.artifact.resolve())
    print("x86 first-party aggregation execution OK (no equivalence claim)")


if __name__ == "__main__":
    main()
