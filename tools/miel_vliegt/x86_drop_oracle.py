#!/usr/bin/env python3
"""Execute the original BARN free-release and numerical fall path."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from typing import Any

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MODE_32, UC_PROT_ALL, Uc, UcError, __version__ as unicorn_version
from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_ESP, UC_X86_REG_FPCW

try:
    from tools.miel_vliegt.x86_micro_oracle import ROOT, OBJECT, SENTINEL, STACK, STACK_SIZE, X86MicroOracle, load_json, sha256_file, validate_contract as validate_air_contract
except ModuleNotFoundError:
    from x86_micro_oracle import ROOT, OBJECT, SENTINEL, STACK, STACK_SIZE, X86MicroOracle, load_json, sha256_file, validate_contract as validate_air_contract


CONTRACT = ROOT / "content/miel_vliegt/x86_drop_oracle_contract.json"
HANGAR = 0x73000000
HANGAR_SIZE = 0x3000


class DropOracleError(RuntimeError):
    pass


def _function_by_name(index: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item.get("name"): item for item in index["functions"] if item.get("name")}


def validate_contract(root: Path = ROOT) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    contract = load_json(root / CONTRACT.relative_to(ROOT))
    identity = load_json(root / contract["source_identity"])
    index = load_json(root / contract["native_function_index"])
    expected_policy = {
        "fixed_image_base": "0x00400000",
        "fpu_control_word": "0x027f",
        "instruction_budget": 1000,
        "unallowlisted_code": "FAIL",
        "unexpected_write": "FAIL",
        "vm_boot_is_not_required": True,
    }
    if contract.get("schema") != 1 or contract.get("protocol") != "miel-vliegt-x86-drop-oracle" \
            or contract.get("policy") != expected_policy:
        raise ValueError("unsupported or weakened x86 drop-oracle contract")
    if identity["executable"]["sha256"] != index["source"]["sha256"]:
        raise ValueError("drop-oracle executable identity drifted")
    indexed = _function_by_name(index)
    rows = [*contract["release"]["closure"], contract["ballistics"]]
    for row in rows:
        native = indexed.get(row["native_name"])
        if native is None or any(native.get(field) != row[field] for field in ("address", "end", "sha256")):
            raise ValueError(f"{row['native_name']}: native function identity drifted")
        if row["native_unit"] != f"fn_{int(row['address'], 16):08x}":
            raise ValueError(f"{row['native_name']}: native unit/address mismatch")
    fragments = contract["ballistics"]["fragments"]
    if [item["view"] for item in fragments] != [0, 1, 2]:
        raise ValueError("drop-oracle view fragments are incomplete")
    cases = contract["ballistics"]["cases"]
    if not cases or len({item["id"] for item in cases}) != len(cases):
        raise ValueError("drop-oracle cases need unique ids")
    return contract, identity, index


def _oracle(executable: Path) -> tuple[X86MicroOracle, dict[str, Any]]:
    air_contract, air_identity, air_index = validate_air_contract()
    if sha256_file(executable) != air_identity["executable"]["sha256"]:
        raise ValueError("drop oracle requires the pinned Dutch executable")
    return X86MicroOracle(executable, air_contract, air_identity, air_index), air_identity


def _trace_hash(trace: list[int]) -> str:
    return hashlib.sha256(b"".join(struct.pack("<I", address) for address in trace)).hexdigest()


def _run(machine: Uc, entry: int, end: int, allowed: list[tuple[int, int]], budget: int) -> list[int]:
    trace: list[int] = []
    violations: list[str] = []

    def on_code(uc: Uc, address: int, size: int, _: object) -> None:
        if not any(begin <= address < finish for begin, finish in allowed):
            violations.append(f"unallowlisted execution at {address:#x}")
            uc.emu_stop()
            return
        trace.append(address)

    def on_invalid(uc: Uc, access: int, address: int, size: int, value: int, _: object) -> bool:
        violations.append(f"invalid memory access {access} at {address:#x} size {size} value {value}")
        uc.emu_stop()
        return False

    machine.hook_add(UC_HOOK_CODE, on_code)
    machine.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
    try:
        machine.emu_start(entry, end, count=budget)
    except UcError as error:
        raise DropOracleError(str(error)) from error
    if violations:
        raise DropOracleError(violations[0])
    if machine.reg_read(UC_X86_REG_EIP) != end:
        raise DropOracleError("drop-oracle instruction budget exhausted")
    return trace


def execute_release(executable: Path, contract: dict[str, Any]) -> dict[str, Any]:
    oracle, _ = _oracle(executable)
    machine = oracle._machine()
    machine.mem_map(HANGAR, HANGAR_SIZE, UC_PROT_ALL)
    machine.mem_write(OBJECT, b"\xa5" * 0x100)
    machine.mem_write(HANGAR, b"\0" * HANGAR_SIZE)
    machine.mem_write(HANGAR + 0x1AA4, struct.pack("<I", OBJECT))
    machine.mem_write(HANGAR + 0x1AB8, struct.pack("<I", 0))
    stack_pointer = STACK + STACK_SIZE - 0x100
    machine.mem_write(stack_pointer, struct.pack("<I", SENTINEL))
    machine.reg_write(UC_X86_REG_ESP, stack_pointer)
    machine.reg_write(UC_X86_REG_ECX, HANGAR)
    machine.reg_write(UC_X86_REG_FPCW, int(contract["policy"]["fpu_control_word"], 16))
    ranges = [(int(item["address"], 16), int(item["end"], 16)) for item in contract["release"]["closure"]]
    trace = _run(
        machine,
        int(contract["release"]["entry"], 16),
        SENTINEL,
        ranges,
        contract["policy"]["instruction_budget"],
    )
    return {
        "instruction_count": len(trace),
        "trace_sha256": _trace_hash(trace),
        "held_cleared": struct.unpack("<I", machine.mem_read(HANGAR + 0x1AA4, 4))[0] == 0,
        "falling": machine.mem_read(OBJECT + 0x14, 1) == b"\x01",
        "field28_bits": struct.unpack("<I", machine.mem_read(OBJECT + 0x28, 4))[0],
        "field2c_bits": struct.unpack("<I", machine.mem_read(OBJECT + 0x2C, 4))[0],
    }


def _surface(group_id: int, y: float) -> tuple[int, float]:
    view = min(group_id, 2)
    if view == 0 and y < 430:
        return 0, 470.0
    if view == 1 and y < 410:
        return 0, 430.0
    if view == 2:
        for index, surface in enumerate((120.0, 223.0, 328.0, 436.0)):
            if y < surface:
                return index, surface
    raise ValueError(f"case does not enter native ballistic fragment: group={group_id} y={y}")


def execute_ballistic(executable: Path, contract: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    oracle, _ = _oracle(executable)
    machine = oracle._machine()
    machine.mem_write(OBJECT, b"\0" * 0x100)
    machine.mem_write(OBJECT + 0x28, struct.pack("<f", case["field28"]))
    machine.mem_write(OBJECT + 0x2C, struct.pack("<f", case["field2c"]))
    stack_pointer = STACK + STACK_SIZE - 0x300
    machine.mem_write(stack_pointer + 0x08, struct.pack("<f", case["screen"][0]))
    machine.mem_write(stack_pointer + 0x0C, struct.pack("<f", case["screen"][1]))
    machine.mem_write(stack_pointer + 0x110, struct.pack("<f", case["elapsed"]))
    surface_index, surface_y = _surface(case["group_id"], case["screen"][1])
    fragment = contract["ballistics"]["fragments"][min(case["group_id"], 2)]
    entry, end = int(fragment["entry"], 16), int(fragment["end"], 16)
    machine.reg_write(UC_X86_REG_ESP, stack_pointer)
    machine.reg_write(UC_X86_REG_ESI, OBJECT)
    machine.reg_write(UC_X86_REG_EDX, surface_index)
    machine.reg_write(UC_X86_REG_FPCW, int(contract["policy"]["fpu_control_word"], 16))
    trace = _run(machine, entry, end, [(entry, end)], contract["policy"]["instruction_budget"])
    screen_bits = [
        struct.unpack("<I", machine.mem_read(stack_pointer + offset, 4))[0]
        for offset in (0x08, 0x0C)
    ]
    field28_bits = struct.unpack("<I", machine.mem_read(OBJECT + 0x28, 4))[0]
    field2c_bits = struct.unpack("<I", machine.mem_read(OBJECT + 0x2C, 4))[0]
    return {
        "id": case["id"],
        "instruction_count": len(trace),
        "trace_sha256": _trace_hash(trace),
        "screen_bits": screen_bits,
        "field28_bits": field28_bits,
        "field2c_bits": field2c_bits,
        "settled": field28_bits == 0 and field2c_bits == 0,
        "surface_index": surface_index,
        "surface_y": surface_y,
    }


def web_results(contract: dict[str, Any], root: Path = ROOT) -> tuple[dict[str, Any], dict[str, str]]:
    process = subprocess.run(
        ["node", str(root / contract["web"]["runner"])], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if process.returncode:
        raise DropOracleError(f"web drop runner failed: {process.stderr.strip()}")
    document = json.loads(process.stdout)
    if document.get("schema") != 1:
        raise DropOracleError("web drop runner returned an invalid document")
    paths = [contract["web"]["runner"], *contract["web"]["runtime_paths"]]
    return document, {path: sha256_file(root / path) for path in paths}


def build_receipt(executable: Path, root: Path = ROOT) -> dict[str, Any]:
    contract, identity, _ = validate_contract(root)
    release = execute_release(executable, contract)
    cases = [execute_ballistic(executable, contract, case) for case in contract["ballistics"]["cases"]]
    web, runtime_hashes = web_results(contract, root)
    comparable_release = {key: release[key] for key in ("held_cleared", "falling", "field28_bits", "field2c_bits")}
    if web.get("release") != {"status": "FALL_AND_SETTLE_STARTED", **comparable_release}:
        raise DropOracleError("native/web free-release divergence")
    web_by_id = {item["id"]: item for item in web.get("cases", [])}
    for case in cases:
        comparable = {key: case[key] for key in (
            "id", "screen_bits", "field28_bits", "field2c_bits", "settled", "surface_index"
        )}
        if web_by_id.get(case["id"]) != comparable:
            raise DropOracleError(f"native/web ballistic divergence for {case['id']}")
    return {
        "schema": 1,
        "protocol": contract["protocol"],
        "executable_sha256": identity["executable"]["sha256"],
        "contract_sha256": sha256_file(root / CONTRACT.relative_to(ROOT)),
        "native_function_index_sha256": sha256_file(root / contract["native_function_index"]),
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "web_runtime_hashes": runtime_hashes,
        "release": release,
        "cases": cases,
        "differential_result": "PASS",
        "native_parity_evidence": True,
        "evidence_scope": ["hangar.drop_release", "hangar.drop_ballistics"],
        "native_units": {
            "hangar.drop_release": ["fn_00413f90", "fn_00417b40"],
            "hangar.drop_ballistics": ["fn_00414010"],
        },
    }


def verify_artifact(path: Path, root: Path = ROOT) -> dict[str, Any]:
    contract, identity, _ = validate_contract(root)
    receipt = load_json(path)
    if receipt.get("schema") != 1 or receipt.get("protocol") != contract["protocol"] \
            or receipt.get("executable_sha256") != identity["executable"]["sha256"] \
            or receipt.get("contract_sha256") != sha256_file(root / CONTRACT.relative_to(ROOT)) \
            or receipt.get("native_function_index_sha256") != sha256_file(root / contract["native_function_index"]) \
            or receipt.get("emulator") != {"name": "unicorn", "version": unicorn_version} \
            or receipt.get("differential_result") != "PASS" \
            or receipt.get("native_parity_evidence") is not True:
        raise ValueError("x86 drop-oracle receipt provenance drifted")
    expected_scope = ["hangar.drop_release", "hangar.drop_ballistics"]
    expected_units = {
        "hangar.drop_release": ["fn_00413f90", "fn_00417b40"],
        "hangar.drop_ballistics": ["fn_00414010"],
    }
    if receipt.get("evidence_scope") != expected_scope or receipt.get("native_units") != expected_units:
        raise ValueError("x86 drop-oracle evidence scope drifted")
    web, runtime_hashes = web_results(contract, root)
    if receipt.get("web_runtime_hashes") != runtime_hashes:
        raise ValueError("x86 drop-oracle web runtime drifted")
    release = receipt.get("release", {})
    comparable_release = {key: release.get(key) for key in ("held_cleared", "falling", "field28_bits", "field2c_bits")}
    if web.get("release") != {"status": "FALL_AND_SETTLE_STARTED", **comparable_release} \
            or release.get("instruction_count", 0) <= 0 or not release.get("trace_sha256"):
        raise ValueError("x86 drop-oracle release differential drifted")
    cases = receipt.get("cases")
    expected_ids = [item["id"] for item in contract["ballistics"]["cases"]]
    if not isinstance(cases, list) or [item.get("id") for item in cases] != expected_ids:
        raise ValueError("x86 drop-oracle ballistic coverage drifted")
    web_by_id = {item["id"]: item for item in web["cases"]}
    for case in cases:
        comparable = {key: case.get(key) for key in (
            "id", "screen_bits", "field28_bits", "field2c_bits", "settled", "surface_index"
        )}
        if web_by_id.get(case["id"]) != comparable \
                or case.get("instruction_count", 0) <= 0 or not case.get("trace_sha256"):
            raise ValueError(f"x86 drop-oracle ballistic differential drifted for {case['id']}")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    verify = sub.add_parser("verify")
    artifact = sub.add_parser("verify-artifact")
    for command in (capture, verify):
        command.add_argument("--executable", type=Path, required=True)
    capture.add_argument("--output", type=Path, default=ROOT / "content/miel_vliegt/x86_drop_oracle.json")
    verify.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_drop_oracle.json")
    artifact.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_drop_oracle.json")
    args = parser.parse_args()
    if args.command == "capture":
        receipt = build_receipt(args.executable.resolve())
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    elif args.command == "verify":
        expected = verify_artifact(args.artifact.resolve())
        actual = build_receipt(args.executable.resolve())
        if actual != expected:
            raise SystemExit("x86 drop-oracle native receipt drifted")
    else:
        verify_artifact(args.artifact.resolve())
    print("x86 BARN drop differential OK")


if __name__ == "__main__":
    main()
