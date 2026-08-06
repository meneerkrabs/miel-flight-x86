#!/usr/bin/env python3
"""Execute allowlisted import-free Miel Vliegt x86 functions as a micro-oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path
from typing import Any

from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MODE_32,
    UC_PROT_ALL,
    Uc,
    UcError,
    __version__ as unicorn_version,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_ECX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
    UC_X86_REG_FPCW,
)

try:
    from tools.miel_vliegt.analyze_native import PeImage
except ModuleNotFoundError:
    from analyze_native import PeImage


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "content/miel_vliegt/x86_micro_oracle_contract.json"
PAGE = 0x1000
STACK = 0x70000000
STACK_SIZE = 0x20000
OBJECT = 0x71000000
OBJECT_SIZE = 0x1000
SENTINEL = 0x72000000


class OracleError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def align(value: int) -> int:
    return (value + PAGE - 1) & ~(PAGE - 1)


def signed32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def case_masks(contract: dict[str, Any]) -> list[int]:
    first, last = contract["cases"]["inclusive_mask_range"]
    masks = list(range(first, last + 1)) + contract["cases"]["edge_masks"]
    if len(masks) != len(set(masks)) or any(not 0 <= mask <= 0xFFFFFFFF for mask in masks):
        raise ValueError("micro-oracle masks must be unique uint32 values")
    return masks


def differential_masks(contract: dict[str, Any]) -> list[int]:
    first, last = contract["cases"]["inclusive_mask_range"]
    return list(range(first, last + 1))


def validate_contract(root: Path = ROOT) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    contract = load_json(root / CONTRACT.relative_to(ROOT))
    identity = load_json(root / contract["source_identity"])
    index = load_json(root / contract["native_function_index"])
    if contract.get("schema") != 1 or contract.get("protocol") != "miel-vliegt-x86-micro-oracle":
        raise ValueError("unsupported x86 micro-oracle contract")
    if contract["policy"] != {
        "fixed_image_base": "0x00400000",
        "fpu_control_word": "0x027f",
        "instruction_budget": 1000,
        "unhandled_import": "FAIL",
        "unallowlisted_code": "FAIL",
        "unexpected_write": "FAIL",
        "vm_boot_is_not_required": True,
    }:
        raise ValueError("x86 micro-oracle policy was weakened")
    indexed = {item.get("name"): item for item in index["functions"]}
    function_ids = [item.get("id") for item in contract["functions"]]
    native_names = [item.get("native_name") for item in contract["functions"]]
    native_units = [item.get("native_unit") for item in contract["functions"]]
    web_results = [item.get("web_result") for item in contract["functions"]]
    if len(function_ids) != len(set(function_ids)) or len(native_names) != len(set(native_names)) \
            or len(native_units) != len(set(native_units)) \
            or len(web_results) != len(set(web_results)) or any(not item for item in web_results):
        raise ValueError("x86 micro-oracle functions require unique ids, native names, units and web results")
    for function in contract["functions"]:
        native = indexed.get(function["native_name"])
        if native is None or any(native.get(field) != function[field] for field in ("address", "end", "sha256")):
            raise ValueError(f"{function['id']}: native function identity drifted")
        if function["native_unit"] != f"fn_{int(function['address'], 16):08x}":
            raise ValueError(f"{function['id']}: native unit does not match its function address")
        if function.get("result") not in {"eax_bool", "eax_int32"}:
            raise ValueError(f"{function['id']}: unsupported micro-oracle result decoder")
        closure = [indexed.get(name) for name in function["closure"]]
        if any(item is None for item in closure):
            raise ValueError(f"{function['id']}: micro-oracle closure names an unknown function")
        closure_addresses = {item["address"] for item in closure}
        for item in closure:
            if item.get("imports") or item.get("unresolved_indirect_calls") \
                    or item.get("unresolved_direct_calls"):
                raise ValueError(f"{function['id']}: micro-oracle closure is not import-free and closed")
            if not set(item.get("calls", [])).issubset(closure_addresses):
                raise ValueError(f"{function['id']}: direct call escapes the micro-oracle closure")
        if function["calling_convention"] != "thiscall":
            raise ValueError(f"{function['id']}: unsupported calling convention")
    if identity["executable"]["sha256"] != index["source"]["sha256"]:
        raise ValueError("micro-oracle executable identity drifted")
    case_masks(contract)
    return contract, identity, index


class X86MicroOracle:
    def __init__(self, executable: Path, contract: dict[str, Any], identity: dict[str, Any], index: dict[str, Any]):
        if sha256_file(executable) != identity["executable"]["sha256"]:
            raise ValueError("micro-oracle requires the pinned Dutch executable")
        self.image = PeImage(executable)
        if self.image.image_base != int(contract["policy"]["fixed_image_base"], 16):
            raise ValueError("micro-oracle executable is not at the fixed image base")
        self.contract = contract
        self.functions = {item["native_name"]: item for item in contract["functions"]}
        self.indexed = {item.get("name"): item for item in index["functions"]}
        self.block_ranges = []
        for function in index["functions"]:
            for block in function.get("basic_blocks", []):
                self.block_ranges.append((int(block["start"], 16), int(block["end"], 16), block["id"]))

    def _machine(self) -> Uc:
        machine = Uc(UC_ARCH_X86, UC_MODE_32)
        image_end = max(
            section.virtual_address + max(section.virtual_size, section.raw_size)
            for section in self.image.sections
        )
        machine.mem_map(self.image.image_base, align(image_end - self.image.image_base), UC_PROT_ALL)
        first_raw = min(section.raw_offset for section in self.image.sections)
        machine.mem_write(self.image.image_base, self.image.data[:first_raw])
        for section in self.image.sections:
            machine.mem_write(
                section.virtual_address,
                self.image.data[section.raw_offset:section.raw_offset + section.raw_size],
            )
        machine.mem_map(STACK, STACK_SIZE, UC_PROT_ALL)
        machine.mem_map(OBJECT, OBJECT_SIZE, UC_PROT_ALL)
        machine.mem_map(SENTINEL, PAGE, UC_PROT_ALL)
        machine.mem_write(SENTINEL, b"\xcc")
        return machine

    def execute(self, function_name: str, component_mask: int) -> dict[str, Any]:
        function = self.functions[function_name]
        closure = [self.indexed[name] for name in function["closure"]]
        allowed = [(int(item["address"], 16), int(item["end"], 16)) for item in closure]
        machine = self._machine()
        machine.mem_write(OBJECT, b"\0" * OBJECT_SIZE)
        offset = self.contract["object_layout"]["component_mask"]["offset"]
        machine.mem_write(OBJECT + offset, struct.pack("<I", component_mask))
        stack_pointer = STACK + STACK_SIZE - 0x100
        machine.mem_write(stack_pointer, struct.pack("<I", SENTINEL))
        machine.reg_write(UC_X86_REG_ESP, stack_pointer)
        machine.reg_write(UC_X86_REG_ECX, OBJECT)
        machine.reg_write(UC_X86_REG_EAX, 0)
        machine.reg_write(UC_X86_REG_FPCW, int(self.contract["policy"]["fpu_control_word"], 16))
        trace: list[int] = []
        reads: set[tuple[int, int]] = set()
        writes: set[tuple[str, int, int]] = set()
        violation: list[str] = []

        def in_range(address: int, size: int, begin: int, length: int) -> bool:
            return begin <= address and address + size <= begin + length

        def on_code(uc: Uc, address: int, size: int, _: object) -> None:
            if not any(begin <= address < end for begin, end in allowed):
                violation.append(f"unallowlisted execution at {address:#x}")
                uc.emu_stop()
                return
            trace.append(address)

        def on_read(_: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
            if in_range(address, size, OBJECT, OBJECT_SIZE):
                object_size = self.contract["object_layout"]["size"]
                if not in_range(address, size, OBJECT, object_size):
                    violation.append(f"object read exceeds declared layout at {address:#x} size {size}")
                    machine.emu_stop()
                else:
                    reads.add((address - OBJECT, size))

        def on_write(uc: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
            if in_range(address, size, STACK, STACK_SIZE):
                writes.add(("stack", address - STACK, size))
            elif in_range(address, size, OBJECT, OBJECT_SIZE):
                object_size = self.contract["object_layout"]["size"]
                if not in_range(address, size, OBJECT, object_size):
                    violation.append(f"object write exceeds declared layout at {address:#x} size {size}")
                    uc.emu_stop()
                else:
                    writes.add(("object", address - OBJECT, size))
            else:
                violation.append(f"unexpected write at {address:#x} size {size}")
                uc.emu_stop()

        def on_invalid(uc: Uc, access: int, address: int, size: int, value: int, _: object) -> bool:
            violation.append(f"invalid memory access {access} at {address:#x} size {size} value {value}")
            uc.emu_stop()
            return False

        machine.hook_add(UC_HOOK_CODE, on_code)
        machine.hook_add(UC_HOOK_MEM_READ, on_read)
        machine.hook_add(UC_HOOK_MEM_WRITE, on_write)
        machine.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
        try:
            machine.emu_start(
                int(function["address"], 16),
                SENTINEL,
                count=self.contract["policy"]["instruction_budget"],
            )
        except UcError as error:
            raise OracleError(f"{function_name} mask {component_mask:#x}: {error}") from error
        if violation:
            raise OracleError(f"{function_name} mask {component_mask:#x}: {violation[0]}")
        if machine.reg_read(UC_X86_REG_EIP) != SENTINEL:
            raise OracleError(f"{function_name} mask {component_mask:#x}: instruction budget exhausted")
        if machine.reg_read(UC_X86_REG_ESP) != stack_pointer + 4:
            raise OracleError(f"{function_name} mask {component_mask:#x}: unbalanced stack")
        blocks = []
        for address in trace:
            block_id = next((block for begin, end, block in self.block_ranges if begin <= address < end), None)
            if block_id and (not blocks or blocks[-1] != block_id):
                blocks.append(block_id)
        trace_bytes = b"".join(struct.pack("<I", address) for address in trace)
        write_rows = [
            {"region": region, "offset": address, "size": size}
            for region, address, size in sorted(writes)
        ]
        return {
            "eax": machine.reg_read(UC_X86_REG_EAX),
            "instruction_count": len(trace),
            "trace_sha256": sha256_bytes(trace_bytes),
            "basic_blocks": blocks,
            "object_reads": [
                {"offset": address, "size": size} for address, size in sorted(reads)
            ],
            "write_count": len(write_rows),
            "write_regions": sorted({row["region"] for row in write_rows}),
            "writes_sha256": sha256_bytes(json.dumps(write_rows, separators=(",", ":")).encode()),
        }


def validate_web_case_coverage(contract: dict[str, Any], cases: Any) -> list[dict[str, Any]]:
    if not isinstance(cases, list):
        raise OracleError("web airworthiness runner returned no cases")
    masks = [item.get("component_mask") for item in cases if isinstance(item, dict)]
    if masks != differential_masks(contract):
        raise OracleError("web airworthiness runner did not cover every differential mask exactly once")
    for case in cases:
        for function in contract["functions"]:
            value = case.get(function["web_result"])
            if function["result"] == "eax_bool":
                valid = isinstance(value, bool)
            else:
                valid = isinstance(value, int) and not isinstance(value, bool) \
                    and -0x80000000 <= value <= 0x7FFFFFFF
            if not valid:
                raise OracleError(
                    f"web airworthiness runner returned an invalid {function['web_result']}"
                )
    return cases


def web_cases(contract: dict[str, Any], root: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    runner = root / contract["web"]["runner"]
    process = subprocess.run(
        ["node", str(runner)], cwd=root, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if process.returncode:
        raise OracleError(f"web airworthiness runner failed: {process.stderr.strip()}")
    document = json.loads(process.stdout)
    if document.get("schema") != 1:
        raise OracleError("web airworthiness runner returned an invalid document")
    cases = validate_web_case_coverage(contract, document.get("cases"))
    paths = [contract["web"]["runner"], *contract["web"]["runtime_paths"]]
    return cases, {path: sha256_file(root / path) for path in paths}


def build_receipt(executable: Path, root: Path = ROOT) -> dict[str, Any]:
    contract, identity, index = validate_contract(root)
    oracle = X86MicroOracle(executable, contract, identity, index)
    web, runtime_hashes = web_cases(contract, root)
    web_by_mask = {item["component_mask"]: item for item in web}
    cases = []
    trace_ids: dict[str, str] = {}
    trace_catalog: dict[str, dict[str, Any]] = {}

    def intern_trace(trace: dict[str, Any]) -> str:
        canonical = json.dumps(trace, sort_keys=True, separators=(",", ":"))
        if canonical not in trace_ids:
            trace_id = f"trace-{len(trace_ids) + 1:02d}"
            trace_ids[canonical] = trace_id
            trace_catalog[trace_id] = trace
        return trace_ids[canonical]

    for mask in case_masks(contract):
        native_results = {}
        native_traces = {}
        for function in contract["functions"]:
            trace = oracle.execute(function["native_name"], mask)
            value = bool(trace["eax"]) if function["result"] == "eax_bool" else signed32(trace["eax"])
            native_results[function["id"]] = value
            native_traces[function["id"]] = intern_trace(trace)
        native_result = {
            function["web_result"]: native_results[function["id"]]
            for function in contract["functions"]
        }
        candidate = web_by_mask.get(mask)
        is_differential = mask in web_by_mask
        if is_differential and any(candidate[key] != value for key, value in native_result.items()):
            raise OracleError(f"native/web airworthiness divergence for mask {mask:#x}")
        cases.append({
            "component_mask": mask,
            "differential": is_differential,
            **native_result,
            "native_results": native_results,
            "native": native_traces,
        })
    return {
        "schema": 1,
        "protocol": contract["protocol"],
        "executable_sha256": identity["executable"]["sha256"],
        "contract_sha256": sha256_file(root / CONTRACT.relative_to(ROOT)),
        "native_function_index_sha256": sha256_file(root / contract["native_function_index"]),
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "web_runtime_hashes": runtime_hashes,
        "trace_catalog": trace_catalog,
        "cases": cases,
        "native_case_count": len(cases) * len(contract["functions"]),
        "differential_case_count": len(web) * len(contract["functions"]),
        "differential_result": "PASS",
        "native_parity_evidence": True,
        "evidence_scope": [item["id"] for item in contract["functions"]],
        "native_units": {
            item["id"]: [item["native_unit"]] for item in contract["functions"]
        },
    }


def verify_artifact(path: Path, root: Path = ROOT) -> dict[str, Any]:
    contract, identity, _ = validate_contract(root)
    receipt = load_json(path)
    if receipt.get("schema") != 1 or receipt.get("protocol") != contract["protocol"]:
        raise ValueError("unsupported x86 micro-oracle receipt")
    if receipt.get("executable_sha256") != identity["executable"]["sha256"]:
        raise ValueError("x86 micro-oracle receipt targets another executable")
    if receipt.get("contract_sha256") != sha256_file(root / CONTRACT.relative_to(ROOT)):
        raise ValueError("x86 micro-oracle receipt contract drifted")
    if receipt.get("native_function_index_sha256") != sha256_file(root / contract["native_function_index"]):
        raise ValueError("x86 micro-oracle receipt native index drifted")
    if receipt.get("emulator") != {"name": "unicorn", "version": unicorn_version}:
        raise ValueError("x86 micro-oracle emulator version drifted")
    masks = case_masks(contract)
    expected_scope = [item["id"] for item in contract["functions"]]
    if receipt.get("evidence_scope") != expected_scope:
        raise ValueError("x86 micro-oracle evidence scope drifted")
    expected_units = {item["id"]: [item["native_unit"]] for item in contract["functions"]}
    if receipt.get("native_units") != expected_units:
        raise ValueError("x86 micro-oracle native-unit coverage drifted")
    cases = receipt.get("cases")
    if not isinstance(cases, list) or [item.get("component_mask") for item in cases] != masks:
        raise ValueError("x86 micro-oracle case coverage is incomplete")
    if receipt.get("native_case_count") != len(masks) * len(contract["functions"]) \
            or receipt.get("differential_case_count") \
            != len(differential_masks(contract)) * len(contract["functions"]) \
            or receipt.get("differential_result") != "PASS" \
            or receipt.get("native_parity_evidence") is not True:
        raise ValueError("x86 micro-oracle receipt is not passing native evidence")
    web, runtime_hashes = web_cases(contract, root)
    if receipt.get("web_runtime_hashes") != runtime_hashes:
        raise ValueError("x86 micro-oracle web runtime drifted")
    web_by_mask = {item["component_mask"]: item for item in web}
    trace_catalog = receipt.get("trace_catalog")
    if not isinstance(trace_catalog, dict) or not trace_catalog:
        raise ValueError("x86 micro-oracle trace catalog is absent")
    used_trace_ids = set()
    for item in cases:
        candidate = web_by_mask.get(item["component_mask"])
        if item.get("differential") is not (candidate is not None):
            raise ValueError("stored x86 micro-oracle differential scope drifted")
        if candidate is not None:
            for function in contract["functions"]:
                web_result = function["web_result"]
                if item.get(web_result) != candidate.get(web_result):
                    raise ValueError(
                        f"stored native/web differential drifted for "
                        f"{function['id']} mask {item['component_mask']:#x}"
                    )
        native = item.get("native", {})
        results = item.get("native_results", {})
        if set(native) != set(expected_scope) or set(results) != set(expected_scope):
            raise ValueError("x86 micro-oracle case function coverage is incomplete")
        for function in contract["functions"]:
            trace_id = native[function["id"]]
            used_trace_ids.add(trace_id)
            trace = trace_catalog.get(trace_id)
            if not isinstance(trace, dict):
                raise ValueError("x86 micro-oracle case references an unknown trace")
            if trace.get("instruction_count", 0) <= 0 or not trace.get("basic_blocks") \
                    or trace.get("object_reads") != [{"offset": 296, "size": 4}]:
                raise ValueError("x86 micro-oracle trace is incomplete")
            expected = bool(trace["eax"]) if function["result"] == "eax_bool" else signed32(trace["eax"])
            if results[function["id"]] != expected:
                raise ValueError("x86 micro-oracle case result is not bound to its native trace")
        for function in contract["functions"]:
            if results[function["id"]] != item[function["web_result"]]:
                raise ValueError("x86 micro-oracle web result is not bound to its function output")
    if used_trace_ids != set(trace_catalog):
        raise ValueError("x86 micro-oracle receipt contains unreferenced native traces")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--executable", type=Path, required=True)
    capture.add_argument("--output", type=Path, default=ROOT / "content/miel_vliegt/x86_micro_oracle_airworthiness.json")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--executable", type=Path, required=True)
    verify.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_micro_oracle_airworthiness.json")
    artifact = subparsers.add_parser("verify-artifact")
    artifact.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_micro_oracle_airworthiness.json")
    args = parser.parse_args()
    if args.command == "capture":
        receipt = build_receipt(args.executable.resolve())
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    elif args.command == "verify":
        expected = verify_artifact(args.artifact.resolve())
        actual = build_receipt(args.executable.resolve())
        if actual != expected:
            raise SystemExit("x86 micro-oracle native receipt drifted")
    else:
        verify_artifact(args.artifact.resolve())
    print("x86 micro-oracle airworthiness differential OK")


if __name__ == "__main__":
    main()
