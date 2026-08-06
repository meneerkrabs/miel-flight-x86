#!/usr/bin/env python3
"""Differentially execute the original recursive aircraft property fold."""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import struct
import subprocess
from pathlib import Path
from typing import Any

from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_PROT_ALL, Uc, UcError, __version__ as unicorn_version
from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_FPCW

try:
    from tools.miel_vliegt.x86_micro_oracle import (
        ROOT, SENTINEL, STACK, STACK_SIZE, X86MicroOracle, load_json, sha256_file,
    )
except ModuleNotFoundError:
    from x86_micro_oracle import ROOT, SENTINEL, STACK, STACK_SIZE, X86MicroOracle, load_json, sha256_file


CONTRACT = ROOT / "content/miel_vliegt/x86_property_fold_contract.json"
ARENA = 0x73000000
ARENA_SIZE = 0x40000
AGGREGATE = ARENA
MASK = ARENA + 0x1000
NODE_BASE = ARENA + 0x2000
PROPERTY_BASE = ARENA + 0x10000
LINK_BASE = ARENA + 0x20000


class PropertyOracleError(RuntimeError):
    pass


_PROPERTY_WORKER: tuple["PropertyFoldOracle", dict[int, dict[str, Any]]] | None = None


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def resolve_jobs(value: int | str | None) -> int:
    jobs = int(value or 1)
    if not 1 <= jobs <= 32:
        raise ValueError("property-fold jobs must be between 1 and 32")
    return jobs


def validate_contract(root: Path = ROOT) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    contract = load_json(root / CONTRACT.relative_to(ROOT))
    identity = load_json(root / contract["source_identity"])
    index = load_json(root / contract["native_function_index"])
    if contract.get("schema") != 1 or contract.get("protocol") != "miel-vliegt-x86-property-fold-oracle":
        raise ValueError("unsupported x86 property-fold contract")
    function = contract["function"]
    indexed = next((item for item in index["functions"] if item.get("name") == function["native_name"]), None)
    if indexed is None or any(indexed.get(field) != function[field] for field in ("address", "end", "sha256")):
        raise ValueError("property-fold native identity drifted")
    if function["native_unit"] != f"fn_{int(function['address'], 16):08x}" \
            or function.get("calling_convention") != "thiscall" \
            or function["closure"] != [function["native_name"]] \
            or indexed.get("imports") or indexed.get("unresolved_indirect_calls") \
            or indexed.get("unresolved_direct_calls") \
            or any(target != function["address"] for target in indexed.get("calls", [])):
        raise ValueError("property-fold closure is not the pinned import-free recursive function")
    if contract["policy"] != {
        "fixed_image_base": "0x00400000", "fpu_control_word": "0x027f",
        "base_instruction_budget": 500, "per_node_instruction_budget": 300,
        "unexpected_code": "FAIL", "unexpected_read": "FAIL", "unexpected_write": "FAIL",
    }:
        raise ValueError("property-fold oracle policy was weakened")
    if identity["executable"]["sha256"] != index["source"]["sha256"]:
        raise ValueError("property-fold executable identity drifted")
    layout = contract.get("aggregate_layout", {})
    offsets = [layout.get("count_offset"), *layout.get("float_offsets", [])]
    if not isinstance(layout.get("size"), int) or layout["size"] <= 0 \
            or len(offsets) != 12 or len(offsets) != len(set(offsets)) \
            or any(not isinstance(offset, int) or offset % 4 or offset < 0
                   or offset + 4 > layout["size"] for offset in offsets):
        raise ValueError("property-fold aggregate layout is invalid")
    if contract.get("cases") != {
        "all_source_singletons": True,
        "all_ordered_source_part_pairs": True,
        "all_exemplar_masks": True,
        "adversarial_long_sequences": True,
        "include_empty": True,
        "include_default_airplane": True,
    }:
        raise ValueError("property-fold case coverage policy was weakened")
    return contract, identity, index


def case_definitions(contract: dict[str, Any], root: Path = ROOT) -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
    components = load_json(root / contract["component_contract"])
    barn = load_json(root / contract["barn_contract"])
    parts = components["parts"]
    by_id = {part["part_id"]: part for part in parts}
    cases = [{"id": "empty", "part_ids": []}]
    cases.extend({"id": f"part-{part['part_id']}", "part_ids": [part["part_id"]]} for part in parts)
    by_type: dict[int, list[dict[str, Any]]] = {}
    for part in parts:
        by_type.setdefault(part["component_type"], []).append(part)
    if set(by_type) != set(range(14)):
        raise ValueError("property-fold source corpus does not cover component types 0..13")
    for parent in parts:
        for child in parts:
            cases.append({
                "id": f"parts-{parent['part_id']}-{child['part_id']}",
                "part_ids": [parent["part_id"], child["part_id"]],
            })
    exemplar_by_slot = {item["component"]: item["part_id"] for item in components["exemplars"]}
    for mask in range(0x200):
        cases.append({
            "id": f"mask-{mask}",
            "part_ids": [
                exemplar_by_slot[slot]
                for index, slot in enumerate(components["policy"]["mask_slot_order"])
                if mask & (1 << index)
            ],
        })
    for component_type in range(14):
        ordered = sorted(by_type[component_type], key=lambda part: (part["fields"], part["part_id"]))
        low, high = ordered[0]["part_id"], ordered[-1]["part_id"]
        cases.extend((
            {
                "id": f"stress-{component_type}-low-high",
                "part_ids": [low, high] * 16,
            },
            {
                "id": f"stress-{component_type}-high-low",
                "part_ids": [high, low] * 16,
            },
        ))
    cases.append({
        "id": "default-airplane",
        "part_ids": [link["part_id"] for link in barn["default_airplane"]],
    })
    ids = [item["id"] for item in cases]
    if len(ids) != len(set(ids)) or any(part_id not in by_id for item in cases for part_id in item["part_ids"]):
        raise ValueError("property-fold case matrix is invalid")
    return cases, by_id


def web_cases(contract: dict[str, Any], root: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    runner = root / contract["web"]["runner"]
    process = subprocess.run(["node", str(runner)], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise PropertyOracleError(f"web property-fold runner failed: {process.stderr.strip()}")
    document = json.loads(process.stdout)
    cases, _ = case_definitions(contract, root)
    rows = document.get("cases") if document.get("schema") == 1 else None
    if not isinstance(rows, list) or [row.get("id") for row in rows] != [case["id"] for case in cases]:
        raise PropertyOracleError("web property-fold runner case coverage drifted")
    for definition, row in zip(cases, rows):
        if row.get("part_ids") != definition["part_ids"] \
                or not isinstance(row.get("component_mask"), int) \
                or not isinstance(row.get("counted_parts"), int) \
                or not isinstance(row.get("float_bits"), list) \
                or len(row["float_bits"]) != len(contract["aggregate_layout"]["float_offsets"]):
            raise PropertyOracleError(f"web property-fold result is invalid for {definition['id']}")
    paths = [contract["web"]["runner"], *contract["web"]["runtime_paths"]]
    return rows, {path: sha256_file(root / path) for path in paths}


class PropertyFoldOracle:
    def __init__(self, executable: Path, contract: dict[str, Any], identity: dict[str, Any], index: dict[str, Any]):
        self.base = X86MicroOracle(executable, {
            **contract,
            "policy": {
                "fixed_image_base": contract["policy"]["fixed_image_base"],
                "fpu_control_word": contract["policy"]["fpu_control_word"],
            },
            "functions": [{"native_name": contract["function"]["native_name"]}],
        }, identity, index)
        self.contract = contract

    def execute(self, definition: dict[str, Any], by_id: dict[int, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        machine = self.base._machine()
        machine.mem_map(ARENA, ARENA_SIZE, UC_PROT_ALL)
        machine.mem_write(ARENA, b"\0" * ARENA_SIZE)
        part_ids = definition["part_ids"]
        for index, part_id in enumerate(part_ids):
            node = NODE_BASE + index * 0x200
            props = PROPERTY_BASE + index * 0x40
            part = by_id[part_id]
            machine.mem_write(node + 0x120, struct.pack("<I", props))
            machine.mem_write(props + 4, struct.pack(
                "<9I", part["component_type"], part["part_id"], *part["fields"],
            ))
            if index + 1 < len(part_ids):
                link = LINK_BASE + index * 0x20
                machine.mem_write(node + 4, struct.pack("<I", link))
                machine.mem_write(link + 0x10, struct.pack("<I", NODE_BASE + (index + 1) * 0x200))
        stack_pointer = STACK + STACK_SIZE - 0x100
        root_pointer = NODE_BASE if part_ids else 0
        machine.mem_write(stack_pointer, struct.pack("<III", SENTINEL, root_pointer, MASK))
        machine.reg_write(UC_X86_REG_ESP, stack_pointer)
        machine.reg_write(UC_X86_REG_ECX, AGGREGATE)
        machine.reg_write(UC_X86_REG_FPCW, int(self.contract["policy"]["fpu_control_word"], 16))
        start = int(self.contract["function"]["address"], 16)
        end = int(self.contract["function"]["end"], 16)
        aggregate_offsets = {
            self.contract["aggregate_layout"]["count_offset"],
            *self.contract["aggregate_layout"]["float_offsets"],
        }
        trace: list[int] = []
        reads: set[tuple[str, int, int]] = set()
        writes: set[tuple[str, int, int]] = set()
        violations: list[str] = []

        readable = [(AGGREGATE + offset, 4, "aggregate", offset) for offset in aggregate_offsets]
        readable.append((MASK, 4, "mask", 0))
        for index in range(len(part_ids)):
            node = NODE_BASE + index * 0x200
            props = PROPERTY_BASE + index * 0x40
            readable.extend((
                (node + 4, 4, "node", index * 0x200 + 4),
                (node + 0x120, 4, "node", index * 0x200 + 0x120),
                (props + 4, 36, "properties", index * 0x40 + 4),
            ))
            if index + 1 < len(part_ids):
                link = LINK_BASE + index * 0x20
                readable.extend((
                    (link + 8, 4, "link", index * 0x20 + 8),
                    (link + 0x10, 4, "link", index * 0x20 + 0x10),
                ))

        def inside(address: int, size: int, base: int, length: int) -> bool:
            return base <= address and address + size <= base + length

        def on_code(uc: Uc, address: int, size: int, _: object) -> None:
            if not start <= address < end:
                violations.append(f"unexpected code at {address:#x}")
                uc.emu_stop()
            else:
                trace.append(address)

        def on_read(uc: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
            if inside(address, size, self.base.image.image_base, 0x200000) \
                    or inside(address, size, STACK, STACK_SIZE):
                return
            region = next(
                ((name, offset + address - begin) for begin, length, name, offset in readable
                 if inside(address, size, begin, length)),
                None,
            )
            if region is None:
                violations.append(f"unexpected read at {address:#x} size {size}")
                uc.emu_stop()
            else:
                reads.add((region[0], region[1], size))

        def on_write(uc: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
            if inside(address, size, STACK, STACK_SIZE):
                writes.add(("stack", address - STACK, size))
            elif address == MASK and size == 4:
                writes.add(("mask", 0, size))
            elif size == 4 and address - AGGREGATE in aggregate_offsets:
                writes.add(("aggregate", address - AGGREGATE, size))
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
        budget = self.contract["policy"]["base_instruction_budget"] \
            + self.contract["policy"]["per_node_instruction_budget"] * len(part_ids)
        try:
            machine.emu_start(start, SENTINEL, count=budget)
        except UcError as error:
            raise PropertyOracleError(f"{definition['id']}: {error}") from error
        if violations:
            raise PropertyOracleError(f"{definition['id']}: {violations[0]}")
        if machine.reg_read(UC_X86_REG_EIP) != SENTINEL \
                or machine.reg_read(UC_X86_REG_ESP) != stack_pointer + 12:
            raise PropertyOracleError(f"{definition['id']}: incomplete execution or unbalanced stack")
        count_offset = self.contract["aggregate_layout"]["count_offset"]
        result = {
            "component_mask": struct.unpack("<I", bytes(machine.mem_read(MASK, 4)))[0],
            "counted_parts": struct.unpack("<i", bytes(machine.mem_read(AGGREGATE + count_offset, 4)))[0],
            "float_bits": [
                struct.unpack("<I", bytes(machine.mem_read(AGGREGATE + offset, 4)))[0]
                for offset in self.contract["aggregate_layout"]["float_offsets"]
            ],
        }
        trace_record = {
            "instruction_count": len(trace),
            "trace_sha256": hashlib.sha256(b"".join(struct.pack("<I", address) for address in trace)).hexdigest(),
            "read_set": [
                {"region": region, "offset": offset, "size": size}
                for region, offset, size in sorted(reads)
            ],
            "write_set": [
                {"region": region, "offset": offset, "size": size}
                for region, offset, size in sorted(writes)
            ],
        }
        return result, trace_record


def _init_property_worker(
    executable: str, contract: dict[str, Any], identity: dict[str, Any],
    index: dict[str, Any], by_id: dict[int, dict[str, Any]],
) -> None:
    global _PROPERTY_WORKER
    _PROPERTY_WORKER = (
        PropertyFoldOracle(Path(executable), contract, identity, index),
        by_id,
    )


def _execute_property_case(
    item: tuple[dict[str, Any], dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if _PROPERTY_WORKER is None:
        raise PropertyOracleError("property-fold worker was not initialized")
    definition, candidate = item
    oracle, by_id = _PROPERTY_WORKER
    native, trace = oracle.execute(definition, by_id)
    if any(native[key] != candidate[key] for key in ("component_mask", "counted_parts", "float_bits")):
        raise PropertyOracleError(f"native/web property-fold divergence for {definition['id']}")
    return native, trace


def build_receipt(executable: Path, root: Path = ROOT, *, jobs: int = 1) -> dict[str, Any]:
    contract, identity, index = validate_contract(root)
    definitions, by_id = case_definitions(contract, root)
    web, runtime_hashes = web_cases(contract, root)
    jobs = resolve_jobs(jobs)
    items = list(zip(definitions, web))
    pool = None
    if jobs == 1:
        _init_property_worker(str(executable), contract, identity, index, by_id)
        executed = map(_execute_property_case, items)
    else:
        method = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
        pool = multiprocessing.get_context(method).Pool(
            jobs,
            initializer=_init_property_worker,
            initargs=(str(executable), contract, identity, index, by_id),
        )
        executed = pool.imap(_execute_property_case, items, chunksize=64)
    traces: dict[str, dict[str, Any]] = {}
    rows = []
    try:
        for definition, (native, trace) in zip(definitions, executed):
            trace_id = sha256_json(trace)
            traces[trace_id] = trace
            rows.append({
                **definition,
                **native,
                "trace": trace_id,
                "native_proof_sha256": sha256_json({
                    "input": definition,
                    "native_result": native,
                    "trace": trace_id,
                }),
            })
    except BaseException:
        if pool is not None:
            pool.terminate()
            pool.join()
            pool = None
        raise
    finally:
        if pool is not None:
            pool.close()
            pool.join()
    return {
        "schema": 1,
        "protocol": contract["protocol"],
        "executable_sha256": identity["executable"]["sha256"],
        "contract_sha256": sha256_file(root / CONTRACT.relative_to(ROOT)),
        "native_function_index_sha256": sha256_file(root / contract["native_function_index"]),
        "source_contract_hashes": {
            contract["component_contract"]: sha256_file(root / contract["component_contract"]),
            contract["barn_contract"]: sha256_file(root / contract["barn_contract"]),
        },
        "web_runtime_hashes": runtime_hashes,
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "cases": rows,
        "case_count": len(rows),
        "differential_result": "PASS",
        "native_parity_evidence": True,
        "trace_catalog": traces,
        "evidence_scope": [contract["function"]["id"]],
        "native_units": {contract["function"]["id"]: [contract["function"]["native_unit"]]},
    }


def verify_artifact(path: Path, root: Path = ROOT) -> dict[str, Any]:
    contract, identity, _ = validate_contract(root)
    receipt = load_json(path)
    definitions, _ = case_definitions(contract, root)
    web, runtime_hashes = web_cases(contract, root)
    if receipt.get("protocol") != contract["protocol"] or receipt.get("schema") != 1 \
            or receipt.get("executable_sha256") != identity["executable"]["sha256"] \
            or receipt.get("contract_sha256") != sha256_file(root / CONTRACT.relative_to(ROOT)) \
            or receipt.get("native_function_index_sha256") != sha256_file(root / contract["native_function_index"]) \
            or receipt.get("web_runtime_hashes") != runtime_hashes \
            or receipt.get("emulator") != {"name": "unicorn", "version": unicorn_version}:
        raise ValueError("x86 property-fold receipt provenance drifted")
    expected_sources = {
        contract["component_contract"]: sha256_file(root / contract["component_contract"]),
        contract["barn_contract"]: sha256_file(root / contract["barn_contract"]),
    }
    if receipt.get("source_contract_hashes") != expected_sources:
        raise ValueError("x86 property-fold source contracts drifted")
    if receipt.get("case_count") != len(definitions) or receipt.get("differential_result") != "PASS" \
            or receipt.get("native_parity_evidence") is not True:
        raise ValueError("x86 property-fold receipt is not passing")
    if receipt.get("evidence_scope") != [contract["function"]["id"]] \
            or receipt.get("native_units") != {contract["function"]["id"]: [contract["function"]["native_unit"]]}:
        raise ValueError("x86 property-fold evidence scope drifted")
    rows = receipt.get("cases")
    if not isinstance(rows, list) or [row.get("id") for row in rows] != [item["id"] for item in definitions]:
        raise ValueError("x86 property-fold case coverage drifted")
    traces = receipt.get("trace_catalog")
    if not isinstance(traces, dict) or not traces:
        raise ValueError("x86 property-fold traces are absent")
    used = set()
    def valid_access_set(value: Any, regions: set[str]) -> bool:
        return isinstance(value, list) and all(
            isinstance(item, dict) and set(item) == {"region", "offset", "size"}
            and item["region"] in regions
            and isinstance(item["offset"], int) and item["offset"] >= 0
            and isinstance(item["size"], int) and item["size"] in {1, 2, 4, 8, 10}
            for item in value
        )

    for definition, row, candidate in zip(definitions, rows, web):
        if row.get("part_ids") != definition["part_ids"] \
                or any(row.get(key) != candidate[key] for key in ("component_mask", "counted_parts", "float_bits")):
            raise ValueError(f"stored native/web property-fold differential drifted for {definition['id']}")
        trace_id = row.get("trace")
        trace = traces.get(trace_id)
        native_result = {
            key: row[key] for key in ("component_mask", "counted_parts", "float_bits")
        }
        if not isinstance(trace, dict) or trace_id != sha256_json(trace) \
                or trace.get("instruction_count", 0) <= 0 \
                or not isinstance(trace.get("trace_sha256"), str) \
                or len(trace["trace_sha256"]) != 64 \
                or not valid_access_set(
                    trace.get("read_set"), {"aggregate", "mask", "node", "properties", "link"}
                ) \
                or not valid_access_set(trace.get("write_set"), {"aggregate", "mask", "stack"}) \
                or (definition["part_ids"] and (
                    not trace["read_set"] or not trace["write_set"]
                )) \
                or row.get("native_proof_sha256") != sha256_json({
                    "input": definition,
                    "native_result": native_result,
                    "trace": trace_id,
                }):
            raise ValueError("x86 property-fold trace is incomplete")
        used.add(trace_id)
    if used != set(traces):
        raise ValueError("x86 property-fold receipt contains unused traces")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--executable", type=Path, required=True)
    capture.add_argument(
        "--jobs", type=resolve_jobs,
        default=resolve_jobs(os.environ.get("PROPERTY_ORACLE_JOBS", "1")),
    )
    capture.add_argument("--output", type=Path, default=ROOT / "content/miel_vliegt/x86_property_fold.json")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--executable", type=Path, required=True)
    verify.add_argument(
        "--jobs", type=resolve_jobs,
        default=resolve_jobs(os.environ.get("PROPERTY_ORACLE_JOBS", "1")),
    )
    verify.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_property_fold.json")
    artifact = subparsers.add_parser("verify-artifact")
    artifact.add_argument("--artifact", type=Path, default=ROOT / "content/miel_vliegt/x86_property_fold.json")
    args = parser.parse_args()
    if args.command == "capture":
        receipt = build_receipt(args.executable.resolve(), jobs=args.jobs)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # The exhaustive 66k-case matrix is intentionally tracked, but canonical
        # compact JSON keeps it reviewable as one generated artifact instead of
        # producing nearly two million formatting-only diff lines.
        args.output.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    elif args.command == "verify":
        expected = verify_artifact(args.artifact.resolve())
        if build_receipt(args.executable.resolve(), jobs=args.jobs) != expected:
            raise SystemExit("x86 property-fold native receipt drifted")
    else:
        verify_artifact(args.artifact.resolve())
    print("x86 property-fold differential OK")


if __name__ == "__main__":
    main()
