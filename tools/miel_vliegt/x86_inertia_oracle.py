#!/usr/bin/env python3
"""Execute CcRigidBody::CalcAuxiliary as a pinned, native-only micro-oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
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
    UC_X86_REG_ECX,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
    UC_X86_REG_FPCW,
)

try:
    from tools.miel_vliegt.analyze_native import PeImage
except ModuleNotFoundError:
    from analyze_native import PeImage


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "content/miel_vliegt/x86_inertia_oracle_contract.json"
RECEIPT = ROOT / "content/miel_vliegt/x86_inertia_oracle_receipt.json"
SCHEMA = ROOT / "tools/miel_vliegt/schemas/x86-inertia-oracle-receipt.schema.json"
PAGE = 0x1000
STACK = 0x70000000
STACK_SIZE = 0x20000
OBJECT = 0x71000000
OBJECT_SIZE = 0x1000
SENTINEL = 0x72000000
F32_FIELDS = (
    "body_inertia",
    "inverse_body_inertia",
    "orientation_wxyz",
    "linear_momentum",
)


class InertiaOracleError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


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


def f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", value))[0]


def f32_bits(value: float) -> str:
    return f"0x{struct.unpack('<I', struct.pack('<f', value))[0]:08x}"


def f64_bits(value: float) -> str:
    return f"0x{struct.unpack('<Q', struct.pack('<d', value))[0]:016x}"


def bits_f32(values: list[float] | tuple[float, ...]) -> list[str]:
    return [f32_bits(value) for value in values]


def unpack_f32_bits(data: bytes) -> list[str]:
    return [f"0x{value:08x}" for value in struct.unpack(f"<{len(data) // 4}I", data)]


def _vector(value: Any, length: int, label: str) -> list[float]:
    if not isinstance(value, list) or len(value) != length:
        raise ValueError(f"{label} must contain exactly {length} numbers")
    result = []
    for index, item in enumerate(value):
        if isinstance(item, bool) or not isinstance(item, (int, float)) \
                or not math.isfinite(float(item)):
            raise ValueError(f"{label}[{index}] is not a finite number")
        result.append(f32(float(item)))
    return result


def _multiply_3x3(left: list[float], right: list[float]) -> list[float]:
    return [
        sum(left[row * 3 + inner] * right[inner * 3 + column] for inner in range(3))
        for row in range(3)
        for column in range(3)
    ]


def _validate_inverse_pair(body: list[float], inverse: list[float], label: str) -> None:
    for direction, product in (
        ("body*inverse", _multiply_3x3(body, inverse)),
        ("inverse*body", _multiply_3x3(inverse, body)),
    ):
        for index, value in enumerate(product):
            expected = 1.0 if index in (0, 4, 8) else 0.0
            if not math.isclose(value, expected, rel_tol=0.0, abs_tol=2e-6):
                raise ValueError(
                    f"{label} {direction} is not identity at lane {index}: {value}"
                )


def _expected_policy() -> dict[str, Any]:
    return {
        "emulator": "unicorn",
        "fixed_cc_image_base": "0x10000000",
        "fpu_control_word": "0x027f",
        "instruction_budget": 2000,
        "unallowlisted_code": "FAIL",
        "unexpected_write": "FAIL",
        "unmapped_read": "FAIL",
        "vm_boot_is_not_required": True,
        "artifact_only_verification": "STRUCTURAL_NOT_NATIVE_REEXECUTION",
        "parity_promotion": "FORBIDDEN_WITHOUT_INDEPENDENT_WEB_DIFFERENTIAL",
    }


def validate_contract(root: Path = ROOT) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = load_json(root / CONTRACT.relative_to(ROOT))
    source_identity = load_json(root / contract["source_identity"])
    state_layout = load_json(root / contract["native_flight_state_layout"])
    cc_api = load_json(root / contract["cc_api_contract"])
    if contract.get("schema") != 1 \
            or contract.get("protocol") != "miel-vliegt-x86-inertia-oracle":
        raise ValueError("unsupported x86 inertia-oracle contract")
    if contract.get("policy") != _expected_policy():
        raise ValueError("x86 inertia-oracle policy was weakened")
    sources = contract.get("sources", {})
    if sources.get("executable_sha256") != source_identity["executable"]["sha256"] \
            or sources.get("cc_dll_sha256") != source_identity["cc_dll"]["sha256"] \
            or sources.get("cc_dll_sha256") != state_layout["source"]["cc_dll_sha256"] \
            or sources.get("cc_dll_sha256") != cc_api["source"]["sha256"]:
        raise ValueError("x86 inertia-oracle source identity drifted")
    function = contract.get("function", {})
    if function.get("symbol") != "?CalcAuxiliary@CcRigidBody@@QAEXXZ" \
            or function.get("calling_convention") != "thiscall" \
            or function.get("address") != "0x1002b810" \
            or function.get("end") != "0x1002ba2b" \
            or function.get("sha256") != \
            "624385093dba8cf59d8f7ed2f97f4bac07a06bef2bfe0715268fc87a74b0c9ae":
        raise ValueError("x86 inertia-oracle function identity drifted")
    closure = function.get("closure")
    if not isinstance(closure, list) or [item.get("symbol") for item in closure] != [
        "?CalcAuxiliary@CcRigidBody@@QAEXXZ",
        "?TransformToMatrix@CcQuaternion@@QAE?AVCc3Matrix@@XZ",
    ] or closure[0].get("sha256") != function["sha256"]:
        raise ValueError("x86 inertia-oracle closure drifted")
    exports = {
        item["decorated_symbol"]: item
        for item in cc_api.get("exports", [])
        if isinstance(item, dict) and isinstance(item.get("decorated_symbol"), str)
    }
    for item in closure:
        exported = exports.get(item["symbol"])
        expected_rva = int(item["address"], 16) - int(
            contract["policy"]["fixed_cc_image_base"], 16
        )
        if exported is None or int(exported.get("rva", "-1"), 16) != expected_rva:
            raise ValueError(f"{item['symbol']}: Cc.dll export-table identity drifted")
    layout = contract.get("object_layout", {})
    expected_layout = {
        "size": 212,
        "mass_f64": {"offset": 16, "size": 8},
        "inverse_body_inertia_3x3_f32": {"offset": 24, "count": 9},
        "orientation_wxyz_f32": {"offset": 76, "count": 4},
        "linear_momentum_xyz_f32": {"offset": 92, "count": 3},
        "angular_momentum_xyz_f32": {"offset": 104, "count": 3},
        "rotation_matrix_3x3_f32": {"offset": 116, "count": 9},
        "inverse_world_inertia_3x3_f32": {"offset": 152, "count": 9},
        "linear_velocity_xyz_f32": {"offset": 188, "count": 3},
        "angular_velocity_xyz_f32": {"offset": 200, "count": 3},
    }
    if layout != expected_layout:
        raise ValueError("x86 inertia-oracle object layout drifted")

    configurations = contract.get("configurations")
    momenta = contract.get("angular_momenta")
    if not isinstance(configurations, list) or len(configurations) < 3 \
            or not isinstance(momenta, list) or len(momenta) != 5:
        raise ValueError("x86 inertia-oracle case matrix is incomplete")
    config_ids = [item.get("id") for item in configurations]
    momentum_ids = [item.get("id") for item in momenta]
    if len(config_ids) != len(set(config_ids)) or len(momentum_ids) != len(set(momentum_ids)):
        raise ValueError("x86 inertia-oracle case ids must be unique")
    if momentum_ids != ["zero", "basis-x", "basis-y", "basis-z", "mixed"]:
        raise ValueError("x86 inertia-oracle basis coverage drifted")
    if [item.get("angular_momentum") for item in momenta[:4]] != [
        [0.0, 0.0, 0.0],
        [1.0, 0.0, 0.0],
        [0.0, 1.0, 0.0],
        [0.0, 0.0, 1.0],
    ]:
        raise ValueError("x86 inertia-oracle unit-basis inputs drifted")
    for configuration in configurations:
        if set(configuration) != {"id", "mass", *F32_FIELDS}:
            raise ValueError(f"{configuration.get('id')}: configuration fields drifted")
        mass = configuration["mass"]
        if isinstance(mass, bool) or not isinstance(mass, (int, float)) \
                or not math.isfinite(float(mass)) or mass <= 0:
            raise ValueError(f"{configuration['id']}: mass must be finite and positive")
        body = _vector(configuration["body_inertia"], 9, "body_inertia")
        inverse = _vector(
            configuration["inverse_body_inertia"], 9, "inverse_body_inertia"
        )
        _validate_inverse_pair(body, inverse, configuration["id"])
        orientation = _vector(configuration["orientation_wxyz"], 4, "orientation_wxyz")
        if not math.isclose(
            sum(component * component for component in orientation),
            1.0,
            rel_tol=0.0,
            abs_tol=2e-6,
        ):
            raise ValueError(f"{configuration['id']}: orientation is not normalized")
        _vector(configuration["linear_momentum"], 3, "linear_momentum")
    for momentum in momenta:
        if set(momentum) != {"id", "angular_momentum"}:
            raise ValueError(f"{momentum.get('id')}: momentum fields drifted")
        _vector(momentum["angular_momentum"], 3, "angular_momentum")
    return contract, {
        "source_identity": source_identity,
        "state_layout": state_layout,
        "cc_api": cc_api,
        "configurations": configurations,
        "momenta": momenta,
    }


def _function_bytes(image: PeImage, item: dict[str, Any]) -> bytes:
    begin = int(item["address"], 16)
    end = int(item["end"], 16)
    if begin >= end:
        raise ValueError(f"{item.get('symbol', item.get('id'))}: invalid code range")
    return image.bytes_at(begin, end - begin)


def validate_cc_binary(
    executable: Path,
    cc_dll: Path,
    contract: dict[str, Any],
) -> PeImage:
    if sha256_file(executable) != contract["sources"]["executable_sha256"]:
        raise ValueError("x86 inertia oracle requires the pinned Dutch MulleMeck.exe")
    if sha256_file(cc_dll) != contract["sources"]["cc_dll_sha256"]:
        raise ValueError("x86 inertia oracle requires the pinned Dutch Cc.dll")
    image = PeImage(cc_dll)
    if image.image_base != int(contract["policy"]["fixed_cc_image_base"], 16):
        raise ValueError("x86 inertia-oracle Cc.dll image base drifted")
    for item in contract["function"]["closure"]:
        if sha256_bytes(_function_bytes(image, item)) != item["sha256"]:
            raise ValueError(f"{item['symbol']}: Cc.dll function bytes drifted")
    for item in contract["function"]["static_slices"]:
        if sha256_bytes(_function_bytes(image, item)) != item["sha256"]:
            raise ValueError(f"{item['id']}: Cc.dll static proof slice drifted")
    return image


def _write_f32(machine: Uc, address: int, values: list[float]) -> None:
    machine.mem_write(address, struct.pack(f"<{len(values)}f", *values))


class CcInertiaOracle:
    def __init__(self, executable: Path, cc_dll: Path, root: Path = ROOT):
        self.contract, self.matrix = validate_contract(root)
        self.image = validate_cc_binary(executable, cc_dll, self.contract)
        self.layout = self.contract["object_layout"]
        self.allowed = [
            (int(item["address"], 16), int(item["end"], 16))
            for item in self.contract["function"]["closure"]
        ]

    def _machine(self) -> Uc:
        machine = Uc(UC_ARCH_X86, UC_MODE_32)
        image_end = max(
            section.virtual_address + max(section.virtual_size, section.raw_size)
            for section in self.image.sections
        )
        machine.mem_map(
            self.image.image_base,
            align(image_end - self.image.image_base),
            UC_PROT_ALL,
        )
        first_raw = min(section.raw_offset for section in self.image.sections)
        machine.mem_write(self.image.image_base, self.image.data[:first_raw])
        for section in self.image.sections:
            machine.mem_write(
                section.virtual_address,
                self.image.data[
                    section.raw_offset:section.raw_offset + section.raw_size
                ],
            )
        machine.mem_map(STACK, STACK_SIZE, UC_PROT_ALL)
        machine.mem_map(OBJECT, OBJECT_SIZE, UC_PROT_ALL)
        machine.mem_map(SENTINEL, PAGE, UC_PROT_ALL)
        machine.mem_write(SENTINEL, b"\xcc")
        return machine

    def execute(
        self,
        configuration: dict[str, Any],
        momentum: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        machine = self._machine()
        machine.mem_write(OBJECT, b"\0" * OBJECT_SIZE)
        machine.mem_write(
            OBJECT + self.layout["mass_f64"]["offset"],
            struct.pack("<d", float(configuration["mass"])),
        )
        _write_f32(
            machine,
            OBJECT + self.layout["inverse_body_inertia_3x3_f32"]["offset"],
            _vector(configuration["inverse_body_inertia"], 9, "inverse_body_inertia"),
        )
        _write_f32(
            machine,
            OBJECT + self.layout["orientation_wxyz_f32"]["offset"],
            _vector(configuration["orientation_wxyz"], 4, "orientation_wxyz"),
        )
        _write_f32(
            machine,
            OBJECT + self.layout["linear_momentum_xyz_f32"]["offset"],
            _vector(configuration["linear_momentum"], 3, "linear_momentum"),
        )
        _write_f32(
            machine,
            OBJECT + self.layout["angular_momentum_xyz_f32"]["offset"],
            _vector(momentum["angular_momentum"], 3, "angular_momentum"),
        )
        stack_pointer = STACK + STACK_SIZE - 0x100
        machine.mem_write(stack_pointer, struct.pack("<I", SENTINEL))
        machine.reg_write(UC_X86_REG_ESP, stack_pointer)
        machine.reg_write(UC_X86_REG_ECX, OBJECT)
        machine.reg_write(UC_X86_REG_EFLAGS, 0x2)
        machine.reg_write(
            UC_X86_REG_FPCW, int(self.contract["policy"]["fpu_control_word"], 16)
        )
        trace: list[int] = []
        reads: set[tuple[int, int]] = set()
        writes: set[tuple[str, int, int]] = set()
        violation: list[str] = []

        def in_range(address: int, size: int, begin: int, length: int) -> bool:
            return begin <= address and address + size <= begin + length

        def on_code(uc: Uc, address: int, size: int, _: object) -> None:
            if not any(begin <= address < end for begin, end in self.allowed):
                violation.append(f"unallowlisted execution at {address:#x}")
                uc.emu_stop()
                return
            trace.append(address)

        def on_read(uc: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
            if in_range(address, size, OBJECT, OBJECT_SIZE):
                if not in_range(address, size, OBJECT, self.layout["size"]):
                    violation.append(
                        f"object read exceeds declared layout at {address:#x} size {size}"
                    )
                    uc.emu_stop()
                else:
                    reads.add((address - OBJECT, size))

        def on_write(uc: Uc, __: int, address: int, size: int, ___: int, ____: object) -> None:
            if in_range(address, size, STACK, STACK_SIZE):
                writes.add(("stack", address - STACK, size))
            elif in_range(address, size, OBJECT, OBJECT_SIZE):
                if not in_range(address, size, OBJECT, self.layout["size"]):
                    violation.append(
                        f"object write exceeds declared layout at {address:#x} size {size}"
                    )
                    uc.emu_stop()
                else:
                    writes.add(("object", address - OBJECT, size))
            else:
                violation.append(f"unexpected write at {address:#x} size {size}")
                uc.emu_stop()

        def on_invalid(
            uc: Uc,
            access: int,
            address: int,
            size: int,
            value: int,
            _: object,
        ) -> bool:
            violation.append(
                f"invalid memory access {access} at {address:#x} size {size} value {value}"
            )
            uc.emu_stop()
            return False

        machine.hook_add(UC_HOOK_CODE, on_code)
        machine.hook_add(UC_HOOK_MEM_READ, on_read)
        machine.hook_add(UC_HOOK_MEM_WRITE, on_write)
        machine.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
        try:
            machine.emu_start(
                int(self.contract["function"]["address"], 16),
                SENTINEL,
                count=self.contract["policy"]["instruction_budget"],
            )
        except UcError as error:
            raise InertiaOracleError(
                f"{configuration['id']}/{momentum['id']}: {error}"
            ) from error
        if violation:
            raise InertiaOracleError(
                f"{configuration['id']}/{momentum['id']}: {violation[0]}"
            )
        if machine.reg_read(UC_X86_REG_EIP) != SENTINEL:
            raise InertiaOracleError(
                f"{configuration['id']}/{momentum['id']}: instruction budget exhausted"
            )
        if machine.reg_read(UC_X86_REG_ESP) != stack_pointer + 4:
            raise InertiaOracleError(
                f"{configuration['id']}/{momentum['id']}: unbalanced stack"
            )

        def field_bits(name: str) -> list[str]:
            field = self.layout[name]
            return unpack_f32_bits(
                bytes(machine.mem_read(OBJECT + field["offset"], field["count"] * 4))
            )

        inputs = {
            "mass_f64_bits": f64_bits(float(configuration["mass"])),
            "body_inertia_3x3_f32_bits": bits_f32(
                _vector(configuration["body_inertia"], 9, "body_inertia")
            ),
            "inverse_body_inertia_3x3_f32_bits": bits_f32(
                _vector(
                    configuration["inverse_body_inertia"],
                    9,
                    "inverse_body_inertia",
                )
            ),
            "orientation_wxyz_f32_bits": bits_f32(
                _vector(configuration["orientation_wxyz"], 4, "orientation_wxyz")
            ),
            "linear_momentum_xyz_f32_bits": bits_f32(
                _vector(configuration["linear_momentum"], 3, "linear_momentum")
            ),
            "angular_momentum_xyz_f32_bits": bits_f32(
                _vector(momentum["angular_momentum"], 3, "angular_momentum")
            ),
        }
        outputs = {
            "rotation_matrix_3x3_f32_bits": field_bits("rotation_matrix_3x3_f32"),
            "inverse_world_inertia_3x3_f32_bits": field_bits(
                "inverse_world_inertia_3x3_f32"
            ),
            "linear_velocity_xyz_f32_bits": field_bits("linear_velocity_xyz_f32"),
            "angular_velocity_xyz_f32_bits": field_bits("angular_velocity_xyz_f32"),
        }
        trace_bytes = b"".join(struct.pack("<I", address) for address in trace)
        write_rows = [
            {"region": region, "offset": offset, "size": size}
            for region, offset, size in sorted(writes)
        ]
        trace_receipt = {
            "instruction_count": len(trace),
            "trace_sha256": sha256_bytes(trace_bytes),
            "object_reads": [
                {"offset": offset, "size": size} for offset, size in sorted(reads)
            ],
            "write_count": len(write_rows),
            "write_regions": sorted({row["region"] for row in write_rows}),
            "writes_sha256": sha256_bytes(canonical_json(write_rows)),
        }
        return {"input": inputs, "output": outputs}, trace_receipt


def _expected_case_inputs(
    configuration: dict[str, Any], momentum: dict[str, Any]
) -> dict[str, Any]:
    return {
        "mass_f64_bits": f64_bits(float(configuration["mass"])),
        "body_inertia_3x3_f32_bits": bits_f32(
            _vector(configuration["body_inertia"], 9, "body_inertia")
        ),
        "inverse_body_inertia_3x3_f32_bits": bits_f32(
            _vector(configuration["inverse_body_inertia"], 9, "inverse_body_inertia")
        ),
        "orientation_wxyz_f32_bits": bits_f32(
            _vector(configuration["orientation_wxyz"], 4, "orientation_wxyz")
        ),
        "linear_momentum_xyz_f32_bits": bits_f32(
            _vector(configuration["linear_momentum"], 3, "linear_momentum")
        ),
        "angular_momentum_xyz_f32_bits": bits_f32(
            _vector(momentum["angular_momentum"], 3, "angular_momentum")
        ),
    }


def _verify_case_relations(
    cases: list[dict[str, Any]],
    configurations: list[dict[str, Any]],
    momenta: list[dict[str, Any]],
) -> dict[str, Any]:
    by_id = {case["id"]: case for case in cases}
    basis_proofs = 0
    mixed_captures = 0
    mass_proofs = 0
    for configuration in configurations:
        config_id = configuration["id"]
        rows = {
            momentum["id"]: by_id[f"{config_id}/{momentum['id']}"]
            for momentum in momenta
        }
        first_output = rows["zero"]["output"]
        for row in rows.values():
            if row["output"]["rotation_matrix_3x3_f32_bits"] != \
                    first_output["rotation_matrix_3x3_f32_bits"] \
                    or row["output"]["inverse_world_inertia_3x3_f32_bits"] != \
                    first_output["inverse_world_inertia_3x3_f32_bits"]:
                raise ValueError(f"{config_id}: inertia output depends on angular momentum")
        inverse_world = first_output["inverse_world_inertia_3x3_f32_bits"]
        zero_velocity = rows["zero"]["output"]["angular_velocity_xyz_f32_bits"]
        if any(int(value, 16) & 0x7FFFFFFF for value in zero_velocity):
            raise ValueError(f"{config_id}: zero angular momentum produced non-zero velocity")
        for column, momentum_id in enumerate(("basis-x", "basis-y", "basis-z")):
            expected = [
                inverse_world[column],
                inverse_world[3 + column],
                inverse_world[6 + column],
            ]
            actual = rows[momentum_id]["output"]["angular_velocity_xyz_f32_bits"]
            if actual != expected:
                raise ValueError(
                    f"{config_id}/{momentum_id}: angular velocity is not the "
                    "inverse-world-inertia basis column"
                )
            basis_proofs += 1
        mixed_captures += 1

        inverse_mass = 1.0 / float(configuration["mass"])
        expected_linear = bits_f32([
            inverse_mass * value
            for value in _vector(
                configuration["linear_momentum"], 3, "linear_momentum"
            )
        ])
        actual_linear = first_output["linear_velocity_xyz_f32_bits"]
        if actual_linear != expected_linear:
            raise ValueError(f"{config_id}: native inverse-mass linear velocity drifted")
        mass_proofs += 1
    return {
        "basis_case_count": basis_proofs,
        "mixed_momentum_capture_count": mixed_captures,
        "mass_case_count": mass_proofs,
    }


def _receipt_hash(document: dict[str, Any]) -> str:
    unsigned = dict(document)
    unsigned.pop("receipt_sha256", None)
    return sha256_bytes(canonical_json(unsigned))


def build_receipt(
    executable: Path,
    cc_dll: Path,
    root: Path = ROOT,
) -> dict[str, Any]:
    contract, matrix = validate_contract(root)
    oracle = CcInertiaOracle(executable, cc_dll, root)
    cases = []
    trace_catalog: dict[str, dict[str, Any]] = {}
    for configuration in matrix["configurations"]:
        for momentum in matrix["momenta"]:
            result, trace = oracle.execute(configuration, momentum)
            trace_id = sha256_bytes(canonical_json(trace))
            trace_catalog[trace_id] = trace
            case = {
                "id": f"{configuration['id']}/{momentum['id']}",
                "configuration_id": configuration["id"],
                "momentum_id": momentum["id"],
                **result,
                "trace": trace_id,
            }
            case["native_proof_sha256"] = sha256_bytes(canonical_json({
                "id": case["id"],
                "input": case["input"],
                "output": case["output"],
                "trace": trace_id,
            }))
            cases.append(case)
    relation_counts = _verify_case_relations(
        cases, matrix["configurations"], matrix["momenta"]
    )
    receipt = {
        "schema": 1,
        "protocol": contract["protocol"],
        "status": "NATIVE_EVIDENCE_ONLY",
        "parity_promotion": False,
        "source": {
            "executable_sha256": contract["sources"]["executable_sha256"],
            "cc_dll_sha256": contract["sources"]["cc_dll_sha256"],
        },
        "contract_sha256": sha256_file(root / CONTRACT.relative_to(ROOT)),
        "cc_api_contract_sha256": sha256_file(root / contract["cc_api_contract"]),
        "receipt_schema_sha256": sha256_file(root / SCHEMA.relative_to(ROOT)),
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "evidence_scope": {
            "proven": [
                "CalcAuxiliary derives inverse mass from the pinned mass field",
                "CalcAuxiliary derives inverse-world inertia from the pinned orientation and inverse-body-inertia fields",
                "CalcAuxiliary derives angular velocity from inverse-world inertia times angular momentum",
            ],
            "not_proven": [
                "how the game derives body inertia from aircraft parts",
                "how or where native code inverts body inertia before CalcAuxiliary",
                "web runtime equivalence or any parity promotion",
            ],
        },
        "configuration_count": len(matrix["configurations"]),
        "momentum_count": len(matrix["momenta"]),
        "case_count": len(cases),
        **relation_counts,
        "cases": cases,
        "trace_catalog": trace_catalog,
    }
    receipt["receipt_sha256"] = _receipt_hash(receipt)
    return receipt


def verify_artifact(path: Path = RECEIPT, root: Path = ROOT) -> dict[str, Any]:
    contract, matrix = validate_contract(root)
    receipt = load_json(path)
    expected_header = {
        "schema": 1,
        "protocol": contract["protocol"],
        "status": "NATIVE_EVIDENCE_ONLY",
        "parity_promotion": False,
        "source": {
            "executable_sha256": contract["sources"]["executable_sha256"],
            "cc_dll_sha256": contract["sources"]["cc_dll_sha256"],
        },
        "contract_sha256": sha256_file(root / CONTRACT.relative_to(ROOT)),
        "cc_api_contract_sha256": sha256_file(root / contract["cc_api_contract"]),
        "receipt_schema_sha256": sha256_file(root / SCHEMA.relative_to(ROOT)),
        "emulator": {"name": "unicorn", "version": unicorn_version},
        "configuration_count": len(matrix["configurations"]),
        "momentum_count": len(matrix["momenta"]),
        "case_count": len(matrix["configurations"]) * len(matrix["momenta"]),
    }
    for key, expected in expected_header.items():
        if receipt.get(key) != expected:
            raise ValueError(f"x86 inertia-oracle receipt drifted at {key}")
    if receipt.get("receipt_sha256") != _receipt_hash(receipt):
        raise ValueError("x86 inertia-oracle receipt self-hash drifted")
    scope = receipt.get("evidence_scope")
    if not isinstance(scope, dict) or set(scope) != {"proven", "not_proven"} \
            or "web runtime equivalence or any parity promotion" not in scope["not_proven"]:
        raise ValueError("x86 inertia-oracle evidence scope drifted")
    expected_ids = [
        f"{configuration['id']}/{momentum['id']}"
        for configuration in matrix["configurations"]
        for momentum in matrix["momenta"]
    ]
    cases = receipt.get("cases")
    traces = receipt.get("trace_catalog")
    if not isinstance(cases, list) or [case.get("id") for case in cases] != expected_ids \
            or not isinstance(traces, dict):
        raise ValueError("x86 inertia-oracle case or trace inventory drifted")
    used_traces = set()
    by_configuration = {
        configuration["id"]: configuration
        for configuration in matrix["configurations"]
    }
    by_momentum = {momentum["id"]: momentum for momentum in matrix["momenta"]}
    for case in cases:
        configuration = by_configuration.get(case.get("configuration_id"))
        momentum = by_momentum.get(case.get("momentum_id"))
        if configuration is None or momentum is None \
                or case["id"] != f"{configuration['id']}/{momentum['id']}":
            raise ValueError(f"{case.get('id')}: case identity drifted")
        if case.get("input") != _expected_case_inputs(configuration, momentum):
            raise ValueError(f"{case['id']}: case input drifted")
        output = case.get("output")
        expected_output_fields = {
            "rotation_matrix_3x3_f32_bits": 9,
            "inverse_world_inertia_3x3_f32_bits": 9,
            "linear_velocity_xyz_f32_bits": 3,
            "angular_velocity_xyz_f32_bits": 3,
        }
        if not isinstance(output, dict) or set(output) != set(expected_output_fields):
            raise ValueError(f"{case['id']}: output fields drifted")
        for field, count in expected_output_fields.items():
            values = output[field]
            if not isinstance(values, list) or len(values) != count \
                    or any(
                        not isinstance(value, str)
                        or len(value) != 10
                        or not value.startswith("0x")
                        or any(character not in "0123456789abcdef" for character in value[2:])
                        for value in values
                    ):
                raise ValueError(f"{case['id']}: invalid {field}")
        trace_id = case.get("trace")
        trace = traces.get(trace_id)
        if not isinstance(trace, dict) or trace_id != sha256_bytes(canonical_json(trace)) \
                or trace.get("instruction_count", 0) <= 0 \
                or trace.get("write_regions") != ["object", "stack"]:
            raise ValueError(f"{case['id']}: native trace is incomplete")
        expected_proof = sha256_bytes(canonical_json({
            "id": case["id"],
            "input": case["input"],
            "output": case["output"],
            "trace": trace_id,
        }))
        if case.get("native_proof_sha256") != expected_proof:
            raise ValueError(f"{case['id']}: native proof hash drifted")
        used_traces.add(trace_id)
    if used_traces != set(traces):
        raise ValueError("x86 inertia-oracle receipt contains unused traces")
    relation_counts = _verify_case_relations(
        cases, matrix["configurations"], matrix["momenta"]
    )
    for key, expected in relation_counts.items():
        if receipt.get(key) != expected:
            raise ValueError(f"x86 inertia-oracle relation count drifted at {key}")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--executable", type=Path, required=True)
    capture.add_argument("--cc-dll", type=Path, required=True)
    capture.add_argument("--output", type=Path, default=RECEIPT)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--executable", type=Path, required=True)
    verify.add_argument("--cc-dll", type=Path, required=True)
    verify.add_argument("--artifact", type=Path, default=RECEIPT)
    artifact = subparsers.add_parser("verify-artifact")
    artifact.add_argument("--artifact", type=Path, default=RECEIPT)
    args = parser.parse_args()
    if args.command == "capture":
        receipt = build_receipt(
            args.executable.resolve(),
            args.cc_dll.resolve(),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        )
    elif args.command == "verify":
        expected = verify_artifact(args.artifact.resolve())
        actual = build_receipt(
            args.executable.resolve(),
            args.cc_dll.resolve(),
        )
        if actual != expected:
            raise SystemExit("x86 inertia-oracle native receipt drifted")
    else:
        verify_artifact(args.artifact.resolve())
    print("x86 CcRigidBody inertia oracle OK")


if __name__ == "__main__":
    main()
