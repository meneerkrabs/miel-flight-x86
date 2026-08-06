#!/usr/bin/env python3
"""Generate the fail-closed native framebuffer row-origin contract.

The contract deliberately separates three authorities:

* pinned native bytes prove that ``GtImage`` stores its first row at the top
  and that the full-surface ``gtSoftware`` ReadScreen path preserves row order;
* reviewed Microsoft documentation defines the DirectDraw Lock(NULL, ...)
  pointer as the top of the entire surface;
* every runtime capture must independently report a positive pitch.

Only their conjunction resolves to TOP_LEFT.  CI never fetches documentation;
the reviewed URL and normalized claims are immutable, hash-bound metadata.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/native_framebuffer_origin_contract.json"
DEFAULT_SCHEMA = ROOT / "tools/miel_vliegt/schemas/native-framebuffer-origin-contract.schema.json"

PROTOCOL = "miel-vliegt-native-framebuffer-origin"
CC_SHA256 = "c7b0599de35db339c4a3acc56987e36c7b07ebf3553fb7511bc31d18d667c70e"
GT_SOFTWARE_SHA256 = "c3cebce34373255993b23ca54e3f678487f44a5fb7c1b9f4a63aa3b5d82a9ee8"
IMAGE_BASE = 0x10000000
READ_SCREEN_SLOT = 47
READ_SCREEN_VTABLE_OFFSET = 0xBC
FULL_SURFACE_LOCK_SITE = 0x1000825B

API_AUTHORITY_CORE = {
    "id": "MICROSOFT_LEARN_IDIRECTDRAWSURFACE7_LOCK",
    "url": (
        "https://learn.microsoft.com/en-us/windows/win32/api/ddraw/"
        "nf-ddraw-idirectdrawsurface7-lock"
    ),
    "title": "IDirectDrawSurface7::Lock method (ddraw.h)",
    "reviewedOn": "2026-07-16",
    "pageLastUpdated": "2022-11-01",
    "claims": [
        {
            "id": "NULL_RECTANGLE_LOCKS_ENTIRE_SURFACE",
            "normalizedClaim": (
                "A NULL destination rectangle requests an entire-surface lock."
            ),
            "reviewedLines": [45, 47],
        },
        {
            "id": "NULL_RECTANGLE_POINTER_IS_SURFACE_TOP",
            "normalizedClaim": (
                "With no rectangle, the returned surface-memory pointer is "
                "the top of the surface."
            ),
            "reviewedLines": [81, 83],
        },
    ],
    "evidenceRole": "REVIEWED_EXTERNAL_API_AUTHORITY",
    "networkRequiredInCi": False,
}

EXPORTS = {
    "Cc.dll": {
        "??_7GtDevice@@6B@": 0x100532B0,
        "?Flip@GtImage@@QAEX_N0@Z": 0x1004BDA0,
        "?GetImagePtr@GtImage@@QAEPAXH@Z": 0x1004AE40,
        "?GetPitch@GtImage@@QAEHH@Z": 0x1004AE00,
        "?ReadScreen@GtDevice@@UAEPAVGtImage@@PAV2@@Z": 0x10006C40,
        "?Save@GtTga@@UAE_NPAD@Z": 0x1004F9C0,
        "?WritePacked@GtTga@@IAEXXZ": 0x1004F300,
    },
    "gtSoftware.dll": {
        "dllCreate": 0x100099E0,
    },
}

IMPORTS = {
    0x1000A034: "Cc.dll!?GetImagePtr@GtImage@@QAEPAXH@Z",
    0x1000A0B0: "Cc.dll!?GetImageSize@GtImage@@QAEHH@Z",
    0x1000A0B8: "Cc.dll!?Create@GtImage@@QAE_NHHW4GT_FMT@@@Z",
}

SLICE_SPECS = (
    ("cc_read_screen_virtual_stub", "Cc.dll", 0x10006C40, 5,
     "5fed5afb29946811bf02359627a94bc01d08d31b779528feaadde3866af9c855"),
    ("cc_read_screen_vtable_slot_47", "Cc.dll", 0x1005336C, 4,
     "22e82b4f31df3dd46495285dcc9a93183bee1989e4275024757d9a1aeacfb743"),
    ("gt_image_get_pitch", "Cc.dll", 0x1004AE00, 48,
     "811b6afce19e44ebb2716738462df9c4305e868d46f181b1212c7f6b51e60971"),
    ("gt_image_get_image_ptr", "Cc.dll", 0x1004AE40, 32,
     "307f529a70c10152a59647dffcffbfff630eaf7188e72a93906f77158b579d86"),
    ("gt_tga_load_origin_normalization", "Cc.dll", 0x1004F944, 19,
     "7525a211505bc3a58debec4d7a09d566efa715742178970ff2c7c0d3df297063"),
    ("gt_tga_write_packed", "Cc.dll", 0x1004F300, 848,
     "691463d8dc9b515199aeef67ffa8d1a34b0564a2affcf6456cd33fec11c77725"),
    ("gt_tga_save_header_and_dispatch", "Cc.dll", 0x1004FA0F, 106,
     "9d0c2e17ca0aa901a944fd35605c379b972b846b6a4b5816efe100c15bc6d201"),
    ("gt_image_flip_vertical_branch", "Cc.dll", 0x1004BFAA, 294,
     "637d84155e65b4822cec83f7902e8fc31f44d52e1c36739f193ef7ccaa820040"),
    ("gt_software_dll_create", "gtSoftware.dll", 0x100099E0, 38,
     "ae074a0d0c3a1ac58f533bab8ee75aee27cc8d80ed9f604a30fd7aaf771603e7"),
    ("gt_software_constructor_vptr_write", "gtSoftware.dll", 0x100050A6, 13,
     "220d46d8f45f5cabe228122205d5e4024c3babad3073266cd96852a11aec3b65"),
    ("gt_software_vtable", "gtSoftware.dll", 0x1000A188, 220,
     "c3626bcb675e1721636b657514a3db583f10f06ad5ef038cc6a4e43d47572343"),
    ("gt_software_read_screen_slot_47", "gtSoftware.dll", 0x1000A244, 4,
     "206ed16360030ded84606a9e0a2464262759e094cc0b3cc262f1535ac2eab02f"),
    ("gt_software_read_screen", "gtSoftware.dll", 0x100081C0, 635,
     "c1f55a6f2ae451c80658218c5b3ff2576ae961f866e391b95046d89745904522"),
    ("gt_software_full_surface_lock", "gtSoftware.dll", 0x10008247, 23,
     "8bd87ad8f31fe75907a3528cdfb24cad880a3ca6dd483057bfb98dcca90ade1b"),
    ("gt_software_window_rect_lock", "gtSoftware.dll", 0x10008365, 30,
     "f5cde1adb2bfb28c1a82c71344795a1ee5ec434b2f08b894110285919c6392d1"),
    ("gt_software_read_screen_image_access", "gtSoftware.dll", 0x100082BF, 34,
     "8cec5e2205037938471627faf7d37bdeca3e9102f947dfcd209044d6b10976a3"),
    ("gt_software_forward_copy_loop_a", "gtSoftware.dll", 0x100082EF, 48,
     "168412785d39de22fe23d4b8f18780d7a4e8f759b5589de5d5a32b48d4a996f2"),
    ("gt_software_forward_copy_loop_b", "gtSoftware.dll", 0x100083E3, 48,
     "168412785d39de22fe23d4b8f18780d7a4e8f759b5589de5d5a32b48d4a996f2"),
    ("gt_software_unlock", "gtSoftware.dll", 0x1000841A, 18,
     "160a13bb314d51c84cc1875efd8eff588a997e053807a894937316974f2aeea5"),
)


class FramebufferOriginContractError(ValueError):
    """Raised when native, reviewed, schema or runtime evidence drifts."""


class Pe32Image:
    """Small dependency-free PE32 reader for immutable proof locations."""

    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise FramebufferOriginContractError(f"{path}: missing MZ header")
        pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise FramebufferOriginContractError(f"{path}: missing PE header")
        coff = pe_offset + 4
        machine, section_count = struct.unpack_from("<HH", self.data, coff)
        optional_size = struct.unpack_from("<H", self.data, coff + 16)[0]
        if machine != 0x14C:
            raise FramebufferOriginContractError(f"{path}: expected i386 PE")
        optional = coff + 20
        if struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise FramebufferOriginContractError(f"{path}: expected PE32")
        self.image_base = struct.unpack_from("<I", self.data, optional + 28)[0]
        directory_count = min(struct.unpack_from("<I", self.data, optional + 92)[0], 16)
        self.directories = tuple(
            struct.unpack_from("<II", self.data, optional + 96 + index * 8)
            for index in range(directory_count)
        )
        section_offset = optional + optional_size
        sections = []
        for index in range(section_count):
            offset = section_offset + index * 40
            name, virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                "<8sIIII", self.data, offset
            )
            sections.append((
                name.rstrip(b"\0").decode("ascii"),
                rva,
                max(virtual_size, raw_size),
                raw_offset,
                raw_size,
            ))
        self.sections = tuple(sections)

    def rva_to_offset(self, rva: int) -> int:
        for _name, section_rva, virtual_span, raw_offset, raw_size in self.sections:
            delta = rva - section_rva
            if 0 <= delta < virtual_span and delta < raw_size:
                return raw_offset + delta
        raise FramebufferOriginContractError(
            f"{self.path}: RVA 0x{rva:08x} is not file-backed"
        )

    def bytes_at(self, address: int, size: int) -> bytes:
        if address < self.image_base or size < 0:
            raise FramebufferOriginContractError(f"{self.path}: invalid byte range")
        offset = self.rva_to_offset(address - self.image_base)
        value = self.data[offset:offset + size]
        if len(value) != size:
            raise FramebufferOriginContractError(f"{self.path}: truncated byte range")
        return value

    def u32(self, address: int) -> int:
        return struct.unpack("<I", self.bytes_at(address, 4))[0]

    def cstring_rva(self, rva: int) -> str:
        offset = self.rva_to_offset(rva)
        end = self.data.find(b"\0", offset)
        if end < 0:
            raise FramebufferOriginContractError(f"{self.path}: unterminated PE string")
        return self.data[offset:end].decode("ascii")

    def exports(self) -> dict[str, int]:
        if not self.directories or not self.directories[0][0]:
            return {}
        export_rva = self.directories[0][0]
        fields = struct.unpack_from("<IIHHIIIIIII", self.data, self.rva_to_offset(export_rva))
        ordinal_base, function_count, name_count = fields[5], fields[6], fields[7]
        functions_rva, names_rva, ordinals_rva = fields[8], fields[9], fields[10]
        result = {}
        for index in range(name_count):
            name_rva = struct.unpack_from(
                "<I", self.data, self.rva_to_offset(names_rva + index * 4)
            )[0]
            ordinal = struct.unpack_from(
                "<H", self.data, self.rva_to_offset(ordinals_rva + index * 2)
            )[0]
            if ordinal >= function_count:
                raise FramebufferOriginContractError(
                    f"{self.path}: export ordinal {ordinal + ordinal_base} is invalid"
                )
            function_rva = struct.unpack_from(
                "<I", self.data, self.rva_to_offset(functions_rva + ordinal * 4)
            )[0]
            result[self.cstring_rva(name_rva)] = self.image_base + function_rva
        return result

    def imports(self) -> dict[int, str]:
        if len(self.directories) < 2 or not self.directories[1][0]:
            return {}
        descriptor_rva = self.directories[1][0]
        result = {}
        while True:
            offset = self.rva_to_offset(descriptor_rva)
            original, _, _, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", self.data, offset
            )
            if not any((original, name_rva, first_thunk)):
                break
            dll = self.cstring_rva(name_rva)
            lookup = original or first_thunk
            index = 0
            while True:
                value = struct.unpack_from(
                    "<I", self.data, self.rva_to_offset(lookup + index * 4)
                )[0]
                if value == 0:
                    break
                if value & 0x80000000:
                    symbol = f"ordinal_{value & 0xffff}"
                else:
                    symbol = self.cstring_rva(value + 2)
                result[self.image_base + first_thunk + index * 4] = f"{dll}!{symbol}"
                index += 1
            descriptor_rva += 20
        return result


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slice_record(
    identifier: str, module: str, address: int, length: int, sha256: str,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "module": module,
        "address": f"0x{address:08x}",
        "length": length,
        "sha256": sha256,
    }


def _expected_contract() -> dict[str, Any]:
    api_authority = copy.deepcopy(API_AUTHORITY_CORE)
    api_authority["claimSha256"] = sha256_json(API_AUTHORITY_CORE)
    slices = [
        _slice_record(identifier, module, address, length, sha256)
        for identifier, module, address, length, sha256 in SLICE_SPECS
    ]
    contract = {
        "schema": 1,
        "protocol": PROTOCOL,
        "reviewStatus": "REVIEWED_CONDITIONAL_PROOF",
        "sources": {
            "Cc.dll": {
                "sha256": CC_SHA256,
                "imageBase": f"0x{IMAGE_BASE:08x}",
                "authority": "PINNED_DUTCH_BINARY",
            },
            "gtSoftware.dll": {
                "sha256": GT_SOFTWARE_SHA256,
                "imageBase": f"0x{IMAGE_BASE:08x}",
                "authority": "PINNED_DUTCH_BINARY",
            },
        },
        "reviewedApiAuthority": api_authority,
        "nativeProof": {
            "exports": [
                {
                    "module": module,
                    "symbol": symbol,
                    "address": f"0x{address:08x}",
                }
                for module, exports in EXPORTS.items()
                for symbol, address in exports.items()
            ],
            "imports": [
                {
                    "module": "gtSoftware.dll",
                    "iatAddress": f"0x{address:08x}",
                    "target": target,
                }
                for address, target in IMPORTS.items()
            ],
            "vtableBinding": {
                "baseVtableAddress": "0x100532b0",
                "derivedVtableAddress": "0x1000a188",
                "slotIndex": READ_SCREEN_SLOT,
                "slotByteOffset": f"0x{READ_SCREEN_VTABLE_OFFSET:02x}",
                "baseTarget": "0x10006c40",
                "derivedTarget": "0x100081c0",
                "constructorVptrWrite": "0x100050ad",
                "conclusion": "DERIVED_READ_SCREEN_OVERRIDE_BOUND",
            },
            "readScreen": {
                "functionAddress": "0x100081c0",
                "fullSurfaceLock": {
                    "callAddress": f"0x{FULL_SURFACE_LOCK_SITE:08x}",
                    "surfaceSource": "[GtSoftwareDevice+0x18a4]",
                    "comVtableByteOffset": "0x64",
                    "arguments": {
                        "lpDestRect": "NULL",
                        "lpDDSurfaceDesc": "STACK_DDSURFACEDESC2",
                        "dwFlags": "0x00000011",
                        "hEvent": "NULL",
                    },
                    "apiScope": "ENTIRE_SURFACE",
                    "returnedPointerField": "DDSURFACEDESC2.lpSurface@+0x24",
                    "returnedPitchField": "DDSURFACEDESC2.lPitch@+0x10",
                    "originEligible": True,
                },
                "excludedAlternativeLock": {
                    "callAddress": "0x10008380",
                    "lpDestRect": "NON_NULL_CLIENT_RECT",
                    "originEligible": False,
                    "reason": (
                        "The external NULL-rectangle premise does not apply "
                        "to this separate window-rectangle path."
                    ),
                },
                "imageDestination": {
                    "level": 0,
                    "pointerMethod": "GtImage::GetImagePtr",
                    "rowBytes": "GtImage::GetImageSize(0)/deviceHeight",
                },
                "forwardLoops": [
                    {
                        "address": "0x100082ef",
                        "sourceStep": "source += DDSURFACEDESC2.lPitch",
                        "destinationStep": "destination += GtImage rowBytes",
                        "rowCounter": "0..deviceHeight-1",
                        "rowTransform": "PRESERVE",
                    },
                    {
                        "address": "0x100083e3",
                        "sourceStep": "source += DDSURFACEDESC2.lPitch",
                        "destinationStep": "destination += GtImage rowBytes",
                        "rowCounter": "0..deviceHeight-1",
                        "rowTransform": "PRESERVE",
                    },
                ],
                "unlockAddress": "0x10008426",
                "conclusion": "SOURCE_ROW_ORDER_PRESERVED",
            },
            "gtImage": {
                "levelZeroPointerField": "[GtImage+0x20]",
                "pitchFormula": "(width >> level) * formatBitsPerPixel >> 3",
                "storageTraversal": "FORWARD_CONTIGUOUS_ROWS",
            },
            "tgaOrigin": {
                "saveDescriptorWriteAddress": "0x1004fa64",
                "saveDescriptorValue": "0x20",
                "descriptorMeaning": "TOP_LEFT_ORIGIN",
                "writePackedTraversal": (
                    "Starts at [GtImage+0x20], computes the positive image end, "
                    "and advances monotonically for 24-bit and 32-bit pixels."
                ),
                "loadNormalization": {
                    "descriptorTestAddress": "0x1004f944",
                    "missingTopOriginAction": "GtImage::Flip(false,true)",
                    "verticalBranchAddress": "0x1004bfaa",
                },
                "conclusion": "GTIMAGE_ROW_ZERO_IS_TOP",
            },
            "slices": slices,
        },
        "runtimeRequirement": {
            "captureLockCallAddress": f"0x{FULL_SURFACE_LOCK_SITE:08x}",
            "measuredPitch": {
                "source": "PER_CAPTURE_DDSURFACEDESC2_LPITCH",
                "operator": ">",
                "threshold": 0,
                "missingOrNonPositive": "FAIL_CLOSED",
            },
        },
        "derivation": {
            "nativeStorageOrigin": "TOP_LEFT",
            "readScreenRowTransform": "PRESERVE",
            "externalSurfaceOrigin": "TOP_LEFT",
            "resultOrigin": "TOP_LEFT",
            "kind": "CONDITIONAL",
            "requiredConditions": [
                "PINNED_NATIVE_PROOF_VALID",
                "REVIEWED_DIRECTDRAW_NULL_LOCK_AUTHORITY_VALID",
                "CAPTURE_USED_FULL_SURFACE_LOCK_SITE_0x1000825b",
                "MEASURED_PITCH_GREATER_THAN_ZERO",
            ],
            "failurePolicy": "NO_ORIGIN_CONCLUSION",
        },
    }
    contract["receiptSha256"] = sha256_json(contract)
    return contract


def validate_schema_guard(schema: dict[str, Any]) -> None:
    required = {
        "schema", "protocol", "reviewStatus", "sources",
        "reviewedApiAuthority", "nativeProof", "runtimeRequirement",
        "derivation", "receiptSha256",
    }
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema" \
            or schema.get("additionalProperties") is not False \
            or set(schema.get("required", [])) != required:
        raise FramebufferOriginContractError("framebuffer origin JSON schema root drifted")
    properties = schema.get("properties", {})
    if properties.get("schema", {}).get("const") != 1 \
            or properties.get("protocol", {}).get("const") != PROTOCOL \
            or properties.get("derivation", {}).get("properties", {}).get(
                "resultOrigin", {}
            ).get("const") != "TOP_LEFT" \
            or properties.get("derivation", {}).get("properties", {}).get(
                "kind", {}
            ).get("const") != "CONDITIONAL":
        raise FramebufferOriginContractError("framebuffer origin JSON schema policy drifted")


def validate_contract(
    contract: dict[str, Any], schema: dict[str, Any] | None = None,
) -> None:
    if schema is not None:
        validate_schema_guard(schema)
    if not isinstance(contract, dict):
        raise FramebufferOriginContractError("framebuffer origin contract is not an object")
    unhashed = copy.deepcopy(contract)
    receipt = unhashed.pop("receiptSha256", None)
    if not isinstance(receipt, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt) \
            or receipt != sha256_json(unhashed):
        raise FramebufferOriginContractError("framebuffer origin receipt hash differs")
    expected = _expected_contract()
    if contract != expected:
        raise FramebufferOriginContractError(
            "framebuffer origin reviewed/native metadata differs"
        )


def _expect_bytes(image: Pe32Image, address: int, expected: bytes, label: str) -> None:
    if image.bytes_at(address, len(expected)) != expected:
        raise FramebufferOriginContractError(f"{label} instruction semantics drifted")


def verify_binaries(cc_path: Path, gt_software_path: Path) -> None:
    if sha256_file(cc_path) != CC_SHA256:
        raise FramebufferOriginContractError("Cc.dll identity drifted")
    if sha256_file(gt_software_path) != GT_SOFTWARE_SHA256:
        raise FramebufferOriginContractError("gtSoftware.dll identity drifted")
    images = {
        "Cc.dll": Pe32Image(cc_path),
        "gtSoftware.dll": Pe32Image(gt_software_path),
    }
    if any(image.image_base != IMAGE_BASE for image in images.values()):
        raise FramebufferOriginContractError("native image base drifted")

    for module, expected_exports in EXPORTS.items():
        actual_exports = images[module].exports()
        for symbol, address in expected_exports.items():
            if actual_exports.get(symbol) != address:
                raise FramebufferOriginContractError(
                    f"{module} export binding drifted: {symbol}"
                )
    actual_imports = images["gtSoftware.dll"].imports()
    for address, target in IMPORTS.items():
        if actual_imports.get(address) != target:
            raise FramebufferOriginContractError(
                f"gtSoftware.dll IAT binding drifted at 0x{address:08x}"
            )

    for identifier, module, address, length, expected_hash in SLICE_SPECS:
        actual_hash = hashlib.sha256(images[module].bytes_at(address, length)).hexdigest()
        if actual_hash != expected_hash:
            raise FramebufferOriginContractError(
                f"native proof slice drifted: {identifier}"
            )

    cc = images["Cc.dll"]
    gt = images["gtSoftware.dll"]
    if cc.u32(0x100532B0 + READ_SCREEN_VTABLE_OFFSET) != 0x10006C40 \
            or gt.u32(0x1000A188 + READ_SCREEN_VTABLE_OFFSET) != 0x100081C0:
        raise FramebufferOriginContractError("ReadScreen vtable slot 47 drifted")

    # Full-surface COM Lock(this, NULL, &desc, 0x11, NULL).
    _expect_bytes(gt, 0x1000824D, b"\x6a\x00", "ReadScreen Lock hEvent")
    _expect_bytes(gt, 0x10008253, b"\x6a\x11", "ReadScreen Lock flags")
    _expect_bytes(gt, 0x10008258, b"\x6a\x00", "ReadScreen Lock rectangle")
    _expect_bytes(gt, FULL_SURFACE_LOCK_SITE, b"\xff\x51\x64", "ReadScreen Lock call")

    # Both success paths copy forward, then add source pitch and destination row size.
    for loop in (0x100082EF, 0x100083E3):
        _expect_bytes(gt, loop + 0x0B, b"\xf3\xa5", "ReadScreen dword copy")
        _expect_bytes(gt, loop + 0x12, b"\xf3\xa4", "ReadScreen tail copy")
        _expect_bytes(gt, loop + 0x1F, b"\x03\xd8", "ReadScreen source pitch step")
        _expect_bytes(gt, loop + 0x25, b"\x03\xf8", "ReadScreen destination step")
        _expect_bytes(gt, loop + 0x2E, b"\x7c\xd0", "ReadScreen forward row loop")

    _expect_bytes(cc, 0x1004FA64, b"\xc6\x44\x24\x29\x20", "TGA top-origin descriptor")
    _expect_bytes(cc, 0x1004F944, b"\xf6\x44\x24\x21\x20", "TGA origin test")
    _expect_bytes(
        cc, 0x1004F94B, b"\x6a\x01\x53\x8b\xce\xe8\x4b\xc4\xff\xff",
        "TGA vertical normalization",
    )


def build_contract(cc_path: Path, gt_software_path: Path) -> dict[str, Any]:
    verify_binaries(cc_path, gt_software_path)
    contract = _expected_contract()
    validate_contract(contract)
    return contract


def resolve_origin(
    contract: dict[str, Any], *, measured_pitch: int,
    lock_call_address: int = FULL_SURFACE_LOCK_SITE,
) -> str:
    """Resolve the conditional result, failing closed on absent prerequisites."""

    validate_contract(contract)
    if isinstance(measured_pitch, bool) or not isinstance(measured_pitch, int) \
            or measured_pitch <= 0:
        raise FramebufferOriginContractError(
            "TOP_LEFT requires a measured positive DirectDraw pitch"
        )
    if lock_call_address != FULL_SURFACE_LOCK_SITE:
        raise FramebufferOriginContractError(
            "TOP_LEFT requires the reviewed NULL/full-surface Lock call site"
        )
    return "TOP_LEFT"


def encode_contract(contract: dict[str, Any]) -> str:
    return json.dumps(contract, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc-dll", type=Path)
    parser.add_argument("--gt-software-dll", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--check-contract", action="store_true")
    args = parser.parse_args()

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    validate_schema_guard(schema)
    if args.check_contract:
        contract = json.loads(args.output.read_text(encoding="utf-8"))
        validate_contract(contract, schema)
        print("Native framebuffer origin contract: reviewed metadata verified")
        return 0
    if args.cc_dll is None or args.gt_software_dll is None:
        parser.error("--write/--check require --cc-dll and --gt-software-dll")
    result = build_contract(args.cc_dll, args.gt_software_dll)
    validate_contract(result, schema)
    encoded = encode_contract(result)
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            raise SystemExit("native framebuffer origin contract drifted")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(
        "Native framebuffer origin contract: "
        f"{len(SLICE_SPECS)} native slices verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
