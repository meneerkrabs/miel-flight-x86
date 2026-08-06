#!/usr/bin/env python3
"""Extract the edition-local static contract for the bespoke Mygghanget mode.

The executable has no symbols and Mygghanget has no UDSP location script.  We
therefore match relocation-tolerant instruction shapes, validate the strings
and constants reached by those instructions, and emit only the behavior that
is exact in static code.  Executing the mode and framebuffer parity remain
separate native-observer obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PeImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError(f"{path}: Mygghanget contract requires a PE executable")
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: invalid PE signature")
        coff = pe + 4
        machine, count, _, _, _, optional_size, _ = struct.unpack_from(
            "<HHIIIHH", self.data, coff
        )
        optional = coff + 20
        if machine != 0x14C or struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise ValueError(f"{path}: Mygghanget contract requires PE32 i386")
        self.image_base = struct.unpack_from("<I", self.data, optional + 28)[0]
        self.sections: list[dict[str, int | str]] = []
        section_offset = optional + optional_size
        for index in range(count):
            offset = section_offset + index * 40
            name, virtual_size, virtual_address, raw_size, raw_offset, _, _, _, _, flags = (
                struct.unpack_from("<8sIIIIIIHHI", self.data, offset)
            )
            self.sections.append({
                "name": name.rstrip(b"\0").decode("ascii"),
                "address": self.image_base + virtual_address,
                "virtualSize": virtual_size,
                "rawSize": raw_size,
                "rawOffset": raw_offset,
                "flags": flags,
            })

    def offset_to_address(self, offset: int) -> int:
        for section in self.sections:
            delta = offset - int(section["rawOffset"])
            if 0 <= delta < int(section["rawSize"]):
                return int(section["address"]) + delta
        raise ValueError(f"file offset {offset:#x} is not inside a PE section")

    def address_to_offset(self, address: int) -> int:
        for section in self.sections:
            delta = address - int(section["address"])
            if 0 <= delta < int(section["rawSize"]):
                return int(section["rawOffset"]) + delta
        raise ValueError(f"address {address:#x} is not backed by a PE section")

    def c_string(self, address: int) -> str:
        offset = self.address_to_offset(address)
        end = self.data.find(b"\0", offset, min(len(self.data), offset + 256))
        if end < 0:
            raise ValueError(f"unterminated native string at {address:#x}")
        try:
            return self.data[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError(f"non-ASCII native string at {address:#x}") from error


def _pattern(spec: str) -> tuple[bytes, bytes]:
    values = bytearray()
    mask = bytearray()
    for token in spec.split():
        if token == "??":
            values.append(0)
            mask.append(0)
        else:
            values.append(int(token, 16))
            mask.append(0xFF)
    return bytes(values), bytes(mask)


def _find_unique(image: PeImage, name: str, spec: str) -> int:
    values, mask = _pattern(spec)
    matches = []
    for section in image.sections:
        if not int(section["flags"]) & 0x20000000:
            continue
        start = int(section["rawOffset"])
        end = start + int(section["rawSize"])
        for offset in range(start, end - len(values) + 1):
            candidate = image.data[offset:offset + len(values)]
            if all(not bit or left == right for left, right, bit in zip(candidate, values, mask)):
                matches.append(offset)
    if len(matches) != 1:
        raise ValueError(f"native Mygghanget {name} shape occurs {len(matches)} times")
    return matches[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _f32(data: bytes, offset: int) -> float:
    return struct.unpack_from("<f", data, offset)[0]


def _relative_target(image: PeImage, instruction_offset: int) -> int:
    displacement = struct.unpack_from("<i", image.data, instruction_offset + 1)[0]
    return image.offset_to_address(instruction_offset + 5) + displacement


def _address(image: PeImage, offset: int) -> str:
    return f"0x{image.offset_to_address(offset):08x}"


def _window(image: PeImage, offset: int, size: int) -> dict[str, object]:
    raw = image.data[offset:offset + size]
    if len(raw) != size:
        raise ValueError("native Mygghanget receipt window exceeds the executable")
    return {"address": _address(image, offset), "size": size, "sha256": _sha256(raw)}


def extract_native_mygghanget_contract(executable: Path) -> dict[str, object]:
    image = PeImage(executable)
    constructor_anchor = _find_unique(
        image,
        "constructor",
        "6a 16 8b f1 68 ?? ?? ?? ?? 50 89 74 24 10 e8 ?? ?? ?? ?? "
        "68 ?? ?? ?? ?? 8b ce c7 44 24 14 00 00 00 00 c7 06 ?? ?? ?? ??",
    )
    constructor = constructor_anchor - 0x1B
    if image.data[constructor:constructor + 2] != b"\x6a\xff":
        raise ValueError("native Mygghanget constructor prologue drifted")
    location_name = image.c_string(_u32(image.data, constructor_anchor + 5))
    mode_name = image.c_string(_u32(image.data, constructor_anchor + 20))
    if (location_name, mode_name) != ("mygghanget", "mode_mygghanget"):
        raise ValueError(
            f"native Mygghanget identity drifted to {(location_name, mode_name)!r}"
        )

    sky_setup = _find_unique(
        image,
        "sky setup",
        "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? "
        "8b 4c 24 08 c6 86 90 48 00 00 00 c6 86 91 48 00 00 01",
    )
    if not constructor <= sky_setup < constructor + 0x100:
        raise ValueError("native Mygghanget sky setup escaped its constructor")
    sky_bank = image.c_string(_u32(image.data, sky_setup + 1))
    sky_condition = image.c_string(_u32(image.data, sky_setup + 6))
    if not sky_condition or not sky_bank:
        raise ValueError("native Mygghanget sky tuple is empty")

    loader = _find_unique(
        image,
        "loader",
        "56 57 8b 7c 24 0c 8b f1 57 e8 ?? ?? ?? ?? 84 c0 75 05 "
        "5f 5e c2 04 00 8b 86 a8 08 00 00 57 c7 40 38 00 00 00 00 "
        "8b 8e a8 08 00 00 c7 41 64 5e 01 00 00",
    )
    layer_shape = _find_unique(
        image,
        "layer offsets",
        "c7 40 38 00 00 00 00 8b 8e a8 08 00 00 c7 41 64 5e 01 00 00 "
        "8b 96 a8 08 00 00 c7 82 90 00 00 00 2c 01 00 00 "
        "8b 86 a8 08 00 00 c7 80 bc 00 00 00 1c 02 00 00",
    )
    if not loader <= layer_shape < loader + 0x100:
        raise ValueError("native Mygghanget layer constants escaped its loader")
    loader_tail = _find_unique(
        image,
        "loader camera constants",
        "68 00 00 48 42 c7 86 a0 09 00 00 00 00 20 c1 "
        "c7 86 a8 09 00 00 00 00 f0 41 e8 ?? ?? ?? ?? "
        "8b 56 5c 6a 50 6a 03 8b ce",
    )
    if not loader <= loader_tail < loader + 0x100:
        raise ValueError("native Mygghanget camera constants escaped its loader")

    open_entry = _find_unique(
        image,
        "open",
        "56 8b f1 c6 86 91 48 00 00 01 e8 ?? ?? ?? ?? 8b 4e 50 "
        "6a 00 6a 11 81 c1 38 01 00 00 e8 ?? ?? ?? ??",
    )
    state_setter = _find_unique(
        image,
        "state setter",
        "8b 44 24 04 85 c0 74 15 83 f8 06 75 17 8b 49 50 "
        "68 ?? ?? ?? ?? e8 ?? ?? ?? ?? c2 04 00 "
        "c6 81 90 48 00 00 01 50 e8 ?? ?? ?? ?? c2 04 00",
    )
    if image.c_string(_u32(image.data, state_setter + 17)) != "mode_barn":
        raise ValueError("native Mygghanget state 6 target is not mode_barn")

    update = _find_unique(
        image,
        "update",
        "83 ec 0c 56 8b f1 57 bf ?? 00 00 00 39 be dc 08 00 00 "
        "0f 85 ?? ?? ?? ?? 8a 86 90 48 00 00 84 c0 75 32",
    )
    voice_block = _find_unique(
        image,
        "voice selection",
        "c6 86 91 48 00 00 00 ff 15 ?? ?? ?? ?? 99 f7 ff 42 52 "
        "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 2a e8 ?? ?? ?? ??",
    )
    if not update <= voice_block < update + 0x106:
        raise ValueError("native Mygghanget voice selection escaped its update function")
    take_count = _u32(image.data, update + 8)
    if not 1 <= take_count < 100:
        raise ValueError(f"native Mygghanget take divisor is invalid: {take_count}")
    voice_bank = image.c_string(_u32(image.data, voice_block + 19))
    voice_owner = image.c_string(_u32(image.data, voice_block + 24))
    if voice_owner != "mulle" or not voice_bank:
        raise ValueError(
            f"native Mygghanget voice tuple drifted to {(voice_owner, voice_bank)!r}"
        )

    barn_entry = _find_unique(
        image,
        "barn entry",
        "68 ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 80 99 09 00 00 01 "
        "8b 8e 5c 01 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ??",
    )
    first_target = image.c_string(_u32(image.data, barn_entry + 1))
    second_target = image.c_string(_u32(image.data, barn_entry + 24))
    if first_target != mode_name or second_target != mode_name:
        raise ValueError("native barn entry no longer primes mode_mygghanget")

    common_open = _find_unique(
        image,
        "common open state selection",
        "38 9e 99 09 00 00 74 11 8b 16 6a 05 8b ce "
        "88 9e 99 09 00 00 ff 52 34 eb 1c 8b 06 53 8b ce ff 50 34",
    )
    state_zero_departure = _find_unique(
        image,
        "state zero departure",
        "8b 4e 5c 8d 84 24 b4 00 00 00 50 8b 11 ff 52 34 "
        "8b 8e a8 08 00 00 50 e8 ?? ?? ?? ?? 84 c0 74 1a "
        "8b 4e 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ??",
    )
    if image.c_string(_u32(image.data, state_zero_departure + 36)) != "mode_fly":
        raise ValueError("native Mygghanget state 0 departure target is not mode_fly")

    barn_input_dispatch = _find_unique(
        image,
        "barn input dispatch",
        "64 a1 00 00 00 00 6a ff 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 "
        "83 ec 64 55 56 8b f1 8b 06 ff 50 04 84 c0",
    )
    barn_escape_lookup = _find_unique(
        image,
        "barn escape lookup",
        "8b 45 10 48 3d cf 00 00 00 0f 87 ?? ?? ?? ?? 33 d2 "
        "8a 90 ?? ?? ?? ?? ff 24 95 ?? ?? ?? ??",
    )
    lookup_table = _u32(image.data, barn_escape_lookup + 19)
    jump_table = _u32(image.data, barn_escape_lookup + 26)
    lookup_index = image.data[image.address_to_offset(lookup_table)]
    escape_action_address = _u32(
        image.data, image.address_to_offset(jump_table) + lookup_index * 4
    )
    escape_action = image.address_to_offset(escape_action_address)
    expected_action = bytes.fromhex("8b 86 90 01 00 00 83 e8 00 74 32")
    if image.data[escape_action:escape_action + len(expected_action)] != expected_action:
        raise ValueError("native barn Escape action drifted")
    outside_branch = escape_action + 11 + image.data[escape_action + 10]
    if image.data[outside_branch:outside_branch + 3] != b"\x8b\xce\xe8":
        raise ValueError("native barn Escape outside-view branch drifted")
    flyaway_handler = _relative_target(image, outside_branch + 2)
    flyaway_offset = image.address_to_offset(flyaway_handler)
    flyaway_prologue = bytes.fromhex("56 8b f1 e8")
    if image.data[flyaway_offset:flyaway_offset + 4] != flyaway_prologue:
        raise ValueError("native barn flyaway handler drifted")
    if not flyaway_offset <= barn_entry < flyaway_offset + 0xA0:
        raise ValueError("native barn flyaway handler no longer primes Mygghanget")

    start_engine_gate = _find_unique(
        image,
        "state five start-engine gate",
        "8b 46 5c d9 80 48 01 00 00 d8 1d ?? ?? ?? ?? df e0 f6 c4 41 "
        "75 07 b8 01 00 00 00 eb 02 33 c0 8a 8e b4 08 00 00 "
        "0a c8 88 8e b4 08 00 00",
    )
    start_engine_threshold_address = _u32(image.data, start_engine_gate + 11)
    start_engine_threshold = _f32(
        image.data, image.address_to_offset(start_engine_threshold_address)
    )
    if start_engine_threshold != 0.5:
        raise ValueError(
            f"native Mygghanget start-engine threshold drifted to "
            f"{start_engine_threshold!r}"
        )

    faster_sampler = _find_unique(
        image,
        "digital faster sampler",
        "8a 46 74 84 c0 74 08 d9 05 ?? ?? ?? ?? eb 06 "
        "d9 05 ?? ?? ?? ?? 8a 46 75 84 c0 74 08 d9 05 ?? ?? ?? ?? "
        "eb 06 d9 05 ?? ?? ?? ?? d8 c1 51 d8 4c 24 10 d9 1c 24 "
        "dd d8 e8 ?? ?? ?? ??",
    )
    throttle_adjust = _relative_target(image, faster_sampler + 54)
    if throttle_adjust != 0x0040F8D0:
        raise ValueError(
            f"native faster sampler target drifted to {throttle_adjust:#x}"
        )

    state_five_departure = _find_unique(
        image,
        "state five direct departure",
        "8b 4e 5c 8d 44 24 6c 50 8b 11 ff 52 34 "
        "8b 8e a8 08 00 00 50 e8 ?? ?? ?? ?? 84 c0 74 1a "
        "8b 4e 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ??",
    )
    if image.c_string(_u32(image.data, state_five_departure + 33)) != "mode_fly":
        raise ValueError("native Mygghanget state 5 departure target is not mode_fly")
    state_five_departure_call = state_five_departure + 37
    if _relative_target(image, state_five_departure_call) != 0x0041E450:
        raise ValueError("native Mygghanget state 5 departure bypasses mode setter")

    presentation_renderer = _find_unique(
        image,
        "global presentation renderer",
        "8b 44 24 0c 8b 54 24 08 56 8b f1 8b 4c 24 08 "
        "89 8e c8 01 00 00 8b 8e 68 01 00 00 89 86 f0 01 00 00 "
        "89 96 cc 01 00 00 8b 01 ff 50 20 8b 86 f0 01 00 00 "
        "85 c0 74 33 8b 84 86 d4 01 00 00 85 c0 74 28",
    )

    presentation_loader = _find_unique(
        image,
        "global presentation loader",
        "68 ?? ?? ?? ?? 50 89 5c 24 24 89 86 c0 01 00 00 ff 15 ?? ?? ?? ?? "
        "8b 96 c0 01 00 00 8b 3d ?? ?? ?? ?? 83 c4 08 68 ?? ?? ?? ?? 52 ff d7 "
        "83 c4 08 8b ce 89 86 e8 01 00 00 6a 05 68 00 00 c8 42 6a 00",
    )
    presentation_controls = _find_unique(
        image,
        "control presentation assets",
        "8b 86 c0 01 00 00 68 ?? ?? ?? ?? 50 ff d7 8b 8e c0 01 00 00 83 c4 08 "
        "89 86 d8 01 00 00 68 ?? ?? ?? ?? 51 ff d7 8b 96 c0 01 00 00 83 c4 08 "
        "89 86 dc 01 00 00 68 ?? ?? ?? ?? 52 ff d7 83 c4 08 89 86 e0 01 00 00 "
        "8b 86 c0 01 00 00 68 ?? ?? ?? ?? 50 ff d7 68 24 04 00 00 "
        "89 86 e4 01 00 00",
    )
    if presentation_controls != presentation_loader + 0x46:
        raise ValueError("native Mygghanget presentation asset loader split drifted")
    misc_directory = image.c_string(_u32(image.data, presentation_loader + 1))
    loading_name = image.c_string(_u32(image.data, presentation_loader + 0x26))
    takeoff_general = image.c_string(_u32(image.data, presentation_controls + 7))
    startengine_name = image.c_string(_u32(image.data, presentation_controls + 0x1E))
    land_general = image.c_string(_u32(image.data, presentation_controls + 0x35))
    land_name = image.c_string(_u32(image.data, presentation_controls + 0x4C))
    presentation_names = [
        loading_name, takeoff_general, startengine_name, land_general, land_name
    ]
    if (
        not misc_directory
        or not misc_directory.lower().startswith("data\\graphics\\")
        or any(not name for name in presentation_names)
        or len(set(presentation_names)) != len(presentation_names)
    ):
        raise ValueError("native Mygghanget presentation resource tuple drifted")

    source = {
        "filename": executable.name,
        "sha256": _sha256(image.data),
        "imageBase": f"0x{image.image_base:08x}",
    }
    return {
        "schema": 1,
        "contract": "miel-vliegt-native-mygghanget",
        "claim": "STATIC_CODE_EXACT",
        "claimLimit": ["RUNTIME_EXECUTION_UNPROVEN", "FRAMEBUFFER_PARITY_UNPROVEN"],
        "source": source,
        "generator": {
            "path": "tools/miel_vliegt/native_mygghanget_contract.py",
            "sha256": _sha256(Path(__file__).read_bytes()),
        },
        "mode": {
            "id": location_name,
            "mode": mode_name,
            "locationId": 22,
            "constructor": _window(image, constructor, 0x89),
            "loader": _window(image, loader, 0xB4),
            "open": _window(image, open_entry, 0x34),
            "stateSetter": _window(image, state_setter, 0x2D),
            "update": _window(image, update, 0x106),
        },
        "fields": {
            "stateU32": "0x8dc",
            "barnEntryU8": "0x999",
            "departureU8": "0x4890",
            "voiceArmedU8": "0x4891",
        },
        "entry": {
            "barnPrimeAddress": _address(image, barn_entry + 10),
            "commonOpenSelectorAddress": _address(image, common_open),
            "barnState": 5,
            "ordinaryState": 0,
        },
        "bootstrapInputContract": {
            "input": {
                "api": "SendInput",
                "kind": "keyboard-scan-code",
                "scanCode": "0x01",
                "nativeKeyCode": 1,
                "name": "DIK_ESCAPE",
            },
            "dispatch": {
                "entry": _address(image, barn_input_dispatch),
                "entryReceipt": _window(image, barn_input_dispatch, 0x23),
                "lookupAddress": _address(image, barn_escape_lookup),
                "lookupReceipt": _window(image, barn_escape_lookup, 0x1E),
                "lookupTable": f"0x{lookup_table:08x}",
                "lookupIndex": lookup_index,
                "jumpTable": f"0x{jump_table:08x}",
                "action": f"0x{escape_action_address:08x}",
                "outsideViewBranch": _address(image, outside_branch),
                "handler": f"0x{flyaway_handler:08x}",
            },
            "startEngine": {
                "input": {
                    "api": "SendInput",
                    "kind": "keyboard-scan-code-held-until-departure",
                    "scanCode": "0x2a",
                    "nativeScanCodes": [42, 54, 78],
                    "name": "DIK_LSHIFT_OR_EQUIVALENT_FASTER",
                },
                "sample": {
                    "entry": _address(image, faster_sampler),
                    "receipt": _window(image, faster_sampler, 59),
                    "managerNodeField": "0x74",
                    "throttleAdjust": f"0x{throttle_adjust:08x}",
                },
                "gate": {
                    "entry": _address(image, start_engine_gate),
                    "receipt": _window(image, start_engine_gate, 48),
                    "sharedFlightField": "0x5c",
                    "throttleField": "0x148",
                    "latchField": "0x8b4",
                    "thresholdAddress": f"0x{start_engine_threshold_address:08x}",
                    "thresholdF32": start_engine_threshold,
                },
                "directDeparture": {
                    "offscreenTestEntry": _address(image, state_five_departure),
                    "receipt": _window(image, state_five_departure, 42),
                    "modeSetCallsite": _address(image, state_five_departure_call),
                    "targetMode": "mode_fly",
                },
            },
            "preconditions": [
                "current-mode-is-mode_barn",
                "pending-mode-is-null",
                "barn-view-field-0x190-is-zero",
                "airplane-complete-predicate-is-true",
            ],
            "postconditions": [
                "mode_mygghanget-field-0x999-set-to-one",
                "mode_mygghanget-open-selects-state-five",
                "native-faster-sample-field-0x74-becomes-one",
                "shared-flight-throttle-field-0x148-reaches-at-least-0.5",
                f"state-five-callsite-{_address(image, state_five_departure_call)}-requests-mode_fly-after-offscreen-test",
                f"alternate-state-zero-callsite-{_address(image, state_zero_departure + 40)}-requests-mode_fly-after-offscreen-test",
            ],
            "policy": "REAL_INPUT_ONLY_NO_DIRECT_HANDLER_OR_STATE_MODE_WRITE",
        },
        "loaderPolicy": {
            "layerVerticalOffsets": [0, 350, 300, 540],
            "sceneFloat9a0": -10.0,
            "sceneFloat9a8": 30.0,
            "rendererSetupFloat": 50.0,
            "anchorLayer": 3,
            "anchorScreenY": 80,
        },
        "assets": {
            "sky": {
                "condition": sky_condition,
                "bank": sky_bank,
                "discoveryPolicy": "contiguous-rectangular-grid",
            },
            "presentationBoundary": {
                "directory": misc_directory.replace("\\", "/"),
                "loaderReceipt": _window(image, presentation_loader, 0xA4),
                "generalSiblings": [takeoff_general, land_general],
                "renderer": {
                    "entry": _address(image, presentation_renderer),
                    "receipt": _window(image, presentation_renderer, 0x76),
                    "selectorHandleBase": "0x1d4",
                    "selectorToHandleField": {
                        "1": "0x1d8",
                        "2": "0x1dc",
                        "3": "0x1e0",
                        "4": "0x1e4",
                        "5": "0x1e8",
                    },
                    "inputSemantics": "NONE_STATIC_RENDER_ONLY",
                },
                "resources": [
                    {
                        "role": "loading",
                        "assetName": loading_name,
                        "handleField": "0x1e8",
                        "loadAddress": _address(image, presentation_loader + 0x25),
                        "classification": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
                    },
                    {
                        "role": "start-engine",
                        "assetName": startengine_name,
                        "handleField": "0x1dc",
                        "loadAddress": _address(image, presentation_controls + 0x1D),
                        "classification": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
                    },
                    {
                        "role": "land",
                        "assetName": land_name,
                        "handleField": "0x1e4",
                        "loadAddress": _address(image, presentation_controls + 0x4B),
                        "classification": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
                    },
                ],
            },
        },
        "stateMachine": {
            "stateField": "0x8dc",
            "flightState": 5,
            "departureState": 0,
            "barnStateCallback": 6,
            "stateZeroSetsDepartureBeforeCommonSetter": True,
            "stateSixTarget": "mode_barn",
            "stateZeroOffscreenTarget": "mode_fly",
            "stateZeroOffscreenAddress": _address(image, state_zero_departure + 35),
            "stateFiveDirectDepartureAddress": _address(
                image, state_five_departure_call
            ),
            "stateFiveBarnOffscreenAddress": _address(image, update + 0x42),
            "updateOrdering": [
                "state-five-barn-offscreen-return",
                "eligible-one-shot-voice",
                "common-location-update",
            ],
        },
        "voice": {
            "owner": voice_owner,
            "scriptNumber": 42,
            "bank": voice_bank,
            "takeDomain": list(range(1, take_count + 1)),
            "selection": "one-native-rand-modulo-take-count-plus-one",
            "voiceSelectionAddress": _address(image, voice_block),
            "armedClearedBeforeRandom": True,
            "rearmedOnOpen": True,
            "blockedAttemptsPreserveArmed": True,
            "eligibility": [
                "state-equals-five",
                "common-voice-countdown-equals-zero",
                "voice-armed",
                "scene-voice-idle",
                "manager-voice-idle",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    contract = extract_native_mygghanget_contract(args.executable)
    payload = json.dumps(contract, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
