#!/usr/bin/env python3
"""Validate, compile and apply the native UDSP scene-navigation contract.

The contract does not invent a location variable.  It follows the executable's
own mode registry: wait until the target location constructor has registered its
mode, rewrite one call to the central mode-change function, then confirm entry at
that location's loader.  The generated C header is consumed by the PE32 debugger
helper running next to the original game.  A second, debugger-independent start
route rewrites the reviewed startup SetMode argument after registry construction;
this makes every scene directly launchable even on hosts without Win32 debug
event forwarding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.miel_vliegt.native_trace import PeImage, sha256_file


DEFAULT_MANIFEST = ROOT / "content/miel_vliegt/native_scene_probe.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
ADDRESS = re.compile(r"^0x[0-9a-f]{8}$")


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1:
        raise ValueError("unsupported native scene probe schema")
    source = manifest.get("source", {})
    if not SHA256.fullmatch(source.get("executable_sha256", "")):
        raise ValueError("scene probe has no pinned executable SHA-256")
    contract_path = ROOT / source.get("mission_contract", "")
    if not contract_path.is_file() or sha256_file(contract_path) != source.get("mission_contract_sha256"):
        raise ValueError("pinned native mission contract drifted")
    scenes = manifest.get("scenes")
    if not isinstance(scenes, list) or not scenes:
        raise ValueError("scene probe must contain scenes")
    seen_ids: set[str] = set()
    seen_modes: set[str] = set()
    seen_locations: set[int] = set()
    required = {
        "id", "location_id", "mode", "mode_address", "constructor",
        "constructor_signature", "loader", "loader_signature",
    }
    for index, scene in enumerate(scenes):
        if not isinstance(scene, dict) or set(scene) != required:
            raise ValueError(f"scene {index} fields differ from the contract")
        if not IDENTIFIER.fullmatch(scene["id"]):
            raise ValueError(f"invalid scene id: {scene['id']!r}")
        if not isinstance(scene["location_id"], int) or isinstance(scene["location_id"], bool):
            raise ValueError(f"invalid location id for {scene['id']}")
        if not scene["mode"].startswith("mode_"):
            raise ValueError(f"invalid native mode for {scene['id']}")
        if scene["id"] in seen_ids or scene["mode"] in seen_modes or scene["location_id"] in seen_locations:
            raise ValueError(f"duplicate scene identity: {scene['id']}")
        seen_ids.add(scene["id"])
        seen_modes.add(scene["mode"])
        seen_locations.add(scene["location_id"])
        for field in ("mode_address", "constructor", "loader"):
            if not ADDRESS.fullmatch(scene[field]):
                raise ValueError(f"invalid {field} for {scene['id']}")
        for field in ("constructor_signature", "loader_signature"):
            try:
                signature = bytes.fromhex(scene[field])
            except ValueError as error:
                raise ValueError(f"invalid {field} for {scene['id']}") from error
            if len(signature) < 8:
                raise ValueError(f"{field} is too short for {scene['id']}")
    mission_contract = json.loads(contract_path.read_text(encoding="utf-8"))
    mission_location_ids = {
        int(dependency["data"])
        for mission in mission_contract.get("missions", [])
        if mission.get("source") == "data/Missions/locationinfo.txt"
        for dependency in mission.get("dependencies", [])
        if dependency.get("type") == "enter_location"
    }
    if mission_location_ids != seen_locations:
        raise ValueError("native scene IDs differ from locationinfo mission evidence")
    startup_targets = manifest.get("startup_targets")
    if not isinstance(startup_targets, list) or not startup_targets:
        raise ValueError("native startup targets must be declared explicitly")
    target_ids = set(seen_ids)
    for index, target in enumerate(startup_targets):
        if not isinstance(target, dict) or set(target) != {
            "id", "kind", "mode", "mode_address",
        }:
            raise ValueError(f"startup target {index} fields differ from the contract")
        if not IDENTIFIER.fullmatch(target["id"]) or target["id"] in target_ids:
            raise ValueError(f"duplicate or invalid startup target: {target.get('id')!r}")
        if target["kind"] != "runtime_mode" or not target["mode"].startswith("mode_") \
                or not ADDRESS.fullmatch(target["mode_address"]):
            raise ValueError(f"invalid native startup target: {target['id']}")
        target_ids.add(target["id"])
    registration_calls = manifest.get("engine", {}).get("scene_registry", {}).get("registration_calls")
    if not isinstance(registration_calls, list) or {
        call.get("scene") for call in registration_calls if isinstance(call, dict)
    } != seen_ids:
        raise ValueError("native scene registry does not construct every scene exactly once")
    return manifest


def _verify_signature(image: PeImage, record: dict[str, Any], label: str) -> None:
    expected = bytes.fromhex(record["signature"])
    address = int(record["address"], 16)
    if image.bytes_at(address, len(expected)) != expected:
        raise ValueError(f"native scene signature drifted: {label}")


def verify_executable(executable: Path, manifest: dict[str, Any]) -> PeImage:
    expected_hash = manifest["source"]["executable_sha256"]
    actual_hash = sha256_file(executable)
    if actual_hash != expected_hash:
        raise ValueError(f"wrong native executable: {actual_hash}")
    image = PeImage(executable)
    if image.image_base != int(manifest["source"]["image_base"], 16):
        raise ValueError("native scene executable image base drifted")
    for name, record in manifest["engine"].items():
        _verify_signature(image, record, name)
    marker = manifest["engine"]["scene_probe_marker"]
    marker_capacity = marker.get("capacity")
    marker_signature = bytes.fromhex(marker["signature"])
    if marker_capacity != len(marker_signature):
        raise ValueError("native scene probe marker capacity drifted")
    create_directory_iat = int(marker["create_directory_iat"], 16)
    if image.bytes_at(create_directory_iat, 4) != bytes.fromhex(marker["create_directory_iat_signature"]):
        raise ValueError("native scene CreateDirectoryA import drifted")
    scenes_by_id = {scene["id"]: scene for scene in manifest["scenes"]}
    for call in manifest["engine"]["scene_registry"]["registration_calls"]:
        address = int(call["address"], 16)
        encoded = bytes.fromhex(call["signature"])
        if len(encoded) != 5 or encoded[0] != 0xE8 or image.bytes_at(address, 5) != encoded:
            raise ValueError(f"native scene registration call drifted: {call['scene']}")
        target = address + 5 + int.from_bytes(encoded[1:], "little", signed=True)
        if target != int(scenes_by_id[call["scene"]]["constructor"], 16):
            raise ValueError(f"native scene registration target drifted: {call['scene']}")
    for scene in manifest["scenes"]:
        for kind in ("constructor", "loader"):
            expected = bytes.fromhex(scene[f"{kind}_signature"])
            address = int(scene[kind], 16)
            if image.bytes_at(address, len(expected)) != expected:
                raise ValueError(f"native scene signature drifted: {scene['id']}.{kind}")
        mode = scene["mode"].encode("ascii") + b"\0"
        if image.bytes_at(int(scene["mode_address"], 16), len(mode)) != mode:
            raise ValueError(f"native scene mode string drifted: {scene['id']}")
    for target in manifest["startup_targets"]:
        mode = target["mode"].encode("ascii") + b"\0"
        if image.bytes_at(int(target["mode_address"], 16), len(mode)) != mode:
            raise ValueError(f"native startup mode string drifted: {target['id']}")
    return image


def scene_by_id(manifest: dict[str, Any], scene_id: str) -> dict[str, Any]:
    for scene in manifest["scenes"]:
        if scene["id"] == scene_id:
            return scene
    raise ValueError(f"unknown native scene: {scene_id}")


def startup_target_by_id(manifest: dict[str, Any], target_id: str) -> dict[str, Any]:
    """Resolve a location or a reviewed non-location runtime mode."""
    for scene in manifest["scenes"]:
        if scene["id"] == target_id:
            return scene
    for target in manifest["startup_targets"]:
        if target["id"] == target_id:
            return target
    raise ValueError(f"unknown native startup target: {target_id}")


def _file_offset(image: PeImage, address: int, size: int) -> int:
    for section in image.sections:
        delta = address - section["virtual_address"]
        if 0 <= delta and delta + size <= section["raw_size"]:
            return section["raw_offset"] + delta
    raise ValueError(f"address 0x{address:08x} is not file-backed")


def patch_executable(
    executable: Path,
    output: Path,
    manifest: dict[str, Any],
    scene: dict[str, Any],
    *,
    marker_directory: str | None = None,
) -> dict[str, Any]:
    """Create a scene-selecting copy; never mutate the pinned source executable.

    Playable copies only replace the immediate pointer passed to the original
    startup SetMode call.  A probe copy may additionally replace the requested
    loader entry with a CreateDirectoryA marker followed by a deliberate loop;
    that proves loader entry without relying on Hangover's Win32 Debug API.
    """
    if executable.resolve() == output.resolve():
        raise ValueError("native scene patch output must differ from its source")
    image = verify_executable(executable, manifest)
    patched = bytearray(image.data)
    transition = manifest["engine"]["startup_mode_transition"]
    transition_address = int(transition["address"], 16)
    argument_offset = transition["argument_offset"]
    transition_signature = bytes.fromhex(transition["signature"])
    if not isinstance(argument_offset, int) or transition_signature[:1] != b"\x68" or argument_offset != 1:
        raise ValueError("unsupported native startup transition encoding")
    if int.from_bytes(transition_signature[1:5], "little") != int(transition["original_mode_address"], 16):
        raise ValueError("native startup mode pointer differs from its contract")
    transition_file_offset = _file_offset(image, transition_address, len(transition_signature))
    mode_address = int(scene["mode_address"], 16)
    patched[transition_file_offset + argument_offset:transition_file_offset + argument_offset + 4] = mode_address.to_bytes(4, "little")

    changes = [{
        "kind": "startup-mode-argument",
        "address": f"0x{transition_address + argument_offset:08x}",
        "before": transition_signature[argument_offset:argument_offset + 4].hex(),
        "after": mode_address.to_bytes(4, "little").hex(),
    }]
    strategy = "startup-mode-argument"
    if marker_directory is not None:
        try:
            marker_bytes = marker_directory.encode("ascii") + b"\0"
        except UnicodeEncodeError as error:
            raise ValueError("native scene marker directory must be ASCII") from error
        marker = manifest["engine"]["scene_probe_marker"]
        marker_capacity = marker["capacity"]
        if not marker_directory or len(marker_bytes) > marker_capacity:
            raise ValueError("native scene marker directory exceeds its pinned storage")
        marker_address = int(marker["address"], 16)
        marker_file_offset = _file_offset(image, marker_address, marker_capacity)
        patched[marker_file_offset:marker_file_offset + len(marker_bytes)] = marker_bytes

        loader_address = int(scene["loader"], 16)
        create_directory_iat = int(marker["create_directory_iat"], 16)
        loader_probe = (
            b"\x68" + marker_address.to_bytes(4, "little")
            + b"\xff\x15" + create_directory_iat.to_bytes(4, "little")
            + b"\xeb\xfe"
        )
        loader_file_offset = _file_offset(image, loader_address, len(loader_probe))
        loader_before = image.bytes_at(loader_address, len(loader_probe))
        if not loader_before.startswith(bytes.fromhex(scene["loader_signature"])):
            raise ValueError(f"native scene loader probe drifted: {scene['id']}")
        patched[loader_file_offset:loader_file_offset + len(loader_probe)] = loader_probe
        changes.extend([
            {
                "kind": "probe-marker-directory",
                "address": f"0x{marker_address:08x}",
                "before": bytes(marker_capacity).hex(),
                "after": marker_bytes.hex(),
            },
            {
                "kind": "probe-loader-marker",
                "address": f"0x{loader_address:08x}",
                "before": loader_before.hex(),
                "after": loader_probe.hex(),
            },
        ])
        strategy += "+probe-loader-marker"

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(patched)
    output.chmod(executable.stat().st_mode)
    return {
        "schema": 1,
        "protocol": "miel-vliegt-native-scene-start-patch",
        "status": "PREPARED",
        "source_executable_sha256": manifest["source"]["executable_sha256"],
        "patched_executable_sha256": sha256_file(output),
        "strategy": strategy,
        "marker_directory": marker_directory,
        "scene": {
            "id": scene["id"], "location_id": scene.get("location_id"),
            "mode": scene["mode"], "kind": scene.get("kind", "location"),
        },
        "changes": changes,
    }


def _c_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit_c_header(manifest: dict[str, Any]) -> str:
    """Emit deterministic data only; debugger behavior remains reviewable C."""
    source_hash = manifest["source"]["executable_sha256"]
    mode_change = int(manifest["engine"]["mode_change"]["address"], 16)
    mode_tick = int(manifest["engine"]["mode_tick"]["address"], 16)
    entrypoint = manifest["engine"]["process_entrypoint"]
    entrypoint_address = int(entrypoint["address"], 16)
    entrypoint_signature = bytes.fromhex(entrypoint["signature"])
    rows = []
    for scene in manifest["scenes"]:
        rows.append(
            "    {%s, %s, %d, 0x%08xu, 0x%08xu, 0x%08xu, {%s}, %d, {%s}, %d},"
            % (
                _c_string(scene["id"]), _c_string(scene["mode"]), scene["location_id"],
                int(scene["mode_address"], 16), int(scene["constructor"], 16),
                int(scene["loader"], 16),
                ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(scene["constructor_signature"])),
                len(bytes.fromhex(scene["constructor_signature"])),
                ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(scene["loader_signature"])),
                len(bytes.fromhex(scene["loader_signature"])),
            )
        )
    hook = bytes.fromhex(manifest["engine"]["mode_change"]["signature"])
    return "\n".join([
        "/* Generated by native_scene_navigator.py; do not hand-edit. */",
        "#ifndef MIEL_NATIVE_SCENES_H",
        "#define MIEL_NATIVE_SCENES_H",
        f"#define MIEL_EXPECTED_EXE_SHA256 {_c_string(source_hash)}",
        f"#define MIEL_ENTRYPOINT_ADDRESS 0x{entrypoint_address:08x}u",
        "static const unsigned char MIEL_ENTRYPOINT_SIGNATURE[] = {%s};" % ", ".join(
            f"0x{byte:02x}" for byte in entrypoint_signature
        ),
        f"#define MIEL_MODE_CHANGE_ADDRESS 0x{mode_change:08x}u",
        f"static const unsigned char MIEL_MODE_CHANGE_SIGNATURE[] = {{{', '.join(f'0x{b:02x}' for b in hook)}}};",
        f"#define MIEL_MODE_TICK_ADDRESS 0x{mode_tick:08x}u",
        "static const unsigned char MIEL_MODE_TICK_SIGNATURE[] = {%s};" % ", ".join(
            f"0x{byte:02x}" for byte in bytes.fromhex(manifest["engine"]["mode_tick"]["signature"])
        ),
        "typedef struct MielSceneSpec {",
        "    const char *id; const char *mode; unsigned location_id;",
        "    unsigned mode_address; unsigned constructor; unsigned loader;",
        "    unsigned char constructor_signature[16]; unsigned constructor_signature_size;",
        "    unsigned char loader_signature[16]; unsigned loader_signature_size;",
        "} MielSceneSpec;",
        "static const MielSceneSpec MIEL_SCENES[] = {",
        *rows,
        "};",
        f"#define MIEL_SCENE_COUNT {len(rows)}u",
        "#endif",
        "",
    ])


def build_receipt(manifest_path: Path, executable: Path, scene: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": 1,
        "protocol": "miel-vliegt-native-scene-navigation",
        "status": "PREPARED",
        "probe_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "executable_sha256": sha256_file(executable),
        "strategy": "native-mode-registry",
        "scene": {
            "id": scene["id"], "location_id": scene.get("location_id"),
            "mode": scene["mode"], "kind": scene.get("kind", "location"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("executable", type=Path)
    header_parser = subparsers.add_parser("emit-header")
    header_parser.add_argument("output", type=Path)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("executable", type=Path)
    prepare_parser.add_argument("scene")
    prepare_parser.add_argument("output", type=Path)
    patch_parser = subparsers.add_parser("patch")
    patch_parser.add_argument("executable", type=Path)
    patch_parser.add_argument("scene")
    patch_parser.add_argument("output", type=Path)
    patch_parser.add_argument("--receipt", type=Path)
    patch_parser.add_argument("--marker-directory")
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    if args.command == "list":
        if args.json:
            print(json.dumps(manifest["scenes"], sort_keys=True, separators=(",", ":")))
        else:
            for scene in manifest["scenes"]:
                print(f"{scene['id']}\t{scene['location_id']}\t{scene['mode']}")
    elif args.command == "verify":
        verify_executable(args.executable, manifest)
        print(f"verified {len(manifest['scenes'])} native scenes")
    elif args.command == "emit-header":
        args.output.write_text(emit_c_header(manifest), encoding="utf-8")
    elif args.command == "prepare":
        verify_executable(args.executable, manifest)
        scene = startup_target_by_id(manifest, args.scene)
        args.output.write_text(
            json.dumps(build_receipt(args.manifest, args.executable, scene), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    elif args.command == "patch":
        scene = startup_target_by_id(manifest, args.scene)
        receipt = patch_executable(
            args.executable, args.output, manifest, scene,
            marker_directory=args.marker_directory,
        )
        rendered = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        if args.receipt:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")


if __name__ == "__main__":
    main()
