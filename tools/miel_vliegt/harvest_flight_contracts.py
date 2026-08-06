#!/usr/bin/env python3
"""Harvest source-pinned Miel Vliegt flight-world and mission contracts."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import struct
from pathlib import Path


MAP_PATH = Path("data/Graphics/Map")
MISSIONS_PATH = Path("data/Missions")
RUNTIME_CONTRACT = {
    "world": {"width": 4000, "depth": 4000, "start": {"x": 1289, "y": 70, "z": 1060}},
    "controls": {
        "left": "turn_left",
        "right": "turn_right",
        "up": "nose_down_descend",
        "down": "nose_up_ascend",
        "shift": "faster",
        "control": "slower",
    },
    "simulation": {"maximum_step_seconds": 0.04, "gravity": 9.81},
    "native_evidence": {
        "start_position": "MulleMeck.exe 0x40e4c9-0x40e4d7",
        "maximum_step": "MulleMeck.exe 0x40e631-0x40e667",
        "controls": "MIELMONTEUR.HLP (Dutch help)",
    },
}
IMAGE_BASE = 0x400000


def _native_runtime_proof(executable: Path) -> dict[str, object]:
    data = executable.read_bytes()
    start_offset = 0x40E4C9 - IMAGE_BASE
    start = data[start_offset:start_offset + 21]
    if len(start) != 21 or any(start[index:index + 3] != opcode for index, opcode in (
        (0, b"\xc7\x46\x70"), (7, b"\xc7\x46\x74"), (14, b"\xc7\x46\x78")
    )):
        raise ValueError("MulleMeck.exe start-position instructions drifted")
    start_values = [struct.unpack_from("<f", start, offset)[0] for offset in (3, 10, 17)]
    if start_values != [1289.0, 70.0, 1060.0]:
        raise ValueError(f"MulleMeck.exe start position drifted: {start_values}")

    step_offset = 0x40E631 - IMAGE_BASE
    step = data[step_offset:step_offset + 56]
    constant_address = 0x44C950
    constant_offset = constant_address - IMAGE_BASE
    maximum_step = struct.unpack_from("<f", data, constant_offset)[0]
    required_instructions = (
        (0, bytes.fromhex("d9442468d81d50c94400")),
        (17, bytes.fromhex("680ad7233d")),
        (33, bytes.fromhex("d82550c94400")),
        (43, bytes.fromhex("d81d50c94400")),
    )
    if len(step) != 56 or any(step[offset:offset + len(expected)] != expected for offset, expected in required_instructions):
        raise ValueError("MulleMeck.exe fixed-step instructions drifted")
    if abs(maximum_step - 0.04) > 1e-7:
        raise ValueError(f"MulleMeck.exe maximum step drifted: {maximum_step}")
    return {
        # Bewijs als hash + lengte, nooit als hex-payload: de repo is publiek
        # en mag geen verbatim executable-bytes herdistribueren.
        "start_position": {
            "address": "0x40e4c9",
            "bytes_sha256": hashlib.sha256(start).hexdigest(),
            "bytes_length": len(start),
            "values": start_values,
        },
        "maximum_step": {
            "address": "0x40e631",
            "constant_address": "0x44c950",
            "instruction_bytes_sha256": hashlib.sha256(step).hexdigest(),
            "instruction_bytes_length": len(step),
            "value": maximum_step,
        },
    }


def _help_controls_proof(help_file: Path) -> dict[str, object]:
    text = help_file.read_bytes().decode("latin-1", errors="ignore")
    fragments = {
        "left": "Druk de linkerpijltoets in als je naar links wil draaien.",
        "right": "Druk de rechterpijltoets in als je naar rechts wil draaien.",
        "up": "Druk de vooruit-pijltoets in als je met het vliegtuig wilt dalen",
        "shift": "Verhoog de snelheid door de shift-toets in te drukken.",
        "control": "Verminder de snelheid door de ctrl-toets in te drukken.",
    }
    missing = [name for name, fragment in fragments.items() if fragment not in text]
    if missing:
        raise ValueError(f"Dutch help control text drifted: {', '.join(missing)}")
    return {name: fragment for name, fragment in fragments.items()}


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _aggregate_hash(paths: list[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _blocks(source: str, keyword: str, *, named: bool = True) -> list[tuple[str | None, str]]:
    """Return named brace blocks without confusing nested mission fields."""
    name = r"\s+([^\s{]+)" if named else r"(?:\s+([^\s{]+))?"
    pattern = re.compile(rf"(?m)^\s*{re.escape(keyword)}{name}\s*\{{")
    result = []
    for match in pattern.finditer(source):
        depth = 1
        index = match.end()
        while index < len(source) and depth:
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
            index += 1
        if depth:
            raise ValueError(f"unterminated {keyword} block {match.group(1)!r}")
        result.append((match.group(1), source[match.end():index - 1]))
    return result


def _field(body: str, name: str) -> str | None:
    match = re.search(rf"(?mi)^\s*{re.escape(name)}\s+([^\r\n]+)", body)
    return match.group(1).strip() if match else None


def _mission_ledger(path: Path, root: Path) -> list[dict[str, object]]:
    source = path.read_text(encoding="latin-1")
    ledger = []
    for name, body in _blocks(source, "MISSION"):
        dependencies = []
        for _, dependency in _blocks(body, "DEPENDENCY", named=False):
            dependencies.append({
                "state": _field(dependency, "STATE"),
                "type": _field(dependency, "TYPE"),
                "data": _field(dependency, "DATA"),
            })
        actions = []
        for _, change in _blocks(body, "STATE_CHANGE", named=False):
            success = _field(change, "SUCCESS")
            actions.append({
                "state": _field(change, "STATE"),
                "command": success.split(None, 1)[0] if success else None,
                "arguments": success.split(None, 1)[1] if success and " " in success else "",
            })
        mission_id = _field(body, "ID")
        ledger.append({
            "name": name,
            "id": int(mission_id) if mission_id and mission_id.isdigit() else mission_id,
            "source": path.relative_to(root).as_posix(),
            "dependencies": dependencies,
            "actions": actions,
        })
    return ledger


def harvest(source_root: Path, *, executable: Path | None = None, help_file: Path | None = None) -> dict[str, object]:
    map_root = source_root / MAP_PATH
    mission_root = source_root / MISSIONS_PATH
    map_scene = map_root / "map_a.ccf"
    layers = map_root / "Map - Layers.raw"
    required = [map_scene, layers, mission_root]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise ValueError(f"missing UDS flight sources: {', '.join(missing)}")

    mission_files = sorted(mission_root.rglob("*.txt"), key=lambda path: path.relative_to(mission_root).as_posix())
    texture_files = sorted((map_root / "Textures").glob("*.gti"), key=lambda path: path.name)
    terrain_texture_files = [
        path for path in texture_files if re.fullmatch(r"[a-z]{2}\d+_\d+\.gti", path.name, re.I)
    ]
    missions = [entry for path in mission_files for entry in _mission_ledger(path, source_root)]
    top_level_files = [path for path in mission_files if path.parent == mission_root]
    package_files = [path for path in mission_files if path.parent != mission_root]
    action_counts: dict[str, int] = {}
    dependency_counts: dict[str, int] = {}
    for mission in missions:
        for action in mission["actions"]:
            command = action["command"]
            if command:
                action_counts[command] = action_counts.get(command, 0) + 1
        for dependency in mission["dependencies"]:
            kind = dependency["type"]
            if kind:
                dependency_counts[kind] = dependency_counts.get(kind, 0) + 1

    sources: dict[str, object] = {
        "map_a.ccf": {"sha256": _hash(map_scene)},
        "Map - Layers.raw": {"sha256": _hash(layers)},
        "missions": {"sha256": _aggregate_hash(mission_files, source_root)},
        "map_textures": {"sha256": _aggregate_hash(texture_files, source_root)},
    }
    native_proofs = {}
    if executable:
        sources["MulleMeck.exe"] = {"sha256": _hash(executable)}
        native_proofs.update(_native_runtime_proof(executable))
    if help_file:
        sources["MIELMONTEUR.HLP"] = {"sha256": _hash(help_file)}
        native_proofs["controls"] = _help_controls_proof(help_file)

    mission_ids = {mission["id"] for mission in missions}
    duplicate_ids = sorted({
        mission["id"] for mission in missions
        if sum(other["id"] == mission["id"] for other in missions) > 1
    })
    return {
        "schema": 1,
        "parity_scope": {
            "proven": ["world_bounds", "start_position", "controls", "fixed_step_cap", "mission_data"],
            "not_yet_parity": [
                "native_3d_rendering", "terrain_height_sampling", "3d_collision_volumes",
                "aerodynamic_field_semantics", "landing_detection", "mission_runtime_execution",
            ],
        },
        "sources": sources,
        "runtime": RUNTIME_CONTRACT,
        "native_proofs": native_proofs,
        "counts": {
            "mission_files": len(top_level_files),
            "package_files": len(package_files),
            "mission_declarations": len(missions),
            "unique_mission_ids": len(mission_ids),
            "duplicate_mission_ids": len(duplicate_ids),
            "terrain_tile_textures": len(terrain_texture_files),
            "alternate_map_textures": len(texture_files) - len(terrain_texture_files),
        },
        "duplicate_mission_ids": duplicate_ids,
        "dependency_counts": dict(sorted(dependency_counts.items())),
        "action_counts": dict(sorted(action_counts.items())),
        "missions": missions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="root containing extracted data/")
    parser.add_argument("output", type=Path)
    parser.add_argument("--executable", type=Path, help="installed native MulleMeck.exe")
    parser.add_argument("--help-file", type=Path, help="installed Dutch MIELMONTEUR.HLP")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(
        harvest(args.source, executable=args.executable, help_file=args.help_file), indent=2
    ) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True), encoded.splitlines(keepends=True),
                fromfile=str(args.output), tofile="fresh UDS flight harvest",
            ))
            raise SystemExit(f"UDS flight parity contract drifted:\n{diff}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
