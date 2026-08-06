#!/usr/bin/env python3
"""Derive a dialogue-free scene contract from Miel Vliegt's UDSP archive.

The location and character DEF trees are one coupled scene domain: location
scripts position actors and dispatch scripts by character-directory plus file
stem.  The ``NAME`` inside a character script is not a unique dispatch key.
This harvester therefore covers both trees and proves every dispatch target.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path, PureWindowsPath
from typing import Iterable

try:
    from tools.miel_vliegt.extract_udsp import UdspArchive
    from tools.miel_vliegt.parse_uds_script import Command, UdsScript
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from extract_udsp import UdspArchive
    from parse_uds_script import Command, UdsScript


LOCATION_ROOT = "data/Scripts/Locations"
CHARACTER_ROOT = "data/Scripts/Characters"
SELECTED_ROOTS = (LOCATION_ROOT, CHARACTER_ROOT)
NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/\\-]+\Z")

STALE_ANIMATION_SELECTION_ALLOWLIST = (
    ("data/Scripts/Characters/ernst/stand.def", 3, 1, 1),
    ("data/Scripts/Characters/fiona/talk.def", 3, 1, 1),
    ("data/Scripts/Characters/fiona/talk.def", 7, 1, 1),
    ("data/Scripts/Characters/linus/talk.def", 4, 1, 2),
)

# Only fields with a proven structural role may retain text. Any field outside
# this table is redacted, while its opcode, arity, node, loop and numeric values
# remain available for parity. This makes future dialogue-like commands safe by
# default instead of depending on a list of words that happen to be dialogue.
ARGUMENT_KINDS: dict[str, dict[int, tuple[str, ...]]] = {
    "AWARD_DIPLOMA": {1: ("number",)},
    "JUDGE_AIRPLANE": {0: ()},
    "PLAY_CHARACTER_ANIMATION": {
        5: ("number", "number", "number", "identifier", "identifier"),
        6: ("number", "number", "number", "identifier", "identifier", "number"),
    },
    "PLAY_CHARACTER_SCRIPT": {
        3: ("character_id", "script_id", "identifier"),
    },
    "PLAY_CHARACTER_SOUND": {
        4: ("character_id", "number", "media_bank", "identifier"),
    },
    "PLAY_MULLEBARNSOUND": {2: ("number", "identifier")},
    "PLAY_RADIO": {
        3: ("media_owner", "number", "media_bank"),
        4: ("media_owner", "number", "media_bank", "identifier"),
    },
    "PLAY_SOUND": {
        4: ("media_owner", "number", "media_bank", "identifier"),
    },
    "POSITION_CHARACTER": {3: ("character_id", "number", "number")},
    "WAIT": {2: ("number", "identifier")},
}


def _hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _normalized_path(path: str) -> str:
    windows = PureWindowsPath(path)
    if windows.is_absolute() or any(part in {".", ".."} for part in windows.parts):
        raise ValueError(f"unsafe archive path {path!r}")
    return windows.as_posix()


def _number(value: str) -> int | float:
    if not NUMBER.fullmatch(value):
        raise ValueError(f"expected numeric argument, got {value!r}")
    number = float(value)
    return int(number) if number.is_integer() else number


def _identifier(value: str, *, source: str) -> str:
    if not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{source}: non-structural text in identifier field")
    return value


def _argument(value: str, kind: str, *, source: str) -> object:
    if kind == "number":
        return _number(value)
    if kind in {"identifier", "character_id", "script_id", "media_owner", "media_bank"}:
        return _identifier(value, source=source)
    if kind == "dialogue":
        return {"redacted": "free_form_text"}
    raise ValueError(f"{source}: unsupported argument kind {kind!r}")


def _command_contract(command: Command, *, source: str) -> dict[str, object]:
    schemas = ARGUMENT_KINDS.get(command.name)
    if schemas is None:
        # Unknown commands remain observable without allowing arbitrary source
        # text into the repository. Numeric arguments are still exact.
        arguments = [
            _number(value) if NUMBER.fullmatch(value) else {"redacted": "unclassified_text"}
            for value in command.arguments
        ]
    else:
        kinds = schemas.get(len(command.arguments))
        if kinds is None:
            raise ValueError(
                f"{source}:{command.line}: unsupported {command.name} arity "
                f"{len(command.arguments)}"
            )
        arguments = [
            _argument(value, kind, source=f"{source}:{command.line}")
            for value, kind in zip(command.arguments, kinds)
        ]
    return {
        "opcode": command.name,
        "arity": len(command.arguments),
        "node": command.node,
        "loop": command.loop,
        "arguments": arguments,
    }


def _content_lines(text: str) -> list[tuple[int, str]]:
    result = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        content = raw.strip()
        if content and not content.startswith(("#", "//")):
            result.append((line_number, content))
    return result


def _fields(content: str) -> list[str]:
    return [field for field in re.split(r"[\s,]+", content) if field]


def parse_character_definition(text: str, *, source: str) -> dict[str, object]:
    """Strictly parse the non-executable CHARACTER descriptor grammar."""

    lines = _content_lines(text)
    index = 0

    def take(expected: str | None = None) -> tuple[int, str]:
        nonlocal index
        if index >= len(lines):
            raise ValueError(f"{source}: unexpected end of CHARACTER definition")
        item = lines[index]
        index += 1
        if expected is not None and item[1] != expected:
            raise ValueError(f"{source}:{item[0]}: expected {expected!r}, got {item[1]!r}")
        return item

    take("CHARACTER")
    take("{")
    character_name: str | None = None
    parts: list[dict[str, object]] = []
    while True:
        line_number, content = take()
        if content == "}":
            break
        fields = _fields(content)
        if fields and fields[0] == "NAME" and len(fields) == 2 and character_name is None:
            character_name = _identifier(fields[1], source=f"{source}:{line_number}")
            continue
        if content != "PART":
            raise ValueError(f"{source}:{line_number}: unsupported CHARACTER field {content!r}")
        take("{")
        part_id: int | None = None
        part_name: str | None = None
        position: list[int | float] | None = None
        animations: list[dict[str, object]] = []
        sequences: list[dict[str, object]] = []
        animation_declarations: list[dict[str, object]] = []
        while True:
            field_line, field_content = take()
            if field_content == "}":
                break
            values = _fields(field_content)
            keyword = values[0] if values else ""
            if keyword == "ID" and len(values) == 2 and part_id is None:
                part_id = _number(values[1])
                if not isinstance(part_id, int):
                    raise ValueError(f"{source}:{field_line}: PART ID must be an integer")
            elif keyword == "NAME" and len(values) == 2 and part_name is None:
                part_name = _identifier(values[1], source=f"{source}:{field_line}")
            elif keyword == "POS" and len(values) == 3 and position is None:
                position = [_number(values[1]), _number(values[2])]
            elif keyword == "ANIMATION" and len(values) == 3:
                animation = {
                    "id": _number(values[1]),
                    "media_id": _identifier(values[2], source=f"{source}:{field_line}"),
                }
                animations.append(animation)
                animation_declarations.append({
                    "kind": "ANIMATION", **animation, "frames": [0],
                })
            elif keyword == "ANIMATION_SEQUENCE" and len(values) == 4:
                sequence_id = _number(values[1])
                media_id = _identifier(values[2], source=f"{source}:{field_line}")
                frame_count = _number(values[3])
                if not isinstance(sequence_id, int) or not isinstance(frame_count, int):
                    raise ValueError(f"{source}:{field_line}: sequence id/count must be integers")
                take("{")
                frames: list[int] = []
                while True:
                    frame_line, frame_content = take()
                    if frame_content == "}":
                        break
                    frame = _number(frame_content)
                    if not isinstance(frame, int):
                        raise ValueError(f"{source}:{frame_line}: animation frame must be an integer")
                    frames.append(frame)
                sequence = {
                    "id": sequence_id,
                    "media_id": media_id,
                    "declared_frame_count": frame_count,
                    "frames": frames,
                }
                sequences.append(sequence)
                animation_declarations.append({"kind": "ANIMATION_SEQUENCE", **sequence})
            else:
                raise ValueError(f"{source}:{field_line}: unsupported PART field {field_content!r}")
        if part_id is None or part_name is None or position is None:
            raise ValueError(f"{source}: PART is missing ID, NAME or POS")
        animation_id_counts = Counter(animation["id"] for animation in animations)
        sequence_id_counts = Counter(sequence["id"] for sequence in sequences)
        parts.append({
            "id": part_id,
            "name": part_name,
            "position": position,
            "animations": animations,
            "animation_sequences": sequences,
            # Native descriptor construction prepends each declaration. Its
            # subsequent first-match lookup therefore selects the last source
            # declaration for duplicate ids. Preserve source order explicitly.
            "animation_declarations": animation_declarations,
            # Duplicate sequence ids occur in the shipped source and may encode
            # ordered alternatives. Preserve them; never collapse to a map.
            "duplicate_animation_ids": sorted(
                animation_id for animation_id, count in animation_id_counts.items() if count > 1
            ),
            "duplicate_animation_sequence_ids": sorted(
                sequence_id for sequence_id, count in sequence_id_counts.items() if count > 1
            ),
        })
    if index != len(lines):
        line_number, content = lines[index]
        raise ValueError(f"{source}:{line_number}: trailing CHARACTER content {content!r}")
    if character_name is None:
        raise ValueError(f"{source}: CHARACTER is missing NAME")
    if len({part["id"] for part in parts}) != len(parts):
        raise ValueError(f"{source}: duplicate PART id")
    if len({str(part["name"]).casefold() for part in parts}) != len(parts):
        raise ValueError(f"{source}: duplicate PART name")
    return {"type": "CHARACTER", "name": character_name, "parts": parts}


def _media_reference(command: Command) -> dict[str, object] | None:
    if command.name in {"PLAY_CHARACTER_SOUND", "PLAY_SOUND", "PLAY_RADIO"}:
        return {
            "opcode": command.name,
            "owner": command.arguments[0],
            "id": _number(command.arguments[1]),
            "bank": command.arguments[2],
        }
    if command.name == "PLAY_MULLEBARNSOUND":
        return {"opcode": command.name, "owner": "barn", "id": _number(command.arguments[0])}
    return None


def _counts(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _structure_metrics(structure: dict[str, object], depth: int = 0) -> tuple[int, int]:
    composites = 0 if structure["node"] is None else 1
    maximum_depth = depth
    for child in structure["children"]:
        if isinstance(child, dict) and set(child) == {"node", "repeat", "children"}:
            child_count, child_depth = _structure_metrics(child, depth + 1)
            composites += child_count
            maximum_depth = max(maximum_depth, child_depth)
    return composites, maximum_depth


def harvest(archive_path: Path) -> dict[str, object]:
    archive = UdspArchive(archive_path)
    entries = []
    seen_paths: set[str] = set()
    archive_root_counts: Counter[str] = Counter()
    for entry in archive.files:
        path = _normalized_path(entry.path)
        if not path.casefold().endswith(".def"):
            continue
        parts = PureWindowsPath(entry.path).parts
        root = PureWindowsPath(*parts[:3]).as_posix() if len(parts) >= 3 else path
        archive_root_counts[root] += 1
        folded = path.casefold()
        if folded in seen_paths:
            raise ValueError(f"duplicate normalized DEF path {path}")
        seen_paths.add(folded)
        if not any(path.casefold().startswith(root.casefold() + "/") for root in SELECTED_ROOTS):
            raise ValueError(f"unclassified DEF root for {path}")
        entries.append((path, entry))
    entries.sort(key=lambda item: (item[0].casefold(), item[0]))

    scripts: list[dict[str, object]] = []
    definitions: list[dict[str, object]] = []
    executable: list[tuple[str, UdsScript]] = []
    location_scene_scripts: defaultdict[str, list[tuple[str, UdsScript]]] = defaultdict(list)
    character_script_targets: set[tuple[str, str]] = set()
    character_directories: set[str] = set()
    descriptor_names: dict[str, str] = {}
    for path, entry in entries:
        payload = archive.payload(entry)
        if b"\0" in payload:
            raise ValueError(f"{path}: NUL byte in DEF text")
        text = payload.decode("latin-1")
        first = next((content for _, content in _content_lines(text)), "")
        parts = path.split("/")
        domain_id = parts[3] if len(parts) > 4 else ""
        if first == "CHARACTER":
            if not path.casefold().startswith(CHARACTER_ROOT.casefold() + "/"):
                raise ValueError(f"{path}: CHARACTER descriptor outside character root")
            parsed = parse_character_definition(text, source=path)
            character_directories.add(domain_id)
            descriptor_names[domain_id] = str(parsed["name"])
            definitions.append({
                "path": path,
                "sha256": _hash(payload),
                "character_id": domain_id,
                **parsed,
            })
            continue
        try:
            script = UdsScript.parse(text, source=path)
        except ValueError as error:
            raise ValueError(f"failed to parse executable DEF {path}: {error}") from error
        expected_root = LOCATION_ROOT if script.script_type == "LOCATION_SCRIPT" else CHARACTER_ROOT
        if not path.casefold().startswith(expected_root.casefold() + "/"):
            raise ValueError(f"{path}: {script.script_type} is under the wrong root")
        if script.name is None:
            raise ValueError(f"{path}: executable script is missing NAME")
        _identifier(script.name, source=path)
        commands = [_command_contract(command, source=path) for command in script.commands]
        structure = asdict(script.structure)
        node_count, maximum_depth = _structure_metrics(structure)
        record = {
            "path": path,
            "sha256": _hash(payload),
            "type": script.script_type,
            "name": script.name,
            "dispatch_id": Path(path).stem,
            "domain_id": domain_id,
            "counts": {
                "commands": len(script.commands),
                "nodes": node_count,
                "maximum_composite_depth": maximum_depth,
                "loop_commands": sum(command.loop for command in script.commands),
            },
            "commands": commands,
            "structure": structure,
        }
        scripts.append(record)
        executable.append((path, script))
        if script.script_type == "LOCATION_SCRIPT":
            location_scene_scripts[domain_id].append((path, script))
        else:
            character_directories.add(domain_id)
            character_script_targets.add((domain_id.casefold(), Path(path).stem.casefold()))

    if set(archive_root_counts) != set(SELECTED_ROOTS):
        raise ValueError(f"DEF root coverage drifted: {dict(archive_root_counts)}")
    if len(descriptor_names) != len(definitions):
        raise ValueError("duplicate CHARACTER descriptor directory")

    command_pairs = [(path, command) for path, script in executable for command in script.commands]
    dispatches = [
        (path, command.arguments[0], command.arguments[1])
        for path, command in command_pairs
        if command.name == "PLAY_CHARACTER_SCRIPT"
    ]
    unresolved_dispatches = sorted({
        f"{character}/{dispatch}"
        for _, character, dispatch in dispatches
        if (character.casefold(), dispatch.casefold()) not in character_script_targets
    })
    if unresolved_dispatches:
        raise ValueError(f"unresolved PLAY_CHARACTER_SCRIPT targets: {unresolved_dispatches}")

    referenced_characters = {
        command.arguments[0]
        for _, command in command_pairs
        if command.name in {"PLAY_CHARACTER_SCRIPT", "PLAY_CHARACTER_SOUND", "POSITION_CHARACTER"}
    }
    unresolved_characters = sorted(
        character for character in referenced_characters
        if character.casefold() not in {item.casefold() for item in character_directories}
    )
    if unresolved_characters:
        raise ValueError(f"unresolved character directories: {unresolved_characters}")

    placements = []
    animations = []
    waits = []
    media = []
    definitions_by_character = {
        str(definition["character_id"]).casefold(): definition for definition in definitions
    }
    stale_selection_misses = []
    resolved_animations = 0
    for path, script in executable:
        for command_index, command in enumerate(script.commands):
            common = {"path": path, "node": command.node, "loop": command.loop}
            if command.name == "POSITION_CHARACTER":
                placements.append({
                **common,
                "character_id": command.arguments[0],
                "x": _number(command.arguments[1]),
                "y": _number(command.arguments[2]),
                })
            elif command.name == "PLAY_CHARACTER_ANIMATION":
                if script.script_type != "CHARACTER_SCRIPT":
                    raise ValueError(f"{path}:{command.line}: animation has no CHARACTER_SCRIPT owner")
                character_id = path.split("/")[3]
                definition = definitions_by_character[character_id.casefold()]
                part_id = _number(command.arguments[0])
                animation_id = _number(command.arguments[1])
                part = next((item for item in definition["parts"] if item["id"] == part_id), None)
                selected = next((
                    declaration for declaration in reversed(part["animation_declarations"])
                    if declaration["id"] == animation_id
                ), None) if part else None
                resolution = "RESOLVED_LAST_DECLARED" if selected else "STALE_SELECTION"
                if selected:
                    resolved_animations += 1
                else:
                    stale_selection_misses.append({
                    "path": path,
                    "command_index": command_index,
                    "part_id": part_id,
                    "animation_id": animation_id,
                    })
                animations.append({
                **common,
                "character_id": character_id,
                "part_id": part_id,
                "animation_id": animation_id,
                "playback_rate_fps": _number(command.arguments[2]),
                "playback": command.arguments[3],
                "modifier": command.arguments[4],
                "repeat_count": _number(command.arguments[5]) if len(command.arguments) == 6 else None,
                "resolution": resolution,
                "selected_declaration": selected,
                })
            elif command.name == "WAIT":
                waits.append({
                **common,
                "duration": _number(command.arguments[0]),
                "mode": command.arguments[1],
                })
            media_reference = _media_reference(command)
            if media_reference is not None:
                media.append({**common, **media_reference})

    actual_stale_allowlist = tuple(
        (record["path"], record["command_index"], record["part_id"], record["animation_id"])
        for record in stale_selection_misses
    )
    if actual_stale_allowlist != STALE_ANIMATION_SELECTION_ALLOWLIST:
        raise ValueError(f"animation stale-selection allowlist drifted: {stale_selection_misses}")

    scenes = []
    for scene_id, scene_scripts in sorted(location_scene_scripts.items()):
        scene_commands = [command for _, script in scene_scripts for command in script.commands]
        scene_paths = {path for path, _ in scene_scripts}
        scene_media = [record for record in media if record["path"] in scene_paths]
        scene_placements = sorted({
            (command.arguments[0], _number(command.arguments[1]), _number(command.arguments[2]))
            for command in scene_commands
            if command.name == "POSITION_CHARACTER"
        })
        scene_animations = sorted({
            (
                _number(command.arguments[0]),
                _number(command.arguments[1]),
                _number(command.arguments[2]),
                command.arguments[3],
                command.arguments[4],
                _number(command.arguments[5]) if len(command.arguments) == 6 else None,
            )
            for command in scene_commands
            if command.name == "PLAY_CHARACTER_ANIMATION"
        }, key=lambda record: tuple("" if value is None else str(value) for value in record))
        scene_waits = sorted({
            (_number(command.arguments[0]), command.arguments[1])
            for command in scene_commands
            if command.name == "WAIT"
        }, key=lambda record: (str(record[0]), record[1]))
        scene_dispatches = sorted({
            (command.arguments[0], command.arguments[1])
            for command in scene_commands
            if command.name == "PLAY_CHARACTER_SCRIPT"
        })
        scene_characters = sorted({
            command.arguments[0]
            for command in scene_commands
            if command.name in {"PLAY_CHARACTER_SCRIPT", "PLAY_CHARACTER_SOUND", "POSITION_CHARACTER"}
        })
        scenes.append({
            "id": scene_id,
            "script_paths": sorted(scene_paths),
            "counts": {
                "scripts": len(scene_scripts),
                "commands": len(scene_commands),
                "nodes": sum(len({c.node for c in script.commands if c.node is not None}) for _, script in scene_scripts),
                "loop_commands": sum(command.loop for command in scene_commands),
                "placements": sum(command.name == "POSITION_CHARACTER" for command in scene_commands),
                "animations": sum(command.name == "PLAY_CHARACTER_ANIMATION" for command in scene_commands),
                "waits": sum(command.name == "WAIT" for command in scene_commands),
                "media_references": len(scene_media),
                "character_script_dispatches": sum(
                    command.name == "PLAY_CHARACTER_SCRIPT" for command in scene_commands
                ),
            },
            "command_counts": _counts(command.name for command in scene_commands),
            "characters": scene_characters,
            "placement_contracts": [
                {"character_id": character, "x": x, "y": y}
                for character, x, y in scene_placements
            ],
            "animation_contracts": [
                {
                    "part_id": part_id,
                    "animation_id": animation_id,
                    "playback_rate_fps": playback_rate_fps,
                    "playback": playback,
                    "modifier": modifier,
                    "repeat_count": repeat_count,
                }
                for part_id, animation_id, playback_rate_fps, playback, modifier, repeat_count
                in scene_animations
            ],
            "wait_contracts": [
                {"duration": duration, "mode": mode} for duration, mode in scene_waits
            ],
            "character_script_dispatches": [
                {"character_id": character, "dispatch_id": dispatch}
                for character, dispatch in scene_dispatches
            ],
            "media_ids": sorted({
                ":".join(str(record[key]) for key in ("opcode", "owner", "id") if key in record)
                + (f":{record['bank']}" if "bank" in record else "")
                for record in scene_media
            }),
        })

    opcodes = sorted({command.name for _, command in command_pairs})
    arities = {
        opcode: sorted({len(command.arguments) for _, command in command_pairs if command.name == opcode})
        for opcode in opcodes
    }
    name_mismatches = [
        {"character_id": character_id, "definition_name": name}
        for character_id, name in sorted(descriptor_names.items())
        if character_id.casefold() != name.casefold()
    ]
    script_name_mismatches = [
        {"path": record["path"], "dispatch_id": record["dispatch_id"], "name": record["name"]}
        for record in scripts
        if record["type"] == "CHARACTER_SCRIPT"
        and str(record["dispatch_id"]).casefold() != str(record["name"]).casefold()
    ]
    descriptor_duplicate_ids = []
    descriptor_frame_count_mismatches = []
    for definition in definitions:
        for part in definition["parts"]:
            if part["duplicate_animation_ids"] or part["duplicate_animation_sequence_ids"]:
                descriptor_duplicate_ids.append({
                    "path": definition["path"],
                    "part_id": part["id"],
                    "animation_ids": part["duplicate_animation_ids"],
                    "animation_sequence_ids": part["duplicate_animation_sequence_ids"],
                })
            for sequence in part["animation_sequences"]:
                if sequence["declared_frame_count"] != len(sequence["frames"]):
                    descriptor_frame_count_mismatches.append({
                        "path": definition["path"],
                        "part_id": part["id"],
                        "sequence_id": sequence["id"],
                        "declared": sequence["declared_frame_count"],
                        "actual": len(sequence["frames"]),
                    })
    command_contracts = [command for script in scripts for command in script["commands"]]
    redacted_arguments = sum(
        isinstance(argument, dict) and "redacted" in argument
        for command in command_contracts
        for argument in command["arguments"]
    )
    return {
        "schema": 2,
        "claim": "SOURCE_STRUCTURE_EXACT",
        "claim_limit": (
            "Derived DEF structure only; free-form/unclassified text is redacted and runtime "
            "branch behavior still requires native observation."
        ),
        "source": {
            "archive": archive_path.name,
            "sha256": _hash(archive_path.read_bytes()),
            "udsp_version": f"{archive.header.version_major}.{archive.header.version_minor}",
        },
        "coverage": {
            "archive_def_roots": dict(sorted(archive_root_counts.items())),
            "selected_roots": list(SELECTED_ROOTS),
            "all_archive_def_files_covered": len(entries),
            "executable_scripts_parsed_by_uds_script": len(scripts),
            "character_definitions_strictly_parsed": len(definitions),
            "location_scenes": len(scenes),
            "resolved_character_script_dispatches": len(dispatches),
            "unresolved_character_script_dispatches": [],
            "unresolved_character_directories": [],
            "definition_name_directory_mismatches": name_mismatches,
            "script_name_dispatch_mismatches": script_name_mismatches,
            "descriptor_duplicate_animation_ids": descriptor_duplicate_ids,
            "descriptor_frame_count_mismatches": descriptor_frame_count_mismatches,
            "actor_animation_resolution": {
                "commands": len(animations),
                "resolved": resolved_animations,
                "stale_selection_misses": stale_selection_misses,
            },
            "scripts_with_nested_composites": sum(
                record["counts"]["maximum_composite_depth"] > 1 for record in scripts
            ),
            "maximum_composite_depth": max(
                record["counts"]["maximum_composite_depth"] for record in scripts
            ),
        },
        "counts": {
            "def_files": len(entries),
            "location_scripts": sum(record["type"] == "LOCATION_SCRIPT" for record in scripts),
            "character_scripts": sum(record["type"] == "CHARACTER_SCRIPT" for record in scripts),
            "character_definitions": len(definitions),
            "commands": len(command_pairs),
            "nodes": sum(record["counts"]["nodes"] for record in scripts),
            "loop_commands": sum(command.loop for _, command in command_pairs),
            "placements": len(placements),
            "animations": len(animations),
            "waits": len(waits),
            "media_references": len(media),
            "redacted_arguments": redacted_arguments,
        },
        "command_vocabulary": {
            "counts": _counts(command.name for _, command in command_pairs),
            "arities": arities,
        },
        "character_ids": sorted(character_directories),
        "referenced_character_ids": sorted(referenced_characters),
        "scenes": scenes,
        "placements": placements,
        "animations": animations,
        "waits": waits,
        "media_references": media,
        "character_definitions": definitions,
        "scripts": scripts,
    }


def encode(contract: dict[str, object]) -> str:
    return json.dumps(contract, indent=2, ensure_ascii=False) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Miel Vliegt data.up")
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true", help="fail when generated output drifted")
    args = parser.parse_args()
    encoded = encode(harvest(args.archive))
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True),
                encoded.splitlines(keepends=True),
                fromfile=str(args.output),
                tofile="fresh scene-script contract",
            ))
            raise SystemExit(f"UDS scene-script contract drifted:\n{diff}")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
