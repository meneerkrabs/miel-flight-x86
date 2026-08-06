#!/usr/bin/env python3
"""Lower edition assets and schema-2 UDSP source into an executable scene IR.

The raw DEF contract preserves source syntax. This contract records the
native parser's media-dependent lowering steps: absent character voice takes
produce no command node, one take produces opcode 5, multiple takes produce
opcode 6 with an ordered take array, and PLAY_SOUND/PLAY_RADIO bind the exact
edition asset for requested take 1. It remains a static construction contract,
not evidence of native/web runtime equivalence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import native_udsp_scene_commands
except ModuleNotFoundError:  # Direct script execution.
    import native_udsp_scene_commands


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCRIPTS = ROOT / "content/miel_vliegt/uds_scene_scripts.json"
DEFAULT_ASSETS = ROOT / "content/miel_vliegt/flight_scene_asset_contract.json"
DEFAULT_NATIVE = ROOT / "content/miel_vliegt/native_udsp_scene_commands.json"
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/executable_udsp_scene_scripts.json"
MODIFIERS = {"NONE", "LOOP", "LOOP_TIMES", "LOOP_RANDOMTIMES", "WAIT_RANDOM", "WAIT", "FINISHDIRECT"}
FIXED_TAKE_OPCODES = {"PLAY_SOUND", "PLAY_RADIO"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pin(path: Path) -> dict[str, str]:
    return {"path": path.resolve().relative_to(ROOT).as_posix(), "sha256": _sha256(path)}


def _sound_key(owner: object, number: object, bank: object) -> tuple[str, int, str]:
    if not isinstance(owner, str) or not isinstance(number, int) or not isinstance(bank, str):
        raise ValueError("invalid PLAY_CHARACTER_SOUND media key")
    return owner.lower(), number, bank.lower()


def _modifier(arguments: list[object]) -> str | None:
    found = [value for value in arguments if isinstance(value, str) and value in MODIFIERS]
    if len(found) > 1:
        raise ValueError(f"ambiguous command modifier: {arguments!r}")
    return found[0] if found else None


def lower_structure(
    structure: dict[str, Any], source_to_executable: dict[int, int | None]
) -> dict[str, Any]:
    """Remap command references while retaining every composite, even empty."""
    if set(structure) != {"node", "repeat", "children"}:
        raise ValueError("UDSP structure shape drifted")
    children = []
    for child in structure["children"]:
        if set(child) == {"command"}:
            source_index = child["command"]
            if source_index not in source_to_executable:
                raise ValueError(f"structure references unknown source command {source_index}")
            executable_index = source_to_executable[source_index]
            if executable_index is not None:
                children.append({
                    "command": executable_index,
                    "sourceCommand": source_index,
                })
        elif set(child) == {"node", "repeat", "children"}:
            children.append(lower_structure(child, source_to_executable))
        else:
            raise ValueError("UDSP structure child shape drifted")
    return {
        "node": structure["node"],
        "repeat": structure["repeat"],
        "children": children,
    }


def _asset_media_index(assets: dict[str, Any]) -> dict[tuple[str, int, str], dict[str, Any]]:
    if assets.get("schema") != 1 or assets.get("contract") != "miel-vliegt-flight-scene-assets":
        raise ValueError("unsupported flight scene asset contract")
    result: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in assets.get("media", []):
        if row.get("opcode") != "PLAY_CHARACTER_SOUND":
            continue
        key = _sound_key(row.get("owner"), row.get("scriptNumber"), row.get("bank"))
        if key in result:
            raise ValueError(f"ambiguous asset media key: {key!r}")
        variants = row.get("variants")
        if not isinstance(variants, list):
            raise ValueError(f"invalid asset variants: {key!r}")
        takes = [variant.get("take") for variant in variants]
        keys = [variant.get("key") for variant in variants]
        if (
            any(not isinstance(take, int) or not 1 <= take < 100 for take in takes)
            or takes != sorted(takes)
            or len(takes) != len(set(takes))
            or any(not isinstance(value, str) or not value for value in keys)
            or len(keys) != len(set(keys))
        ):
            raise ValueError(f"ambiguous or unordered asset takes: {key!r}")
        expected_status = "ABSENT_NO_COMMAND_NODE" if not variants else "RESOLVED"
        if row.get("status") != expected_status:
            raise ValueError(f"asset media status/take mismatch: {key!r}")
        result[key] = row
    return result


def _barn_media_index(assets: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Index the native barn sound table by its source clip number.

    PLAY_MULLEBARNSOUND's first argument is a clip number. The native parser
    resolves the existing 1..99 takes before constructing opcode 14, so the
    executable contract must bind those takes instead of treating the source
    argument as a random-selection count.
    """
    if assets.get("schema") != 1 or assets.get("contract") != "miel-vliegt-flight-scene-assets":
        raise ValueError("unsupported flight scene asset contract")
    expected_bank = assets.get("resolution", {}).get("barnBank")
    if not isinstance(expected_bank, str) or not expected_bank:
        raise ValueError("flight scene asset contract has no barn bank")
    result: dict[int, dict[str, Any]] = {}
    for row in assets.get("media", []):
        if row.get("opcode") != "PLAY_MULLEBARNSOUND":
            continue
        number = row.get("scriptNumber")
        if (
            row.get("owner") != "barn"
            or not isinstance(number, int)
            or row.get("bank") != expected_bank
            or row.get("status") != "RESOLVED"
            or number in result
        ):
            raise ValueError(f"invalid or ambiguous barn media row: {number!r}")
        variants = row.get("variants")
        if not isinstance(variants, list) or not variants:
            raise ValueError(f"barn media has no native takes: {number!r}")
        takes = [variant.get("take") for variant in variants]
        keys = [variant.get("key") for variant in variants]
        if (
            any(not isinstance(take, int) or not 1 <= take < 100 for take in takes)
            or takes != sorted(takes)
            or len(takes) != len(set(takes))
            or any(not isinstance(value, str) or not value for value in keys)
            or len(keys) != len(set(keys))
        ):
            raise ValueError(f"ambiguous or unordered barn takes: {number!r}")
        result[number] = row
    return result


def _fixed_take_media_index(
    assets: dict[str, Any],
) -> dict[tuple[str, str, int, str], dict[str, Any]]:
    """Bind native take-1 requests to one edition-owned audio asset.

    The native filename builder receives take zero for PLAY_SOUND and
    PLAY_RADIO and clamps that request to take 1 without consuming request RNG.
    The executable artifact therefore carries one concrete asset key, not a
    selectable take array.
    """
    if assets.get("schema") != 1 or assets.get("contract") != "miel-vliegt-flight-scene-assets":
        raise ValueError("unsupported flight scene asset contract")
    prefixes = assets.get("resolution", {}).get("ownerPrefixes")
    if not isinstance(prefixes, dict):
        raise ValueError("flight scene asset contract has no owner-prefix map")

    audio_by_key: dict[str, list[dict[str, Any]]] = {}
    for audio in assets.get("audio", []):
        if not isinstance(audio, dict):
            raise ValueError("invalid audio asset row")
        asset_key = audio.get("key")
        if isinstance(asset_key, str):
            audio_by_key.setdefault(asset_key, []).append(audio)

    result: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for row in assets.get("media", []):
        opcode = row.get("opcode")
        if opcode not in FIXED_TAKE_OPCODES:
            continue
        owner, number, bank = _sound_key(
            row.get("owner"), row.get("scriptNumber"), row.get("bank")
        )
        key = (opcode, owner, number, bank)
        if key in result:
            raise ValueError(f"ambiguous fixed-take asset media key: {key!r}")
        prefix = prefixes.get(owner)
        if (
            not isinstance(prefix, str)
            or not prefix
            or row.get("owner") != owner
            or row.get("resolvedPrefix") != prefix
            or row.get("resolvedClip") != number
            or row.get("bank") != bank
            or row.get("status") != "RESOLVED"
        ):
            raise ValueError(f"fixed-take media identity drifted: {key!r}")
        variants = row.get("variants")
        if not isinstance(variants, list):
            raise ValueError(f"fixed-take media has invalid variants: {key!r}")
        take_one = [
            variant for variant in variants
            if isinstance(variant, dict) and variant.get("take") == 1
        ]
        if len(take_one) != 1:
            raise ValueError(f"fixed-take media must expose exactly one take 1: {key!r}")
        asset_key = take_one[0].get("key")
        if not isinstance(asset_key, str) or not asset_key:
            raise ValueError(f"fixed-take media has invalid take-1 asset key: {key!r}")
        audio_rows = audio_by_key.get(asset_key, [])
        if len(audio_rows) != 1:
            raise ValueError(
                f"fixed-take media must resolve exactly one audio row: {key!r}"
            )
        audio = audio_rows[0]
        if (
            audio.get("type") != "audio"
            or audio.get("prefix") != prefix
            or audio.get("take") != 1
            or audio.get("clip") != number
            or audio.get("bank") != bank
        ):
            raise ValueError(f"fixed-take audio identity drifted: {key!r}")
        result[key] = {"assetKey": asset_key, "media": row}
    return result


def _source_opcode_index(native: dict[str, Any]) -> dict[str, int]:
    native_udsp_scene_commands.validate_contract(native, verify_artifacts=False)
    result = {row["name"]: row["id"] for row in native["commands"]}
    if len(result) != 15:
        raise ValueError("native command-name map is ambiguous")
    return result


def _lower_command(
    command: dict[str, Any],
    source_index: int,
    executable_index: int,
    opcode_index: dict[str, int],
    discarded_source_opcodes: set[str],
    asset_index: dict[tuple[str, int, str], dict[str, Any]],
    barn_index: dict[int, dict[str, Any]],
    fixed_take_index: dict[tuple[str, str, int, str], dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    opcode = command.get("opcode")
    arguments = command.get("arguments")
    if opcode not in opcode_index or not isinstance(arguments, list):
        raise ValueError(f"unsupported source command at index {source_index}: {opcode!r}")
    base = {
        "executableCommandIndex": executable_index,
        "sourceCommandIndex": source_index,
        "sourceNode": command.get("node"),
        "loop": command.get("loop"),
        "sourceOpcode": opcode,
        "arguments": arguments,
        "modifier": _modifier(arguments),
    }
    if opcode in discarded_source_opcodes:
        return None, {
            "sourceCommandIndex": source_index,
            "sourceNode": command.get("node"),
            "loop": command.get("loop"),
            "sourceOpcode": opcode,
            "arguments": arguments,
            "reason": "DISCARD_DIRECT_OPCODE_NATIVE_PARSER",
        }
    if opcode == "PLAY_MULLEBARNSOUND":
        if len(arguments) != 2 or not isinstance(arguments[0], int):
            raise ValueError(f"PLAY_MULLEBARNSOUND arity drifted at index {source_index}")
        media = barn_index.get(arguments[0])
        if media is None:
            raise ValueError(f"missing barn asset media key: {arguments[0]!r}")
        return {
            **base,
            "nativeOpcode": opcode_index[opcode],
            "takes": [
                {"take": variant["take"], "assetKey": variant["key"]}
                for variant in media["variants"]
            ],
        }, None
    if opcode in FIXED_TAKE_OPCODES:
        valid_arity = len(arguments) == 4 if opcode == "PLAY_SOUND" else len(arguments) in {3, 4}
        expected_modifier = "WAIT" if len(arguments) == 4 else None
        if not valid_arity or base["modifier"] != expected_modifier:
            raise ValueError(f"{opcode} arity/modifier drifted at index {source_index}")
        owner, number, bank = _sound_key(arguments[0], arguments[1], arguments[2])
        media = fixed_take_index.get((opcode, owner, number, bank))
        if media is None:
            raise ValueError(
                f"missing fixed-take asset media key: {(opcode, owner, number, bank)!r}"
            )
        return {
            **base,
            "nativeOpcode": opcode_index[opcode],
            "assetKey": media["assetKey"],
        }, None
    if opcode != "PLAY_CHARACTER_SOUND":
        return {**base, "nativeOpcode": opcode_index[opcode]}, None

    if len(arguments) != 4:
        raise ValueError(f"PLAY_CHARACTER_SOUND arity drifted at index {source_index}")
    if base["modifier"] != "WAIT":
        raise ValueError(f"PLAY_CHARACTER_SOUND must use WAIT at index {source_index}")
    key = _sound_key(arguments[0], arguments[1], arguments[2])
    media = asset_index.get(key)
    if media is None:
        raise ValueError(f"missing asset media key: {key!r}")
    variants = media["variants"]
    if not variants:
        removed = {
            "sourceCommandIndex": source_index,
            "sourceNode": command.get("node"),
            "loop": command.get("loop"),
            "sourceOpcode": opcode,
            "arguments": arguments,
            "reason": "ABSENT_NO_COMMAND_NODE",
        }
        return None, removed
    if len(variants) == 1:
        return {
            **base,
            "nativeOpcode": 5,
            "assetKey": variants[0]["key"],
        }, None
    return {
        **base,
        "nativeOpcode": 6,
        "takes": [
            {"take": variant["take"], "assetKey": variant["key"]}
            for variant in variants
        ],
    }, None


def build_contract_data(
    scripts: dict[str, Any],
    assets: dict[str, Any],
    native: dict[str, Any],
    *,
    source_pins: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    if scripts.get("schema") != 2 or scripts.get("claim") != "SOURCE_STRUCTURE_EXACT":
        raise ValueError("unsupported raw UDSP scene-script contract")
    opcode_index = _source_opcode_index(native)
    discarded_source_opcodes = {
        row["name"]
        for row in native["commands"]
        if row["parser_behavior"] in {
            "DISCARD_OPCODE", "DISCARD_DIRECT_TOKEN_SYNTHESIZED_BY_OPCODE_5"
        }
    }
    asset_index = _asset_media_index(assets)
    barn_index = _barn_media_index(assets)
    fixed_take_index = _fixed_take_media_index(assets)
    source_sound_references: Counter[tuple[tuple[str, int, str], str, object, object]] = Counter()
    for script in scripts.get("scripts", []):
        for command in script.get("commands", []):
            if command.get("opcode") == "PLAY_CHARACTER_SOUND":
                arguments = command.get("arguments", [])
                if len(arguments) != 4:
                    raise ValueError(f"PLAY_CHARACTER_SOUND arity drifted: {script.get('path')}")
                source_sound_references[(
                    _sound_key(arguments[0], arguments[1], arguments[2]),
                    script["path"],
                    command.get("node"),
                    command.get("loop"),
                )] += 1
    asset_sound_references: Counter[tuple[tuple[str, int, str], str, object, object]] = Counter()
    for key, media in asset_index.items():
        for reference in media.get("references", []):
            asset_sound_references[(
                key,
                reference.get("path"),
                reference.get("node"),
                reference.get("loop"),
            )] += 1
    if asset_sound_references != source_sound_references:
        raise ValueError("asset/source PLAY_CHARACTER_SOUND references drifted")

    source_barn_references: Counter[tuple[int, str, object, object]] = Counter()
    for script in scripts.get("scripts", []):
        for command in script.get("commands", []):
            if command.get("opcode") != "PLAY_MULLEBARNSOUND":
                continue
            arguments = command.get("arguments", [])
            if len(arguments) != 2 or not isinstance(arguments[0], int):
                raise ValueError(f"PLAY_MULLEBARNSOUND arity drifted: {script.get('path')}")
            source_barn_references[(
                arguments[0], script["path"], command.get("node"), command.get("loop")
            )] += 1
    asset_barn_references: Counter[tuple[int, str, object, object]] = Counter()
    for number, media in barn_index.items():
        for reference in media.get("references", []):
            asset_barn_references[(
                number,
                reference.get("path"),
                reference.get("node"),
                reference.get("loop"),
            )] += 1
    if asset_barn_references != source_barn_references:
        raise ValueError("asset/source PLAY_MULLEBARNSOUND references drifted")

    source_fixed_take_references: Counter[
        tuple[tuple[str, str, int, str], str, object, object]
    ] = Counter()
    for script in scripts.get("scripts", []):
        for command in script.get("commands", []):
            opcode = command.get("opcode")
            if opcode not in FIXED_TAKE_OPCODES:
                continue
            arguments = command.get("arguments", [])
            if len(arguments) not in ({4} if opcode == "PLAY_SOUND" else {3, 4}):
                raise ValueError(f"{opcode} arity drifted: {script.get('path')}")
            owner, number, bank = _sound_key(arguments[0], arguments[1], arguments[2])
            source_fixed_take_references[(
                (opcode, owner, number, bank),
                script["path"], command.get("node"), command.get("loop"),
            )] += 1
    asset_fixed_take_references: Counter[
        tuple[tuple[str, str, int, str], str, object, object]
    ] = Counter()
    for key, binding in fixed_take_index.items():
        for reference in binding["media"].get("references", []):
            asset_fixed_take_references[(
                key,
                reference.get("path"), reference.get("node"), reference.get("loop"),
            )] += 1
    if asset_fixed_take_references != source_fixed_take_references:
        raise ValueError("asset/source fixed-take media references drifted")

    zero_take_references = Counter(
        (key, reference.get("path"), reference.get("node"), reference.get("loop"))
        for key, media in asset_index.items()
        if not media["variants"]
        for reference in media.get("references", [])
    )
    unresolved_references = Counter(
        (
            _sound_key(row.get("owner"), row.get("scriptNumber"), row.get("bank")),
            row.get("reference", {}).get("path"),
            row.get("reference", {}).get("node"),
            row.get("reference", {}).get("loop"),
        )
        for row in assets.get("unresolvedReferencedMedia", [])
        if row.get("opcode") == "PLAY_CHARACTER_SOUND"
    )
    if unresolved_references != zero_take_references:
        raise ValueError("zero-take unresolved-media evidence drifted")
    lowered_scripts = []
    removed_commands = []
    native_counts: Counter[int] = Counter()
    sound_take_counts: Counter[int] = Counter()
    direct_discard_count = 0
    raw_count = 0

    for script in scripts.get("scripts", []):
        commands = script.get("commands")
        if not isinstance(commands, list):
            raise ValueError(f"script commands missing: {script.get('path')!r}")
        source_to_executable: dict[int, int | None] = {}
        lowered_commands = []
        for source_index, command in enumerate(commands):
            raw_count += 1
            executable_index = len(lowered_commands)
            lowered, removed = _lower_command(
                command,
                source_index,
                executable_index,
                opcode_index,
                discarded_source_opcodes,
                asset_index,
                barn_index,
                fixed_take_index,
            )
            if lowered is None:
                source_to_executable[source_index] = None
                removed_commands.append({"path": script["path"], **removed})
                if removed["reason"] == "ABSENT_NO_COMMAND_NODE":
                    sound_take_counts[0] += 1
                else:
                    direct_discard_count += 1
            else:
                source_to_executable[source_index] = executable_index
                lowered_commands.append(lowered)
                native_counts[lowered["nativeOpcode"]] += 1
                if command["opcode"] == "PLAY_CHARACTER_SOUND":
                    sound_take_counts[1 if lowered["nativeOpcode"] == 5 else len(lowered["takes"])] += 1
        lowered_scripts.append({
            "path": script["path"],
            "sourceSha256": script["sha256"],
            "type": script["type"],
            "name": script["name"],
            "dispatchId": script["dispatch_id"],
            "domainId": script["domain_id"],
            "counts": {
                "rawCommandNodes": len(commands),
                "executableCommandNodes": len(lowered_commands),
                "removedCommandNodes": len(commands) - len(lowered_commands),
            },
            "commands": lowered_commands,
            "structure": lower_structure(script["structure"], source_to_executable),
        })

    if any(
        command["modifier"] != "WAIT"
        for script in lowered_scripts
        for command in script["commands"]
        if command["nativeOpcode"] == 6
    ):
        raise ValueError("all synthesized opcode-6 nodes must retain WAIT")
    executable_count = sum(len(script["commands"]) for script in lowered_scripts)
    if raw_count != executable_count + len(removed_commands):
        raise ValueError("raw/executable/removed command algebra drifted")

    pins = source_pins or {
        "scripts": {"path": "<memory>", "sha256": "UNPINNED"},
        "assets": {"path": "<memory>", "sha256": "UNPINNED"},
        "nativeCommands": {"path": "<memory>", "sha256": "UNPINNED"},
        "generator": {"path": "<memory>", "sha256": "UNPINNED"},
    }
    return {
        "schema": 1,
        "contract": "miel-vliegt-executable-udsp-scene-scripts",
        "edition": assets["edition"],
        "claim": "STATIC_NATIVE_PARSER_LOWERING_EXACT_FOR_PINNED_EDITION_ASSETS",
        "claimLimit": (
            "Preserves schema-2 source structure and the native media-count/fixed-take "
            "lowering decisions. "
            "It does not establish scheduler, RNG, audio-service, rendering, or native/web runtime parity."
        ),
        "sources": pins,
        "sourceIdentities": {
            "rawUdspArchiveSha256": scripts["source"]["sha256"],
            "nativeExecutableSha256": native["source"]["executable_sha256"],
            "editionDataArchiveSha256": assets["sources"]["data"]["sha256"],
            "editionSoundsArchiveSha256": assets["sources"]["sounds"]["sha256"],
            "nativeVoiceExecutableSha256": assets["sources"]["nativeVoice"]["source"]["sha256"],
        },
        "lowering": native["engine"]["sound_lowering"],
        "counts": {
            "scripts": len(lowered_scripts),
            "rawCommandNodes": raw_count,
            "executableCommandNodes": executable_count,
            "removedCommandNodes": len(removed_commands),
            "sourceCharacterSounds": sum(sound_take_counts.values()),
            "removedZeroTakeCharacterSounds": sound_take_counts[0],
            "removedDirectParserDiscards": direct_discard_count,
            "oneTakeCharacterSounds": native_counts[5],
            "multipleTakeCharacterSounds": native_counts[6],
            "nativeOpcode5Nodes": native_counts[5],
            "nativeOpcode6Nodes": native_counts[6],
        },
        "removedCommands": removed_commands,
        "scripts": lowered_scripts,
    }


def build_contract(
    scripts_path: Path = DEFAULT_SCRIPTS,
    assets_path: Path = DEFAULT_ASSETS,
    native_path: Path = DEFAULT_NATIVE,
) -> dict[str, Any]:
    paths = {
        "scripts": scripts_path,
        "assets": assets_path,
        "nativeCommands": native_path,
        "generator": Path(__file__),
    }
    data = {
        name: json.loads(path.read_text(encoding="utf-8"))
        for name, path in paths.items()
        if name != "generator"
    }
    return build_contract_data(
        data["scripts"],
        data["assets"],
        data["nativeCommands"],
        source_pins={name: _pin(path) for name, path in paths.items()},
    )


def validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    expected = build_contract()
    if contract != expected:
        raise ValueError("generated executable UDSP contract drifted")
    return contract


def check_output(output: Path = DEFAULT_OUTPUT) -> None:
    expected = build_contract()
    if not output.is_file() or json.loads(output.read_text(encoding="utf-8")) != expected:
        raise ValueError(f"generated artifact drifted: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts", type=Path, default=DEFAULT_SCRIPTS)
    parser.add_argument("--assets", type=Path, default=DEFAULT_ASSETS)
    parser.add_argument("--native", type=Path, default=DEFAULT_NATIVE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    contract = build_contract(args.scripts, args.assets, args.native)
    if args.check:
        if not args.output.is_file() or json.loads(args.output.read_text(encoding="utf-8")) != contract:
            raise SystemExit(f"generated artifact drifted: {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
