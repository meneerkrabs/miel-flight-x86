#!/usr/bin/env python3
"""Generate and validate the canonical flight visual-checkpoint inventory.

The inventory is deliberately evidence-neutral: source contracts determine
which visual states must be checked, while only an independent native/web
framebuffer pair and an exact canonical-RGBA8 PASS receipt may promote an
individual checkpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.behavior_evidence import load_json_strict, sha256
    from tools.miel_vliegt.verify_flight_runtime_contract import (
        PIXEL_COMPARATOR,
        PIXEL_COMPARISON_POLICY,
        validate_pixel_proof,
    )
except ModuleNotFoundError:  # Direct script execution.
    from behavior_evidence import load_json_strict, sha256
    from verify_flight_runtime_contract import (
        PIXEL_COMPARATOR,
        PIXEL_COMPARISON_POLICY,
        validate_pixel_proof,
    )


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "content/miel_vliegt/visual_checkpoint_inventory.json"
PROTOCOL = "miel-vliegt-visual-checkpoint-inventory"
UNPROVEN_BLOCKER = (
    "MISSING_INDEPENDENT_NATIVE_AND_WEB_FRAMEBUFFERS_AND_EXACT_RGBA8_PASS_RECEIPT"
)
SOURCE_PATHS = {
    "native_mode_bodies": "content/miel_vliegt/native_mode_bodies.json",
    "native_udsp_scene_commands": "content/miel_vliegt/native_udsp_scene_commands.json",
    "scene_dispatch_contract": "content/miel_vliegt/scene_dispatch_contract.json",
    "executable_udsp_scene_scripts": "content/miel_vliegt/executable_udsp_scene_scripts.json",
}
VISUAL_OUTRO_OPCODES = {
    "POSITION_CHARACTER",
    "PLAY_CHARACTER_SCRIPT",
    "PLAY_CHARACTER_ANIMATION",
    "STOP_CHARACTER_ANIMATION",
}
CHECKPOINT_FIELDS = {
    "id", "kind", "coordinates", "subject_sha256",
    "status", "blocker", "proof",
}
PROOF_FIELDS = {"native_frame", "web_frame", "pixel_receipt"}


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _load_sources(root: Path) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, Any]]]:
    identities: dict[str, dict[str, str]] = {}
    documents: dict[str, dict[str, Any]] = {}
    for key, relative in SOURCE_PATHS.items():
        path = root / relative
        if not path.is_file():
            raise ValueError(f"missing visual inventory source: {relative}")
        identities[key] = {"path": relative, "sha256": sha256(path)}
        documents[key] = load_json_strict(path)
    return identities, documents


def _command(document: dict[str, Any], identifier: int) -> dict[str, Any]:
    rows = [row for row in document.get("commands", []) if row.get("id") == identifier]
    if len(rows) != 1:
        raise ValueError(f"native command {identifier} must have exactly one contract row")
    return rows[0]


def _script(
    document: dict[str, Any], domain_id: str, dispatch_id: str,
) -> dict[str, Any]:
    rows = [
        row for row in document.get("scripts", [])
        if row.get("domainId") == domain_id and row.get("dispatchId") == dispatch_id
    ]
    if len(rows) != 1:
        raise ValueError(f"script {domain_id}/{dispatch_id} must have exactly one executable row")
    return rows[0]


def _dispatch_artifact(document: dict[str, Any], artifact_key: str) -> dict[str, Any]:
    rows = [
        row for row in document.get("artifacts", [])
        if row.get("artifactKey") == artifact_key
    ]
    if len(rows) != 1:
        raise ValueError(f"dispatch artifact {artifact_key} must have exactly one row")
    return rows[0]


def _checkpoint(
    identifier: str,
    kind: str,
    coordinates: dict[str, Any],
    subject: Any,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "kind": kind,
        "coordinates": coordinates,
        "subject_sha256": _canonical_sha256(subject),
        "status": "UNPROVEN",
        "blocker": UNPROVEN_BLOCKER,
        "proof": None,
    }


def build_inventory(root: Path = ROOT) -> dict[str, Any]:
    """Derive every required visual checkpoint from pinned native contracts."""

    sources, documents = _load_sources(root)
    bodies = documents["native_mode_bodies"]
    commands = documents["native_udsp_scene_commands"]
    dispatch = documents["scene_dispatch_contract"]
    scripts = documents["executable_udsp_scene_scripts"]

    modes = bodies.get("modes")
    if not isinstance(modes, list) or len(modes) != 22:
        raise ValueError("native mode inventory must contain exactly 22 modes")
    mode_ids = [row.get("id") for row in modes]
    mode_names = [row.get("mode") for row in modes]
    if any(not isinstance(value, str) or not value for value in mode_ids + mode_names) \
            or len(mode_ids) != len(set(mode_ids)) \
            or len(mode_names) != len(set(mode_names)):
        raise ValueError("native mode inventory contains missing or duplicate identities")
    for row in modes:
        render = row.get("lifecycle", {}).get("render")
        if not isinstance(render, str) or not render.startswith("0x"):
            raise ValueError(f"native mode {row.get('mode')} lacks a render entry")

    animation_command = _command(commands, 3)
    judge_command = _command(commands, 10)
    diploma_command = _command(commands, 11)
    expected_names = {
        3: "PLAY_CHARACTER_ANIMATION",
        10: "JUDGE_AIRPLANE",
        11: "AWARD_DIPLOMA",
    }
    for row in (animation_command, judge_command, diploma_command):
        if row.get("name") != expected_names[row["id"]]:
            raise ValueError(f"native command {row['id']} identity drifted")

    observed = commands.get("observed_runtime_contracts", {})
    judge_contract = observed.get("10")
    diploma_contract = observed.get("11")
    animation_contract = observed.get("3")
    if not all(isinstance(row, dict) for row in (
        judge_contract, diploma_contract, animation_contract,
    )):
        raise ValueError("native visual command observations are incomplete")

    clip_domain = judge_contract.get("media_identity", {}).get("clip_domain")
    if clip_domain != [4, 5, 6, 7, 8]:
        raise ValueError("judge score clip domain drifted")
    judge_axis = [{"score": 0, "phase": "CLEARED", "clip": None}] + [
        {"score": clip - 3, "phase": "VISIBLE", "clip": clip}
        for clip in clip_domain
    ]

    clips = diploma_contract.get("award_clip_table")
    assets = diploma_contract.get("award_asset_table")
    if not isinstance(clips, list) or not isinstance(assets, list) \
            or len(clips) != 6 or len(assets) != 6:
        raise ValueError("diploma award axis must contain exactly six values")
    diploma_axis = [
        {"index": index, "asset": asset, "clip": clip}
        for index, (asset, clip) in enumerate(zip(assets, clips))
    ]
    diploma_phases = ["ACTIVE", "COMPLETED"]

    outro_artifact = _dispatch_artifact(
        dispatch, "LOCATION_SCRIPT:varldsutstallning/outro",
    )
    outro = _script(scripts, "varldsutstallning", "outro")
    if outro.get("sourceSha256") != outro_artifact.get("sha256"):
        raise ValueError("outro executable row differs from dispatch artifact")
    outro_axis = [
        {
            "executable_command_index": row["executableCommandIndex"],
            "source_opcode": row["sourceOpcode"],
            "arguments": row["arguments"],
            "modifier": row.get("modifier"),
        }
        for row in outro.get("commands", [])
        if row.get("sourceOpcode") in VISUAL_OUTRO_OPCODES
    ]
    if not outro_axis:
        raise ValueError("outro contains no visual command checkpoints")
    outro_indices = [row["executable_command_index"] for row in outro_axis]
    if len(outro_indices) != len(set(outro_indices)):
        raise ValueError("outro visual command indices are not unique")

    modifier_execution = commands.get("engine", {}).get("modifier_execution", {})
    animation_modifiers = [
        {
            "modifier": name,
            "animation_def_observations": contract["animation_def_observations"],
        }
        for name, contract in sorted(modifier_execution.items())
        if isinstance(contract, dict)
        and isinstance(contract.get("animation_def_observations"), int)
        and contract["animation_def_observations"] > 0
    ]
    expected_modifiers = ["LOOP", "LOOP_RANDOMTIMES", "LOOP_TIMES", "WAIT"]
    if [row["modifier"] for row in animation_modifiers] != expected_modifiers:
        raise ValueError("native animation modifier axis drifted")
    animation_phases = ["STARTED", "ACTIVE", "COMPLETED"]

    checkpoints: list[dict[str, Any]] = []
    for row in modes:
        checkpoints.append(_checkpoint(
            f"mode:{row['mode']}:render",
            "MODE_RENDER",
            {"mode_id": row["id"], "mode": row["mode"], "phase": "RENDER"},
            row,
        ))
    for coordinate in judge_axis:
        checkpoints.append(_checkpoint(
            f"judge:score:{coordinate['score']}",
            "JUDGE_STATE",
            coordinate,
            {"command": judge_command, "contract": judge_contract, "state": coordinate},
        ))
    for award in diploma_axis:
        for phase in diploma_phases:
            coordinate = {**award, "phase": phase}
            checkpoints.append(_checkpoint(
                f"diploma:award:{award['index']}:{phase.lower()}",
                "DIPLOMA_STATE",
                coordinate,
                {"command": diploma_command, "contract": diploma_contract, "state": coordinate},
            ))
    for coordinate in outro_axis:
        index = coordinate["executable_command_index"]
        checkpoints.append(_checkpoint(
            f"outro:command:{index:03d}",
            "OUTRO_VISUAL_COMMAND",
            coordinate,
            {
                "script_path": outro["path"],
                "script_sha256": outro["sourceSha256"],
                "command": coordinate,
            },
        ))
    for modifier in animation_modifiers:
        phases = animation_phases[:2] if modifier["modifier"] == "LOOP" else animation_phases
        for phase in phases:
            coordinate = {**modifier, "phase": phase}
            checkpoints.append(_checkpoint(
                f"animation:{modifier['modifier'].lower()}:{phase.lower()}",
                "ANIMATION_STATE",
                coordinate,
                {
                    "command": animation_command,
                    "contract": animation_contract,
                    "modifier_execution": modifier_execution[modifier["modifier"]],
                    "state": coordinate,
                },
            ))

    checkpoint_ids = [row["id"] for row in checkpoints]
    if len(checkpoint_ids) != len(set(checkpoint_ids)):
        raise ValueError("source generation produced duplicate visual checkpoint ids")

    axes = {
        "mode.render": mode_names,
        "judge.score": judge_axis,
        "diploma.award": diploma_axis,
        "diploma.phase": diploma_phases,
        "outro.visual_command": outro_axis,
        "animation.modifier": animation_modifiers,
        "animation.phase": animation_phases,
    }
    kind_counts = {
        kind: sum(row["kind"] == kind for row in checkpoints)
        for kind in sorted({row["kind"] for row in checkpoints})
    }
    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "edition": dispatch.get("edition"),
        "sources": sources,
        "policy": {
            "status_values": ["UNPROVEN", "PIXEL_EQUIVALENT"],
            "canonical_pixel_format": "rgba8",
            "comparison": "EXACT_BYTES",
            "comparator": PIXEL_COMPARATOR,
            "comparison_policy": PIXEL_COMPARISON_POLICY,
            "promotion_requires": [
                "independent native framebuffer manifest",
                "independent web framebuffer manifest",
                "canonical-rgba8-exact-v1 PASS receipt",
            ],
            "unproven_blocker": UNPROVEN_BLOCKER,
            "missing_checkpoint": "ERROR",
        },
        "axes": axes,
        "counts": {
            "checkpoints": len(checkpoints),
            "by_kind": kind_counts,
            "pixel_equivalent": 0,
            "unproven": len(checkpoints),
        },
        "checkpoints": checkpoints,
    }


def validate_inventory(document: dict[str, Any], *, root: Path = ROOT) -> None:
    """Fail closed on source drift, coverage shrinkage, or false promotion."""

    if not isinstance(document, dict) or set(document) != {
        "schema", "protocol", "edition", "sources", "policy", "axes", "counts", "checkpoints",
    }:
        raise ValueError("visual inventory has an invalid top-level schema")
    expected = build_inventory(root)
    for field in ("schema", "protocol", "edition", "sources", "policy", "axes"):
        if document.get(field) != expected[field]:
            raise ValueError(f"visual inventory source-generated header differs at {field}")

    checkpoints = document.get("checkpoints")
    if not isinstance(checkpoints, list):
        raise ValueError("visual inventory checkpoints must be a list")
    identifiers = [
        row.get("id") if isinstance(row, dict) else None
        for row in checkpoints
    ]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("visual inventory contains a duplicate checkpoint")
    expected_by_id = {row["id"]: row for row in expected["checkpoints"]}
    if set(identifiers) != set(expected_by_id):
        raise ValueError("visual inventory is not the exact checkpoint inventory")

    promoted = 0
    for row in checkpoints:
        if set(row) != CHECKPOINT_FIELDS:
            raise ValueError(f"{row.get('id')}: invalid checkpoint schema")
        expected_row = expected_by_id[row["id"]]
        for field in ("id", "kind", "coordinates", "subject_sha256"):
            if row.get(field) != expected_row[field]:
                raise ValueError(f"{row['id']}: checkpoint structural identity drifted")
        if row.get("status") == "UNPROVEN":
            if row.get("blocker") != UNPROVEN_BLOCKER or row.get("proof") is not None:
                raise ValueError(f"{row['id']}: invalid UNPROVEN checkpoint evidence state")
            continue
        if row.get("status") != "PIXEL_EQUIVALENT":
            raise ValueError(f"{row['id']}: unsupported checkpoint status")
        proof = row.get("proof")
        if not isinstance(proof, dict) or set(proof) != PROOF_FIELDS:
            raise ValueError(f"{row['id']}: proof must contain exactly {sorted(PROOF_FIELDS)}")
        if row.get("blocker") is not None:
            raise ValueError(f"{row['id']}: promoted checkpoint retains a blocker")
        validate_pixel_proof(root, proof, row["id"])
        promoted += 1

    counts = document.get("counts")
    expected_counts = {
        "checkpoints": len(checkpoints),
        "by_kind": {
            kind: sum(row["kind"] == kind for row in checkpoints)
            for kind in sorted({row["kind"] for row in checkpoints})
        },
        "pixel_equivalent": promoted,
        "unproven": len(checkpoints) - promoted,
    }
    if counts != expected_counts:
        raise ValueError("visual inventory counts differ from validated checkpoint states")


def _write(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate the checked-in inventory")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if args.write:
        document = build_inventory(ROOT)
        _write(args.output, document)
    else:
        document = load_json_strict(args.output)
    validate_inventory(document, root=ROOT)
    print(json.dumps(document["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
