#!/usr/bin/env python3
"""Build the honest action-boundary inventory from harvested Dutch UDS missions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


RUNTIME = {"GET_AIRPLANEPART", "GET_ITEM", "LOSE_ITEM"}
MEDIA = {"PLAY_OUTRO", "PLAY_RADIO", "PLAY_SOUND"}


def build(source: dict) -> dict:
    counts = source["action_counts"]
    rows = []
    for opcode in sorted(counts):
        if opcode in RUNTIME:
            owner = "mission-state"
            gap = "Native underflow, capacity and collection-side effects still require traces."
        elif opcode in MEDIA:
            owner = "media-event-protocol"
            gap = "Ordering and typed UDS arguments are preserved; channel, interruption, duration and completion require native traces."
        else:
            owner = "explicit-boundary"
            gap = "Typed UDS intent only; no world, package/RNG, photo, crop or script effect is inferred."
        evidence = ["content/miel_vliegt/uds_flight_contracts.json"]
        if opcode == "PLAY_RADIO":
            evidence.append("content/miel_vliegt/dutch_help_contract.json#navigation.radio")
        rows.append({
            "opcode": opcode,
            "occurrences": counts[opcode],
            "owner": owner,
            "disposition": "PARTIAL",
            "evidence": evidence,
            "gap": gap,
        })
    return {
        "schema": 1,
        "policy": {
            "unit": "typed UDS action opcode",
            "equivalent_requires": "native effect trace and deterministic web replay receipt",
            "unknown_semantics": "remain explicit injected boundaries",
        },
        "actions": rows,
    }


def validate(source: dict, artifact: dict) -> None:
    if artifact.get("schema") != 1:
        raise ValueError("unsupported mission action contract schema")
    rows = artifact.get("actions")
    if not isinstance(rows, list):
        raise ValueError("mission action contracts must be an array")
    opcodes = [row.get("opcode") for row in rows]
    expected = sorted(source["action_counts"])
    if opcodes != expected or len(opcodes) != len(set(opcodes)):
        raise ValueError("mission action contracts must cover source opcodes exactly once in sorted order")
    valid_owners = {"mission-state", "media-event-protocol", "explicit-boundary"}
    for row in rows:
        opcode = row["opcode"]
        if row.get("occurrences") != source["action_counts"][opcode]:
            raise ValueError(f"{opcode}: occurrence count drifted from UDS source")
        expected_owner = "mission-state" if opcode in RUNTIME else "media-event-protocol" if opcode in MEDIA else "explicit-boundary"
        if row.get("owner") != expected_owner or row.get("owner") not in valid_owners:
            raise ValueError(f"{opcode}: invalid action boundary owner")
        if row.get("disposition") != "PARTIAL" or not row.get("gap") or not row.get("evidence"):
            raise ValueError(f"{opcode}: incomplete actions require evidence and an explicit gap")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    source_path = root / "content/miel_vliegt/uds_flight_contracts.json"
    artifact_path = root / "content/miel_vliegt/mission_action_contracts.json"
    source = json.loads(source_path.read_text())
    generated = build(source)
    if args.write:
        artifact_path.write_text(json.dumps(generated, indent=2) + "\n")
    if not artifact_path.is_file():
        raise ValueError("mission action contract artifact is missing; run with --write")
    stored = json.loads(artifact_path.read_text())
    validate(source, stored)
    if stored != generated:
        raise ValueError("mission action contract artifact is stale; run with --write")
    print(f"mission action contracts OK: opcodes={len(stored['actions'])}, occurrences={sum(row['occurrences'] for row in stored['actions'])}")


if __name__ == "__main__":
    main()
