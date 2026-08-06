#!/usr/bin/env python3
"""Generate the fail-closed clean-room completion matrix for Miel Vliegt.

The matrix is intentionally a release *ledger*, not a progress estimate.  It
joins every existing evidence surface while preserving the distinction between
static inventory and observed semantic parity.  A dimension is complete only
when every item in that dimension carries the evidence class named below.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.engine_runtime_contract import CANONICAL_GAMEPLAY_RUNTIMES
    from tools.miel_vliegt import production_consumer_registry
except ModuleNotFoundError:
    from engine_runtime_contract import CANONICAL_GAMEPLAY_RUNTIMES
    import production_consumer_registry


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = "content/miel_vliegt/flight_cleanroom_completion.json"
DOCUMENTATION = "docs/flight-cleanroom-completion.md"
PROTOCOL = "miel-vliegt-cleanroom-completion"
ENGINE_OWNED_UDSP_OPCODES = frozenset({"WAIT", "PLAY_CHARACTER_SCRIPT"})
NATIVE_FUNCTION_DISPOSITIONS = frozenset({
    "GAME_BEHAVIOR", "PLATFORM_SUBSTITUTION", "COMPILER_SUBSTITUTION",
    "IMPORT_BOUNDARY", "PROVEN_UNREACHABLE", "UNKNOWN",
})
NATIVE_SUBSTITUTION_DISPOSITIONS = frozenset({
    "PLATFORM_SUBSTITUTION", "COMPILER_SUBSTITUTION", "IMPORT_BOUNDARY",
})
NATIVE_BOUNDARY_RECEIPT_PROTOCOL = "miel-vliegt-native-function-boundary-evidence"
NATIVE_REACHABILITY_CLOSURES = frozenset({
    "roots", "callbacks", "vtables", "indirectTargets",
})
SHA256 = re.compile(r"^[0-9a-f]{64}$")

INPUTS = {
    "assets": "content/miel_vliegt/flight_scene_asset_contract.json",
    "asset_payload_differential":
        "content/miel_vliegt/flight_scene_payload_differential.json",
    "engine": "content/miel_vliegt/engine_implementation.json",
    "executable_scene_scripts": "content/miel_vliegt/executable_udsp_scene_scripts.json",
    "mode_bodies": "content/miel_vliegt/native_mode_bodies.json",
    "native_code_map": "content/miel_vliegt/native_code_map.json",
    "native_dispatch_hooks": "content/miel_vliegt/native_dispatch_hook_contract.json",
    "native_udsp_commands": "content/miel_vliegt/native_udsp_scene_commands.json",
    "native_pipeline": "content/miel_vliegt/native_engine_pipeline_contract.json",
    "runtime": "content/miel_vliegt/flight_runtime_parity_contract.json",
    "runtime_trace": "content/miel_vliegt/flight_runtime_trace_contract.json",
    "scene_coverage": "tools/miel_vliegt/scene_coverage_ledger.json",
    "scene_probe": "content/miel_vliegt/native_scene_probe.json",
    "semantic": "content/miel_vliegt/scene_semantic_coverage.json",
    "semantic_batches": "content/miel_vliegt/scene_semantic_evidence_batches.json",
    "transitions": "content/miel_vliegt/native_scene_transitions.json",
    "visual_checkpoints": "content/miel_vliegt/visual_checkpoint_inventory.json",
    "web_semantic_evidence":
        "content/miel_vliegt/web_scene_semantic_evidence_manifest.json",
    "web_transition_build": "content/miel_vliegt/web_transition_build.json",
    "flight_checkpoints": "content/miel_vliegt/flight_parity_checkpoints.json",
}

WIRING_SOURCES = {
    "production_consumer_test_receipt":
        "content/miel_vliegt/flight_production_consumer_test_receipt.json",
    "production_consumer_test_runner":
        "tools/miel_vliegt/run_production_consumer_receipt.py",
    "phaser_session": "src/flight/browser/FlightPhaserSession.js",
    "scene_pack_preloader": "src/flight/browser/FlightScenePackPreloader.js",
    "udsp_runtime": "src/flight/engine/scene/UdspSceneRuntime.js",
    "mygghanget_state": "src/scenes/flight_mygghanget.js",
    "flight_hangar_state": "src/scenes/flight_hangar.js",
    "flight_location_state": "src/scenes/flight_location.js",
    "flight_world_state": "src/scenes/flight_world.js",
    "game_registry": "src/game.js",
    "scene_pack_preloader_test":
        "src/flight/browser/__tests__/FlightScenePackPreloader.test.js",
    "flight_location_integration_test":
        "src/scenes/__tests__/flight-location-integration.test.js",
    "mygghanget_integration_test": "src/scenes/__tests__/flight-mygghanget-integration.test.js",
}

DIMENSION_IDS = (
    "modes",
    "locations",
    "gameplay_runtimes",
    "semantic_claims",
    "natural_edges",
    "subsystems",
    "assets",
    "production_wiring",
    "native_functions",
)


class CompletionError(ValueError):
    """Raised when inputs cannot form an unambiguous completion matrix."""


WEB_SEMANTIC_MIN_CAPTURED = 261


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CompletionError(f"cannot load completion input: {path}") from error
    if not isinstance(value, dict):
        raise CompletionError(f"completion input is not an object: {path}")
    return value


def load_documents(root: Path = ROOT) -> dict[str, dict[str, Any]]:
    return {name: _load(root / relative) for name, relative in INPUTS.items()}


def _unique(rows: list[dict[str, Any]], field: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        identifier = row.get(field) if isinstance(row, dict) else None
        if not isinstance(identifier, str) or not identifier or identifier in result:
            raise CompletionError(f"{label} contains a missing or duplicate {field}")
        result[identifier] = row
    return result


def _item(identifier: str, complete: bool, reason: str, **fields: Any) -> dict[str, Any]:
    subject = fields.pop("_subject", {"id": identifier})
    proof = fields.pop("_proof", None)
    if not isinstance(subject, dict) or not subject:
        raise CompletionError(f"completion item has no canonical subject: {identifier}")
    row = {
        "id": identifier,
        "status": "COMPLETE" if complete else "BLOCKED",
        "blocker": None if complete else reason,
        "subject_sha256": hashlib.sha256(_canonical(subject)).hexdigest(),
        "proof_sha256": None,
        **fields,
    }
    if complete:
        proof_identity = proof if proof is not None else {
            "subject_sha256": row["subject_sha256"], "fields": fields,
        }
        row["proof_sha256"] = hashlib.sha256(_canonical(proof_identity)).hexdigest()
    return row


def _dimension(
    identifier: str,
    requirement: str,
    items: list[dict[str, Any]],
    **metadata: Any,
) -> dict[str, Any]:
    if not items:
        raise CompletionError(f"completion dimension is empty: {identifier}")
    complete = sum(row.get("status") == "COMPLETE" for row in items)
    return {
        "id": identifier,
        "evidence_requirement": requirement,
        "status": "COMPLETE" if complete == len(items) else "BLOCKED",
        "required": len(items),
        "complete": complete,
        "blocked": len(items) - complete,
        **metadata,
        "items": items,
    }


def release_decision(dimensions: list[dict[str, Any]]) -> bool:
    """Return true only for an exact, non-empty and wholly complete matrix."""

    by_id = _unique(dimensions, "id", "completion dimensions")
    if set(by_id) != set(DIMENSION_IDS):
        return False
    return all(
        row.get("status") == "COMPLETE"
        and isinstance(row.get("required"), int)
        and row["required"] > 0
        and row.get("complete") == row["required"]
        and row.get("blocked") == 0
        for row in by_id.values()
    )


def _flight_editions(scene_coverage: dict[str, Any]) -> list[str]:
    editions = scene_coverage.get("editions")
    if not isinstance(editions, dict):
        raise CompletionError("scene coverage editions are unavailable")
    result = sorted(
        identifier for identifier, row in editions.items()
        if isinstance(row, dict) and row.get("game") == "flight"
    )
    if not result:
        raise CompletionError("scene coverage contains no flight edition")
    return result


def _body_claims(scene_coverage: dict[str, Any], edition: str) -> dict[str, dict[str, Any]]:
    rows = scene_coverage["editions"][edition].get("claims")
    if not isinstance(rows, list):
        raise CompletionError(f"flight scene claims are unavailable: {edition}")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        scene = row.get("scene") if isinstance(row, dict) else None
        if not isinstance(scene, str) or not scene or scene in result:
            raise CompletionError(f"flight scene claims have an invalid identity: {edition}")
        gate = row.get("gates", {}).get("BODY_PARITY")
        if not isinstance(gate, dict):
            # A legacy negative claim is still safely unproven.
            gate = {"status": "UNPROVEN", "evidence": []}
        result[scene] = gate
    return result


def _transition_claims(
    scene_coverage: dict[str, Any], edition: str,
) -> dict[str, dict[str, Any]]:
    matrices = scene_coverage.get("flight_transition_claims")
    rows = matrices.get(edition) if isinstance(matrices, dict) else None
    if not isinstance(rows, list):
        raise CompletionError(f"flight transition claims are unavailable: {edition}")
    return _unique(rows, "edge", f"flight transition claims for {edition}")


def _natural_edges(transitions: dict[str, Any]) -> list[dict[str, Any]]:
    direct = transitions.get("edges")
    locations = transitions.get("location_edges")
    if not isinstance(direct, list) or not isinstance(locations, list):
        raise CompletionError("native transition topology is unavailable")
    flattened = list(direct)
    for row in locations:
        if not isinstance(row, dict) or not isinstance(row.get("landing"), dict) \
                or not isinstance(row.get("departure"), dict):
            raise CompletionError("native location transition topology is invalid")
        flattened.extend((row["landing"], row["departure"]))
    natural = [row for row in flattened if row.get("natural") is True]
    _unique(natural, "id", "natural transition topology")
    if not natural:
        raise CompletionError("native transition topology has no natural edges")
    return sorted(natural, key=lambda row: row["id"])


def _runtime_checkpoint(runtime: dict[str, Any], identifier: str) -> dict[str, Any] | None:
    rows = runtime.get("checkpoints")
    if not isinstance(rows, list):
        raise CompletionError("runtime checkpoints are unavailable")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") == identifier]
    if len(matches) != 1:
        return None
    return matches[0]


def _build_modes(documents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    modes = documents["mode_bodies"].get("modes")
    if not isinstance(modes, list):
        raise CompletionError("native mode body inventory is unavailable")
    _unique(modes, "mode", "native mode bodies")
    items = []
    for edition in _flight_editions(documents["scene_coverage"]):
        claims = _body_claims(documents["scene_coverage"], edition)
        for mode in sorted(modes, key=lambda row: row["mode"]):
            claim = claims.get(mode["mode"])
            complete = claim is not None and claim.get("status") == "PARITY_PROVEN" \
                and bool(claim.get("evidence"))
            items.append(_item(
                f"{edition}:{mode['mode']}", complete,
                "paired native/web body traces and PASS differential are missing",
                edition=edition, mode=mode["mode"], mode_type=mode.get("mode_type"),
                static_inventory=mode.get("runtime_body_equivalence"),
                _subject={"edition": edition, "mode": mode["mode"],
                          "mode_type": mode.get("mode_type")},
                _proof=None if claim is None else claim.get("evidence"),
            ))
    return _dimension(
        "modes", "PAIRED_NATIVE_WEB_BODY_TRACE_AND_PASS_DIFFERENTIAL", items,
    )


def _build_semantics(documents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    semantic = documents["semantic"]
    records = semantic.get("records")
    if not isinstance(records, list):
        raise CompletionError("semantic claim inventory is unavailable")
    _unique(records, "id", "semantic claims")
    web_evidence = documents["web_semantic_evidence"]
    web_counts = web_evidence.get("counts")
    web_records = web_evidence.get("records")
    web_captured = sum(
        row.get("status") == "CAPTURED_CANDIDATE"
        for row in web_records if isinstance(row, dict)
    ) if isinstance(web_records, list) else -1
    web_blocked = sum(
        row.get("status") == "BLOCKED"
        for row in web_records if isinstance(row, dict)
    ) if isinstance(web_records, list) else -1
    if not isinstance(web_records, list) \
            or web_evidence.get("semanticStatus") != "UNPROVEN" \
            or web_evidence.get("parityEligible") is not False \
            or web_evidence.get("promotionAllowed") is not False \
            or web_evidence.get("nativeComparison") != "NOT_RUN" \
            or not SHA256.fullmatch(str(web_evidence.get("manifestSha256", ""))) \
            or not isinstance(web_counts, dict) \
            or web_counts.get("jobs") != len(records) \
            or len(web_records) != len(records) \
            or web_counts.get("captured") != web_captured \
            or web_counts.get("blocked") != web_blocked \
            or web_captured < WEB_SEMANTIC_MIN_CAPTURED \
            or web_captured + web_blocked != len(web_records) \
            or len({
                row.get("webSliceId") for row in web_records if isinstance(row, dict)
            }) != len(web_records):
        raise CompletionError("web semantic slot closure is unavailable or drifted")
    items = []
    for row in sorted(records, key=lambda value: value["id"]):
        complete = row.get("status") == "PROVEN" and bool(row.get("evidence"))
        items.append(_item(
            row["id"], complete,
            "claim-bound runtime evidence is missing; structural parse/lowering is not parity",
            evidence_class=row.get("evidenceClass"),
            _subject={"claim": row["id"], "evidence_class": row.get("evidenceClass")},
            _proof=row.get("evidence"),
        ))
    return _dimension(
        "semantic_claims", "CLAIM_BOUND_RUNTIME_SEMANTIC_EVIDENCE", items,
        by_evidence_class=dict(sorted(Counter(
            row.get("evidenceClass") for row in records
        ).items())),
        web_slot_closure={
            "manifest_sha256": web_evidence["manifestSha256"],
            "jobs": web_counts["jobs"],
            "captured_candidate": web_counts["captured"],
            "blocked": web_counts["blocked"],
            "semantic_status": web_evidence["semanticStatus"],
            "parity_eligible": False,
            "promotion_allowed": False,
            "native_comparison": web_evidence["nativeComparison"],
        },
    )


def _build_edges(documents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    edges = _natural_edges(documents["transitions"])
    items = []
    for edition in _flight_editions(documents["scene_coverage"]):
        claims = _transition_claims(documents["scene_coverage"], edition)
        for edge in edges:
            claim = claims.get(edge["id"])
            complete = claim is not None and claim.get("status") == "PARITY_PROVEN" \
                and bool(claim.get("evidence"))
            items.append(_item(
                f"{edition}:{edge['id']}", complete,
                "natural native/web transition traces and PASS differential are missing",
                edition=edition, edge=edge["id"],
                static_evidence=edge.get("evidence_status"),
                statically_parity_eligible=edge.get("parity_eligible"),
                _subject={"edition": edition, "edge": edge["id"]},
                _proof=None if claim is None else claim.get("evidence"),
            ))
    return _dimension(
        "natural_edges", "NATURAL_NATIVE_WEB_TRACE_AND_PASS_DIFFERENTIAL", items,
    )


def _build_locations(
    documents: dict[str, dict[str, Any]],
    mode_dimension: dict[str, Any], semantic_dimension: dict[str, Any],
    edge_dimension: dict[str, Any],
) -> dict[str, Any]:
    scenes = documents["scene_probe"].get("scenes")
    if not isinstance(scenes, list):
        raise CompletionError("native location inventory is unavailable")
    _unique(scenes, "mode", "native locations")
    body = {row["id"]: row for row in mode_dimension["items"]}
    semantic = {row["id"]: row for row in semantic_dimension["items"]}
    edges = {row["id"]: row for row in edge_dimension["items"]}
    items = []
    for edition in _flight_editions(documents["scene_coverage"]):
        for scene in sorted(scenes, key=lambda row: row["mode"]):
            mode = scene["mode"]
            domain = scene["id"]
            dependencies = [body.get(f"{edition}:{mode}")]
            dependencies.extend(
                row for identifier, row in semantic.items()
                if identifier.startswith(f"LOCATION_POLICY:{domain}:")
            )
            dependencies.extend((
                edges.get(f"{edition}:location.landing.{mode}"),
                edges.get(f"{edition}:location.departure.{mode}"),
            ))
            missing_dependency = any(
                row is None or row.get("status") != "COMPLETE" for row in dependencies
            )
            has_policy = any(
                identifier.startswith(f"LOCATION_POLICY:{domain}:")
                for identifier in semantic
            )
            complete = bool(dependencies) and has_policy and not missing_dependency
            items.append(_item(
                f"{edition}:{domain}", complete,
                "location body, policy claims, landing or departure parity remains incomplete",
                edition=edition, domain=domain, mode=mode,
                _subject={"edition": edition, "domain": domain, "mode": mode},
                _proof={"dependencies": [row["proof_sha256"] for row in dependencies
                                          if row is not None]},
            ))
    return _dimension(
        "locations", "BODY_POLICY_AND_BIDIRECTIONAL_TRANSITION_PARITY", items,
    )


def _build_engine_rows(
    documents: dict[str, dict[str, Any]], key: str, identifier: str, root: Path,
) -> dict[str, Any]:
    rows = documents["engine"].get(key)
    if not isinstance(rows, list):
        raise CompletionError(f"engine {key} inventory is unavailable")
    _unique(rows, "id", f"engine {key}")
    items = []
    for row in sorted(rows, key=lambda value: value["id"]):
        disposition = row.get("disposition")
        complete = disposition == "EQUIVALENT" and bool(row.get("native_evidence_receipt"))
        if identifier == "subsystems" and disposition == "PLATFORM_SUBSTITUTION":
            complete = bool(row.get("substitution_receipt"))
        receipt_path = row.get(
            "native_evidence_receipt" if disposition == "EQUIVALENT"
            else "substitution_receipt" if disposition == "PLATFORM_SUBSTITUTION"
            else "",
        )
        receipt_sha256 = _sha256(root / receipt_path) if isinstance(receipt_path, str) else None
        items.append(_item(
            row["id"], complete,
            "runtime is partial/missing or lacks native differential evidence",
            disposition=disposition,
            receipt=receipt_path,
            receipt_sha256=receipt_sha256,
            _subject={"boundary": row["id"], "kind": identifier,
                      "runtime": row.get("runtime")},
            _proof={"receipt": receipt_path, "sha256": receipt_sha256},
        ))
    requirement = "EQUIVALENT_WITH_NATIVE_DIFFERENTIAL"
    if identifier == "subsystems":
        requirement += "_OR_REVIEWED_PLATFORM_SUBSTITUTION"
    return _dimension(identifier, requirement, items)


def _build_gameplay_runtimes(
    documents: dict[str, dict[str, Any]], root: Path,
) -> dict[str, Any]:
    rows = documents["engine"].get("gameplay_runtimes")
    if not isinstance(rows, list):
        rows = []
    actual = _unique(rows, "id", "engine gameplay_runtimes") if rows else {}
    items = []
    for identifier, owner in sorted(CANONICAL_GAMEPLAY_RUNTIMES.items()):
        row = actual.get(identifier)
        disposition = None if row is None else row.get("disposition")
        complete = row is not None and row.get("runtime") == owner \
            and disposition == "EQUIVALENT" and bool(row.get("native_evidence_receipt"))
        receipt_path = None if row is None else row.get("native_evidence_receipt")
        receipt_sha256 = _sha256(root / receipt_path) if isinstance(receipt_path, str) else None
        items.append(_item(
            identifier, complete,
            "canonical runtime is absent, partial, moved or lacks native differential evidence",
            disposition=disposition, runtime_owner=owner,
            receipt=receipt_path, receipt_sha256=receipt_sha256,
            _subject={"runtime_id": identifier, "runtime_owner": owner},
            _proof={"receipt": receipt_path, "sha256": receipt_sha256},
        ))
    for identifier in sorted(set(actual) - set(CANONICAL_GAMEPLAY_RUNTIMES)):
        items.append(_item(
            identifier, False,
            "unknown gameplay runtime cannot extend the canonical inventory implicitly",
            disposition=actual[identifier].get("disposition"),
            runtime_owner=actual[identifier].get("runtime"),
            _subject={"runtime_id": identifier,
                      "runtime_owner": actual[identifier].get("runtime")},
        ))
    return _dimension(
        "gameplay_runtimes", "CANONICAL_RUNTIME_WITH_NATIVE_DIFFERENTIAL", items,
    )


def _absence_key(
    opcode: Any, owner: Any, number: Any, bank: Any, reference: Any,
) -> tuple[Any, ...] | None:
    if not isinstance(reference, dict):
        return None
    path = reference.get("path")
    node = reference.get("node")
    loop = reference.get("loop")
    if not isinstance(opcode, str) or not isinstance(owner, str) \
            or not isinstance(number, int) or not isinstance(bank, str) \
            or not isinstance(path, str) or not isinstance(loop, bool):
        return None
    return opcode, owner.lower(), number, bank.lower(), path, node, loop


def _expected_native_absence_closure(
    assets: dict[str, Any], executable: dict[str, Any],
) -> tuple[bool, dict[str, int]]:
    unresolved = assets.get("unresolvedReferencedMedia")
    media = assets.get("media")
    removed = executable.get("removedCommands")
    counts = executable.get("counts")
    asset_counts = assets.get("counts")
    if not all(isinstance(value, list) for value in (unresolved, media, removed)) \
            or not isinstance(counts, dict) or not isinstance(asset_counts, dict):
        return False, {}

    unresolved_keys = Counter(
        _absence_key(
            row.get("opcode"), row.get("owner"), row.get("scriptNumber"),
            row.get("bank"), row.get("reference"),
        ) if isinstance(row, dict) else None
        for row in unresolved
    )
    absent_media = [
        row for row in media if isinstance(row, dict)
        and row.get("status") == "ABSENT_NO_COMMAND_NODE"
    ]
    media_keys = Counter()
    media_shape_ok = True
    for row in absent_media:
        references = row.get("references")
        if not isinstance(references, list) or len(references) != 1 \
                or row.get("variants") != [] or row.get("resolvedClip") is not None:
            media_shape_ok = False
            continue
        media_keys[_absence_key(
            row.get("opcode"), row.get("owner"), row.get("scriptNumber"),
            row.get("bank"), references[0],
        )] += 1

    removed_absences = [
        row for row in removed if isinstance(row, dict)
        and row.get("reason") == "ABSENT_NO_COMMAND_NODE"
    ]
    removed_keys = Counter()
    removed_shape_ok = True
    for row in removed_absences:
        arguments = row.get("arguments")
        if not isinstance(arguments, list) or len(arguments) < 3:
            removed_shape_ok = False
            continue
        removed_keys[_absence_key(
            row.get("sourceOpcode"), arguments[0], arguments[1], arguments[2],
            {
                "path": row.get("path"), "node": row.get("sourceNode"),
                "loop": row.get("loop"),
            },
        )] += 1

    total = len(unresolved)
    algebra = {
        "source_references": total,
        "absent_media": len(absent_media),
        "lowered_absences": len(removed_absences),
        "removed_commands": len(removed),
    }
    valid = None not in unresolved_keys and None not in media_keys \
        and None not in removed_keys and media_shape_ok and removed_shape_ok \
        and unresolved_keys == media_keys == removed_keys \
        and asset_counts.get("unresolvedMedia") == total \
        and counts.get("removedZeroTakeCharacterSounds") == total \
        and counts.get("removedCommandNodes") == len(removed)
    return valid, algebra


def _build_assets(documents: dict[str, dict[str, Any]]) -> dict[str, Any]:
    assets = documents["assets"]
    payload = documents["asset_payload_differential"]
    counts = assets.get("counts")
    if not isinstance(counts, dict):
        raise CompletionError("asset counts are unavailable")
    collections = {
        "images": assets.get("images"),
        "logicalMedia": assets.get("media"),
        "audioVariants": assets.get("audio"),
    }
    inventory_algebra_ok = all(
        isinstance(rows, list) and counts.get(name) == len(rows)
        for name, rows in collections.items()
    )
    payload_classes = payload.get("classes")
    payload_summary = payload.get("summary")
    payload_contract = payload.get("inputs", {}).get("contract", {})
    payload_ok = payload.get("protocol") \
        == "miel-vliegt-flight-scene-payload-differential" \
        and payload.get("claim") == "EXACT_EXPORTED_SCENE_PAYLOAD" \
        and payload.get("claimLimit") == [
            "SCENE_COMPOSITION_UNPROVEN",
            "NATIVE_FRAMEBUFFER_PARITY_UNPROVEN",
        ] \
        and isinstance(payload_classes, dict) \
        and set(payload_classes) == {"sceneImages", "sceneAudio", "phaserPack"} \
        and all(
            isinstance(row, dict) and row.get("status") == "EXACT"
            for row in payload_classes.values()
        ) \
        and isinstance(payload_summary, dict) \
        and payload_summary.get("status") == "EXACT" \
        and payload_summary.get("files") == counts.get("images", 0) \
            + counts.get("audioVariants", 0) \
        and payload_summary.get("assetClasses") == 3 \
        and payload_summary.get("framebufferParityClaimed") is False \
        and payload_contract.get("canonicalSha256") \
            == hashlib.sha256(_canonical(assets)).hexdigest() \
        and SHA256.fullmatch(str(payload.get("subjectSha256", ""))) is not None
    algebra_ok = inventory_algebra_ok and payload_ok
    expected_absences_ok, absence_algebra = _expected_native_absence_closure(
        assets, documents["executable_scene_scripts"],
    )
    pixels = _runtime_checkpoint(documents["runtime"], "rendering.native_pixels")
    visual = documents["visual_checkpoints"]
    visual_rows = visual.get("checkpoints")
    if not isinstance(visual_rows, list) or not visual_rows:
        raise CompletionError("visual checkpoint inventory is unavailable")
    visual_complete = sum(
        isinstance(row, dict) and row.get("status") == "PIXEL_EQUIVALENT"
        for row in visual_rows
    )
    pixels_ok = pixels is not None and pixels.get("status") == "PIXEL_EQUIVALENT" \
        and bool(pixels.get("proofs")) and visual_complete == len(visual_rows)
    inventory_members: dict[str, str] = {}
    for prefix, rows in (("image", assets.get("images", [])),
                         ("audio", assets.get("audio", []))):
        for row in rows:
            key = row.get("key") if isinstance(row, dict) else None
            if not isinstance(key, str) or not key:
                raise CompletionError(f"asset {prefix} identity is unavailable")
            member = f"{prefix}:{key}"
            if member in inventory_members:
                raise CompletionError(f"duplicate asset member identity: {member}")
            inventory_members[member] = hashlib.sha256(_canonical(row)).hexdigest()
    for row in assets.get("media", []):
        if not isinstance(row, dict):
            raise CompletionError("logical media identity is unavailable")
        identity = (row.get("opcode"), row.get("owner"), row.get("scriptNumber"),
                    row.get("bank"))
        if not isinstance(identity[0], str) or not isinstance(identity[1], str) \
                or not isinstance(identity[2], int) or not isinstance(identity[3], str):
            raise CompletionError("logical media identity is unavailable")
        member = "media:" + ":".join(map(str, identity))
        if member in inventory_members:
            raise CompletionError(f"duplicate asset member identity: {member}")
        inventory_members[member] = hashlib.sha256(_canonical(row)).hexdigest()
    absence_members: dict[str, str] = {}
    for row in assets.get("unresolvedReferencedMedia", []):
        key = _absence_key(
            row.get("opcode"), row.get("owner"), row.get("scriptNumber"),
            row.get("bank"), row.get("reference"),
        ) if isinstance(row, dict) else None
        if key is None:
            raise CompletionError("expected native absence identity is unavailable")
        member = "absence:" + hashlib.sha256(_canonical(key)).hexdigest()
        if member in absence_members:
            raise CompletionError(f"duplicate expected absence identity: {member}")
        absence_members[member] = hashlib.sha256(_canonical(row)).hexdigest()
    items = [
        _item(
            "source_inventory", algebra_ok,
            "asset inventory or reconstructed payload differential drifted",
            evidence_level="STATIC_PAYLOAD_DIFFERENTIAL",
            payload_differential=None if not payload_ok else {
                "subject_sha256": payload["subjectSha256"],
                "classes": payload_classes,
                "summary": payload_summary,
            },
            members=dict(sorted(inventory_members.items())),
            _proof=None if not payload_ok else {
                "members": dict(sorted(inventory_members.items())),
                "payload_subject_sha256": payload["subjectSha256"],
            },
        ),
        _item(
            "referenced_media", expected_absences_ok,
            "unresolved media is not a one-to-one native ABSENT_NO_COMMAND_NODE lowering",
            unresolved=counts.get("unresolvedMedia"), absence_algebra=absence_algebra,
            members=dict(sorted(absence_members.items())),
            _proof={"members": dict(sorted(absence_members.items()))},
        ),
        _item(
            "native_pixels", pixels_ok,
            "source assets are present but the complete native/web visual differential is missing",
            runtime_status=None if pixels is None else pixels.get("status"),
            required_visual_checkpoints=len(visual_rows),
            complete_visual_checkpoints=visual_complete,
            visual_by_kind=visual.get("counts", {}).get("by_kind"),
            _proof=None if not pixels_ok else {
                "runtime": pixels.get("proofs"),
                "visual_checkpoints": [row.get("proof") for row in visual_rows],
            },
        ),
    ]
    return _dimension(
        "assets", "SOURCE_CLOSURE_AND_NATIVE_PIXEL_DIFFERENTIAL", items,
        inventory={**counts, "packSections": len(assets.get("packSections", []))},
    )


def _manifest_is_fresh(manifest: dict[str, Any], root: Path) -> bool:
    inputs = manifest.get("inputs")
    if manifest.get("schema") != 1 \
            or manifest.get("protocol") != "miel-web-scene-transition-build" \
            or not isinstance(inputs, list) or not inputs:
        return False
    for row in inputs:
        if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
            return False
        path = (root / row["path"]).resolve()
        try:
            path.relative_to(root.resolve())
        except (TypeError, ValueError):
            return False
        if not path.is_file() or _sha256(path) != row["sha256"]:
            return False
    identity = {"schema": 1, "protocol": manifest["protocol"], "inputs": inputs}
    return manifest.get("build_sha256") == hashlib.sha256(_canonical(identity)).hexdigest()


def _repo_runtime_paths(engine: dict[str, Any]) -> list[str]:
    result = []
    for key in ("subsystems", "gameplay_runtimes"):
        for row in engine.get(key, []):
            runtime = row.get("runtime") if isinstance(row, dict) else None
            if isinstance(runtime, str) and runtime.startswith("src/"):
                result.append(runtime)
    return sorted(set(result))


def _required_presenter_opcodes(
    documents: dict[str, dict[str, Any]], root: Path,
) -> list[str]:
    commands = documents["native_udsp_commands"].get("commands")
    scripts = documents["executable_scene_scripts"].get("scripts")
    if not isinstance(commands, list) or not isinstance(scripts, list):
        raise CompletionError("native/executable UDSP command inventories are unavailable")
    native_by_name = _unique(commands, "name", "native UDSP commands")
    used = {
        command.get("sourceOpcode")
        for script in scripts if isinstance(script, dict)
        for command in script.get("commands", []) if isinstance(command, dict)
    }
    if None in used or not used or not used.issubset(native_by_name):
        raise CompletionError("executable UDSP opcodes differ from the native command inventory")
    if not ENGINE_OWNED_UDSP_OPCODES.issubset(used):
        raise CompletionError("UDSP engine-owned opcode boundary is unavailable")
    return sorted(used - ENGINE_OWNED_UDSP_OPCODES)


def production_consumer_requirements(
    documents: dict[str, dict[str, Any]], root: Path = ROOT,
) -> tuple[list[str], list[str], list[str]]:
    """Derive the NL release-consumer closure from executable opcodes and packs."""
    required_opcodes = _required_presenter_opcodes(documents, root)
    pack_sections = documents["assets"].get("packSections")
    if not isinstance(pack_sections, list):
        raise CompletionError("flight scene pack sections are unavailable")
    pack_by_key = _unique(pack_sections, "key", "flight scene pack sections")
    consumer_ids = sorted([
        *(f"presenter_opcode:{opcode}" for opcode in required_opcodes),
        *(f"asset_pack:{key}" for key in pack_by_key),
        "location_presentation_consumer",
        "mygghanget_presentation_consumer",
        "parity_observation_surface",
    ])
    return consumer_ids, required_opcodes, sorted(pack_by_key)


def _build_production_wiring(
    documents: dict[str, dict[str, Any]], root: Path,
) -> dict[str, Any]:
    checkpoints = documents["flight_checkpoints"]
    route = checkpoints.get("render", {}).get("flight_world", {})
    route_ok = route.get("release_reachable") is True \
        and route.get("runtime_contract") == INPUTS["runtime"]
    manifest_ok = _manifest_is_fresh(documents["web_transition_build"], root)
    runtime_paths = _repo_runtime_paths(documents["engine"])
    runtimes_ok = bool(runtime_paths) and all((root / path).is_file() for path in runtime_paths)
    consumer_ids, required_opcodes, required_packs = production_consumer_requirements(
        documents, root,
    )
    registry = production_consumer_registry.build(consumer_ids, root)
    consumers = _unique(registry["consumers"], "id", "production consumers")
    items = [
        _item("player_route", route_ok, "flight runtime is not release-reachable"),
        _item(
            "transition_producer_build", manifest_ok,
            "web transition producer manifest is absent or stale",
        ),
        _item(
            "runtime_owners", runtimes_ok,
            "one or more declared gameplay runtime owners are absent",
            paths=runtime_paths,
        ),
    ]
    for consumer_id in consumer_ids:
        consumer = consumers[consumer_id]
        items.append(_item(
            consumer_id, consumer.get("status") == "COMPLETE",
            "typed callable production consumer lacks a release-reachable PASS integration",
            consumer=consumer,
            opcode=consumer_id.split(":", 1)[1]
            if consumer_id.startswith("presenter_opcode:") else None,
            pack=consumer_id.split(":", 1)[1]
            if consumer_id.startswith("asset_pack:") else None,
            _subject={"consumer_id": consumer_id},
            _proof=consumer,
        ))
    return _dimension(
        "production_wiring", "HASH_PINNED_RELEASE_REACHABLE_RUNTIME_WIRING", items,
        required_presenter_opcodes=required_opcodes,
        required_asset_packs=required_packs,
    )


def _native_boundary_receipt(
    reference: Any, *, identifier: str, disposition: str,
    pipeline: dict[str, dict[str, Any]], code: dict[str, dict[str, Any]], root: Path,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        return None
    relative = reference.get("path")
    digest = reference.get("sha256")
    if not isinstance(relative, str) or not relative \
            or not isinstance(digest, str) or not SHA256.fullmatch(digest):
        return None
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return None
    if not path.is_file() or _sha256(path) != digest:
        return None
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    common = {
        "schema", "protocol", "reviewStatus", "boundaryId", "disposition",
        "claims", "boundarySha256",
    }
    disposition_fields = (
        {"apiImportMapping"} if disposition in NATIVE_SUBSTITUTION_DISPOSITIONS
        else {"reachabilityClosure"} if disposition == "PROVEN_UNREACHABLE"
        else {"ownershipBoundary", "effectBoundary", "sourceEvidence"}
        if disposition == "GAME_BEHAVIOR" else set()
    )
    if not isinstance(receipt, dict) or set(receipt) != common | disposition_fields \
            or receipt.get("schema") != 1 \
            or receipt.get("protocol") != NATIVE_BOUNDARY_RECEIPT_PROTOCOL \
            or receipt.get("reviewStatus") != "REVIEWED" \
            or receipt.get("disposition") != disposition \
            or not isinstance(receipt.get("boundaryId"), str) \
            or not receipt["boundaryId"]:
        return None
    unhashed = dict(receipt)
    boundary_sha = unhashed.pop("boundarySha256", None)
    if boundary_sha != hashlib.sha256(_canonical(unhashed)).hexdigest():
        return None
    claims = receipt.get("claims")
    if not isinstance(claims, list) or not claims:
        return None
    by_function: dict[str, dict[str, Any]] = {}
    for claim in claims:
        if not isinstance(claim, dict) or set(claim) != {
            "boundaryId", "disposition", "functionId", "nativeFunctionSha256",
            "membershipSha256",
        }:
            return None
        function_id = claim.get("functionId")
        native_row = pipeline.get(function_id)
        code_row = code.get(function_id)
        identity = {
            "boundaryId": receipt["boundaryId"],
            "disposition": disposition,
            "functionId": function_id,
            "nativeFunctionSha256": None if native_row is None
            else native_row.get("pe", {}).get("sha256"),
        }
        if function_id in by_function \
                or code_row is None \
                or any(claim.get(field) != value for field, value in identity.items()) \
                or claim.get("membershipSha256") != hashlib.sha256(
                    _canonical(identity)
                ).hexdigest():
            return None
        if disposition == "PROVEN_UNREACHABLE" and (
            code_row.get("entrypoint_reachable") is not False
            or code_row.get("has_unresolved_direct_calls") is not False
            or code_row.get("has_unresolved_indirect_calls") is not False
        ):
            return None
        by_function[function_id] = claim
    membership = by_function.get(identifier)
    if membership is None:
        return None
    if disposition in NATIVE_SUBSTITUTION_DISPOSITIONS:
        mappings = receipt.get("apiImportMapping")
        if not isinstance(mappings, list) or len(mappings) != len(claims):
            return None
        mapped_functions = set()
        for mapping in mappings:
            if not isinstance(mapping, dict) or set(mapping) != {
                "functionId", "nativeInterfaces", "replacementOwner",
                "replacementModule", "replacementExport",
                "replacementSourceSha256",
            } or any(not isinstance(mapping.get(field), str) or not mapping[field]
                     for field in (
                         "functionId", "replacementOwner", "replacementModule",
                         "replacementExport", "replacementSourceSha256",
                     )) \
                    or not SHA256.fullmatch(mapping["replacementSourceSha256"]):
                return None
            function_id = mapping["functionId"]
            native_row = pipeline.get(function_id)
            interfaces = mapping["nativeInterfaces"]
            expected_imports = native_row.get("native_interfaces", {}).get("imports") \
                if native_row is not None else None
            fallback = native_row.get("native_interfaces", {}).get("fallback") \
                if native_row is not None else None
            expected_interfaces = expected_imports if expected_imports else [fallback]
            module = (root / mapping["replacementModule"]).resolve()
            try:
                module.relative_to(root.resolve())
            except ValueError:
                return None
            if function_id not in by_function or function_id in mapped_functions \
                    or not isinstance(interfaces, list) or not interfaces \
                    or interfaces != expected_interfaces \
                    or any(not isinstance(value, str) or not value for value in interfaces) \
                    or not module.is_file() \
                    or _sha256(module) != mapping["replacementSourceSha256"]:
                return None
            try:
                source = module.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return None
            if not re.search(
                rf"\b{re.escape(mapping['replacementExport'])}\b", source,
            ):
                return None
            mapped_functions.add(function_id)
        if mapped_functions != set(by_function):
            return None
    elif disposition == "PROVEN_UNREACHABLE":
        closure = receipt.get("reachabilityClosure")
        if not isinstance(closure, dict) or set(closure) != NATIVE_REACHABILITY_CLOSURES:
            return None
        for proof in closure.values():
            if not isinstance(proof, dict) or set(proof) != {
                "closed", "reviewedTargetsSha256", "unresolvedPaths",
            } or proof.get("closed") is not True \
                    or not isinstance(proof.get("reviewedTargetsSha256"), str) \
                    or not SHA256.fullmatch(proof["reviewedTargetsSha256"]) \
                    or proof.get("unresolvedPaths") != []:
                return None
    elif disposition == "GAME_BEHAVIOR":
        ownership = receipt.get("ownershipBoundary")
        effects = receipt.get("effectBoundary")
        if not isinstance(ownership, dict) or set(ownership) != {
            "reviewed", "owner", "boundarySha256",
        } or ownership.get("reviewed") is not True \
                or not isinstance(ownership.get("owner"), str) or not ownership["owner"] \
                or not isinstance(ownership.get("boundarySha256"), str) \
                or not SHA256.fullmatch(ownership["boundarySha256"]):
            return None
        if not isinstance(effects, dict) or set(effects) != {
            "reviewed", "effects", "boundarySha256",
        } or effects.get("reviewed") is not True \
                or not isinstance(effects.get("effects"), list) \
                or not effects["effects"] \
                or any(not isinstance(effect, str) or not effect
                       for effect in effects["effects"]) \
                or len(set(effects["effects"])) != len(effects["effects"]) \
                or not isinstance(effects.get("boundarySha256"), str) \
                or not SHA256.fullmatch(effects["boundarySha256"]):
            return None
        if any(
            ownership["owner"] not in code[claim["functionId"]]
            .get("ownership", {}).get("modules", [])
            for claim in claims
        ):
            return None
        claim_identity = [
            {
                "functionId": claim["functionId"],
                "nativeFunctionSha256": claim["nativeFunctionSha256"],
            }
            for claim in claims
        ]
        expected_ownership_sha = hashlib.sha256(_canonical({
            "owner": ownership["owner"], "claims": claim_identity,
        })).hexdigest()
        effect_identity = {
            "effects": effects["effects"],
            "claims": [
                {
                    "functionId": claim["functionId"],
                    "effectClass": pipeline[claim["functionId"]]
                    .get("classification", {}).get("effect_class"),
                }
                for claim in claims
            ],
        }
        if ownership["boundarySha256"] != expected_ownership_sha \
                or effects["effects"] != sorted(set(
                    row["effectClass"] for row in effect_identity["claims"]
                )) \
                or effects["boundarySha256"] != hashlib.sha256(
                    _canonical(effect_identity)
                ).hexdigest():
            return None
        source_evidence = receipt.get("sourceEvidence")
        if not isinstance(source_evidence, list) or len(source_evidence) != len(claims):
            return None
        expected_sources = []
        for claim in claims:
            row = pipeline[claim["functionId"]]
            evidence = row.get("evidence")
            differential = evidence.get("differential") if isinstance(evidence, dict) else None
            implementation = evidence.get("implementation") if isinstance(evidence, dict) else None
            tests = evidence.get("tests") if isinstance(evidence, dict) else None
            abi_path = evidence.get("abi_contract") if isinstance(evidence, dict) else None
            if not isinstance(differential, dict) or set(differential) != {"contract", "receipt"} \
                    or not isinstance(implementation, list) or not implementation \
                    or not isinstance(tests, list) or not tests \
                    or not isinstance(abi_path, str):
                return None

            def source_hash(path_value: Any) -> str | None:
                if not isinstance(path_value, str):
                    return None
                source_path = (root / path_value).resolve()
                try:
                    source_path.relative_to(root.resolve())
                except ValueError:
                    return None
                return _sha256(source_path) if source_path.is_file() else None

            value = {
                "functionId": row["id"],
                "nativeFunctionSha256": row.get("pe", {}).get("sha256"),
                "pipelineEvidenceSha256": hashlib.sha256(_canonical(evidence)).hexdigest(),
                "abiContractSha256": source_hash(abi_path),
                "differentialContractSha256": source_hash(differential["contract"]),
                "differentialReceiptSha256": source_hash(differential["receipt"]),
                "implementationHashes": {
                    path_value: source_hash(path_value) for path_value in implementation
                },
                "testHashes": {
                    path_value: source_hash(path_value) for path_value in tests
                },
            }
            if any(value[field] is None for field in (
                "abiContractSha256", "differentialContractSha256",
                "differentialReceiptSha256",
            )) or any(digest is None for field in ("implementationHashes", "testHashes")
                      for digest in value[field].values()):
                return None
            expected_sources.append({
                **value,
                "sourceEvidenceSha256": hashlib.sha256(_canonical(value)).hexdigest(),
            })
        if source_evidence != expected_sources:
            return None
    return receipt, membership


def _build_native_functions(
    documents: dict[str, dict[str, Any]], root: Path = ROOT,
) -> dict[str, Any]:
    pipeline_rows = documents["native_pipeline"].get("functions")
    code_rows = documents["native_code_map"].get("functions")
    if not isinstance(pipeline_rows, list) or not isinstance(code_rows, list):
        raise CompletionError("native function pipeline is unavailable")
    pipeline = _unique(pipeline_rows, "id", "native pipeline")
    code = _unique(code_rows, "id", "native code map")
    if set(pipeline) != set(code):
        raise CompletionError("native ownership and pipeline inventories differ")
    if any(
        pipeline[identifier].get("pe", {}).get("sha256") != code[identifier].get("sha256")
        for identifier in pipeline
    ):
        raise CompletionError("native pipeline and code-map function hashes differ")
    items = []
    ownership_counts: Counter[str] = Counter()
    disposition_counts: Counter[str] = Counter()
    stage_order = documents["native_pipeline"].get("policy", {}).get("stage_order")
    if not isinstance(stage_order, list) or not stage_order \
            or any(not isinstance(stage, str) or not stage for stage in stage_order):
        raise CompletionError("native pipeline stage order is unavailable")
    stage_debt: Counter[str] = Counter({stage: 0 for stage in stage_order})
    for identifier in sorted(pipeline):
        ownership = code[identifier].get("ownership", {}).get("status")
        disposition = pipeline[identifier].get("disposition", "UNKNOWN")
        if disposition not in NATIVE_FUNCTION_DISPOSITIONS:
            disposition = "UNKNOWN"
        disposition_counts[disposition] += 1
        stages = pipeline[identifier].get("stages", {})
        ownership_counts[str(ownership)] += 1
        if set(stages) != set(stage_order):
            raise CompletionError(f"native pipeline stages differ: {identifier}")
        for stage, status in stages.items():
            if status != "PASS":
                stage_debt[stage] += 1
        boundary = _native_boundary_receipt(
            pipeline[identifier].get("boundary_evidence_receipt"),
            identifier=identifier, disposition=disposition,
            pipeline=pipeline, code=code, root=root,
        ) if disposition != "UNKNOWN" else None
        stage_complete = all(status == "PASS" for status in stages.values()) \
            and stages.get("implemented") == "PASS" \
            and stages.get("differential") == "PASS"
        complete = boundary is not None and (
            disposition != "GAME_BEHAVIOR"
            or ownership == "reviewed" and stage_complete
        )
        reason = (
            "native function remains UNKNOWN"
            if disposition == "UNKNOWN" else
            "reviewed ownership, effect boundary, implementation or differential is missing"
            if disposition == "GAME_BEHAVIOR" else
            "exact reviewed substitution receipt and API/import mapping are missing"
            if disposition in NATIVE_SUBSTITUTION_DISPOSITIONS else
            "closed root/callback/vtable/indirect-target reachability proof is missing"
        )
        items.append(_item(
            identifier, complete, reason,
            disposition=disposition, ownership=ownership, stages=stages,
            boundary_evidence_receipt=pipeline[identifier].get(
                "boundary_evidence_receipt"
            ),
            cluster_membership=None if boundary is None else boundary[1],
            _subject={
                "id": identifier,
                "native_sha256": pipeline[identifier].get("pe", {}).get("sha256"),
                "disposition": disposition,
            },
            _proof=None if boundary is None else {
                "receipt": pipeline[identifier].get("boundary_evidence_receipt"),
                "membership": boundary[1],
                "stages": stages if disposition == "GAME_BEHAVIOR" else None,
            },
        ))
    return _dimension(
        "native_functions", "REVIEWED_NATIVE_FUNCTION_DISPOSITION", items,
        ownership=dict(sorted(ownership_counts.items())),
        dispositions=dict(sorted(disposition_counts.items())),
        stage_debt=dict(sorted(stage_debt.items())),
    )


def build(
    documents: dict[str, dict[str, Any]], root: Path = ROOT,
) -> dict[str, Any]:
    missing = set(INPUTS) - set(documents)
    if missing:
        raise CompletionError(f"completion inputs are missing: {sorted(missing)}")
    if any(document.get("schema") != 1 for name, document in documents.items()
           if name not in {"scene_coverage", "scene_probe"}) \
            or documents["scene_coverage"].get("schema") != 2 \
            or documents["scene_probe"].get("schema") != 1:
        raise CompletionError("completion inputs use unsupported schemas")

    modes = _build_modes(documents)
    semantics = _build_semantics(documents)
    edges = _build_edges(documents)
    dimensions = [
        modes,
        _build_locations(documents, modes, semantics, edges),
        _build_gameplay_runtimes(documents, root),
        semantics,
        edges,
        _build_engine_rows(documents, "subsystems", "subsystems", root),
        _build_assets(documents),
        _build_production_wiring(documents, root),
        _build_native_functions(documents, root),
    ]
    release_ready = release_decision(dimensions)
    source_paths = {
        **INPUTS,
        **{f"wiring_{name}": path for name, path in WIRING_SOURCES.items()},
        "gameplay_runtime_contract": "tools/miel_vliegt/engine_runtime_contract.py",
        "engine_evidence_validator": "tools/miel_vliegt/verify_engine_implementation.py",
        "production_consumer_registry": "tools/miel_vliegt/production_consumer_registry.py",
        "semantic_normalizer": "tools/miel_vliegt/udsp_semantic_oracle.py",
        "web_dispatch_semantic_producer":
            "src/flight/engine/scene/SceneDispatchRuntime.js",
        "generator": "tools/miel_vliegt/flight_cleanroom_completion.py",
    }
    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "edition": documents["semantic"].get("edition"),
        "policy": {
            "release_rule": "Every item in every dimension must be COMPLETE.",
            "structural_coverage_is_semantic_parity": False,
            "semantic_parity_requires": "claim-bound native/runtime differential evidence",
            "pixel_parity_requires": "hash-bound native and web framebuffer PASS receipt",
            "missing_or_unknown": "BLOCKED",
        },
        "sources": {
            name: {"path": path, "sha256": _sha256(root / path)}
            for name, path in sorted(source_paths.items())
        },
        "summary": {
            "dimensions": len(dimensions),
            "complete_dimensions": sum(row["status"] == "COMPLETE" for row in dimensions),
            "blocked_dimensions": sum(row["status"] != "COMPLETE" for row in dimensions),
            "release_ready": release_ready,
            "complete": release_ready,
        },
        "dimensions": dimensions,
    }


def build_from_root(root: Path = ROOT) -> dict[str, Any]:
    documents = load_documents(root)
    validate_authorities(root, documents)
    return build(documents, root)


def validate_authorities(
    root: Path, documents: dict[str, dict[str, Any]],
) -> None:
    """Run the authoritative evidence validators before deriving status.

    The compact matrix deliberately does not duplicate receipt validation.
    Calling the owning validators here prevents a caller from promoting a row
    by merely editing a status string or adding an arbitrary evidence path.
    """

    try:
        from tools.miel_vliegt import (
            build_native_engine_pipeline,
            native_dispatch_hook_contract,
            native_mode_bodies,
            scene_coverage,
            scene_semantic_evidence_batches,
            scene_semantic_coverage,
            flight_scene_payload_differential,
            visual_checkpoint_inventory,
            web_scene_semantic_evidence,
            web_transition_build,
        )
        from tools.miel_vliegt.verify_engine_implementation import validate as validate_engine
        from tools.miel_vliegt.verify_flight_runtime_contract import validate as validate_runtime
    except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
        import build_native_engine_pipeline
        import native_dispatch_hook_contract
        import native_mode_bodies
        import scene_coverage
        import scene_semantic_evidence_batches
        import scene_semantic_coverage
        import flight_scene_payload_differential
        import visual_checkpoint_inventory
        import web_scene_semantic_evidence
        import web_transition_build
        from verify_engine_implementation import validate as validate_engine
        from verify_flight_runtime_contract import validate as validate_runtime

    scene_coverage.validate_ledger(root / INPUTS["scene_coverage"])
    scene_semantic_coverage.load_and_validate(
        root / INPUTS["semantic"],
        dispatch_path=root / "content/miel_vliegt/scene_dispatch_contract.json",
        udsp_path=root / "content/miel_vliegt/uds_scene_scripts.json",
        executable_path=root / "content/miel_vliegt/executable_udsp_scene_scripts.json",
    )
    scene_semantic_evidence_batches.validate_plan(
        documents["semantic_batches"],
        ledger_path=root / INPUTS["semantic"],
    )
    try:
        web_scene_semantic_evidence.validate_manifest(
            documents["web_semantic_evidence"],
            output=root / INPUTS["web_semantic_evidence"],
        )
    except web_scene_semantic_evidence.WebSceneSemanticEvidenceError as error:
        raise CompletionError(
            f"web semantic evidence closure is invalid: {error}"
        ) from error
    native_dispatch_hook_contract.validate_contract(
        documents["native_dispatch_hooks"]
    )
    try:
        flight_scene_payload_differential.validate_receipt(
            documents["asset_payload_differential"]
        )
    except flight_scene_payload_differential.PayloadDifferentialError as error:
        raise CompletionError(
            f"flight scene payload differential is invalid: {error}"
        ) from error
    native_mode_bodies.validate_contract(documents["mode_bodies"], root=root)
    visual_checkpoint_inventory.validate_inventory(
        documents["visual_checkpoints"], root=root,
    )
    runtime_errors = validate_runtime(
        documents["runtime"], documents["runtime_trace"], root,
    )
    if runtime_errors:
        raise CompletionError("runtime evidence contract is invalid: " + runtime_errors[0])
    validate_engine(root)
    web_transition_build.validate_manifest(
        root / INPUTS["web_transition_build"], root,
    )
    expected_pipeline = build_native_engine_pipeline.build_from_root(root)
    if documents["native_pipeline"] != expected_pipeline:
        raise CompletionError("native function pipeline contract drifted")


def render_markdown(matrix: dict[str, Any]) -> str:
    dimensions = {row["id"]: row for row in matrix["dimensions"]}
    web_semantic_closure = dimensions["semantic_claims"]["web_slot_closure"]
    lines = [
        "# Flight clean-room completion",
        "",
        "<!-- Generated by tools/miel_vliegt/flight_cleanroom_completion.py; do not edit. -->",
        "",
        "This is the fail-closed release ledger for the clean-room flight port. "
        "It is generated from the source-bound inventories and evidence contracts; "
        "it does not estimate progress and never promotes structural coverage to parity.",
        "",
        f"Edition: `{matrix['edition']}`",
        "",
        f"Release ready: **{'YES' if matrix['summary']['release_ready'] else 'NO'}**",
        "",
        "| Dimension | Complete | Required | Blocked | Evidence required |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for row in matrix["dimensions"]:
        lines.append(
            f"| `{row['id']}` | {row['complete']} | {row['required']} | "
            f"{row['blocked']} | `{row['evidence_requirement']}` |"
        )
    lines.extend((
        "",
        "## Current blockers",
        "",
    ))
    for dimension in matrix["dimensions"]:
        blockers = [row for row in dimension["items"] if row["status"] == "BLOCKED"]
        if not blockers:
            continue
        lines.append(f"### {dimension['id']}")
        lines.append("")
        reason_counts = Counter(row["blocker"] for row in blockers)
        for reason, count in sorted(reason_counts.items()):
            lines.append(f"- {count} item(s): {reason}")
        lines.append("")
    lines.extend((
        "## Gate semantics",
        "",
        "- Parsed scripts, recovered bytes, function boundaries, static transitions and "
        "decoded assets are inventories. They are not behavioral evidence.",
        "- A missing voice file closes source assets only when its reference, "
        "`ABSENT_NO_COMMAND_NODE` media row and executable removed command form an exact bijection.",
        "- Runtime file presence or an empty presenter lease is not production wiring; "
        "every observed effect port and asset pack needs a release-reachable consumer.",
        "- Scene bodies and natural edges require independent native and web traces plus "
        "a hash-bound passing differential.",
        f"- The headless web semantic manifest closes all "
        f"{web_semantic_closure['jobs']} web evidence slots as "
        f"{web_semantic_closure['captured_candidate']} captured candidates and "
        f"{web_semantic_closure['blocked']} explicit blockers; this inventory cannot "
        "promote a semantic claim without its native differential.",
        "- Rendering completion additionally requires a native/web framebuffer differential.",
        "- Exported flight scene PNG, WAV and Phaser-pack payloads are checked byte-for-byte "
        "and metadata-for-metadata; this does not establish scene composition or framebuffer parity.",
        "- Native functions remain debt until ownership is reviewed and every pipeline "
        "stage through `differential` passes.",
        "- The native parity ratchet compares stable dimension/item IDs to the previous "
        "commit; proven items and complete counts may not regress.",
        "",
        "Regenerate or check the ledger:",
        "",
        "```sh",
        "python3 tools/miel_vliegt/flight_cleanroom_completion.py",
        "python3 tools/miel_vliegt/flight_cleanroom_completion.py --check",
        "python3 tools/miel_vliegt/flight_cleanroom_completion.py --require-complete",
        "```",
        "",
    ))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    matrix = build_from_root(root)
    encoded = json.dumps(matrix, indent=2, ensure_ascii=True) + "\n"
    markdown = render_markdown(matrix)
    output = root / OUTPUT
    documentation = root / DOCUMENTATION
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != encoded:
            raise SystemExit("flight clean-room completion matrix drifted")
        if not documentation.is_file() or documentation.read_text(encoding="utf-8") != markdown:
            raise SystemExit("flight clean-room completion documentation drifted")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        documentation.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
        documentation.write_text(markdown, encoding="utf-8")
    print(
        "flight clean-room completion: "
        f"{matrix['summary']['complete_dimensions']}/{matrix['summary']['dimensions']} "
        "dimensions complete"
    )
    if args.require_complete and not matrix["summary"]["release_ready"]:
        raise SystemExit("flight clean-room completion gate is blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
