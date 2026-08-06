#!/usr/bin/env python3
"""Build and verify non-authoritative external flight research.

This registry deliberately stores only normalized factual hypotheses and
source metadata.  It is not a parity evidence producer and cannot promote a
claim beyond UNVERIFIED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = ROOT / "content/miel_vliegt/external_hypothesis_registry.json"
DEFAULT_RATCHET = ROOT / "content/miel_vliegt/external_hypothesis_ratchet.json"
DEFAULT_SCHEMA = Path(__file__).resolve().parent / "schemas/external-hypothesis-registry.schema.json"

UNVERIFIED = "UNVERIFIED"
EXTERNAL_CLASS = "EXTERNAL_COMMUNITY_DOCUMENTATION"
FORBIDDEN_KEYS = frozenset({"quote", "excerpt", "raw_text", "source_code", "image", "image_data"})


SOURCES = [
    {
        "id": "openmulle",
        "repository_url": "https://github.com/henkery/openMulle",
        "default_branch": "main",
        "commit": "9561d6b953b7f7821e5c50b3cfd36dcf51a4dabe",
        "pin_role": "DEFAULT_BRANCH_HEAD_AT_CAPTURE",
        "commit_url": "https://github.com/henkery/openMulle/commit/9561d6b953b7f7821e5c50b3cfd36dcf51a4dabe",
        "readme_url": "https://github.com/henkery/openMulle/blob/9561d6b953b7f7821e5c50b3cfd36dcf51a4dabe/README.md",
        "readme_git_blob_sha1": "04d1454063d1999d598ba255682e5f38ccef29c9",
        "readme_sha256": "2ad5ae7b30b7558fbab58fc2a191b8142cae05f226710b10db37918a979fa408",
        "source_role": "SECONDARY_ENGINE_REFERENCE",
        "runtime_equivalence_eligible": False,
        "license_status": "DUAL_LICENSED",
        "license_expression": "MIT OR Apache-2.0",
        "license_files": ["LICENSE-MIT", "LICENSE-APACHE"],
        "reuse_policy": "METADATA_AND_LICENSED_IDEAS_ONLY",
    },
    {
        "id": "willywerkel",
        "repository_url": "https://github.com/Yepoleb/willywerkel",
        "default_branch": "master",
        "commit": "ac37fa19a468143df58864986ccfe5384a48d339",
        "pin_role": "DEFAULT_BRANCH_HEAD_AT_CAPTURE",
        "commit_url": "https://github.com/Yepoleb/willywerkel/commit/ac37fa19a468143df58864986ccfe5384a48d339",
        "readme_url": "https://github.com/Yepoleb/willywerkel/blob/ac37fa19a468143df58864986ccfe5384a48d339/README.md",
        "readme_git_blob_sha1": "513182abc34d0814e9a948bd096b0e46d67917b3",
        "readme_sha256": "6e1573c6141cf4b38305fa1ccc5998d1abb1f1a1ddb24ba780bf2cf683a1f2e6",
        "source_role": "SECONDARY_GAMEPLAY_HYPOTHESIS_SOURCE",
        "runtime_equivalence_eligible": False,
        "license_status": "NO_LICENSE_FILE",
        "license_expression": None,
        "license_files": [],
        "reuse_policy": "FACTUAL_METADATA_ONLY_NO_COPY",
    },
    {
        "id": "cc_tools",
        "repository_url": "https://github.com/RonnyReverse/cc-tools",
        "default_branch": "master",
        "commit": "e34efcd858ec4475fa03d3f8668fa4e26f9e780e",
        "pin_role": "DEFAULT_BRANCH_HEAD_AT_CAPTURE",
        "commit_url": "https://github.com/RonnyReverse/cc-tools/commit/e34efcd858ec4475fa03d3f8668fa4e26f9e780e",
        "readme_url": "https://github.com/RonnyReverse/cc-tools/blob/e34efcd858ec4475fa03d3f8668fa4e26f9e780e/README.md",
        "readme_git_blob_sha1": "bb7f0b7269e58e0f7d811171a0b706dbdd729a75",
        "readme_sha256": "e0a2bdd89c100ecabcc8f570852f69abb65e2380169f0e735419fa29c9c9b9f6",
        "source_role": "SECONDARY_STRUCTURAL_ORACLE",
        "runtime_equivalence_eligible": False,
        "license_status": "LICENSED",
        "license_expression": "CC0-1.0",
        "license_files": ["LICENSE"],
        "reuse_policy": "CC0_STRUCTURAL_REFERENCE_NO_COPY",
    },
]


def point(item_id: str, x: int, y: int, radius: int | None = None, **extra: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"item_id": item_id, "x": x, "y": y, "placement_radius": radius}
    result.update(extra)
    return result


def coordinate_claim(hypothesis_id: str, subject: str, points: list[dict[str, Any]]) -> dict[str, Any]:
    return hypothesis(
        hypothesis_id,
        "Map Locations",
        {"kind": "MISSION_COORDINATES", "subject": subject, "points": points},
    )


def rule_claim(
    hypothesis_id: str,
    heading: str,
    rule_kind: str,
    subject: str,
    requirements: list[str],
) -> dict[str, Any]:
    return hypothesis(
        hypothesis_id,
        heading,
        {
            "kind": "MISSION_RULE",
            "rule_kind": rule_kind,
            "subject": subject,
            "requirements": requirements,
        },
    )


def issue_rule_claim(
    hypothesis_id: str,
    rule_kind: str,
    subject: str,
    requirements: list[str],
) -> dict[str, Any]:
    item = rule_claim(hypothesis_id, "Issue #2", rule_kind, subject, requirements)
    item["source_locator"] = {
        "document": "GITHUB_ISSUE",
        "issue_number": 2,
        "issue_id": 2707042725,
        "issue_url": "https://github.com/Yepoleb/willywerkel/issues/2",
        "author": "AndreasHeinze",
        "created_at": "2024-11-30T09:23:33Z",
        "updated_at": "2026-03-07T23:33:24Z",
        "body_sha256": "814e2bc5a5468ed3aece9209932f2304cbe76d23962bc799debc78e1d3083b7d",
    }
    return item


def hypothesis(hypothesis_id: str, heading: str, claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": hypothesis_id,
        "source_id": "willywerkel",
        "source_locator": {"document": "README.md", "heading": heading},
        "status": UNVERIFIED,
        "evidence_class": EXTERNAL_CLASS,
        "parity_evidence_eligible": False,
        "promotion_requires": ["FIRST_PARTY_NATIVE_TRACE", "ORIGINAL_GAME_CORROBORATION"],
        "claim": claim,
    }


HYPOTHESES = [
    coordinate_claim("map.anton.book", "anton.book", [point("book", 500, 1740, 50)]),
    coordinate_claim("map.doris.antennas", "doris.antennas", [
        point("antenna.1", 3660, 680), point("antenna.2", 2963, -79), point("antenna.3", 1800, 206),
    ]),
    coordinate_claim("map.ernst.metal_sheets", "ernst.metal_sheets", [point("metal_sheets", 3800, 2110)]),
    coordinate_claim("map.fiona.birds", "fiona.birds", [
        point("bird.1", 3686, 1450), point("bird.2", 3603, 1345), point("bird.3", 3554, 1382),
    ]),
    coordinate_claim("map.gabriella.furniture", "gabriella.furniture", [
        point("chair.1", 3660, 250, 150), point("chair.2", 3660, 0, 150),
        point("chair.3", 3460, 100, 150), point("chair.4", 3760, 0, 150),
        point("table.1", 3660, 200, 150), point("table.2", 3560, 50, 150),
    ]),
    coordinate_claim("map.grotte.vacuum_cleaner", "grotte.vacuum_cleaner", [point("vacuum_cleaner", 2080, 2000, 200)]),
    coordinate_claim("map.hugo.meteorite_craters", "hugo.meteorite_craters", [
        point("crater.1", 2500, 1300), point("crater.2", 2500, 1080), point("crater.3", 2410, 1060),
    ]),
    coordinate_claim("map.erik.random_events", "erik.random_events", [
        point("mobile_phone.1", 1855, 1441, 1000), point("clock", 1855, 1441, 1000),
        point("hang_glider", 1855, 1441, 1000), point("sunglasses", 1855, 1441, 1000),
        point("mobile_phone.2", 1855, 1441, 1000),
    ]),
    coordinate_claim("map.sampo.reindeer", "sampo.reindeer", [point("reindeer", 617, 2822, 100)]),
    coordinate_claim("map.viktor.seismograph_ground", "viktor.seismograph_part_1", [point("seismograph_part.1", 2545, 2900, 100)]),
    coordinate_claim("map.viktor.seismograph_bird", "viktor.seismograph_part_3", [
        point("seismograph_part.3", 500, -200, 20, interaction="FLY_THROUGH_WHITE_BIRD_FLOCK"),
    ]),
    rule_claim("mission.roy.photos", "Difficult Missions / Roy", "SEQUENCE", "roy.photos", [
        "OBTAIN_CAMERA_FROM_SAM", "TRAVERSE_WHOLE_MAP", "USE_CLICKABLE_MINIMAP", "DEVELOP_PHOTOS",
    ]),
    rule_claim("mission.viola.seeds", "Difficult Missions / Viola", "EQUIPMENT", "viola.spread_seeds", ["ATTACH_FARMING_TOOL"]),
    rule_claim("mission.viola.water", "Difficult Missions / Viola", "EQUIPMENT", "viola.water_field", ["ATTACH_FARMING_TOOL"]),
    rule_claim("mission.viola.moles", "Difficult Missions / Viola", "EQUIPMENT", "viola.scare_moles", ["ATTACH_THREE_SPIKE_NOSE"]),
    rule_claim("mission.pelle.exhibition_leaflets", "Difficult Missions / Pelle", "FLYOVER", "pelle.exhibition_leaflets", ["FLY_OVER_WORLD_EXHIBITION", "ANY_PLANE"]),
    rule_claim("mission.pelle.city_leaflets", "Difficult Missions / Pelle", "FLYOVER", "pelle.city_leaflets", ["FLY_OVER_CITY", "ANY_PLANE", "VTOL_MISSION_CONTEXT"]),
    rule_claim("mission.plane_competition", "Difficult Missions / Plane competition", "LANDING_TARGET", "plane_competition", ["FLY_TO_WORLD_EXHIBITION", "LAND_ON_LEFT_SIDE"]),
    rule_claim("landing.sampo", "Landing", "LANDING_EQUIPMENT", "sampo", ["SKIS"]),
    rule_claim("landing.kalle", "Landing", "LANDING_EQUIPMENT", "kalle", ["SKIS"]),
    rule_claim("landing.fiona", "Landing", "LANDING_CONSTRAINT", "fiona", ["GRAPPLING_HOOK", "HOUSE_PLATFORM_ONLY", "MID_HEIGHT_COLLISION_BOUNDARY"]),
    rule_claim("landing.gabriella", "Landing", "LANDING_EQUIPMENT", "gabriella", ["FLOATS"]),
    rule_claim("landing.pelle", "Landing", "LANDING_CONSTRAINT", "pelle", ["GRAPPLING_HOOK", "SHIP_DECK", "MOVING_WOODEN_WIND_INDICATOR"]),
    rule_claim("landing.viktor", "Landing", "LANDING_EQUIPMENT", "viktor", ["FLOATS"]),
    rule_claim("part.ture.grappling_hook", "New Parts", "PART_REWARD", "ture", ["GRAPPLING_HOOK"]),
    rule_claim("part.pelle.wing_floats", "New Parts", "PART_REWARD", "pelle", ["WING_FLOATS"]),
    rule_claim("part.viktor.flight_parts", "New Parts", "PART_REWARD", "viktor", ["SKIS", "VTOL_PARTS", "MOLE_SCARER"]),
    issue_rule_claim("issue2.erik.yarn", "MISSION_SEQUENCE", "erik.special_thread", [
        "COLLECT_FOUR_ERIK_ITEMS", "FIND_MOBILE_PHONE_AGAIN", "ARRIVE_SAM_SCRIBBLER",
        "RECEIVE_SPECIAL_THREAD",
    ]),
    issue_rule_claim("issue2.erik.search_region", "QUALITATIVE_LOCATION", "erik.random_items", [
        "ABOVE_ANNA", "RIGHT_AND_BELOW_ANTON", "LEFT_OF_RIKKI",
    ]),
    issue_rule_claim("issue2.anna.interactions", "LOCATION_ROUTING", "anna.location", [
        "LEFT_AIRPLANE_RATING", "CENTER_ANNA", "RIGHT_FLYING_CIRCUS",
    ]),
    issue_rule_claim("issue2.final_diploma", "DIPLOMA_GATE", "airplane.rating", [
        "HAVE_FIVE_DIPLOMAS", "VISIT_RATING_AREA", "RECEIVE_FINAL_DIPLOMA",
    ]),
    issue_rule_claim("issue2.five_point_build", "AIRPLANE_BUILD_SCORE", "competition.five_points", [
        "GREEN_METAL_CONTAINER_BODY", "DRAGON_WINGS", "WATER_LANDING_GEAR", "LANDING_HOOK",
        "RED_ROCKET_FRONT", "WHITE_ARROW_BACK", "PADDLE_OR_WINDMILL_ROTOR",
    ]),
]


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def semantic_sha256(value: Any) -> str:
    compact = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(compact).hexdigest()


def build_registry() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "evidence_policy": {
            "classification": "HYPOTHESIS_ONLY",
            "default_status": UNVERIFIED,
            "parity_evidence_eligible": False,
            "may_satisfy_parity_gate": False,
            "copied_code_or_images": False,
        },
        "sources": SOURCES,
        "hypotheses": HYPOTHESES,
        "parity_evidence_exports": [],
    }


def _walk_forbidden_keys(value: Any, path: str = "$ ") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_KEYS:
                errors.append(f"{path}.{key}: copied material field is forbidden")
            errors.extend(_walk_forbidden_keys(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_walk_forbidden_keys(child, f"{path}[{index}]"))
    return errors


def validate_registry(registry: dict[str, Any], ratchet: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != 1:
        errors.append("schema_version must equal 1")
    policy = registry.get("evidence_policy")
    expected_policy = build_registry()["evidence_policy"]
    if policy != expected_policy:
        errors.append("evidence_policy must remain the fail-closed HYPOTHESIS_ONLY policy")
    if registry.get("parity_evidence_exports") != []:
        errors.append("parity_evidence_exports must remain empty")

    sources = registry.get("sources")
    if not isinstance(sources, list):
        return errors + ["sources must be an array"]
    source_by_id = {source.get("id"): source for source in sources if isinstance(source, dict)}
    if len(source_by_id) != len(sources):
        errors.append("source ids must be present and unique")
    for source_id, expected_head in ratchet.get("pinned_source_heads", {}).items():
        source = source_by_id.get(source_id)
        if not source:
            errors.append(f"ratcheted source missing: {source_id}")
            continue
        if source.get("commit") != expected_head:
            errors.append(f"{source_id}: commit must remain pinned to {expected_head}")
        if source.get("pin_role") != "DEFAULT_BRANCH_HEAD_AT_CAPTURE":
            errors.append(f"{source_id}: pin_role must identify the captured HEAD")
        if source.get("runtime_equivalence_eligible") is not False:
            errors.append(f"{source_id}: external sources cannot prove runtime equivalence")
        for key in ("commit_url", "readme_url"):
            if expected_head not in str(source.get(key, "")):
                errors.append(f"{source_id}: {key} must contain the pinned commit")
        for digest_key, size in (("commit", 40), ("readme_git_blob_sha1", 40), ("readme_sha256", 64)):
            digest = source.get(digest_key)
            if not isinstance(digest, str) or len(digest) != size or any(c not in "0123456789abcdef" for c in digest):
                errors.append(f"{source_id}: invalid {digest_key}")
    willy = source_by_id.get("willywerkel", {})
    if willy.get("license_status") != "NO_LICENSE_FILE" or willy.get("license_expression") is not None:
        errors.append("willywerkel must remain marked as having no license file")
    if willy.get("license_files") != [] or willy.get("reuse_policy") != "FACTUAL_METADATA_ONLY_NO_COPY":
        errors.append("willywerkel must remain metadata-only/no-copy")
    open_mulle = source_by_id.get("openmulle", {})
    if open_mulle.get("license_expression") != "MIT OR Apache-2.0":
        errors.append("openMulle dual-license expression drifted")
    cc_tools = source_by_id.get("cc_tools", {})
    if cc_tools.get("license_expression") != "CC0-1.0":
        errors.append("cc-tools CC0-1.0 license expression drifted")
    if cc_tools.get("source_role") != "SECONDARY_STRUCTURAL_ORACLE":
        errors.append("cc-tools may only be a SECONDARY_STRUCTURAL_ORACLE")
    if cc_tools.get("runtime_equivalence_eligible") is not False:
        errors.append("cc-tools cannot prove runtime equivalence")

    hypotheses = registry.get("hypotheses")
    if not isinstance(hypotheses, list):
        return errors + ["hypotheses must be an array"]
    by_id = {item.get("id"): item for item in hypotheses if isinstance(item, dict)}
    if len(by_id) != len(hypotheses):
        errors.append("hypothesis ids must be present and unique")
    for hypothesis_id, item in by_id.items():
        if item.get("status") != UNVERIFIED:
            errors.append(f"{hypothesis_id}: external claim status must be UNVERIFIED")
        if item.get("evidence_class") != EXTERNAL_CLASS:
            errors.append(f"{hypothesis_id}: invalid evidence_class")
        if item.get("parity_evidence_eligible") is not False:
            errors.append(f"{hypothesis_id}: cannot be parity evidence")
        if item.get("promotion_requires") != ["FIRST_PARTY_NATIVE_TRACE", "ORIGINAL_GAME_CORROBORATION"]:
            errors.append(f"{hypothesis_id}: promotion requirements drifted")
        locator = item.get("source_locator", {})
        if item.get("source_id") != "willywerkel":
            errors.append(f"{hypothesis_id}: source must be the pinned willywerkel repository")
        if locator.get("document") == "README.md":
            if not locator.get("heading"):
                errors.append(f"{hypothesis_id}: README source needs a heading")
        elif locator.get("document") == "GITHUB_ISSUE":
            expected_issue = {
                "issue_number": 2,
                "issue_id": 2707042725,
                "issue_url": "https://github.com/Yepoleb/willywerkel/issues/2",
                "author": "AndreasHeinze",
                "created_at": "2024-11-30T09:23:33Z",
                "updated_at": "2026-03-07T23:33:24Z",
                "body_sha256": "814e2bc5a5468ed3aece9209932f2304cbe76d23962bc799debc78e1d3083b7d",
            }
            for key, expected in expected_issue.items():
                if locator.get(key) != expected:
                    errors.append(f"{hypothesis_id}: issue locator {key} drifted")
        else:
            errors.append(f"{hypothesis_id}: unsupported source locator")
        claim = item.get("claim", {})
        if claim.get("kind") == "MISSION_COORDINATES":
            points = claim.get("points")
            if not isinstance(points, list) or not points:
                errors.append(f"{hypothesis_id}: coordinate claim requires points")
            else:
                for index, coordinate in enumerate(points):
                    if not isinstance(coordinate.get("x"), int) or not isinstance(coordinate.get("y"), int):
                        errors.append(f"{hypothesis_id}: point {index} needs integer x/y")
                    radius = coordinate.get("placement_radius")
                    if radius is not None and (not isinstance(radius, int) or radius < 0):
                        errors.append(f"{hypothesis_id}: point {index} has invalid radius")
        elif claim.get("kind") == "MISSION_RULE":
            if not claim.get("rule_kind") or not claim.get("subject"):
                errors.append(f"{hypothesis_id}: mission rule needs kind and subject")
            requirements = claim.get("requirements")
            if not isinstance(requirements, list) or not requirements or not all(isinstance(v, str) and v for v in requirements):
                errors.append(f"{hypothesis_id}: mission rule needs normalized requirements")
        else:
            errors.append(f"{hypothesis_id}: unsupported claim kind")

    locked = ratchet.get("locked_hypotheses", {})
    for hypothesis_id, expected_digest in locked.items():
        item = by_id.get(hypothesis_id)
        if item is None:
            errors.append(f"ratcheted hypothesis missing: {hypothesis_id}")
        elif semantic_sha256(item) != expected_digest:
            errors.append(f"ratcheted hypothesis changed: {hypothesis_id}")
    minimum = ratchet.get("minimum_hypothesis_count")
    if not isinstance(minimum, int) or len(hypotheses) < minimum:
        errors.append(f"hypothesis count regressed below ratchet: {minimum}")
    errors.extend(_walk_forbidden_keys(registry))
    return errors


def validate_schema_guard(schema: dict[str, Any]) -> list[str]:
    """Ensure the checked-in schema preserves the non-promotable boundary."""
    errors: list[str] = []
    try:
        properties = schema["properties"]
        policy = properties["evidence_policy"]["properties"]
        source = properties["sources"]["items"]["properties"]
        hypothesis = properties["hypotheses"]["items"]["properties"]
    except (KeyError, TypeError):
        return ["schema does not describe the required registry structure"]
    expected_consts = {
        "classification": "HYPOTHESIS_ONLY",
        "default_status": UNVERIFIED,
        "parity_evidence_eligible": False,
        "may_satisfy_parity_gate": False,
        "copied_code_or_images": False,
    }
    for key, expected in expected_consts.items():
        if policy.get(key, {}).get("const") != expected:
            errors.append(f"schema policy {key} must be pinned to {expected!r}")
    if hypothesis.get("status", {}).get("const") != UNVERIFIED:
        errors.append("schema hypothesis status must be UNVERIFIED")
    if hypothesis.get("parity_evidence_eligible", {}).get("const") is not False:
        errors.append("schema must forbid hypothesis parity eligibility")
    if source.get("runtime_equivalence_eligible", {}).get("const") is not False:
        errors.append("schema must forbid external runtime equivalence")
    if properties.get("parity_evidence_exports", {}).get("const") != []:
        errors.append("schema must keep parity_evidence_exports empty")
    return errors


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--ratchet", type=Path, default=DEFAULT_RATCHET)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    expected = canonical_bytes(build_registry())
    if args.check:
        if not args.output.is_file() or args.output.read_bytes() != expected:
            print(f"external hypothesis registry is stale: {args.output}")
            return 1
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(expected)

    try:
        ratchet = load_json(args.ratchet)
        schema = load_json(args.schema)
        registry = load_json(args.output) if args.check else build_registry()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error)
        return 1
    errors = validate_schema_guard(schema) + validate_registry(registry, ratchet)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"external hypotheses: {len(registry['hypotheses'])} UNVERIFIED; parity exports: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
