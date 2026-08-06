#!/usr/bin/env python3
"""Project the seven exact native flight runs onto canonical completion gates.

The calibrated suite is deliberately candidate evidence.  This adapter validates
its two cold runs and framebuffer bytes, compares a native trace with an already
registered canonical web trace when one exists, and then reports what the
authoritative clean-room completion matrix accepts.

It never changes ``engine_implementation.json``, the runtime trace contract, or
the visual checkpoint ledger.  Those existing validators remain the only
promotion authorities; consequently a candidate-only native suite can diagnose
a match but cannot turn a completion item green by itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Callable

try:
    from tools.miel_vliegt import flight_cleanroom_completion as completion
    from tools.miel_vliegt import flight_trace_differential as differential
    from tools.miel_vliegt import hangover_probe
    from tools.miel_vliegt import native_scenario_artifacts as artifacts
    from tools.miel_vliegt import verify_flight_runtime_contract as runtime_validator
except ModuleNotFoundError:
    import flight_cleanroom_completion as completion
    import flight_trace_differential as differential
    import hangover_probe
    import native_scenario_artifacts as artifacts
    import verify_flight_runtime_contract as runtime_validator


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "miel-vliegt-flight-scenario-completion-adapter"
VERSION = 1
NATIVE_SUITE_PROTOCOL = "miel-vliegt-native-semantic-calibrated-suite-run"
NATIVE_SUITE_VERSION = 2
NATIVE_SUITE_STATUS = "REPRODUCIBLE_CANDIDATE_ONLY"
SHA256 = re.compile(r"^[0-9a-f]{64}$")

EXACT_PROJECTION_FIELDS = (
    "observation_profile",
    "semantic_sha256",
    "framebuffer_raw_sha256",
    "framebuffer_rgba_sha256",
    "runtime_initial_state",
    "flight_activation_rng",
    "flight_activation_clock",
    "particle_activation",
    "particle_lifecycle",
    "render_presentation",
    "shadow_render",
    "shadow_camera_render",
    "shadow_render_room",
    "shadow_visible_objects",
    "shadow_visible_polygons",
    "shadow_polygon_render",
    "shadow_world_relation",
    "shadow_rotation_setter",
)

EXACT_SUMMARY_HASH_FIELDS = (
    "semantic_sha256",
    "framebuffer_raw_sha256",
    "framebuffer_rgba_sha256",
    "flight_activation_rng_sha256",
    "flight_activation_clock_sha256",
    "particle_lifecycle_sha256",
    "particle_activation_sha256",
    "render_presentation_sha256",
    "shadow_render_sha256",
    "shadow_camera_render_sha256",
    "shadow_render_room_sha256",
    "shadow_visible_objects_sha256",
    "shadow_visible_polygons_sha256",
    "shadow_polygon_render_sha256",
    "shadow_world_relation_sha256",
    "shadow_rotation_setter_sha256",
)

EXTRACTORS: dict[str, Callable[[Path], dict[str, Any]]] = {
    "flight_activation_rng": artifacts.extract_flight_activation_rng,
    "flight_activation_clock": artifacts.extract_flight_activation_clock,
    "particle_activation": artifacts.extract_particle_activation_lifecycle,
    "particle_lifecycle": artifacts.extract_particle_lifecycle,
    "render_presentation": artifacts.extract_render_presentation,
    "shadow_render": artifacts.extract_shadow_render,
    "shadow_camera_render": artifacts.extract_shadow_camera_render,
    "shadow_render_room": artifacts.extract_shadow_render_room,
    "shadow_visible_objects": artifacts.extract_shadow_visible_objects,
    "shadow_visible_polygons": artifacts.extract_shadow_visible_polygons,
    "shadow_polygon_render": artifacts.extract_shadow_polygon_render,
    "shadow_world_relation": artifacts.extract_shadow_world_relation,
    "shadow_rotation_setter": artifacts.extract_shadow_rotation_setter,
}

CHECKPOINT_SCENARIOS = {
    checkpoint: tuple(sorted(specification["trace_scenarios"]))
    for checkpoint, specification in runtime_validator.RELEASE_GATES.items()
}

# These are dependency projections, not equivalence claims.  A target still
# passes only when flight_cleanroom_completion.py says it is COMPLETE.
SUBSYSTEM_CHECKPOINTS = {
    "input": ("controls.native_response",),
    "physics_collision": (
        "physics.native_trajectories",
        "systems.native_response",
        "collision.native_response",
    ),
    "rendering": (
        "camera.native_response",
        "rendering.native_pixels",
    ),
}
ASSET_CHECKPOINTS = {
    "native_pixels": ("rendering.native_pixels",),
}


class AdapterError(ValueError):
    """The supplied candidate or canonical authority is malformed."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise AdapterError("adapter evidence is not canonical JSON") from error


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterError(f"{label} is not readable JSON: {path}") from error
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must contain an object")
    return value


def _strict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = set(value) if isinstance(value, dict) else set()
        raise AdapterError(
            f"{label} fields differ: missing={sorted(fields - actual)} "
            f"unknown={sorted(actual - fields)}"
        )
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise AdapterError(f"{label} must be a lowercase SHA-256")
    return value


def _below(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise AdapterError(f"{label} must be a relative path")
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise AdapterError(f"{label} escapes its artifact root") from error
    if not path.is_file():
        raise AdapterError(f"{label} is missing: {relative}")
    return path


def _bundle_directory(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise AdapterError(f"{label} must be a canonical bundle-relative path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or pure.as_posix() != relative \
            or any(part in {"", ".", ".."} for part in pure.parts):
        raise AdapterError(f"{label} must be a canonical bundle-relative path")
    root = root.resolve()
    candidate = root
    for part in pure.parts:
        candidate /= part
        if candidate.is_symlink():
            raise AdapterError(f"{label} must not contain symlink components")
    path = candidate.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise AdapterError(f"{label} escapes its artifact bundle") from error
    if not path.is_dir():
        raise AdapterError(f"{label} is missing: {relative}")
    return path


def _repo_file(root: Path, reference: Any, label: str) -> Path:
    if not isinstance(reference, str) or not reference:
        raise AdapterError(f"{label} must be a repository reference")
    return _below(root, reference.split("#", 1)[0], label)


def _validate_projection(
    receipt: dict[str, Any], log_path: Path, profile: dict[str, Any],
) -> None:
    runtime_initial_state = artifacts.extract_bound_runtime_initial_state(log_path)
    if receipt["runtime_initial_state"] != runtime_initial_state:
        raise AdapterError("exact native runtime initial-state readback drifted")
    for field, extractor in EXTRACTORS.items():
        if field not in profile["applicable_receipt_channels"]:
            if receipt[field] != _not_applicable(profile, field):
                raise AdapterError(
                    f"exact native omitted-channel marker drifted: {field}"
                )
        elif receipt[field] != extractor(log_path):
            raise AdapterError(f"exact native projection drifted: {field}")


def _not_applicable(profile: dict[str, Any], channel: str) -> dict[str, str]:
    return {
        "status": "NOT_APPLICABLE",
        "profile_id": profile["id"],
        "channel": channel,
        "reason": "omitted_by_observation_profile",
    }


def _summary_channel(
    value: Any, profile: dict[str, Any], channel: str,
) -> Any:
    if channel not in profile["applicable_receipt_channels"]:
        marker = _not_applicable(profile, channel)
        if value != marker:
            raise AdapterError(f"omitted exact channel is not N/A: {channel}")
        return marker
    if isinstance(value, str):
        return _hash(value, channel)
    if isinstance(value, dict):
        return _hash(value.get("sha256"), channel)
    raise AdapterError(f"applicable exact channel has no SHA-256: {channel}")


def _framebuffer_checkpoint_id(scenario: dict[str, Any]) -> str:
    rows = [
        row["id"] for row in scenario["checkpoints"]
        if "render.framebuffer" in row["required_channels"]
    ]
    if len(rows) != 1:
        raise AdapterError(
            f"{scenario['id']}: scenario has no unique framebuffer checkpoint"
        )
    return rows[0]


def _validate_exact_run(
    *,
    output_root: Path,
    suite_root: Path,
    suite_manifest_sha256: str,
    backend_id: str,
    executable_sha256: str,
    scenario: dict[str, Any],
    relative: str,
) -> dict[str, Any]:
    path = _below(output_root, relative, f"{scenario['id']} exact run")
    expected_fields = {
        "status", "production_claim", "scenario", "semantic_sha256",
        "observer_log_sha256", "framebuffer_raw_sha256",
        "framebuffer_rgba_sha256", "runtime_initial_state",
        "observation_profile", "hook_observation_profile",
        *EXTRACTORS,
    }
    receipt = _strict(_load(path, "exact native run"), expected_fields, "exact native run")
    if receipt["status"] != "CANDIDATE_ONLY" \
            or receipt["production_claim"] is not False \
            or receipt["scenario"] != scenario["id"]:
        raise AdapterError(f"{scenario['id']}: exact run identity is not candidate-only")

    run_root = path.parent
    observer = run_root / f"native-observer-{backend_id}.log"
    metadata_path = run_root / f"native-frame-{scenario['id']}-{backend_id}.json"
    raw_path = metadata_path.with_suffix(".raw")
    manifest = artifacts.load_scenario_suite_manifest(suite_root / "suite-spec.json")
    entry = artifacts.scenario_suite_entry(manifest, scenario["id"])
    profile = artifacts.validate_scenario_observation_profile(
        entry["observation_profile"], scenario_id=scenario["id"],
    )
    if not observer.is_file():
        raise AdapterError(f"{scenario['id']}: observer log is missing")
    profile_receipt = receipt["observation_profile"]
    if not isinstance(profile_receipt, dict) \
            or profile_receipt.get("sha256") != \
                artifacts.observation_profile_sha256(
                    profile, scenario_id=scenario["id"],
                ) \
            or {
                key: value for key, value in profile_receipt.items()
                if key != "sha256"
            } != profile:
        raise AdapterError(f"{scenario['id']}: observation profile drifted")
    hook_profile = hangover_probe.validate_scenario_observation_profile_receipt(
        observer, profile,
    )
    if receipt["hook_observation_profile"] != hook_profile:
        raise AdapterError(f"{scenario['id']}: hook observation profile drifted")
    if artifacts.sha256_file(suite_root / "suite-spec.json") != suite_manifest_sha256:
        raise AdapterError("calibrated suite manifest drifted during exact validation")
    validated_trace = artifacts.validate_completed_scenario_trace(
        observer, scenario, root=suite_root,
    )
    if receipt["semantic_sha256"] != validated_trace["semantic_sha256"] \
            or receipt["observer_log_sha256"] != artifacts.sha256_file(observer):
        raise AdapterError(f"{scenario['id']}: observer semantic identity drifted")

    native_metadata_path = metadata_path.with_name(
        f"{metadata_path.stem}.native.json"
    )
    native_raw_path = native_metadata_path.with_name(
        native_metadata_path.name.removesuffix(".json") + ".raw"
    )
    framebuffer_artifacts = (
        (metadata_path, "framebuffer metadata"),
        (raw_path, "framebuffer bytes"),
        (native_metadata_path, "native framebuffer metadata"),
        (native_raw_path, "native framebuffer bytes"),
    )
    if profile["framebuffer_required"]:
        for artifact_path, label in framebuffer_artifacts:
            if not artifact_path.is_file():
                raise AdapterError(f"{scenario['id']}: {label} is missing")
        metadata = artifacts.load_framebuffer_metadata(metadata_path)
        replay_path = suite_root / entry["native_replay"]["path"]
        if metadata["scenario"] != scenario["id"] \
                or metadata["scenario_sha256"] != artifacts.sha256_file(replay_path) \
                or metadata["tick"] != entry["capture_tick"]:
            raise AdapterError(f"{scenario['id']}: framebuffer/scenario binding drifted")
        raw = raw_path.read_bytes()
        rgba_sha256 = hashlib.sha256(
            artifacts.canonicalize_native_framebuffer(metadata, raw)
        ).hexdigest()
        if receipt["framebuffer_raw_sha256"] != metadata["raw_sha256"] \
                or receipt["framebuffer_rgba_sha256"] != rgba_sha256:
            raise AdapterError(f"{scenario['id']}: framebuffer identity drifted")
        framebuffer_evidence = artifacts.build_native_framebuffer_evidence(
            metadata_path,
            root=run_root,
            checkpoint_id=_framebuffer_checkpoint_id(scenario),
        )
    else:
        unexpected = [
            artifact_path.name
            for artifact_path, _label in framebuffer_artifacts
            if artifact_path.exists()
        ]
        if unexpected:
            raise AdapterError(
                f"{scenario['id']}: omitted framebuffer artifacts exist: "
                + ", ".join(unexpected)
            )
        for field in ("framebuffer_raw_sha256", "framebuffer_rgba_sha256"):
            if receipt[field] != _not_applicable(profile, "framebuffer"):
                raise AdapterError(
                    f"{scenario['id']}: omitted framebuffer marker drifted"
                )
        framebuffer_evidence = None

    _validate_projection(receipt, observer, profile)
    native_trace = differential.native_semantic_to_trace(
        validated_trace,
        {
            "executable_sha256": executable_sha256,
            "exact_run_sha256": _sha256(path),
            "evidence_status": "REPRODUCIBLE_CANDIDATE_ONLY",
            "production_claim": False,
        },
        scenario,
        framebuffer_evidence,
    )
    return {
        "path": str(path),
        "sha256": _sha256(path),
        "receipt": receipt,
        "native_trace": native_trace,
        "framebuffer_metadata_sha256": (
            _sha256(metadata_path)
            if profile["framebuffer_required"]
            else _not_applicable(profile, "framebuffer")
        ),
        "framebuffer_raw_sha256": (
            _sha256(raw_path)
            if profile["framebuffer_required"]
            else _not_applicable(profile, "framebuffer")
        ),
    }


def validate_native_suite(path: Path) -> dict[str, Any]:
    """Validate all seven repeat pairs and their raw framebuffer identities."""

    path = path.resolve()
    output_root = path.parent
    value = _strict(_load(path, "calibrated native suite"), {
        "schema", "protocol", "status", "production_claim", "scenario_order",
        "provenance", "prefix", "calibration", "calibrated_suite",
        "exact_runs", "blocker",
    }, "calibrated native suite")
    if value["schema"] != NATIVE_SUITE_VERSION \
            or value["protocol"] != NATIVE_SUITE_PROTOCOL \
            or value["status"] != NATIVE_SUITE_STATUS \
            or value["production_claim"] is not False \
            or value["scenario_order"] != list(artifacts.SCENARIO_ID_ORDER) \
            or value["blocker"] is not None:
        raise AdapterError("calibrated suite is not the canonical candidate-only suite")
    calibrated = _strict(value["calibrated_suite"], {
        "path", "manifest_sha256", "scenario_order",
        "flight_activation_rng_sha256",
    }, "calibrated_suite")
    if calibrated["scenario_order"] != list(artifacts.SCENARIO_ID_ORDER):
        raise AdapterError("calibrated suite scenario order drifted")
    suite_root = _bundle_directory(
        output_root.parent,
        calibrated["path"],
        "calibrated_suite.path",
    )
    manifest_path = suite_root / "suite-spec.json"
    if not manifest_path.is_file() \
            or _sha256(manifest_path) != _hash(
                calibrated["manifest_sha256"], "calibrated_suite.manifest_sha256"
            ):
        raise AdapterError("calibrated suite manifest hash drifted")
    activation_path = suite_root / "flight-activation-rng.json"
    if not activation_path.is_file() \
            or _sha256(activation_path) != _hash(
                calibrated["flight_activation_rng_sha256"],
                "calibrated_suite.flight_activation_rng_sha256",
            ):
        raise AdapterError("calibrated activation RNG suite hash drifted")
    manifest = artifacts.load_scenario_suite_manifest(manifest_path)
    if manifest["scenario_order"] != list(artifacts.SCENARIO_ID_ORDER):
        raise AdapterError("calibrated suite manifest scenario order drifted")

    provenance = value["provenance"]
    backend = provenance.get("backend") if isinstance(provenance, dict) else None
    backend_id = backend.get("id") if isinstance(backend, dict) else None
    if backend_id not in {"box64", "fex"}:
        raise AdapterError("calibrated suite has no reviewed backend identity")
    paths = provenance.get("paths") if isinstance(provenance, dict) else None
    source = paths.get("source_executable") if isinstance(paths, dict) else None
    executable_sha256 = source.get("sha256") if isinstance(source, dict) else None
    _hash(executable_sha256, "provenance.paths.source_executable.sha256")

    rows = value["exact_runs"]
    if not isinstance(rows, list) or len(rows) != len(artifacts.SCENARIO_ID_ORDER):
        raise AdapterError("calibrated suite must contain seven exact-run pairs")
    results: dict[str, Any] = {}
    used_run_paths: set[str] = set()
    for expected_id, row in zip(artifacts.SCENARIO_ID_ORDER, rows, strict=True):
        fields = {
            "id", "run_1", "run_2", "observation_profile",
            *EXACT_SUMMARY_HASH_FIELDS,
        }
        row = _strict(row, fields, f"exact_runs[{expected_id}]")
        if row["id"] != expected_id:
            raise AdapterError("calibrated exact-run order drifted")
        run_paths = {row["run_1"], row["run_2"]}
        if len(run_paths) != 2 or used_run_paths & run_paths:
            raise AdapterError("calibrated exact-run references are not independent")
        used_run_paths.update(run_paths)
        scenario_entry = artifacts.scenario_suite_entry(manifest, expected_id)
        scenario = artifacts.load_scenario(
            suite_root / scenario_entry["scenario"]["path"], root=suite_root,
        )
        pair = [
            _validate_exact_run(
                output_root=output_root,
                suite_root=suite_root,
                suite_manifest_sha256=calibrated["manifest_sha256"],
                backend_id=backend_id,
                executable_sha256=executable_sha256,
                scenario=scenario,
                relative=row[field],
            )
            for field in ("run_1", "run_2")
        ]
        first = pair[0]["receipt"]
        second = pair[1]["receipt"]
        if any(first[field] != second[field] for field in EXACT_PROJECTION_FIELDS):
            raise AdapterError(f"{expected_id}: cold exact native repeats drifted")
        expected_summary = {
            "semantic_sha256": first["semantic_sha256"],
            "framebuffer_raw_sha256": _summary_channel(
                first["framebuffer_raw_sha256"],
                first["observation_profile"], "framebuffer",
            ),
            "framebuffer_rgba_sha256": _summary_channel(
                first["framebuffer_rgba_sha256"],
                first["observation_profile"], "framebuffer",
            ),
            **{
                f"{field}_sha256": _summary_channel(
                    first[field], first["observation_profile"], field,
                )
                for field in EXTRACTORS
            },
        }
        if row["observation_profile"] != first["observation_profile"]:
            raise AdapterError(
                f"{expected_id}: exact suite observation profile drifted"
            )
        for field in EXACT_SUMMARY_HASH_FIELDS:
            if field == "semantic_sha256" \
                    or field.startswith("flight_activation_"):
                _hash(row[field], f"{expected_id}.{field}")
            if row[field] != expected_summary[field]:
                raise AdapterError(f"{expected_id}: exact suite summary drifted at {field}")
        results[expected_id] = {
            "scenario": scenario,
            "run_1": pair[0],
            "run_2": pair[1],
        }
    return {
        "path": str(path),
        "sha256": _sha256(path),
        "status": value["status"],
        "production_claim": value["production_claim"],
        "suite_root": str(suite_root),
        "manifest_sha256": calibrated["manifest_sha256"],
        "executable_sha256": executable_sha256,
        "scenarios": results,
    }


def _scenario_diagnostics(
    native: dict[str, Any],
    runtime_trace: dict[str, Any],
    root: Path,
) -> list[dict[str, Any]]:
    trace_rows = {
        row["id"]: row for row in runtime_trace["scenarios"]
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    rows = []
    for scenario_id in artifacts.SCENARIO_ID_ORDER:
        canonical = trace_rows[scenario_id]
        web_reference = canonical.get("web_output")
        domain_rows = {}
        if not web_reference:
            for domain in canonical["domains"]:
                domain_rows[domain] = {
                    "status": "BLOCKED",
                    "reason": "WEB_TRACE_MISSING_IN_CANONICAL_RUNTIME_CONTRACT",
                }
            web = None
        else:
            web_path = _repo_file(
                root, web_reference, f"{scenario_id}.web_output",
            )
            web = differential.load_trace(web_path)
            native_trace = native["scenarios"][scenario_id]["run_1"]["native_trace"]
            for domain in canonical["domains"]:
                report = differential.compare_trace_domain(
                    native_trace, web, domain,
                )
                domain_rows[domain] = {
                    "status": "MATCH_CANDIDATE_ONLY" if report.matches else "DIVERGED",
                    "frames_compared": report.frames_compared,
                    "reason": (
                        "NATIVE_SUITE_IS_CANDIDATE_ONLY"
                        if report.matches else report.divergence.reason
                    ),
                }
        rows.append({
            "id": scenario_id,
            "native_status": "EXACT_REPEAT_VALIDATED_CANDIDATE_ONLY",
            "web_output": web_reference,
            "web_trace_available": web is not None,
            "promotion_allowed": False,
            "promotion_blocker": "REVIEWED_PRODUCTION_NATIVE_OBSERVER_RECEIPT_MISSING",
            "domains": domain_rows,
        })
    return rows


def _dependency_blockers(
    checkpoints: tuple[str, ...],
    checkpoint_rows: dict[str, dict[str, Any]],
    diagnostics: dict[str, dict[str, Any]],
) -> list[str]:
    blockers = []
    for checkpoint in checkpoints:
        row = checkpoint_rows[checkpoint]
        if row.get("status") == "BLOCKED_NATIVE_REFERENCE":
            blockers.append(f"CANONICAL_RUNTIME_CHECKPOINT_BLOCKED:{checkpoint}")
        for scenario_id in CHECKPOINT_SCENARIOS[checkpoint]:
            domain = runtime_validator.RELEASE_GATES[checkpoint]["domain"]
            diagnostic = diagnostics[scenario_id]["domains"].get(domain)
            if diagnostic is None:
                blockers.append(
                    f"SCENARIO_DOMAIN_NOT_CAPTURED:{scenario_id}:{domain}"
                )
            elif diagnostic["status"] == "BLOCKED":
                blockers.append(
                    f"WEB_TRACE_MISSING:{scenario_id}:{domain}"
                )
            elif diagnostic["status"] == "DIVERGED":
                blockers.append(
                    f"NATIVE_WEB_DIVERGED:{scenario_id}:{domain}"
                )
    blockers.append("REVIEWED_PRODUCTION_NATIVE_OBSERVER_RECEIPT_MISSING")
    return list(dict.fromkeys(blockers))


def _completion_dimension(
    matrix: dict[str, Any], identifier: str,
) -> dict[str, Any]:
    rows = [
        row for row in matrix["dimensions"]
        if row.get("id") == identifier
    ]
    if len(rows) != 1:
        raise AdapterError(f"completion matrix has no unique {identifier} dimension")
    return rows[0]


def _project_dimension(
    *,
    matrix: dict[str, Any],
    identifier: str,
    checkpoint_mapping: dict[str, tuple[str, ...]],
    checkpoint_rows: dict[str, dict[str, Any]],
    diagnostics: dict[str, dict[str, Any]],
    visual: dict[str, Any],
) -> dict[str, Any]:
    dimension = _completion_dimension(matrix, identifier)
    items = []
    for canonical in dimension["items"]:
        target = canonical["id"]
        if canonical["status"] == "COMPLETE":
            status = "PASS"
            blockers: list[str] = []
        else:
            status = "BLOCKED"
            checkpoints = checkpoint_mapping.get(target)
            if checkpoints is None:
                blockers = [
                    f"NO_CANONICAL_SCENARIO_TO_COMPLETION_BOUNDARY:{identifier}:{target}",
                ]
            else:
                blockers = _dependency_blockers(
                    checkpoints, checkpoint_rows, diagnostics,
                )
                if identifier in {"gameplay_runtimes", "subsystems"}:
                    blockers.append(
                        f"CANONICAL_ENGINE_EQUIVALENCE_RECEIPT_MISSING:{target}"
                    )
                if identifier == "assets" and target == "native_pixels":
                    incomplete = [
                        row["id"] for row in visual["checkpoints"]
                        if row.get("status") != "PIXEL_EQUIVALENT"
                    ]
                    if incomplete:
                        blockers.append(
                            "VISUAL_CHECKPOINTS_INCOMPLETE:"
                            f"{len(incomplete)}/{len(visual['checkpoints'])}"
                        )
            if canonical.get("blocker"):
                blockers.insert(0, f"CANONICAL_COMPLETION:{canonical['blocker']}")
            blockers = list(dict.fromkeys(blockers))
        items.append({
            "id": target,
            "status": status,
            "canonical_status": canonical["status"],
            "canonical_subject_sha256": canonical["subject_sha256"],
            "canonical_proof_sha256": canonical["proof_sha256"],
            "checkpoints": list(checkpoint_mapping.get(target, ())),
            "blockers": blockers,
        })
    return {
        "id": identifier,
        "status": "PASS" if all(row["status"] == "PASS" for row in items) else "BLOCKED",
        "items": items,
        "counts": dict(sorted(Counter(row["status"] for row in items).items())),
    }


def build_report(
    native_suite_path: Path,
    *,
    root: Path = ROOT,
    native_evidence: dict[str, Any] | None = None,
    completion_matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one source-bound, fail-closed projection report."""

    root = root.resolve()
    native = (
        validate_native_suite(native_suite_path)
        if native_evidence is None else native_evidence
    )
    runtime = _load(
        root / "content/miel_vliegt/flight_runtime_parity_contract.json",
        "runtime parity contract",
    )
    trace = _load(
        root / "content/miel_vliegt/flight_runtime_trace_contract.json",
        "runtime trace contract",
    )
    runtime_errors = runtime_validator.validate(runtime, trace, root)
    if runtime_errors:
        raise AdapterError(
            "canonical runtime authority is invalid: " + "; ".join(runtime_errors)
        )
    expected_executable = trace.get("source_identity", {}).get("executable_sha256")
    if native.get("executable_sha256") != expected_executable:
        raise AdapterError(
            "native suite executable identity differs from the canonical runtime contract"
        )
    matrix = (
        completion.build_from_root(root)
        if completion_matrix is None else completion_matrix
    )
    visual = _load(
        root / "content/miel_vliegt/visual_checkpoint_inventory.json",
        "visual checkpoint inventory",
    )
    diagnostics_list = _scenario_diagnostics(native, trace, root)
    diagnostics = {row["id"]: row for row in diagnostics_list}
    checkpoint_rows = {
        row["id"]: row for row in runtime["checkpoints"]
        if row.get("id") in runtime_validator.RELEASE_GATES
    }

    dimensions = [
        _project_dimension(
            matrix=matrix,
            identifier="gameplay_runtimes",
            checkpoint_mapping={},
            checkpoint_rows=checkpoint_rows,
            diagnostics=diagnostics,
            visual=visual,
        ),
        _project_dimension(
            matrix=matrix,
            identifier="subsystems",
            checkpoint_mapping=SUBSYSTEM_CHECKPOINTS,
            checkpoint_rows=checkpoint_rows,
            diagnostics=diagnostics,
            visual=visual,
        ),
        _project_dimension(
            matrix=matrix,
            identifier="assets",
            checkpoint_mapping=ASSET_CHECKPOINTS,
            checkpoint_rows=checkpoint_rows,
            diagnostics=diagnostics,
            visual=visual,
        ),
    ]
    item_count = sum(len(row["items"]) for row in dimensions)
    passed = sum(
        item["status"] == "PASS"
        for dimension in dimensions for item in dimension["items"]
    )
    report = {
        "schema": VERSION,
        "protocol": PROTOCOL,
        "status": "PASS" if passed == item_count else "BLOCKED",
        "promotion_allowed": False,
        "policy": {
            "authoritative_status":
                "tools/miel_vliegt/flight_cleanroom_completion.py",
            "runtime_comparator":
                "tools/miel_vliegt/flight_trace_differential.py",
            "candidate_native_suite_can_promote": False,
            "manual_green_status": False,
            "missing_or_unmapped": "BLOCKED",
        },
        "sources": {
            "native_suite": {
                "path": native["path"],
                "sha256": native["sha256"],
                "status": native["status"],
                "production_claim": native["production_claim"],
                "executable_sha256": native["executable_sha256"],
            },
            "runtime": {
                "path": "content/miel_vliegt/flight_runtime_parity_contract.json",
                "sha256": _sha256(
                    root / "content/miel_vliegt/flight_runtime_parity_contract.json"
                ),
            },
            "runtime_trace": {
                "path": "content/miel_vliegt/flight_runtime_trace_contract.json",
                "sha256": _sha256(
                    root / "content/miel_vliegt/flight_runtime_trace_contract.json"
                ),
            },
            "visual_checkpoints": {
                "path": "content/miel_vliegt/visual_checkpoint_inventory.json",
                "sha256": _sha256(
                    root / "content/miel_vliegt/visual_checkpoint_inventory.json"
                ),
            },
            "completion_matrix_sha256": _canonical_sha256(matrix),
        },
        "summary": {
            "scenarios": len(diagnostics_list),
            "dimensions": len(dimensions),
            "items": item_count,
            "pass": passed,
            "blocked": item_count - passed,
        },
        "scenarios": diagnostics_list,
        "dimensions": dimensions,
    }
    report["report_sha256"] = _canonical_sha256(report)
    return report


def validate_report(report: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema", "protocol", "status", "promotion_allowed", "policy",
        "sources", "summary", "scenarios", "dimensions", "report_sha256",
    }
    _strict(report, required, "adapter report")
    if report["schema"] != VERSION or report["protocol"] != PROTOCOL \
            or report["promotion_allowed"] is not False:
        raise AdapterError("unsupported or promotable adapter report")
    expected_hash = report["report_sha256"]
    payload = {key: value for key, value in report.items() if key != "report_sha256"}
    if expected_hash != _canonical_sha256(payload):
        raise AdapterError("adapter report hash drifted")
    scenarios = report["scenarios"]
    dimensions = report["dimensions"]
    if not isinstance(scenarios, list) \
            or [row.get("id") for row in scenarios] \
            != list(artifacts.SCENARIO_ID_ORDER):
        raise AdapterError("adapter report scenario inventory drifted")
    if not isinstance(dimensions, list) \
            or [row.get("id") for row in dimensions] \
            != ["gameplay_runtimes", "subsystems", "assets"]:
        raise AdapterError("adapter report dimension inventory drifted")
    items = [item for row in dimensions for item in row.get("items", [])]
    identities = [
        (dimension["id"], item.get("id"))
        for dimension in dimensions for item in dimension.get("items", [])
    ]
    if len(items) != 22 or len(set(identities)) != 22 \
            or any(identifier is None for _dimension, identifier in identities):
        raise AdapterError("adapter report completion item inventory drifted")
    passed = sum(item.get("status") == "PASS" for item in items)
    summary = report["summary"]
    if summary != {
        "scenarios": 7,
        "dimensions": 3,
        "items": len(items),
        "pass": passed,
        "blocked": len(items) - passed,
    }:
        raise AdapterError("adapter report summary drifted")
    expected_status = "PASS" if passed == len(items) else "BLOCKED"
    if report["status"] != expected_status:
        raise AdapterError("adapter report status drifted")
    return report


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--native-suite", required=True, type=Path,
        help="path to calibrated-suite-run.json",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--require-all", action="store_true",
        help="return non-zero while any mapped completion item is blocked",
    )
    args = parser.parse_args(argv)
    try:
        report = validate_report(build_report(args.native_suite))
        _write(args.output, report)
    except (AdapterError, artifacts.ArtifactError, OSError, ValueError) as error:
        print(f"INVALID FLIGHT SCENARIO EVIDENCE: {error}", file=sys.stderr)
        return 2
    print(
        f"{report['status']}: {report['summary']['pass']}/"
        f"{report['summary']['items']} canonical completion items pass"
    )
    if args.require_all and report["status"] != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
