#!/usr/bin/env python3
"""Verify hash-addressed production-browser flight captures.

This gate accepts only traces emitted through the interactive flight-world
step boundary and a real rasterizing WebGL browser. It produces a diagnostic
receipt; native equivalence remains a separate differential and review gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import sys
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import native_scenario_artifacts as scenarios
except ModuleNotFoundError:
    import native_scenario_artifacts as scenarios


PROTOCOL = "miel-vliegt-production-browser-flight-capture"
REPORT_PROTOCOL = f"{PROTOCOL}-verification"
BOUNDARY = "FlightWorldState.stepProductionFlightFrame"
STATUS = "CAPTURED_PRODUCTION_WEB_CANDIDATE"
SHA256 = set("0123456789abcdef")
REPO_ROOT = Path(__file__).resolve().parents[2]
AIRPLANE_CONTRACT = REPO_ROOT / "content/miel_vliegt/uds_barn_contracts.json"
PARTS_CONTRACT = REPO_ROOT / "content/miel_vliegt/uds_flight_parts.json"
MATERIAL_CONTRACT = REPO_ROOT / "content/miel_vliegt/ccf_material_contract.json"
CAMERA_POLICY = "web-chase-provisional-v1"
INITIAL_STATE_POLICY = "CALIBRATED_NATIVE_RUNTIME_PRECONDITION"
RUNTIME_PROJECTION = "native-runtime-state-precondition-v1"


class BrowserCaptureError(ValueError):
    pass


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BrowserCaptureError(
            f"{path}: invalid JSON at line {error.lineno}",
        ) from error


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in SHA256 for character in value)
    )


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BrowserCaptureError(f"{label} has an invalid shape")
    return value


def _artifact_root(manifest_path: Path) -> Path:
    if manifest_path.parent.name != "manifests":
        raise BrowserCaptureError("capture manifest must live below manifests/")
    return manifest_path.parent.parent


def _capture_subject_contract() -> tuple[dict[str, Any], list[dict[str, str]]]:
    airplane = _load(AIRPLANE_CONTRACT)
    parts = _load(PARTS_CONTRACT)
    materials = _load(MATERIAL_CONTRACT)
    graph = airplane.get("default_airplane")
    if not isinstance(graph, list) or not graph:
        raise BrowserCaptureError("source default airplane contract is invalid")
    part_ids = [link.get("part_id") for link in graph if isinstance(link, dict)]
    if len(part_ids) != len(graph) or parts.get("default_airplane") != part_ids:
        raise BrowserCaptureError("source default airplane contracts disagree")
    selected = {
        part["part_id"]: part
        for part in parts.get("parts", [])
        if isinstance(part, dict) and part.get("part_id") in set(part_ids)
    }
    if set(selected) != set(part_ids):
        raise BrowserCaptureError("source default airplane parts are incomplete")
    texture_names = sorted({
        material["texture"]
        for part_id in part_ids
        for material in selected[part_id].get("materials", {}).values()
        if isinstance(material, dict) and material.get("texture")
    })
    by_id = {
        entry.get("id", "").lower(): entry
        for entry in materials.get("textures", [])
        if isinstance(entry, dict)
    }
    catalog = []
    for name in texture_names:
        entry = by_id.get(name.lower())
        if entry is None:
            raise BrowserCaptureError(f"source texture contract is missing {name}")
        catalog.append({
            "id": entry["id"],
            "asset_url": entry["asset_url"],
            "png_sha256": entry["png_sha256"],
            "decoded_rgba_sha256": entry["decoded_rgba_sha256"],
            "width": entry["width"],
            "height": entry["height"],
        })
    assets = [{
        "id": entry["id"],
        "asset_url": entry["asset_url"],
        "observed_sha256": entry["png_sha256"],
    } for entry in catalog]
    return {
        "airplane_graph": graph,
        "airplane_graph_sha256": scenarios.canonical_sha256(graph),
        "texture_catalog": catalog,
        "texture_catalog_sha256": scenarios.canonical_sha256(catalog),
        "texture_readiness": {
            "requested": len(catalog),
            "loaded": len(catalog),
            "failed": 0,
        },
        "camera_policy": CAMERA_POLICY,
        "native_camera_match": False,
    }, assets


def _validate_capture_subject(
    subject: Any,
    texture_assets: Any,
    texture_assets_sha256: Any,
    label: str,
) -> None:
    expected_subject, expected_assets = _capture_subject_contract()
    subject = _exact(subject, {
        "airplane_graph", "airplane_graph_sha256",
        "texture_catalog", "texture_catalog_sha256",
        "texture_readiness", "camera_policy", "native_camera_match",
    }, label)
    if subject != expected_subject:
        raise BrowserCaptureError(
            f"{label} differs from the source default airplane or texture contract",
        )
    if texture_assets != expected_assets \
            or texture_assets_sha256 != scenarios.canonical_sha256(expected_assets):
        raise BrowserCaptureError(f"{label} texture assets differ from source bytes")


def _validate_trace(trace: Any, label: str) -> dict[str, Any]:
    trace = _exact(trace, {
        "protocol", "version", "capture_kind", "source", "scenario", "frames",
    }, label)
    if trace["protocol"] != "miel-vliegt-flight-frame-trace" \
            or trace["version"] != 2 or trace["capture_kind"] != "web":
        raise BrowserCaptureError(f"{label} uses an unsupported trace protocol")
    if not isinstance(trace["source"], dict) or not trace["source"] \
            or not isinstance(trace["scenario"], dict):
        raise BrowserCaptureError(f"{label} has invalid provenance")
    frames = trace["frames"]
    if not isinstance(frames, list) or not frames:
        raise BrowserCaptureError(f"{label} has no frames")
    for index, frame in enumerate(frames):
        frame = _exact(frame, {
            "frame", "time_seconds", "inputs", "events",
            "numeric", "camera", "render",
        }, f"{label} frame {index}")
        if frame["frame"] != index or not _finite(frame["time_seconds"]):
            raise BrowserCaptureError(f"{label} has an invalid frame at {index}")
        _validate_inputs(frame["inputs"], f"{label} frame {index} inputs")
        _validate_json_array(frame["events"], f"{label} frame {index} events")
        if frame["events"]:
            raise BrowserCaptureError(
                f"{label} frame {index} invented an unobserved event channel",
            )
        _validate_numeric(frame["numeric"], f"{label} frame {index} numeric")
        _validate_camera(frame["camera"], f"{label} frame {index} camera")
        _validate_render(frame["render"], f"{label} frame {index} render")
    return trace


def _finite(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def _non_negative_integer(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _validate_json(value: Any, label: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if _finite(value):
        return
    if isinstance(value, list):
        for index, entry in enumerate(value):
            _validate_json(entry, f"{label}[{index}]")
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, entry in value.items():
            _validate_json(entry, f"{label}.{key}")
        return
    raise BrowserCaptureError(f"{label} is not canonical JSON")


def _validate_json_array(value: Any, label: str) -> None:
    if not isinstance(value, list):
        raise BrowserCaptureError(f"{label} must be an array")
    _validate_json(value, label)


def _validate_inputs(value: Any, label: str) -> dict[str, bool]:
    value = _exact(value, set(scenarios.CONTROL_KEYS), label)
    if any(not isinstance(value[key], bool) for key in scenarios.CONTROL_KEYS):
        raise BrowserCaptureError(f"{label} must contain exact boolean controls")
    return value


def _vector(value: Any, length: int, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, list) or len(value) != length \
            or any(not _finite(entry) for entry in value):
        raise BrowserCaptureError(
            f"{label} must contain exactly {length} finite values",
        )


def _validate_collisions(value: Any, label: str) -> None:
    value = _exact(value, {"observed", "contacts"}, label)
    if type(value["observed"]) is not bool:
        raise BrowserCaptureError(f"{label}.observed must be boolean")
    _validate_json_array(value["contacts"], f"{label}.contacts")
    if not value["observed"] and value["contacts"]:
        raise BrowserCaptureError(
            f"{label}.contacts requires an observed collision channel",
        )
    required = {
        "kind", "contactPosition", "contactNormal", "relativeVelocity",
        "damage", "landingClassification",
    }
    for index, contact in enumerate(value["contacts"]):
        contact_label = f"{label}.contacts[{index}]"
        contact = _exact(contact, required, contact_label)
        if not isinstance(contact["kind"], str) or not contact["kind"] \
                or not isinstance(contact["landingClassification"], str) \
                or not contact["landingClassification"] \
                or not _finite(contact["damage"]):
            raise BrowserCaptureError(f"{contact_label} is invalid")
        for field in ("contactPosition", "contactNormal", "relativeVelocity"):
            _vector(contact[field], 3, f"{contact_label}.{field}")


def _validate_numeric(value: Any, label: str) -> None:
    value = _exact(value, {"timing", "physics", "collisions"}, label)
    timing = _exact(
        value["timing"],
        {"deltaSeconds", "fixedStepSeconds", "stepIndex"},
        f"{label}.timing",
    )
    if not _finite(timing["deltaSeconds"]) or timing["deltaSeconds"] <= 0 \
            or not _finite(timing["fixedStepSeconds"]) \
            or timing["fixedStepSeconds"] <= 0 \
            or not _non_negative_integer(timing["stepIndex"]):
        raise BrowserCaptureError(f"{label}.timing is invalid")
    physics = _exact(
        value["physics"],
        {"position", "orientation", "velocity", "angularVelocity"},
        f"{label}.physics",
    )
    _vector(physics["position"], 3, f"{label}.physics.position")
    _vector(physics["orientation"], 4, f"{label}.physics.orientation")
    _vector(physics["velocity"], 3, f"{label}.physics.velocity")
    _vector(
        physics["angularVelocity"], 3,
        f"{label}.physics.angularVelocity", nullable=True,
    )
    _validate_collisions(value["collisions"], f"{label}.collisions")


def _validate_camera(value: Any, label: str) -> None:
    value = _exact(value, {
        "projection_matrix", "view_matrix", "vertical_fov_radians",
        "near_clip", "far_clip", "viewport", "control",
    }, label)
    _vector(value["projection_matrix"], 16, f"{label}.projection_matrix")
    _vector(value["view_matrix"], 16, f"{label}.view_matrix")
    if not _finite(value["vertical_fov_radians"]) \
            or value["vertical_fov_radians"] <= 0 \
            or not _finite(value["near_clip"]) or value["near_clip"] <= 0 \
            or not _finite(value["far_clip"]) \
            or value["far_clip"] <= value["near_clip"]:
        raise BrowserCaptureError(f"{label} projection parameters are invalid")
    viewport = _exact(
        value["viewport"], {"x", "y", "width", "height"},
        f"{label}.viewport",
    )
    if viewport != {"x": 0, "y": 0, "width": 640, "height": 480}:
        raise BrowserCaptureError(f"{label}.viewport is not canonical")
    control = value["control"]
    if isinstance(control, dict) and control.get("owner") == "common_location":
        control = _exact(control, {"owner", "state"}, f"{label}.control")
        if not _non_negative_integer(control["state"]):
            raise BrowserCaptureError(f"{label}.control state is invalid")
    elif isinstance(control, dict) and control.get("owner") == "mode_fly":
        control = _exact(control, {
            "owner", "manual_camera_enabled", "move_forward", "move_backward",
        }, f"{label}.control")
        if any(not isinstance(control[field], bool) for field in (
            "manual_camera_enabled", "move_forward", "move_backward",
        )):
            raise BrowserCaptureError(f"{label}.control flags are invalid")
    else:
        raise BrowserCaptureError(f"{label}.control owner is invalid")


def _validate_render(value: Any, label: str) -> None:
    if not isinstance(value, dict) or set(value) not in (
        {"diagnostics"}, {"diagnostics", "pixel_checkpoint"},
    ):
        raise BrowserCaptureError(f"{label} has an invalid shape")
    diagnostics = _exact(value["diagnostics"], {"webgl"}, f"{label}.diagnostics")
    webgl = _exact(diagnostics["webgl"], {
        "drawCalls", "triangles", "bufferUploads", "textureBinds",
    }, f"{label}.diagnostics.webgl")
    if any(not _non_negative_integer(webgl[field]) for field in webgl) \
            or webgl["drawCalls"] <= 0:
        raise BrowserCaptureError(f"{label}.diagnostics.webgl is invalid")
    if "pixel_checkpoint" in value \
            and not _valid_pixel_checkpoint(value["pixel_checkpoint"]):
        raise BrowserCaptureError(f"{label}.pixel_checkpoint is invalid")


def _f32_from_bits(value: str) -> float:
    return struct.unpack(">f", struct.pack(">I", int(value, 16)))[0]


def _expected_input_schedule(scenario: dict[str, Any]) -> list[dict[str, bool]]:
    events_by_tick: dict[int, list[dict[str, Any]]] = {}
    for event in scenario["input_script"]["events"]:
        events_by_tick.setdefault(event["tick"], []).append(event)
    pressed: set[str] = set()
    focus_active = True
    schedule = []
    for tick in range(scenario["input_script"]["tick_count"]):
        for event in events_by_tick.get(tick, []):
            if event["type"] == "focus":
                focus_active = event["active"]
            elif event["action"] == "down":
                pressed.add(event["key"])
            else:
                pressed.remove(event["key"])
        schedule.append({
            key: focus_active and key in pressed
            for key in scenarios.CONTROL_KEYS
        })
    return schedule


def _validate_schedule(
    trace: dict[str, Any], scenario: dict[str, Any], label: str,
) -> None:
    expected_inputs = _expected_input_schedule(scenario)
    elapsed = 0.0
    expected_step = 0
    for index, (frame, clock, inputs) in enumerate(zip(
        trace["frames"],
        scenario["clock_transcript"]["samples"],
        expected_inputs,
        strict=True,
    )):
        delta = _f32_from_bits(clock["dt_f32_bits"])
        elapsed += delta
        expected_step += 1
        if frame["time_seconds"] != elapsed \
                or frame["numeric"]["timing"]["deltaSeconds"] != delta \
                or frame["numeric"]["timing"]["stepIndex"] != expected_step:
            raise BrowserCaptureError(
                f"{label} timing differs from canonical schedule at frame {index}",
            )
        if frame["inputs"] != inputs:
            raise BrowserCaptureError(
                f"{label} inputs differ from canonical schedule at frame {index}",
            )


def _valid_pixel_checkpoint(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "id", "width", "height", "pixel_format", "origin", "alpha_mode",
        "reference_sha256",
    }:
        return False
    return (
        isinstance(value["id"], str) and bool(value["id"])
        and value["width"] == 640 and value["height"] == 480
        and value["pixel_format"] == "rgba8"
        and value["origin"] == "top-left"
        and value["alpha_mode"] == "straight"
        and _hash(value["reference_sha256"])
    )


def verify_capture(
    manifest_path: Path, suite_path: Path,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    suite_path = suite_path.resolve()
    root = _artifact_root(manifest_path)
    if manifest_path.name != f"{_sha256(manifest_path)}.json":
        raise BrowserCaptureError("capture manifest path is not content-addressed")
    manifest = _exact(_load(manifest_path), {
        "schema", "protocol", "status", "promotion_allowed", "suite",
        "producer", "runtime_identity", "artifacts",
    }, "capture manifest")
    if manifest["schema"] != 1 or manifest["protocol"] != PROTOCOL \
            or manifest["status"] != STATUS \
            or manifest["promotion_allowed"] is not False:
        raise BrowserCaptureError("capture manifest is not a fail-closed candidate")

    suite = scenarios.load_scenario_suite_manifest(suite_path)
    suite_ref = _exact(manifest["suite"], {
        "spec_sha256", "scenario_order", "scenarios",
    }, "capture suite")
    if suite_ref["spec_sha256"] != _sha256(suite_path) \
            or suite_ref["scenario_order"] != list(scenarios.SCENARIO_ID_ORDER):
        raise BrowserCaptureError("capture suite identity differs")
    expected_scenarios = [{
        "id": entry["id"],
        "scenario_sha256": entry["scenario"]["sha256"],
        "scenario_semantic_sha256": entry["scenario"]["semantic_sha256"],
    } for entry in suite["scenarios"]]
    if suite_ref["scenarios"] != expected_scenarios:
        raise BrowserCaptureError("capture scenario identities differ")

    producer = _exact(manifest["producer"], {
        "entry_driver", "state", "boundary", "initial_state_policy",
        "camera_policy", "native_camera_match", "renderer",
    }, "capture producer")
    if producer != {
        "entry_driver": "browser-parity-harness-source-default",
        "state": "flight_world",
        "boundary": BOUNDARY,
        "initial_state_policy": INITIAL_STATE_POLICY,
        "camera_policy": CAMERA_POLICY,
        "native_camera_match": False,
        "renderer": producer["renderer"],
    }:
        raise BrowserCaptureError("capture did not use the production scene boundary")
    renderer = _exact(producer["renderer"], {
        "kind", "rasterized", "framebuffer_evidence", "width", "height",
    }, "capture renderer")
    if renderer["kind"] != "browser-webgl1-canonical-fbo" \
            or renderer["rasterized"] is not True \
            or renderer["framebuffer_evidence"] is not True \
            or renderer["width"] != 640 or renderer["height"] != 480:
        raise BrowserCaptureError("capture renderer is not canonical raster evidence")

    runtime = _exact(manifest["runtime_identity"], {
        "bundle", "parts", "subject", "texture_assets",
        "texture_assets_sha256", "browser", "webgl",
    }, "capture runtime identity")
    for name in ("bundle", "parts"):
        reference = _exact(runtime[name], {"url", "sha256"}, f"runtime {name}")
        if not isinstance(reference["url"], str) or not reference["url"] \
                or not _hash(reference["sha256"]):
            raise BrowserCaptureError(f"runtime {name} identity is invalid")
    _exact(runtime["browser"], {"name", "version", "user_agent"}, "browser identity")
    _exact(
        runtime["webgl"],
        {"version", "shading_language_version", "vendor", "renderer"},
        "WebGL identity",
    )
    if runtime["parts"]["sha256"] != _sha256(PARTS_CONTRACT):
        raise BrowserCaptureError("runtime flight-parts bytes differ from the source contract")
    _validate_capture_subject(
        runtime["subject"],
        runtime["texture_assets"],
        runtime["texture_assets_sha256"],
        "capture runtime subject",
    )
    expected_subject = runtime["subject"]
    expected_source_base = {
        "runtime_sha256": runtime["bundle"]["sha256"],
        "parts_sha256": runtime["parts"]["sha256"],
        **expected_subject,
        "texture_assets": runtime["texture_assets"],
        "texture_assets_sha256": runtime["texture_assets_sha256"],
        "capture_boundary": BOUNDARY,
        "initial_state_applied": True,
        "runtime_projection": RUNTIME_PROJECTION,
    }

    artifact_rows = manifest["artifacts"]
    if not isinstance(artifact_rows, list) \
            or len(artifact_rows) != len(scenarios.SCENARIO_ID_ORDER):
        raise BrowserCaptureError("capture must contain seven trace artifacts")
    suite_root = suite_path.parent
    verified = []
    total_pixels = 0
    for expected_id, suite_entry, row in zip(
        scenarios.SCENARIO_ID_ORDER, suite["scenarios"], artifact_rows, strict=True,
    ):
        row = _exact(row, {
            "scenario", "path", "sha256", "frame_count",
            "pixel_checkpoint_count", "framebuffer_artifacts",
        }, f"capture artifact {expected_id}")
        if row["scenario"] != expected_id or not _hash(row["sha256"]) \
                or row["path"] != f"traces/{row['sha256']}.json":
            raise BrowserCaptureError(f"capture artifact path is not content-addressed: {expected_id}")
        trace_path = root / row["path"]
        if not trace_path.is_file() or _sha256(trace_path) != row["sha256"]:
            raise BrowserCaptureError(f"capture artifact hash differs: {expected_id}")
        trace = _load(trace_path)
        trace = _validate_trace(trace, f"browser capture {expected_id}")
        scenario_path = suite_root / suite_entry["scenario"]["path"]
        scenario = scenarios.load_scenario(scenario_path)
        if trace["capture_kind"] != "web" or trace["scenario"] != scenario:
            raise BrowserCaptureError(f"capture scenario differs: {expected_id}")
        _validate_schedule(trace, scenario, f"browser capture {expected_id}")
        initial_state_readback = scenario["initial_state"]["values"]
        expected_source = {
            **expected_source_base,
            "initial_state_readback": initial_state_readback,
            "initial_state_readback_sha256": scenarios.canonical_sha256(
                initial_state_readback,
            ),
        }
        source = _exact(trace["source"], set(expected_source), (
            f"browser capture {expected_id} source"
        ))
        if source != expected_source:
            raise BrowserCaptureError(f"capture source provenance differs: {expected_id}")
        if len(trace["frames"]) != scenario["input_script"]["tick_count"] \
                or row["frame_count"] != len(trace["frames"]):
            raise BrowserCaptureError(f"capture frame count differs: {expected_id}")
        if any(
            "systems" in frame.get("numeric", {})
            or "controls" in frame.get("numeric", {})
            for frame in trace["frames"]
        ):
            raise BrowserCaptureError(
                f"capture invented unobserved production domains: {expected_id}",
            )
        pixel_count = sum(
            "pixel_checkpoint" in frame.get("render", {})
            for frame in trace["frames"]
        )
        expected_pixels = [
            (checkpoint["tick"], checkpoint["id"])
            for checkpoint in scenario["checkpoints"]
            if "render.framebuffer" in checkpoint["required_channels"]
        ]
        observed_pixels = [
            (frame["frame"], frame["render"]["pixel_checkpoint"].get("id"))
            for frame in trace["frames"]
            if "pixel_checkpoint" in frame.get("render", {})
        ]
        if observed_pixels != expected_pixels:
            raise BrowserCaptureError(
                f"raster checkpoints differ from the scenario: {expected_id}",
            )
        if any(
            not _valid_pixel_checkpoint(frame["render"]["pixel_checkpoint"])
            for frame in trace["frames"]
            if "pixel_checkpoint" in frame.get("render", {})
        ):
            raise BrowserCaptureError(f"raster checkpoint is invalid: {expected_id}")
        if row["pixel_checkpoint_count"] != pixel_count:
            raise BrowserCaptureError(f"pixel checkpoint count differs: {expected_id}")
        raw_rows = row["framebuffer_artifacts"]
        if not isinstance(raw_rows, list) or len(raw_rows) != pixel_count:
            raise BrowserCaptureError(
                f"raw framebuffer artifact count differs: {expected_id}",
            )
        expected_raw = [
            (
                frame["frame"],
                frame["render"]["pixel_checkpoint"],
            )
            for frame in trace["frames"]
            if "pixel_checkpoint" in frame.get("render", {})
        ]
        for (tick, checkpoint), raw in zip(
            expected_raw, raw_rows, strict=True,
        ):
            raw = _exact(raw, {
                "id", "tick", "path", "sha256", "byte_length",
                "width", "height", "pixel_format", "origin", "alpha_mode",
            }, f"raw framebuffer {expected_id}:{tick}")
            expected_length = checkpoint["width"] * checkpoint["height"] * 4
            if raw != {
                "id": checkpoint["id"],
                "tick": tick,
                "path": f"framebuffers/{raw['sha256']}.rgba",
                "sha256": checkpoint["reference_sha256"],
                "byte_length": expected_length,
                "width": checkpoint["width"],
                "height": checkpoint["height"],
                "pixel_format": checkpoint["pixel_format"],
                "origin": checkpoint["origin"],
                "alpha_mode": checkpoint["alpha_mode"],
            }:
                raise BrowserCaptureError(
                    f"raw framebuffer metadata differs: {expected_id}:{tick}",
                )
            raw_path = root / raw["path"]
            if not raw_path.is_file() or raw_path.stat().st_size != expected_length \
                    or _sha256(raw_path) != raw["sha256"]:
                raise BrowserCaptureError(
                    f"raw framebuffer bytes differ: {expected_id}:{tick}",
                )
        if expected_id == "default-airplane-fixed-camera-frame" and pixel_count < 1:
            raise BrowserCaptureError("fixed-camera scenario has no raster checkpoint")
        if any(
            frame.get("render", {}).get("diagnostics", {})
            .get("webgl", {}).get("drawCalls", 0) <= 0
            for frame in trace["frames"]
        ):
            raise BrowserCaptureError(f"capture contains an unrendered frame: {expected_id}")
        total_pixels += pixel_count
        verified.append({
            "scenario": expected_id,
            "trace_sha256": row["sha256"],
            "frames": len(trace["frames"]),
            "pixel_checkpoints": pixel_count,
        })

    if total_pixels != 1:
        raise BrowserCaptureError(
            "capture suite must contain exactly one canonical raw framebuffer",
        )

    return {
        "schema": 1,
        "protocol": REPORT_PROTOCOL,
        "status": "VERIFIED_WEB_CANDIDATE",
        "promotion_allowed": False,
        "manifest_sha256": _sha256(manifest_path),
        "suite_sha256": _sha256(suite_path),
        "producer_boundary": BOUNDARY,
        "verified": verified,
        "domain_readiness": {
            "timing": "CAPTURED_WEB_CANDIDATE",
            "physics": "CAPTURED_WEB_CANDIDATE",
            "camera": "WEB_POLICY_CAPTURED_NATIVE_MATCH_REQUIRED",
            "rendering": (
                "RASTERIZED_WEB_CANDIDATE_NATIVE_CAMERA_MATCH_REQUIRED"
                if total_pixels else "WEB_RASTER_EVIDENCE_MISSING"
            ),
            "controls": "WEB_OBSERVATION_CHANNEL_INCOMPLETE",
            "systems": "WEB_OBSERVATION_CHANNEL_INCOMPLETE",
            "collision": "WEB_OBSERVATION_CHANNEL_INCOMPLETE",
        },
        "remaining_external_steps": [
            "Capture all seven matching production-native FEX traces.",
            "Add production controls, systems and collision observation channels.",
            "Run per-domain native/web differentials and review each PASS receipt.",
            "Compare canonical native and browser raster bytes under the pixel policy.",
        ],
    }


def _render(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False)
        + "\n"
    ).encode("utf-8")


def write_report(manifest_path: Path, report: dict[str, Any]) -> Path:
    root = _artifact_root(manifest_path.resolve())
    payload = _render(report)
    digest = hashlib.sha256(payload).hexdigest()
    path = root / "reports" / f"{digest}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != payload:
        raise BrowserCaptureError("content-addressed report collision")
    path.write_bytes(payload)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = verify_capture(args.manifest, args.suite)
        report_path = None if args.check else write_report(args.manifest, report)
    except (OSError, ValueError, TypeError) as error:
        print(f"BROWSER FLIGHT CAPTURE FAILED: {error}", file=sys.stderr)
        return 2
    suffix = "" if report_path is None else f" report={report_path}"
    print(
        "browser flight capture: "
        f"scenarios={len(report['verified'])} "
        f"status={report['status']}{suffix}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
