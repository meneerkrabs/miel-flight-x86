#!/usr/bin/env python3
"""Validate that every dynamic flight gate has honest, executable evidence."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import browser_flight_evidence_registry
    from tools.miel_vliegt import flight_trace_differential as differential
    from tools.miel_vliegt import native_observer
except ModuleNotFoundError:
    import browser_flight_evidence_registry
    import flight_trace_differential as differential
    import native_observer


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "content/miel_vliegt/flight_runtime_parity_contract.json"
TRACE = ROOT / "content/miel_vliegt/flight_runtime_trace_contract.json"
DOMAINS = {
    "controls", "physics", "systems", "collision", "camera", "rendering",
}
DYNAMIC_STATUSES = {
    "BLOCKED_NATIVE_REFERENCE", "TRACE_EQUIVALENT", "PIXEL_EQUIVALENT"
}
FRAMEBUFFER_PROTOCOL = "miel-vliegt-framebuffer"
PIXEL_COMPARATOR = "canonical-rgba8-exact-v1"
PIXEL_COMPARISON_POLICY = {
    "canonical_format": "rgba8",
    "comparison": "EXACT_BYTES",
}
CANONICAL_SCENARIOS = {
    "controls-press-hold-release", "taxi-straight", "takeoff-climb",
    "level-flight-turn", "approach-landing", "impact-crash",
    "default-airplane-fixed-camera-frame",
}
RELEASE_GATES = {
    "controls.native_response": {
        "domain": "controls",
        "trace_scenarios": {"controls-press-hold-release"},
        "required_scenarios": {
            "press", "hold", "release", "opposing-keys",
            "focus-loss-reactivation",
        },
    },
    "physics.native_trajectories": {
        "domain": "physics",
        "trace_scenarios": {
            "taxi-straight", "takeoff-climb", "level-flight-turn",
            "approach-landing", "impact-crash",
        },
    },
    "systems.native_response": {
        "domain": "systems",
        "trace_scenarios": {
            "taxi-straight", "takeoff-climb", "level-flight-turn",
            "approach-landing", "impact-crash",
        },
        "evidence": "content/miel_vliegt/native_flight_state_layout.json#/systems",
        "native_functions": {
            "0x40e610", "0x410cb0", "0x42db70", "0x42e240",
        },
        "native_observation_sites": {
            "0x0040e610", "0x0040ee14", "0x0040f5cb",
            "0x00410cdf", "0x0042db70", "0x0042e240",
        },
    },
    "collision.native_response": {
        "domain": "collision",
        "trace_scenarios": {
            "taxi-straight", "takeoff-climb", "approach-landing",
            "impact-crash",
        },
    },
    "camera.native_response": {
        "domain": "camera",
        "trace_scenarios": {
            "taxi-straight", "takeoff-climb", "level-flight-turn",
            "approach-landing", "impact-crash",
            "default-airplane-fixed-camera-frame",
        },
    },
    "rendering.native_pixels": {
        "domain": "rendering",
        "trace_scenarios": {"default-airplane-fixed-camera-frame"},
    },
}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected an object")
    return value


def _file_part(reference: str) -> str:
    return reference.split("#", 1)[0]


def _require_reference(root: Path, reference: Any, label: str) -> None:
    if not isinstance(reference, str) or not reference:
        raise ValueError(f"{label} must be a repository reference")
    relative = Path(_file_part(reference))
    if relative.is_absolute():
        raise ValueError(f"{label} escapes the repository")
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the repository") from error
    if not path.is_file():
        raise ValueError(f"{label} does not exist: {reference}")
    if "#" not in reference:
        return
    fragment = reference.split("#", 1)[1]
    if not fragment.startswith("/"):
        raise ValueError(f"{label} has an invalid JSON pointer: {reference}")
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"{label} uses a JSON pointer on non-JSON evidence: {reference}"
        ) from error
    for raw_token in fragment[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
            continue
        if isinstance(value, list):
            try:
                index = int(token)
            except ValueError:
                index = -1
            if 0 <= index < len(value):
                value = value[index]
                continue
        raise ValueError(f"{label} JSON pointer does not exist: {reference}")


def _artifact(root: Path, reference: Any, label: str) -> tuple[Path, dict[str, Any]]:
    _require_reference(root, reference, label)
    path = root / _file_part(reference)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not a JSON evidence artifact") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return path, value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def _framebuffer_manifest(
    root: Path, reference: Any, label: str,
) -> tuple[Path, bytes, tuple[int, int]]:
    path, manifest = _artifact(root, reference, label)
    required = {
        "schema", "protocol", "width", "height", "row_stride", "pixel_format",
        "origin", "alpha_mode", "data",
    }
    if set(manifest) != required or manifest.get("schema") != 1 \
            or manifest.get("protocol") != FRAMEBUFFER_PROTOCOL:
        raise ValueError(f"{label}: invalid framebuffer manifest")
    width = manifest.get("width")
    height = manifest.get("height")
    row_stride = manifest.get("row_stride")
    if not all(isinstance(value, int) and value > 0
               for value in (width, height, row_stride)) \
            or row_stride < width * 4:
        raise ValueError(f"{label}: invalid framebuffer dimensions")
    pixel_format = manifest.get("pixel_format")
    origin = manifest.get("origin")
    alpha_mode = manifest.get("alpha_mode")
    if pixel_format not in {"rgba8", "bgra8", "bgrx8"} \
            or origin not in {"top-left", "bottom-left"} \
            or alpha_mode not in {"opaque", "straight", "premultiplied"}:
        raise ValueError(f"{label}: unsupported framebuffer format")
    data = manifest.get("data")
    if not isinstance(data, dict) or set(data) != {"path", "sha256"}:
        raise ValueError(f"{label}: invalid framebuffer data identity")
    raw_path = root / _file_part(data.get("path", ""))
    _require_reference(root, data.get("path"), f"{label}.data")
    if not isinstance(data.get("sha256"), str) or _sha256(raw_path) != data["sha256"]:
        raise ValueError(f"{label}: framebuffer data hash drifted")
    raw = raw_path.read_bytes()
    if len(raw) != row_stride * height:
        raise ValueError(f"{label}: framebuffer byte length differs")

    rgba = bytearray(width * height * 4)
    for target_y in range(height):
        source_y = target_y if origin == "top-left" else height - target_y - 1
        for x in range(width):
            source = source_y * row_stride + x * 4
            target = (target_y * width + x) * 4
            c0, green, c2, stored_alpha = raw[source:source + 4]
            if pixel_format == "rgba8":
                red, blue = c0, c2
            else:
                blue, red = c0, c2
            alpha = 255 if alpha_mode == "opaque" or pixel_format == "bgrx8" \
                else stored_alpha
            if alpha_mode == "premultiplied":
                if alpha == 0:
                    red = green = blue = 0
                else:
                    red = min(255, (red * 255 + alpha // 2) // alpha)
                    green = min(255, (green * 255 + alpha // 2) // alpha)
                    blue = min(255, (blue * 255 + alpha // 2) // alpha)
            rgba[target:target + 4] = bytes((red, green, blue, alpha))
    return path, bytes(rgba), (width, height)


def validate_pixel_proof(root: Path, proof: dict[str, Any], scenario: str) -> None:
    """Recompute exact canonical RGBA8 equality for one runtime pixel proof."""

    native_path, native_rgba, native_size = _framebuffer_manifest(
        root, proof.get("native_frame"), f"{scenario}.native_frame",
    )
    web_path, web_rgba, web_size = _framebuffer_manifest(
        root, proof.get("web_frame"), f"{scenario}.web_frame",
    )
    if native_path.resolve() == web_path.resolve():
        raise ValueError(f"{scenario}: native and web framebuffers must be independent")
    _receipt_path, receipt = _artifact(
        root, proof.get("pixel_receipt"), f"{scenario}.pixel_receipt",
    )
    required = {
        "schema", "status", "scenario", "native_frame_sha256", "web_frame_sha256",
        "canonical_rgba_sha256", "comparator", "comparison_policy",
        "comparison_policy_sha256",
    }
    if set(receipt) != required or receipt.get("schema") != 1 \
            or receipt.get("status") != "PASS" or receipt.get("scenario") != scenario \
            or receipt.get("native_frame_sha256") != _sha256(native_path) \
            or receipt.get("web_frame_sha256") != _sha256(web_path) \
            or receipt.get("comparator") != PIXEL_COMPARATOR \
            or receipt.get("comparison_policy") != PIXEL_COMPARISON_POLICY \
            or receipt.get("comparison_policy_sha256") \
            != _canonical_sha256(PIXEL_COMPARISON_POLICY):
        raise ValueError(f"{scenario}: invalid pixel PASS receipt")
    if native_size != web_size:
        raise ValueError(f"{scenario}: canonical framebuffer dimensions differ")
    if native_rgba != web_rgba:
        raise ValueError(f"{scenario}: canonical RGBA8 bytes differ")
    canonical_sha256 = hashlib.sha256(native_rgba).hexdigest()
    if receipt.get("canonical_rgba_sha256") != canonical_sha256:
        raise ValueError(f"{scenario}: canonical RGBA8 hash differs")


def _validate_trace_proofs(
    root: Path, checkpoint_id: str, checkpoint: dict[str, Any],
    expected_executable: str, registered_web_outputs: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    expected_scenarios = set(checkpoint["trace_scenarios"])
    proofs = checkpoint.get("proofs")
    proof_scenarios = [
        row.get("scenario") for row in proofs if isinstance(row, dict)
    ] if isinstance(proofs, list) else []
    if len(proof_scenarios) != len(expected_scenarios) \
            or set(proof_scenarios) != expected_scenarios:
        return [f"{checkpoint_id}: proofs must be an exact bijection over trace_scenarios"]
    for proof in proofs:
        scenario = proof["scenario"]
        label = f"{checkpoint_id}.proofs[{scenario}]"
        try:
            if proof.get("web_output") != registered_web_outputs.get(scenario):
                raise ValueError(
                    f"{label}.web_output is not the immutable browser "
                    "evidence registry output"
                )
            native_path, native = _artifact(root, proof.get("native_output"), f"{label}.native_output")
            web_path, web = _artifact(root, proof.get("web_output"), f"{label}.web_output")
            receipt_path, receipt = _artifact(
                root, proof.get("differential_receipt"), f"{label}.differential_receipt"
            )
            observer_path = root / _file_part(proof.get("native_observer_receipt", ""))
            _require_reference(
                root, proof.get("native_observer_receipt"),
                f"{label}.native_observer_receipt",
            )
            observer_receipt, _capture = native_observer.verify_receipt(
                observer_path, root=root, require_production=True,
            )
            differential.validate_trace(native, f"{label}.native")
            differential.validate_trace(web, f"{label}.web")
            if native["capture_kind"] != "native" or web["capture_kind"] != "web":
                raise ValueError(f"{label}: capture kinds must be native and web")
            if native["scenario"] != web["scenario"] or native["scenario"].get("id") != scenario:
                raise ValueError(f"{label}: trace scenario identity differs")
            if native["source"].get("executable_sha256") != expected_executable:
                raise ValueError(f"{label}: native trace executable identity differs")
            if native["source"].get("observer_receipt_sha256") != _sha256(observer_path):
                raise ValueError(f"{label}: native trace is not bound to its observer receipt")
            observer_scenario = json.loads(
                (root / _file_part(observer_receipt["scenario"])).read_text(encoding="utf-8")
            )
            if observer_scenario.get("id") != scenario:
                raise ValueError(f"{label}: observer scenario identity differs")
            required_receipt = {
                "schema", "status", "scenario", "native_sha256", "web_sha256",
                "tolerances",
            }
            if set(receipt) != required_receipt or receipt.get("schema") != 1 \
                    or receipt.get("status") != "PASS" or receipt.get("scenario") != scenario:
                raise ValueError(f"{label}: invalid differential PASS receipt")
            if receipt["native_sha256"] != _sha256(native_path) \
                    or receipt["web_sha256"] != _sha256(web_path):
                raise ValueError(f"{label}: differential receipt hashes differ")
            tolerance_path = root / _file_part(receipt["tolerances"])
            _require_reference(root, receipt["tolerances"], f"{label}.tolerances")
            policy = differential.load_tolerance_policy(tolerance_path)
            if not differential.compare_traces(native, web, policy).matches:
                raise ValueError(f"{label}: differential no longer passes")
            if checkpoint["status"] == "PIXEL_EQUIVALENT":
                validate_pixel_proof(root, proof, scenario)
        except (KeyError, TypeError, ValueError) as error:
            errors.append(str(error))
    return errors


def validate(
    runtime: dict[str, Any], trace: dict[str, Any], root: Path = ROOT,
) -> list[str]:
    errors: list[str] = []
    checkpoints = runtime.get("checkpoints", [])
    scenarios = trace.get("scenarios", [])
    if runtime.get("schema") != 1 or not isinstance(checkpoints, list):
        return ["unsupported flight runtime parity contract"]
    if trace.get("schema") != 1 or not isinstance(scenarios, list):
        return ["unsupported flight runtime trace contract"]

    try:
        _registry, registered_web_outputs = (
            browser_flight_evidence_registry.verify_registry(root=root)
        )
    except (OSError, TypeError, ValueError) as error:
        errors.append(f"browser evidence registry: {error}")
        registered_web_outputs = {}

    scenario_by_id = {row.get("id"): row for row in scenarios if isinstance(row, dict)}
    if None in scenario_by_id or len(scenario_by_id) != len(scenarios):
        errors.append("flight runtime trace scenarios need unique non-empty ids")
    if set(scenario_by_id) != CANONICAL_SCENARIOS:
        errors.append("flight runtime trace must contain exactly the canonical seven scenarios")
    for scenario_id, scenario in scenario_by_id.items():
        web_output = scenario.get("web_output")
        if web_output is not None \
                and web_output != registered_web_outputs.get(scenario_id):
            errors.append(
                f"{scenario_id}: web_output is not the immutable browser "
                "evidence registry output"
            )

    checkpoint_by_id = {
        row.get("id"): row for row in checkpoints if isinstance(row, dict)
    }
    if None in checkpoint_by_id or len(checkpoint_by_id) != len(checkpoints):
        errors.append("flight runtime checkpoints need unique non-empty ids")

    actual_release_gates = {
        identifier for identifier, row in checkpoint_by_id.items()
        if row.get("release_gate") is True
    }
    if actual_release_gates != set(RELEASE_GATES):
        errors.append("flight runtime must contain exactly the six canonical release gates")

    channels = trace.get("capture_channels")
    channel_by_domain = {
        row.get("domain"): row for row in channels if isinstance(row, dict)
    } if isinstance(channels, list) else {}
    if set(channel_by_domain) != DOMAINS or len(channel_by_domain) != len(channels or []):
        errors.append("flight runtime needs one unique capture channel per dynamic domain")

    gated_domains: set[str] = set()
    expected_executable = trace.get("source_identity", {}).get("executable_sha256")
    for checkpoint_id, checkpoint in checkpoint_by_id.items():
        domain = checkpoint.get("domain")
        if domain not in DOMAINS:
            errors.append(f"{checkpoint_id}: invalid domain {domain!r}")
        if checkpoint.get("web_owner"):
            try:
                _require_reference(root, checkpoint["web_owner"], f"{checkpoint_id}.web_owner")
            except ValueError as error:
                errors.append(str(error))
        if checkpoint.get("evidence"):
            try:
                _require_reference(root, checkpoint["evidence"], f"{checkpoint_id}.evidence")
            except ValueError as error:
                errors.append(str(error))

        if checkpoint.get("release_gate") is not True:
            continue
        canonical = RELEASE_GATES.get(checkpoint_id)
        if canonical is None:
            continue
        if domain != canonical["domain"]:
            errors.append(f"{checkpoint_id}: canonical domain drifted")
        if set(checkpoint.get("trace_scenarios", [])) != canonical["trace_scenarios"]:
            errors.append(f"{checkpoint_id}: canonical trace_scenarios drifted")
        required = set(checkpoint.get("required_scenarios", []))
        expected_required = canonical.get(
            "required_scenarios", canonical["trace_scenarios"],
        )
        if required != expected_required:
            errors.append(f"{checkpoint_id}: canonical required_scenarios drifted")
        for field in ("evidence", "native_functions", "native_observation_sites"):
            if field not in canonical:
                continue
            actual = checkpoint.get(field)
            expected = canonical[field]
            if isinstance(expected, set):
                actual = set(actual) if isinstance(actual, list) else actual
            if actual != expected:
                errors.append(f"{checkpoint_id}: canonical {field} drifted")
        gated_domains.add(domain)
        status = checkpoint.get("status")
        if status not in DYNAMIC_STATUSES:
            errors.append(f"{checkpoint_id}: invalid dynamic status {status!r}")
        trace_ids = checkpoint.get("trace_scenarios")
        if not isinstance(trace_ids, list) or not trace_ids:
            errors.append(f"{checkpoint_id}: release gate has no trace_scenarios")
            continue
        for scenario_id in trace_ids:
            scenario = scenario_by_id.get(scenario_id)
            if scenario is None:
                errors.append(f"{checkpoint_id}: unknown trace scenario {scenario_id}")
            elif domain not in scenario.get("domains", []):
                errors.append(
                    f"{checkpoint_id}: scenario {scenario_id} does not observe {domain}"
                )

        if status == "BLOCKED_NATIVE_REFERENCE":
            continue
        channel = channel_by_domain.get(domain, {})
        if channel.get("native_layout") is None \
                or channel.get("status") == "BLOCKED_NATIVE_REFERENCE":
            errors.append(f"{checkpoint_id}: promoted gate requires a reviewed native layout")
        for scenario_id in trace_ids:
            scenario = scenario_by_id.get(scenario_id, {})
            if scenario.get("status") == "BLOCKED_NATIVE_REFERENCE":
                errors.append(
                    f"{checkpoint_id}: scenario is still BLOCKED_NATIVE_REFERENCE: {scenario_id}"
                )
            for field in (
                "input_script", "clock_transcript", "rng_transcript",
                "initial_state", "native_reference", "native_output", "web_output",
            ):
                if not scenario.get(field):
                    errors.append(
                        f"{checkpoint_id}: promoted scenario {scenario_id} lacks {field}"
                    )
            web_output = scenario.get("web_output")
            if web_output and web_output != registered_web_outputs.get(scenario_id):
                errors.append(
                    f"{checkpoint_id}: promoted scenario {scenario_id} web_output "
                    "is not the immutable browser evidence registry output"
                )
        errors.extend(_validate_trace_proofs(
            root, checkpoint_id, checkpoint, expected_executable,
            registered_web_outputs,
        ))

    missing_domains = DOMAINS - gated_domains
    if missing_domains:
        errors.append(f"dynamic flight domains lack release gates: {sorted(missing_domains)}")

    for scenario_id, scenario in scenario_by_id.items():
        status = scenario.get("status")
        if status == "BLOCKED_NATIVE_REFERENCE":
            for field in ("native_reference", "native_output"):
                if scenario.get(field) is not None:
                    errors.append(f"{scenario_id}: blocked scenario contains {field}")
            if not scenario.get("blockers"):
                errors.append(f"{scenario_id}: blocked scenario has no blockers")
    if any(
        row.get("status") == "BLOCKED_NATIVE_REFERENCE"
        for row in checkpoint_by_id.values() if row.get("release_gate") is True
    ) and trace.get("policy", {}).get("current_status") != "BLOCKED_NATIVE_REFERENCE":
        errors.append("policy.current_status must remain BLOCKED_NATIVE_REFERENCE while a release gate is blocked")
    return errors


def main() -> None:
    errors = validate(load(RUNTIME), load(TRACE))
    if errors:
        raise SystemExit("flight runtime contract failed:\n- " + "\n- ".join(errors))
    print("flight runtime contract OK: all dynamic domains are gated by honest trace scenarios")


if __name__ == "__main__":
    main()
