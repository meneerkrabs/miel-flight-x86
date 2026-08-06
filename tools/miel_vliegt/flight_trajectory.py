#!/usr/bin/env python3
"""Capture/import, replay and differentially compare flight trajectories.

This module deliberately separates protocol verification from parity evidence.
The checked-in web fixture proves deterministic replay. A native baseline can
only be imported with the pinned executable and a reviewed state-layout file.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "content/miel_vliegt/trajectory_contract.json"
PROBE_PATH = ROOT / "content/miel_vliegt/native_trace_probe.json"
RUNNER_PATH = ROOT / "tools/miel_vliegt/run_web_trajectory.cjs"
PROTOCOL = "miel-vliegt-trajectory"
VERSION = 1
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    contract = load_json(path)
    if contract.get("schema") != 1 or contract.get("protocol") != PROTOCOL:
        raise ValueError("unsupported trajectory contract")
    return contract


def load_scenario(path: Path) -> dict[str, Any]:
    scenario = load_json(path)
    required = {"schema", "id", "description", "evidence", "step_seconds", "body", "integrator", "ticks"}
    if scenario.get("schema") != 1 or not required.issubset(scenario):
        raise ValueError("invalid trajectory scenario")
    if scenario["evidence"] not in {"WEB_FIXTURE", "NATIVE_SCRIPT"}:
        raise ValueError("scenario evidence must be WEB_FIXTURE or NATIVE_SCRIPT")
    if not scenario["ticks"]:
        raise ValueError("trajectory scenario must contain ticks")
    maximum = scenario["integrator"].get("maximum_step")
    if scenario["step_seconds"] <= 0 or scenario["step_seconds"] > maximum:
        raise ValueError("scenario step_seconds exceeds the fixed-step contract")
    return scenario


def _finite(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{path} must be a finite number")
    return float(value)


def _validate_vector(value: Any, keys: tuple[str, ...], path: str) -> None:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{path} must contain exactly {', '.join(keys)}")
    for key in keys:
        _finite(value[key], f"{path}.{key}")


def _validate_finite_tree(value: Any, path: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            _validate_finite_tree(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_finite_tree(item, f"{path}[{index}]")
    elif isinstance(value, float):
        _finite(value, path)
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise ValueError(f"{path} contains a non-JSON value")


def _canonical_orientation(value: dict[str, Any]) -> dict[str, Any]:
    result = {key: value[key] for key in ("x", "y", "z", "w")}
    # q and -q encode the same orientation. Choose one representation before
    # comparing engines; this does not relax any rotational difference.
    sign_probe = next((result[key] for key in ("w", "x", "y", "z") if result[key] != 0), 0)
    if sign_probe < 0:
        result = {key: -number for key, number in result.items()}
    return result


def validate_sample(sample: dict[str, Any], expected_sequence: int) -> None:
    required = {"record", "sequence", "tick", "time_seconds", "controls", "state", "systems", "events"}
    if set(sample) != required or sample.get("record") != "trajectory_sample":
        raise ValueError(f"sample {expected_sequence} has an invalid shape")
    if sample["sequence"] != expected_sequence or sample["tick"] != expected_sequence:
        raise ValueError("trajectory sample sequence/tick is missing or out of order")
    _finite(sample["time_seconds"], "time_seconds")
    if not isinstance(sample["controls"], dict) or not isinstance(sample["events"], list):
        raise ValueError("controls must be an object and events must be an array")
    _validate_finite_tree(sample["controls"], "controls")
    _validate_finite_tree(sample["events"], "events")
    state = sample["state"]
    if not isinstance(state, dict) or set(state) != {"position", "velocity", "orientation", "angular_velocity"}:
        raise ValueError("sample state has an invalid shape")
    _validate_vector(state["position"], ("x", "y", "z"), "state.position")
    _validate_vector(state["velocity"], ("x", "y", "z"), "state.velocity")
    _validate_vector(state["orientation"], ("x", "y", "z", "w"), "state.orientation")
    _validate_vector(state["angular_velocity"], ("x", "y", "z"), "state.angular_velocity")
    state["orientation"] = _canonical_orientation(state["orientation"])
    systems = sample["systems"]
    if not isinstance(systems, dict) or set(systems) != {"fuel", "integrity"}:
        raise ValueError("systems must contain exactly fuel and integrity")
    for key, value in systems.items():
        if value is not None:
            _finite(value, f"systems.{key}")


def canonicalize_trace(header: dict[str, Any], samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = [copy.deepcopy(header), *copy.deepcopy(samples)]
    validate_header(records[0])
    for index, sample in enumerate(records[1:]):
        validate_sample(sample, index)
    body = "".join(canonical_json(record) + "\n" for record in records).encode("utf-8")
    records.append({
        "record": "trajectory_footer",
        "sample_count": len(samples),
        "content_sha256": sha256_bytes(body),
    })
    validate_trace(records)
    return records


def validate_header(header: dict[str, Any]) -> None:
    required = {"record", "protocol", "version", "capture_kind", "source", "scenario"}
    if set(header) != required or header.get("record") != "trajectory_header":
        raise ValueError("invalid trajectory header shape")
    if header.get("protocol") != PROTOCOL or header.get("version") != VERSION:
        raise ValueError("unsupported trajectory protocol")
    if header.get("capture_kind") not in {"native", "web"}:
        raise ValueError("capture_kind must be native or web")
    source = header["source"]
    if not isinstance(source, dict) or not SHA256.fullmatch(source.get("executable_sha256", "")):
        raise ValueError("trajectory must pin the native executable")
    if header["capture_kind"] == "native":
        if set(source) != {
            "edition", "executable_sha256", "state_layout_sha256",
            "state_layout_review", "capture_receipt_sha256"
        }:
            raise ValueError("native trajectory source has an invalid shape")
        if not SHA256.fullmatch(source["state_layout_sha256"]) \
                or not SHA256.fullmatch(source["capture_receipt_sha256"]) \
                or source["state_layout_review"] != "REVIEWED":
            raise ValueError("native trajectory requires a reviewed state-layout hash")
    else:
        if set(source) != {"edition", "executable_sha256", "runtime_sha256", "evidence"}:
            raise ValueError("web trajectory source has an invalid shape")
        if not SHA256.fullmatch(source["runtime_sha256"]) or source["evidence"] != "WEB_FIXTURE":
            raise ValueError("web trajectory requires a pinned fixture runtime")
    scenario = header["scenario"]
    if not isinstance(scenario, dict) or set(scenario) != {"id", "description", "input_sha256"}:
        raise ValueError("trajectory scenario header has an invalid shape")
    if not SHA256.fullmatch(scenario["input_sha256"]):
        raise ValueError("trajectory scenario needs a lowercase SHA-256")


def validate_trace(records: list[dict[str, Any]]) -> None:
    if len(records) < 3:
        raise ValueError("trajectory needs a header, at least one sample and footer")
    validate_header(records[0])
    for index, sample in enumerate(records[1:-1]):
        validate_sample(sample, index)
    footer = records[-1]
    if set(footer) != {"record", "sample_count", "content_sha256"} or footer["record"] != "trajectory_footer":
        raise ValueError("invalid trajectory footer")
    if footer["sample_count"] != len(records) - 2:
        raise ValueError("trajectory footer sample count mismatch")
    body = "".join(canonical_json(record) + "\n" for record in records[:-1]).encode("utf-8")
    if footer["content_sha256"] != sha256_bytes(body):
        raise ValueError("trajectory footer content hash mismatch")


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid JSON") from error
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_number}: record must be an object")
        records.append(record)
    return records


def write_ndjson(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(canonical_json(record) + "\n" for record in records), encoding="utf-8")


def runtime_sha256() -> str:
    physics = ROOT / "src/flight/engine/physics"
    files = sorted(path for path in physics.rglob("*.js") if "__tests__" not in path.parts)
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(ROOT)).encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def make_header(capture_kind: str, scenario_path: Path, scenario: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "record": "trajectory_header",
        "protocol": PROTOCOL,
        "version": VERSION,
        "capture_kind": capture_kind,
        "source": source,
        "scenario": {
            "id": scenario["id"],
            "description": scenario["description"],
            "input_sha256": sha256_file(scenario_path),
        },
    }


def run_web(scenario_path: Path, output: Path, node: str = "node") -> list[dict[str, Any]]:
    scenario = load_scenario(scenario_path)
    if scenario["evidence"] != "WEB_FIXTURE":
        raise ValueError("web replay requires an explicit WEB_FIXTURE scenario")
    process = subprocess.run(
        [node, str(RUNNER_PATH), str(scenario_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(f"web trajectory runner failed: {process.stderr.strip()}")
    temporary = output.with_suffix(output.suffix + ".raw")
    temporary.write_text(process.stdout, encoding="utf-8")
    try:
        samples = read_ndjson(temporary)
    finally:
        temporary.unlink(missing_ok=True)
    if len(samples) != len(scenario["ticks"]):
        raise ValueError("web runner sample count differs from scenario ticks")
    contract = load_contract()
    header = make_header("web", scenario_path, scenario, {
        "edition": contract["source"]["edition"],
        "executable_sha256": contract["source"]["executable_sha256"],
        "runtime_sha256": runtime_sha256(),
        "evidence": "WEB_FIXTURE",
    })
    records = canonicalize_trace(header, samples)
    write_ndjson(output, records)
    return records


def validate_state_layout(path: Path, executable_sha256: str) -> dict[str, Any]:
    layout = load_json(path)
    required_fields = {
        "state.position", "state.velocity", "state.orientation",
        "state.angular_velocity", "systems.fuel", "systems.integrity",
    }
    if layout.get("schema") != 1 or layout.get("review_status") != "REVIEWED":
        raise ValueError("native state layout must be schema 1 and REVIEWED")
    if layout.get("executable_sha256") != executable_sha256:
        raise ValueError("native state layout targets a different executable")
    if set(layout.get("fields", {})) != required_fields:
        raise ValueError("native state layout does not define every trajectory field")
    for field, evidence in layout["fields"].items():
        if not isinstance(evidence, dict) or not evidence.get("address_or_offset") or not evidence.get("evidence"):
            raise ValueError(f"native state layout field lacks evidence: {field}")
    return layout


def validate_capture_receipt(
    path: Path, raw_path: Path, scenario_path: Path, executable: Path, state_layout: Path
) -> dict[str, Any]:
    receipt = load_json(path)
    probe = load_json(PROBE_PATH)
    hook = next(item for item in probe["behavior_hooks"] if item["id"] == "flight.step.enter")
    required = {
        "schema", "protocol", "review_status", "executable_sha256", "target_module",
        "step_hook", "scenario_input_sha256", "raw_sha256", "state_layout_sha256",
        "capture_tool", "capture_host",
    }
    if set(receipt) != required or receipt.get("schema") != 1 \
            or receipt.get("protocol") != "miel-vliegt-native-capture" \
            or receipt.get("review_status") != "REVIEWED":
        raise ValueError("native capture receipt must be complete and REVIEWED")
    if receipt["executable_sha256"] != sha256_file(executable):
        raise ValueError("native capture receipt targets a different executable")
    if receipt["target_module"] != {"filename": executable.name, "image_base": "0x00400000"}:
        raise ValueError("native capture receipt does not bind the target module and image base")
    if receipt["step_hook"] != {"address": hook["address"], "signature": hook["signature"]}:
        raise ValueError("native capture receipt does not bind the reviewed flight-step hook")
    if receipt["scenario_input_sha256"] != sha256_file(scenario_path) \
            or receipt["raw_sha256"] != sha256_file(raw_path) \
            or receipt["state_layout_sha256"] != sha256_file(state_layout):
        raise ValueError("native capture receipt input hashes drifted")
    if not isinstance(receipt["capture_tool"], str) or not receipt["capture_tool"].strip():
        raise ValueError("native capture receipt has no capture tool")
    host = receipt["capture_host"]
    if not isinstance(host, dict) or host.get("kind") not in {"windows-i386", "hangover-arm64"}:
        raise ValueError("native capture receipt has no reviewed capture host")
    if host["kind"] == "hangover-arm64":
        host_path = ROOT / host.get("receipt", "")
        host_receipt = load_json(host_path)
        if host_receipt.get("capture_host_usable") is not True \
                or host_receipt.get("native_parity_evidence") is not False \
                or host_receipt.get("executable_sha256") != receipt["executable_sha256"]:
            raise ValueError("Hangover capture host receipt is absent or invalid")
    elif host.get("review_status") != "REVIEWED":
        raise ValueError("Windows capture host must be explicitly reviewed")
    return receipt


def import_native(
    raw_path: Path, output: Path, scenario_path: Path, executable: Path,
    state_layout: Path, capture_receipt: Path
) -> list[dict[str, Any]]:
    scenario = load_scenario(scenario_path)
    if scenario["evidence"] != "NATIVE_SCRIPT":
        raise ValueError("native import requires a NATIVE_SCRIPT scenario")
    contract = load_contract()
    executable_sha256 = sha256_file(executable)
    if executable_sha256 != contract["source"]["executable_sha256"]:
        raise ValueError("wrong native executable")
    layout = validate_state_layout(state_layout, executable_sha256)
    receipt = validate_capture_receipt(
        capture_receipt, raw_path, scenario_path, executable, state_layout
    )
    samples = read_ndjson(raw_path)
    if len(samples) != len(scenario["ticks"]):
        raise ValueError("native sample count differs from scenario ticks")
    header = make_header("native", scenario_path, scenario, {
        "edition": contract["source"]["edition"],
        "executable_sha256": executable_sha256,
        "state_layout_sha256": sha256_file(state_layout),
        "state_layout_review": layout["review_status"],
        "capture_receipt_sha256": sha256_file(capture_receipt),
    })
    records = canonicalize_trace(header, samples)
    write_ndjson(output, records)
    return records


def _tolerance_for(path: str, tolerances: dict[str, float]) -> float | None:
    if path in tolerances:
        return tolerances[path]
    wildcard = ".".join([*path.split(".")[:-1], "*"])
    return tolerances.get(wildcard)


def _compare(left: Any, right: Any, path: str, tolerances: dict[str, float]) -> str | None:
    if isinstance(left, dict) and isinstance(right, dict):
        if set(left) != set(right):
            return f"{path}: keys {sorted(left)} != {sorted(right)}"
        for key in sorted(left):
            difference = _compare(left[key], right[key], f"{path}.{key}" if path else key, tolerances)
            if difference:
                return difference
        return None
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return f"{path}: length {len(left)} != {len(right)}"
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            difference = _compare(left_item, right_item, f"{path}[{index}]", tolerances)
            if difference:
                return difference
        return None
    tolerance = _tolerance_for(path, tolerances)
    if tolerance is not None and isinstance(left, (int, float)) and isinstance(right, (int, float)):
        if abs(left - right) > tolerance:
            return f"{path}: {left} != {right} (absolute tolerance {tolerance})"
        return None
    if left != right:
        return f"{path}: {left!r} != {right!r}"
    return None


def compare_trajectories(baseline: list[dict[str, Any]], candidate: list[dict[str, Any]], contract: dict[str, Any]) -> list[str]:
    validate_trace(baseline)
    validate_trace(candidate)
    differences = []
    if baseline[0]["capture_kind"] != "native":
        differences.append("baseline is not native evidence")
    if candidate[0]["capture_kind"] != "web":
        differences.append("candidate is not a web runtime trace")
    elif candidate[0]["source"].get("runtime_sha256") != runtime_sha256():
        differences.append("candidate web runtime hash is stale")
    if baseline[-1]["content_sha256"] == candidate[-1]["content_sha256"]:
        differences.append("baseline and candidate are the same trace artifact")
    if baseline[0]["source"]["executable_sha256"] != candidate[0]["source"]["executable_sha256"]:
        differences.append("source executable SHA-256 differs")
    if baseline[0]["scenario"] != candidate[0]["scenario"]:
        differences.append("scenario identity/hash differs")
    baseline_samples = baseline[1:-1]
    candidate_samples = candidate[1:-1]
    if len(baseline_samples) != len(candidate_samples):
        differences.append(f"sample count: {len(baseline_samples)} != {len(candidate_samples)}")
    tolerances = contract["comparison"]["absolute_tolerances"]
    for tick, (left, right) in enumerate(zip(baseline_samples, candidate_samples)):
        # Sequence is framing, while controls/state/systems/events are behavior.
        comparable_left = {key: value for key, value in left.items() if key not in {"record", "sequence", "tick"}}
        comparable_right = {key: value for key, value in right.items() if key not in {"record", "sequence", "tick"}}
        difference = _compare(comparable_left, comparable_right, "", tolerances)
        if difference:
            differences.append(f"tick {tick}: {difference}")
            break
    return differences


def verify_contract(contract_path: Path = CONTRACT_PATH) -> dict[str, Any]:
    contract = load_contract(contract_path)
    probe = load_json(PROBE_PATH)
    if probe["source"]["executable_sha256"] != contract["source"]["executable_sha256"]:
        raise ValueError("trajectory contract and native probe executable differ")
    hook = next(item for item in probe["behavior_hooks"] if item["id"] == "flight.step.enter")
    if hook["address"] != "0x0040e610" or contract["source"]["native_function"] != "fn_0040e610":
        raise ValueError("trajectory native step hook drifted")
    native_step = next(item for item in probe["static_assertions"] if item["id"] == "flight.maximum_step_seconds")
    if native_step["expected"] != contract["source"]["native_maximum_step_seconds"]:
        raise ValueError("trajectory fixed-step evidence drifted")
    native_available = contract["status"]["native_trajectory_available"]
    expected_backlog = {"taxi-straight", "takeoff-climb", "level-flight-turn", "approach-landing", "impact-crash"}
    backlog = contract.get("native_scenario_backlog", [])
    if {row.get("id") for row in backlog} != expected_backlog:
        raise ValueError("native trajectory scenario backlog is incomplete")
    for row in backlog:
        if row.get("status") == "MISSING" and row.get("input_script") is not None:
            raise ValueError(f"missing native scenario already names input evidence: {row['id']}")
        if row.get("status") not in {"MISSING", "CAPTURED", "DIFFERENTIAL_PASS"}:
            raise ValueError(f"invalid native scenario status: {row['id']}")
    native_paths = []
    for row in contract["scenarios"]:
        scenario_path = ROOT / row["input"]
        scenario = load_scenario(scenario_path)
        if scenario["id"] != row["id"]:
            raise ValueError(f"trajectory scenario id drifted: {row['id']}")
        if row["evidence"] == "WEB_FIXTURE":
            if row["native_trace"] is not None or scenario["evidence"] != "WEB_FIXTURE":
                raise ValueError(f"web fixture makes a native claim: {row['id']}")
            trace = read_ndjson(ROOT / row["web_trace"])
            validate_trace(trace)
            if trace[0]["capture_kind"] != "web" or trace[0]["scenario"]["input_sha256"] != sha256_file(scenario_path):
                raise ValueError(f"web trajectory receipt drifted: {row['id']}")
            if trace[0]["source"].get("runtime_sha256") != runtime_sha256():
                raise ValueError(f"web trajectory runtime receipt drifted: {row['id']}")
        if row["native_trace"]:
            native_paths.append(row["native_trace"])
            trace = read_ndjson(ROOT / row["native_trace"])
            validate_trace(trace)
            if trace[0]["capture_kind"] != "native":
                raise ValueError(f"native trajectory is not native: {row['id']}")
            if trace[0]["source"]["executable_sha256"] != contract["source"]["executable_sha256"]:
                raise ValueError(f"native trajectory executable drifted: {row['id']}")
            if trace[0]["scenario"]["id"] != row["id"] or trace[0]["scenario"]["input_sha256"] != sha256_file(scenario_path):
                raise ValueError(f"native trajectory scenario receipt drifted: {row['id']}")
            layout_path = row.get("state_layout")
            if not layout_path:
                raise ValueError(f"native trajectory has no reviewed state layout: {row['id']}")
            layout_file = ROOT / layout_path
            validate_state_layout(layout_file, contract["source"]["executable_sha256"])
            if trace[0]["source"]["state_layout_sha256"] != sha256_file(layout_file):
                raise ValueError(f"native trajectory state-layout receipt drifted: {row['id']}")
            capture_receipt_path = row.get("capture_receipt")
            if not capture_receipt_path:
                raise ValueError(f"native trajectory has no capture receipt: {row['id']}")
            web_path = row.get("web_trace")
            if not web_path:
                raise ValueError(f"native trajectory has no web candidate: {row['id']}")
            native_file = ROOT / row["native_trace"]
            web_file = ROOT / web_path
            if native_file.resolve() == web_file.resolve():
                raise ValueError(f"native and web trajectory paths are identical: {row['id']}")
            validate_capture_receipt(
                ROOT / capture_receipt_path,
                ROOT / row["raw_trace"], scenario_path,
                ROOT / row["executable"], layout_file,
            )
            if trace[0]["source"].get("capture_receipt_sha256") != sha256_file(ROOT / capture_receipt_path):
                raise ValueError(f"native trajectory capture receipt drifted: {row['id']}")
            differences = compare_trajectories(trace, read_ndjson(web_file), contract)
            if differences:
                raise ValueError(f"native trajectory differential failed: {row['id']}: {differences[0]}")
    candidate_paths = []
    for row in contract.get("native_candidate_observations", []):
        if set(row) != {"id", "status", "artifact", "runs", "ticks", "claim", "limitation"}:
            raise ValueError("native candidate observation has an invalid shape")
        if row["status"] != "CANDIDATE_PARTIAL_NATIVE_EVIDENCE":
            raise ValueError(f"native candidate has an invalid status: {row['id']}")
        artifact_path = ROOT / row["artifact"]
        artifact = load_json(artifact_path)
        if artifact.get("schema") != 1 \
                or artifact.get("protocol") != "miel-vliegt-native-flight-consensus" \
                or artifact.get("status") != row["status"] \
                or artifact.get("promotion_allowed") is not False:
            raise ValueError(f"native candidate is not fail-closed: {row['id']}")
        if artifact.get("scenario") != row["id"] \
                or artifact.get("provenance", {}).get("executable_sha256") \
                != contract["source"]["executable_sha256"]:
            raise ValueError(f"native candidate provenance drifted: {row['id']}")
        determinism = artifact.get("determinism", {})
        samples = artifact.get("samples")
        if not isinstance(samples, list) \
                or determinism.get("run_count") != row["runs"] \
                or determinism.get("sample_count") != row["ticks"] \
                or len(samples) != row["ticks"] \
                or determinism.get("projection_sha256") != sha256_bytes(
                    canonical_json(samples).encode("utf-8")
                ):
            raise ValueError(f"native candidate consensus drifted: {row['id']}")
        if [sample.get("tick") for sample in samples] != list(range(row["ticks"])):
            raise ValueError(f"native candidate ticks are not contiguous: {row['id']}")
        candidate_paths.append(row["artifact"])
    if native_available != bool(native_paths):
        raise ValueError("native_trajectory_available disagrees with checked native traces")
    if contract["status"]["disposition"] == "EQUIVALENT" and not native_paths:
        raise ValueError("EQUIVALENT requires checked native trajectory evidence")
    return {
        "scenarios": len(contract["scenarios"]),
        "native_scenario_backlog": len(backlog),
        "native_trajectories": len(native_paths),
        "native_candidate_observations": len(candidate_paths),
        "disposition": contract["status"]["disposition"],
    }


def capture_plan() -> dict[str, Any]:
    contract = load_contract()
    probe = load_json(PROBE_PATH)
    hook = next(item for item in probe["behavior_hooks"] if item["id"] == "flight.step.enter")
    return {
        "executable_sha256": contract["source"]["executable_sha256"],
        "step_hook": {"function": contract["source"]["native_function"], "address": hook["address"], "signature": hook["signature"]},
        "fixed_step_seconds": contract["source"]["native_maximum_step_seconds"],
        "required_state_layout_fields": [field for field in contract["sample_fields"] if field != "events"],
        "required_event_channel": "events",
        "state_layout_status": "MISSING",
        "capture_receipt_fields": [
            "target_module", "step_hook", "scenario_input_sha256", "raw_sha256",
            "state_layout_sha256", "capture_tool", "capture_host", "review_status"
        ],
        "instruction": "Review state addresses/offsets against the pinned EXE, create a REVIEWED layout and capture receipt, then emit one raw trajectory_sample per completed native step.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    web = commands.add_parser("run-web")
    web.add_argument("--scenario", type=Path, required=True)
    web.add_argument("--output", type=Path, required=True)
    native = commands.add_parser("import-native")
    native.add_argument("--raw", type=Path, required=True)
    native.add_argument("--output", type=Path, required=True)
    native.add_argument("--scenario", type=Path, required=True)
    native.add_argument("--executable", type=Path, required=True)
    native.add_argument("--state-layout", type=Path, required=True)
    native.add_argument("--capture-receipt", type=Path, required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    replay = commands.add_parser("replay")
    replay.add_argument("trace", type=Path)
    replay.add_argument("--require-native", action="store_true")
    commands.add_parser("verify")
    commands.add_parser("capture-plan")
    args = parser.parse_args()

    if args.command == "run-web":
        records = run_web(args.scenario, args.output)
        print(f"web trajectory: samples={len(records) - 2} sha256={records[-1]['content_sha256']}")
    elif args.command == "import-native":
        records = import_native(
            args.raw, args.output, args.scenario, args.executable,
            args.state_layout, args.capture_receipt
        )
        print(f"native trajectory: samples={len(records) - 2} sha256={records[-1]['content_sha256']}")
    elif args.command == "compare":
        differences = compare_trajectories(read_ndjson(args.baseline), read_ndjson(args.candidate), load_contract())
        if differences:
            print("\n".join(differences))
            raise SystemExit(1)
        print("flight trajectories match")
    elif args.command == "replay":
        records = read_ndjson(args.trace)
        validate_trace(records)
        if args.require_native and records[0]["capture_kind"] != "native":
            raise SystemExit("trajectory is web replay, not native evidence")
        print(json.dumps({
            "capture_kind": records[0]["capture_kind"],
            "scenario": records[0]["scenario"]["id"],
            "samples": records[-1]["sample_count"],
            "content_sha256": records[-1]["content_sha256"],
        }, indent=2))
    elif args.command == "verify":
        print(json.dumps(verify_contract(), sort_keys=True))
    else:
        print(json.dumps(capture_plan(), indent=2))


if __name__ == "__main__":
    main()
