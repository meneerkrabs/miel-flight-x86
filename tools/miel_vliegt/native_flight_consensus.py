#!/usr/bin/env python3
"""Build a fail-closed consensus fixture from independent native flight logs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.native_scenario_artifacts import parse_semantic_log
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from native_scenario_artifacts import parse_semantic_log


PROTOCOL = "miel-vliegt-native-flight-consensus"
ROOT = Path(__file__).resolve().parents[2]
STATE_CHANNELS = {
    "physics.state": ("enter", "leave"),
    "collision.state": ("enter", "commit"),
}
SINGLE_CHANNELS = ("clock.tick", "input.sample", "controls.post", "system.fuel")
NONDETERMINISTIC_STATE_FIELDS = frozenset({"damage_gate_timer_f32_bits"})


class ConsensusError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def _project_values(channel: str, values: dict[str, Any]) -> dict[str, Any]:
    projected = dict(values)
    if channel in STATE_CHANNELS:
        for field in NONDETERMINISTIC_STATE_FIELDS:
            projected.pop(field, None)
    return projected


def _records_by_tick(trace: dict[str, Any]) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = {}
    for row in trace["records"]:
        tick = row.get("tick")
        if isinstance(tick, int) and tick >= 0:
            result.setdefault(tick, []).append(row)
    return result


def _one(rows: list[dict[str, Any]], channel: str, *, phase: str | None = None) -> dict[str, Any]:
    matches = [
        row for row in rows
        if row.get("channel") == channel
        and (phase is None or row.get("values", {}).get("phase") == phase)
        and (channel not in STATE_CHANNELS or row.get("values", {}).get("outer") is True)
    ]
    if len(matches) != 1:
        suffix = f"/{phase}" if phase else ""
        raise ConsensusError(f"expected exactly one {channel}{suffix}, got {len(matches)}")
    values = matches[0].get("values")
    if not isinstance(values, dict):
        raise ConsensusError(f"{channel} values must be an object")
    return _project_values(channel, values)


def project_trace(trace: dict[str, Any]) -> list[dict[str, Any]]:
    by_tick = _records_by_tick(trace)
    clock_ticks = sorted(
        row["tick"] for row in trace["records"] if row.get("channel") == "clock.tick"
    )
    if clock_ticks != list(range(len(clock_ticks))) or not clock_ticks:
        raise ConsensusError("clock ticks must be non-empty and contiguous")

    samples = []
    for tick in clock_ticks:
        rows = by_tick[tick]
        sample: dict[str, Any] = {"tick": tick}
        for channel in SINGLE_CHANNELS:
            sample[channel] = _one(rows, channel)
        for channel, phases in STATE_CHANNELS.items():
            sample[channel] = {phase: _one(rows, channel, phase=phase) for phase in phases}
        samples.append(sample)
    return samples


def _launcher_provenance(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != "miel-vliegt-native-observer-launch" \
            or value.get("status") != "PASS" \
            or value.get("checks", {}).get("scenario_completion_event") is not True:
        raise ConsensusError(f"launcher receipt did not complete: {path}")
    return {
        "path": _portable_path(path),
        "sha256": _sha256_file(path),
        "executable_sha256": value.get("original_executable_sha256"),
        "observer_dll_sha256": value.get("observer_dll_sha256"),
    }


def build_consensus(logs: list[Path], launchers: list[Path]) -> dict[str, Any]:
    if len(logs) < 2 or len(logs) != len(launchers):
        raise ConsensusError("consensus requires at least two logs and one launcher per log")
    traces = [parse_semantic_log(path, require_complete=True) for path in logs]
    scenarios = {trace["scenario_id"] for trace in traces}
    profiles = {trace["profile"] for trace in traces}
    if len(scenarios) != 1 or profiles != {"production-session"}:
        raise ConsensusError("native runs must share one production scenario")

    projections = [project_trace(trace) for trace in traces]
    reference = projections[0]
    for index, projection in enumerate(projections[1:], start=2):
        if projection != reference:
            raise ConsensusError(f"native run {index} differs in the deterministic projection")

    launcher_rows = [_launcher_provenance(path) for path in launchers]
    executable_hashes = {row["executable_sha256"] for row in launcher_rows}
    observer_hashes = {row["observer_dll_sha256"] for row in launcher_rows}
    if len(executable_hashes) != 1 or len(observer_hashes) != 1:
        raise ConsensusError("native runs do not share executable and observer identities")

    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "status": "CANDIDATE_PARTIAL_NATIVE_EVIDENCE",
        "promotion_allowed": False,
        "scenario": next(iter(scenarios)),
        "provenance": {
            "executable_sha256": next(iter(executable_hashes)),
            "observer_dll_sha256": next(iter(observer_hashes)),
            "runs": [
                {
                    "observer_log_path": _portable_path(path),
                    "observer_log_sha256": trace["raw_log_sha256"],
                    "observer_semantic_sha256": trace["semantic_sha256"],
                    "launcher": launcher,
                }
                for path, trace, launcher in zip(logs, traces, launcher_rows)
            ],
        },
        "determinism": {
            "run_count": len(logs),
            "sample_count": len(reference),
            "projection_sha256": hashlib.sha256(_canonical(reference)).hexdigest(),
            "excluded": [
                {
                    "path": "*.damage_gate_timer_f32_bits",
                    "reason": "wall-clock-derived diagnostic differs between otherwise bit-identical runs",
                },
                {
                    "path": "rng.* and render.framebuffer",
                    "reason": "not physics-state inputs and not bit-identical in this capture pair",
                },
            ],
        },
        "coverage": {
            "proved": [
                "30 contiguous native no-input trajectory transitions",
                "30 native fuel observations",
                "30 native non-contact collision passes",
                "two-run bit identity for the retained projection",
            ],
            "not_proved": [
                "web trajectory equivalence",
                "aerodynamic input semantics",
                "terrain height sampling",
                "contact response",
                "landing or crash classification",
                "fuel depletion, refuelling, damage, forced return or ejection",
            ],
        },
        "samples": reference,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", action="append", type=Path, required=True)
    parser.add_argument("--launcher", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    value = build_consensus(args.log, args.launcher)
    rendered = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != rendered:
            raise ConsensusError(f"consensus artifact is stale: {args.output}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
