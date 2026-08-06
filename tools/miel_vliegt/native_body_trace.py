#!/usr/bin/env python3
"""Validate fail-closed native mode lifecycle BODY traces.

`MVB` records are diagnostic BODY-only evidence.  They can prove that a
hash-reviewed native lifecycle entry returned on the original engine thread;
they can never prove a natural scene transition or web/native equivalence.
Constructor capture is deliberately unresolved because the observer uses
vtable interposition and cannot pair a constructor before its vtable exists.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.miel_vliegt import native_mode_bodies


DEFAULT_CONTRACT = ROOT / "content/miel_vliegt/native_mode_bodies.json"
PREFIX = "MVB "
PROTOCOL = "miel-vliegt-native-body-lifecycle"
VALIDATION_SCHEMA = 2
DISPATCH_PROTOCOL = "miel-vliegt-native-body-dispatch"
DISPATCH_SCHEMA = 2
PHASES = ("LOAD", "OPEN", "TICK", "RENDER", "CLOSE", "UNLOAD")
CORE_PHASES = ("LOAD", "OPEN", "TICK", "RENDER")
EDGES = ("ENTER", "LEAVE")
ADDRESS = re.compile(r"^0x[0-9a-f]{8}$")
FIELDS = {
    "schema",
    "protocol",
    "sequence",
    "evidence_scope",
    "natural_transition_evidence",
    "mode_id",
    "object",
    "vtable",
    "phase",
    "entry",
    "edge",
    "thread",
    "tick",
    "depth",
}
PAIR_FIELDS = (
    "mode_id", "object", "vtable", "phase", "entry", "thread", "tick", "depth"
)


class BodyTraceError(ValueError):
    """Raised when BODY evidence does not satisfy the canonical contract."""


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    contract = json.loads(path.read_text(encoding="utf-8"))
    native_mode_bodies.validate_contract(
        contract,
        root=ROOT,
        verify_artifacts=path.resolve() == DEFAULT_CONTRACT.resolve(),
    )
    return contract


def expected_lifecycles(contract: dict[str, Any]) -> dict[str, dict[str, str]]:
    return {
        row["id"]: {
            "mode": row["mode"],
            "vtable": row["vtable"],
            **{phase.upper(): entry for phase, entry in row["lifecycle"].items()},
        }
        for row in contract["modes"]
    }


def parse_records(lines: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line.startswith(PREFIX):
            continue
        try:
            record = json.loads(line[len(PREFIX):])
        except json.JSONDecodeError as error:
            raise BodyTraceError(f"BODY line {line_number} is invalid JSON") from error
        if not isinstance(record, dict):
            raise BodyTraceError(f"BODY line {line_number} is not an object")
        records.append(record)
    return records


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def expected_return_mode(requested_mode: str) -> str:
    """Return the distinct mode used to force the requested mode's teardown."""

    return "mode_login" if requested_mode == "mode_barn" else "mode_barn"


def validate_dispatch_receipt(
    receipt: dict[str, Any], *, executable_sha256: str, requested_mode: str,
    mode_id: str, lifecycle_validation: dict[str, Any],
) -> dict[str, Any]:
    """Bind schema-2 dispatcher state-machine evidence to paired MVB records.

    Schema 1 proved only activation and is deliberately rejected here: it
    cannot establish a return callback, fresh core work or native teardown.
    """

    if receipt.get("schema") == 1:
        raise BodyTraceError(
            "BODY dispatcher schema 1 cannot prove lifecycle completion"
        )
    if receipt.get("schema") != DISPATCH_SCHEMA:
        raise BodyTraceError("BODY dispatcher schema-2 receipt is required")
    required = {
        "schema", "protocol", "status", "evidence_scope",
        "natural_transition_evidence", "debug_skip_used",
        "executable_sha256", "requested_mode", "return_mode", "command",
        "callback_count", "manager_thread", "dispatch_thread", "ticks",
        "entry", "core", "return", "teardown", "lifecycle_complete",
    }
    expected_return = expected_return_mode(requested_mode)
    flight = requested_mode == "mode_fly"
    expected_status = "INCOMPLETE" if flight else "PASS"
    expected_missing = ["UNLOAD"] if flight else []
    if (
        set(receipt) != required
        or receipt.get("protocol") != DISPATCH_PROTOCOL
        or receipt.get("status") != expected_status
        or receipt.get("evidence_scope") != "BODY_ONLY"
        or receipt.get("natural_transition_evidence") is not False
        or receipt.get("debug_skip_used") is not False
        or receipt.get("executable_sha256") != executable_sha256
        or receipt.get("requested_mode") != requested_mode
        or receipt.get("return_mode") != expected_return
        or receipt.get("command") != {
            "name": "engine_mode", "id": 15,
            "dispatch": "registered-command-callback",
        }
        or receipt.get("callback_count") != 2
        or receipt.get("manager_thread") is not True
        or not _non_negative_int(receipt.get("dispatch_thread"))
        or receipt.get("dispatch_thread") == 0
        or receipt.get("lifecycle_complete") is not (not flight)
    ):
        raise BodyTraceError("BODY dispatcher schema-2 envelope failed closed")

    ticks = receipt.get("ticks")
    tick_fields = (
        "entry_dispatch", "target_activation", "core_ready",
        "return_dispatch", "return_activation",
    )
    if (
        not isinstance(ticks, dict)
        or set(ticks) != set(tick_fields)
        or not all(_non_negative_int(ticks.get(field)) for field in tick_fields)
        or not (
            ticks["entry_dispatch"] <= ticks["target_activation"]
            <= ticks["core_ready"] <= ticks["return_dispatch"]
            <= ticks["return_activation"]
        )
    ):
        raise BodyTraceError("BODY dispatcher tick ordering failed closed")

    expected_entry_post = (
        {
            "current_mode": "mode_barn", "pending_mode": None,
            "dispatch_effect": "SAME_MODE_NOOP",
        }
        if requested_mode == "mode_barn"
        else {
            "current_mode": "mode_barn", "pending_mode": requested_mode,
            "dispatch_effect": "PENDING_TARGET",
        }
    )
    entry = receipt.get("entry")
    if entry != {
        "pre": {
            "manager_canonical": True, "current_mode": "mode_barn",
            "pending_null": True, "target_resolved_before_mutation": True,
            "registry_record_resolved": True,
        },
        "post": expected_entry_post,
        "activation": {
            "current_mode": requested_mode, "pending_null": True,
            "loaded": True, "opened": True,
        },
    }:
        raise BodyTraceError("BODY dispatcher entry transition failed closed")

    return_transition = receipt.get("return")
    if return_transition != {
        "pre": {
            "current_mode": requested_mode, "pending_null": True,
            "loaded": True, "opened": True,
        },
        "post": {
            "current_mode": requested_mode, "pending_mode": expected_return,
            "dispatch_effect": "PENDING_RETURN",
        },
        "activation": {
            "current_mode": expected_return, "pending_null": True,
            "loaded": True, "opened": True,
        },
    }:
        raise BodyTraceError("BODY dispatcher return transition failed closed")

    coverage = lifecycle_validation.get("phase_coverage")
    mode_coverage = coverage.get(mode_id) if isinstance(coverage, dict) else None
    if (
        lifecycle_validation.get("protocol")
        != "miel-vliegt-native-body-lifecycle-validation"
        or lifecycle_validation.get("schema") != VALIDATION_SCHEMA
        or lifecycle_validation.get("engine_thread") != receipt["dispatch_thread"]
        or not isinstance(mode_coverage, dict)
        or mode_coverage.get("mode") != requested_mode
    ):
        raise BodyTraceError("BODY dispatcher/lifecycle identity failed closed")

    counts = mode_coverage.get("counts")
    leave_ticks = mode_coverage.get("last_leave_ticks")
    core = receipt.get("core")
    if (
        not isinstance(counts, dict)
        or not isinstance(leave_ticks, dict)
        or not isinstance(core, dict)
        or set(core) != {
            "paired_counts", "last_leave_ticks", "fresh_after_activation",
            "complete",
        }
        or core.get("paired_counts") != {
            phase: counts.get(phase) for phase in CORE_PHASES
        }
        or core.get("last_leave_ticks") != {
            phase: leave_ticks.get(phase) for phase in CORE_PHASES
        }
        or core.get("fresh_after_activation") != {"TICK": True, "RENDER": True}
        or core.get("complete") is not True
        or any(not _non_negative_int(counts.get(phase)) or counts[phase] < 1
               for phase in CORE_PHASES)
        or any(not _non_negative_int(leave_ticks.get(phase))
               for phase in CORE_PHASES)
        or leave_ticks["TICK"] < ticks["target_activation"]
        or leave_ticks["RENDER"] < ticks["target_activation"]
        or any(leave_ticks[phase] > ticks["core_ready"] for phase in CORE_PHASES)
    ):
        raise BodyTraceError("BODY dispatcher core freshness failed closed")

    teardown = receipt.get("teardown")
    expected_teardown = {
        "close_pairs_delta": 1,
        "unload_pairs_delta": 0 if flight else 1,
        "close_observed": True,
        "unload_observed": not flight,
        "unload_policy": "SKIPPED_MODE_FLY" if flight else "MANAGER_COMMIT",
        "missing_phases": expected_missing,
        "complete": not flight,
    }
    if (
        teardown != expected_teardown
        or counts.get("CLOSE") != teardown["close_pairs_delta"]
        or counts.get("UNLOAD") != teardown["unload_pairs_delta"]
        or mode_coverage.get("missing_phases") != expected_missing
        or mode_coverage.get("complete") is not (not flight)
    ):
        raise BodyTraceError("BODY dispatcher teardown binding failed closed")
    return dict(receipt)


def validate_records(
    records: list[dict[str, Any]], contract: dict[str, Any],
    required_mode_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    if not records:
        raise BodyTraceError("BODY trace contains no lifecycle records")
    expected = expected_lifecycles(contract)
    stack: list[dict[str, Any]] = []
    pairs: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    last_leave_ticks: dict[str, dict[str, int]] = defaultdict(dict)
    engine_thread: int | None = None

    for sequence, record in enumerate(records):
        if set(record) != FIELDS:
            raise BodyTraceError(
                f"BODY sequence {sequence} fields drifted: "
                f"missing={sorted(FIELDS - set(record))}, "
                f"unknown={sorted(set(record) - FIELDS)}"
            )
        if record["schema"] != 1 or record["protocol"] != PROTOCOL:
            raise BodyTraceError(f"BODY sequence {sequence} protocol drifted")
        if record["sequence"] != sequence:
            raise BodyTraceError(
                f"BODY sequence is not contiguous: expected {sequence}, "
                f"got {record['sequence']!r}"
            )
        if (
            record["evidence_scope"] != "BODY_ONLY"
            or record["natural_transition_evidence"] is not False
        ):
            raise BodyTraceError(
                f"BODY sequence {sequence} escaped BODY-only evidence policy"
            )
        mode = expected.get(record["mode_id"])
        if mode is None:
            raise BodyTraceError(f"BODY sequence {sequence} has unknown mode")
        if record["phase"] not in PHASES or record["edge"] not in EDGES:
            raise BodyTraceError(f"BODY sequence {sequence} has unknown phase or edge")
        if not ADDRESS.fullmatch(record["object"]) or record["object"] == "0x00000000":
            raise BodyTraceError(f"BODY sequence {sequence} has invalid object")
        if record["vtable"] != mode["vtable"]:
            raise BodyTraceError(f"BODY sequence {sequence} vtable differs from canonical mode")
        if record["entry"] != mode[record["phase"]]:
            raise BodyTraceError(f"BODY sequence {sequence} entry differs from canonical phase")
        if not all(_non_negative_int(record[key]) for key in ("thread", "tick", "depth")):
            raise BodyTraceError(f"BODY sequence {sequence} has invalid numeric identity")
        if record["thread"] == 0:
            raise BodyTraceError(f"BODY sequence {sequence} has a null thread")
        if engine_thread is None:
            engine_thread = record["thread"]
        elif record["thread"] != engine_thread:
            raise BodyTraceError("BODY trace contains a non-engine thread")

        if record["edge"] == "ENTER":
            if record["depth"] != len(stack):
                raise BodyTraceError(f"BODY sequence {sequence} ENTER depth is not nested")
            stack.append(record)
            continue

        if not stack:
            raise BodyTraceError(f"BODY sequence {sequence} LEAVE has no ENTER")
        entered = stack.pop()
        if record["depth"] != len(stack):
            raise BodyTraceError(f"BODY sequence {sequence} LEAVE depth is not nested")
        if any(record[field] != entered[field] for field in PAIR_FIELDS):
            raise BodyTraceError(f"BODY sequence {sequence} does not pair with ENTER")
        pairs[record["mode_id"]][record["phase"]] += 1
        last_leave_ticks[record["mode_id"]][record["phase"]] = record["tick"]

    if stack:
        raise BodyTraceError("BODY trace ends with unpaired ENTER records")
    if required_mode_ids is None:
        required_modes = sorted(pairs)
    else:
        required_modes = list(required_mode_ids)
        if (
            not required_modes
            or any(not isinstance(mode_id, str) for mode_id in required_modes)
            or len(set(required_modes)) != len(required_modes)
            or any(mode_id not in expected for mode_id in required_modes)
        ):
            raise BodyTraceError("BODY required-mode coverage contract is invalid")
    phase_coverage = {}
    for mode_id in required_modes:
        counts = {phase: pairs[mode_id].get(phase, 0) for phase in PHASES}
        missing = [phase for phase in PHASES if counts[phase] == 0]
        phase_coverage[mode_id] = {
            "mode": expected[mode_id]["mode"],
            "counts": counts,
            "last_leave_ticks": {
                phase: last_leave_ticks[mode_id].get(phase) for phase in PHASES
            },
            "missing_phases": missing,
            "complete": not missing,
        }
    coverage_complete = bool(required_modes) and all(
        row["complete"] for row in phase_coverage.values()
    )
    return {
        "schema": VALIDATION_SCHEMA,
        "protocol": "miel-vliegt-native-body-lifecycle-validation",
        "status": "PASS" if coverage_complete else "INCOMPLETE",
        "evidence_scope": "BODY_ONLY",
        "natural_transition_evidence": False,
        "engine_thread": engine_thread,
        "record_count": len(records),
        "pair_count": len(records) // 2,
        "observed": {
            mode_id: dict(sorted(phases.items()))
            for mode_id, phases in sorted(pairs.items())
        },
        "required_modes": required_modes,
        "phase_coverage": phase_coverage,
        "coverage_complete": coverage_complete,
        "constructor_capture": "UNRESOLVED",
        "runtime_body_equivalence": "UNPROVEN",
        "parity_eligible": False,
    }


def validate_trace(
    trace_path: Path, contract_path: Path = DEFAULT_CONTRACT,
    required_mode_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    contract = load_contract(contract_path)
    with trace_path.open(encoding="utf-8", errors="strict") as trace:
        return validate_records(
            parse_records(trace), contract, required_mode_ids,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    args = parser.parse_args()
    result = validate_trace(args.trace, args.contract)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
