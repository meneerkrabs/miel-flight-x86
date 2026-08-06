#!/usr/bin/env python3
"""Producer-independent integrity and identity gate for semantic evidence.

The envelope is shared by native, web and callback producers. It binds one
content-addressed payload to the edition claim, expectation, runtime session,
event occurrence and producer build that created it. Hashes are integrity
bindings, not a claim of third-party cryptographic attestation.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from typing import Any


PROTOCOL = "miel-authenticated-evidence-envelope"
AUDIO_CALLBACK_PROTOCOL = "miel-flight-audio-callback-completion"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ENVELOPE_FIELDS = {
    "schema", "protocol", "producer", "evidenceKind", "edition", "claimId",
    "evidenceClass", "subjectSha256", "expectationSha256",
    "runtimeSessionSha256", "occurrenceId", "producerBuildSha256",
    "payloadSha256", "envelopeSha256",
}
AUDIO_PAYLOAD_FIELDS = {
    "schema", "protocol", "semanticStatus", "parityEligible", "script",
    "executableCommandIndex", "sourceCommandIndex", "opcode", "nativeOpcode",
    "assetKey", "assetSourceSha256", "take", "completionRoute",
    "armedByEventOccurrenceId", "eventOccurrenceId", "acceptedSignal",
    "lifecycleTranscript",
}
AUDIO_SIGNALS = {"PHASER_ON_COMPLETE", "PHASER_ON_STOP"}
AUDIO_ROUTES = {"DIRECT_PHASER_CALLBACK", "NATIVE_AUDIO_SERVICE_POLL"}
AUDIO_LIFECYCLE_EVENTS = {
    "START_ATTEMPT", "STARTED", "CALLBACK_ACCEPTED", "START_FAILED",
    "RELEASED", "SOUND_REUSED", "SOUND_PREEMPTED", "RADIO_ENQUEUED",
    "RADIO_PRIMARY_STARTED", "RADIO_PRIMARY_ENDED", "RADIO_ALERT_STARTED",
    "RADIO_ALERT_ENDED", "POLL_ACTIVE", "POLL_QUEUED", "POLL_ABSENT",
}


class AuthenticatedEvidenceError(ValueError):
    """Raised when an evidence envelope is forged, reused or misbound."""


def canonical_sha256(value: Any) -> str:
    def normalize(item: Any) -> Any:
        if type(item) is bool or item is None or isinstance(item, str):
            return item
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            bits = struct.unpack(">Q", struct.pack(">d", float(item)))[0]
            return {"$numberF64": f"0x{bits:016x}"}
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise AuthenticatedEvidenceError("evidence object key is not a string")
            return {key: normalize(item[key]) for key in sorted(item)}
        raise AuthenticatedEvidenceError("evidence payload is not plain JSON")

    encoded = json.dumps(
        normalize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise AuthenticatedEvidenceError(f"{label} is not a lowercase SHA-256")
    return value


def _non_negative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise AuthenticatedEvidenceError(f"{label} is not a non-negative integer")
    return value


def runtime_occurrence_events(
    event_occurrence_ids: list[str],
    receipts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if len(event_occurrence_ids) != len(receipts):
        raise AuthenticatedEvidenceError(
            "runtime receipt and occurrence counts differ"
        )
    events: list[dict[str, Any]] = []
    for receipt_index, receipt in enumerate(receipts):
        parent_occurrence = _sha(
            event_occurrence_ids[receipt_index], "runtime event occurrence"
        )
        events.append({
            "event": receipt,
            "occurrenceId": parent_occurrence,
            "order": len(events),
        })

        def visit(branches: Any, path: list[int]) -> None:
            if branches is None:
                return
            if not isinstance(branches, list):
                raise AuthenticatedEvidenceError(
                    "nested runtime branches are not an array"
                )
            for branch_index, branch in enumerate(branches):
                if not isinstance(branch, dict):
                    raise AuthenticatedEvidenceError(
                        "nested runtime branch is not an object"
                    )
                branch_path = [*path, branch_index]
                occurrence = canonical_sha256({
                    "protocol": "miel-vliegt-web-scene-nested-event-occurrence",
                    "parentEventOccurrenceId": parent_occurrence,
                    "branchPath": branch_path,
                    "branchSha256": canonical_sha256(branch),
                })
                events.append({
                    "event": branch,
                    "occurrenceId": occurrence,
                    "order": len(events),
                })
                outcome = branch.get("outcome")
                visit(
                    outcome.get("branches")
                    if isinstance(outcome, dict) else None,
                    branch_path,
                )

        outcome = receipt.get("outcome") if isinstance(receipt, dict) else None
        visit(outcome.get("branches") if isinstance(outcome, dict) else None, [])
    occurrence_ids = [row["occurrenceId"] for row in events]
    if len(occurrence_ids) != len(set(occurrence_ids)):
        raise AuthenticatedEvidenceError("runtime event occurrence is reused")
    return events


def validate_audio_callback_payload(
    payload: Any,
    *,
    event_occurrence_ids: list[str],
    receipts: list[dict[str, Any]],
    asset_source_sha256_by_key: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != AUDIO_PAYLOAD_FIELDS \
            or payload.get("schema") != 1 \
            or payload.get("protocol") != AUDIO_CALLBACK_PROTOCOL \
            or payload.get("semanticStatus") != "UNPROVEN" \
            or payload.get("parityEligible") is not False:
        raise AuthenticatedEvidenceError("audio callback payload fields differ")
    for field in ("script", "opcode", "assetKey"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise AuthenticatedEvidenceError(f"audio callback {field} differs")
    for field in ("executableCommandIndex", "sourceCommandIndex", "nativeOpcode", "take"):
        _non_negative_int(payload.get(field), f"audio callback {field}")
    _sha(payload.get("assetSourceSha256"), "audio callback assetSourceSha256")
    if asset_source_sha256_by_key is not None \
            and asset_source_sha256_by_key.get(payload["assetKey"]) \
            != payload["assetSourceSha256"]:
        raise AuthenticatedEvidenceError(
            "audio callback asset source hash differs"
        )
    armed = _sha(
        payload.get("armedByEventOccurrenceId"),
        "audio callback armedByEventOccurrenceId",
    )
    completed = _sha(
        payload.get("eventOccurrenceId"), "audio callback eventOccurrenceId",
    )
    if payload.get("acceptedSignal") not in AUDIO_SIGNALS \
            or payload.get("completionRoute") not in AUDIO_ROUTES:
        raise AuthenticatedEvidenceError("audio callback route/signal differs")
    occurrence_events = runtime_occurrence_events(event_occurrence_ids, receipts)
    by_occurrence = {
        row["occurrenceId"]: row for row in occurrence_events
    }
    try:
        armed_event = by_occurrence[armed]
        completed_event = by_occurrence[completed]
    except KeyError as error:
        raise AuthenticatedEvidenceError(
            "audio callback occurrence is outside its runtime session"
        ) from error
    if armed_event["order"] >= completed_event["order"]:
        raise AuthenticatedEvidenceError(
            "audio callback completion does not follow its armed occurrence"
        )
    expected_command = (
        payload["script"], payload["executableCommandIndex"],
        payload["sourceCommandIndex"], payload["opcode"],
    )
    for label, receipt in (
        ("armed", armed_event["event"]), ("completion", completed_event["event"]),
    ):
        actual_command = (
            receipt.get("script"), receipt.get("executableCommandIndex"),
            receipt.get("sourceCommandIndex"), receipt.get("opcode"),
        )
        outcome = receipt.get("outcome")
        media_binding = outcome.get("mediaBinding", {}) if isinstance(outcome, dict) else {}
        if actual_command != expected_command or not isinstance(outcome, dict) \
                or outcome.get("port") != payload["opcode"] \
                or media_binding.get("assetKey") != payload["assetKey"] \
                or media_binding.get("nativeOpcode") \
                != payload["nativeOpcode"]:
            raise AuthenticatedEvidenceError(
                f"audio callback {label} command/asset binding differs"
            )
        expected_take = media_binding.get("take", 1)
        if payload["take"] != expected_take:
            raise AuthenticatedEvidenceError(
                f"audio callback {label} take binding differs"
            )
    def completion_state(event: dict[str, Any]) -> Any:
        scheduler = event.get("scheduler")
        return scheduler.get("complete") if isinstance(scheduler, dict) \
            else event.get("complete")

    if completion_state(armed_event["event"]) is not False \
            or completion_state(completed_event["event"]) is not True:
        raise AuthenticatedEvidenceError(
            "audio callback does not bind STARTED then COMPLETE command occurrences"
        )
    lifecycle = payload.get("lifecycleTranscript")
    if not isinstance(lifecycle, list) or not lifecycle:
        raise AuthenticatedEvidenceError("audio callback lifecycle transcript is empty")
    callback_rows = []
    lifecycle_events = []
    for sequence, row in enumerate(lifecycle):
        if not isinstance(row, dict) or set(row) != {"sequence", "event", "details"} \
                or row.get("sequence") != sequence \
                or row.get("event") not in AUDIO_LIFECYCLE_EVENTS \
                or (row.get("details") is not None
                    and not isinstance(row.get("details"), dict)):
            raise AuthenticatedEvidenceError("audio callback lifecycle fields differ")
        lifecycle_events.append(row["event"])
        if row["event"] == "CALLBACK_ACCEPTED":
            callback_rows.append(row)
    if len(callback_rows) != 1 \
            or callback_rows[0].get("details") != {
                "signal": payload["acceptedSignal"],
            }:
        raise AuthenticatedEvidenceError(
            "audio callback lifecycle lacks one exact accepted callback"
        )
    if "POLL_ABSENT" not in lifecycle_events:
        raise AuthenticatedEvidenceError(
            "audio callback lifecycle lacks the completing absent poll"
        )
    if "STARTED" not in lifecycle_events and "SOUND_REUSED" not in lifecycle_events:
        raise AuthenticatedEvidenceError(
            "audio callback lifecycle lacks playback start or exact reuse"
        )
    callback_sequence = callback_rows[0]["sequence"]
    if any(event in {"START_FAILED", "RELEASED", "SOUND_PREEMPTED"}
           for event in lifecycle_events):
        raise AuthenticatedEvidenceError(
            "audio callback completion contains a terminal non-callback cause"
        )
    start_sequence = max(
        index for index, event in enumerate(lifecycle_events)
        if event in {"STARTED", "SOUND_REUSED"}
    )
    completing_polls = [
        index for index, event in enumerate(lifecycle_events)
        if event == "POLL_ABSENT" and index > callback_sequence
    ]
    if start_sequence >= callback_sequence or not completing_polls:
        raise AuthenticatedEvidenceError(
            "audio callback lifecycle ordering differs"
        )
    return payload


def validate_record(
    record: Any,
    *,
    expected: dict[str, Any],
    event_occurrence_ids: list[str],
    receipts: list[dict[str, Any]],
    used_envelopes: set[str] | None = None,
    used_payloads: set[str] | None = None,
    used_occurrences: set[str] | None = None,
    asset_source_sha256_by_key: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != {"envelope", "payload"}:
        raise AuthenticatedEvidenceError("authenticated evidence record fields differ")
    envelope = record.get("envelope")
    payload = record.get("payload")
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS \
            or envelope.get("schema") != 1 or envelope.get("protocol") != PROTOCOL:
        raise AuthenticatedEvidenceError("authenticated evidence envelope fields differ")
    for field in (
        "producer", "evidenceKind", "edition", "claimId", "evidenceClass",
    ):
        if not isinstance(envelope.get(field), str) or not envelope[field]:
            raise AuthenticatedEvidenceError(f"authenticated evidence {field} differs")
    for field in (
        "subjectSha256", "expectationSha256", "runtimeSessionSha256",
        "occurrenceId", "producerBuildSha256", "payloadSha256", "envelopeSha256",
    ):
        _sha(envelope.get(field), f"authenticated evidence {field}")
    for field, value in expected.items():
        if envelope.get(field) != value:
            raise AuthenticatedEvidenceError(
                f"authenticated evidence {field} differs"
            )
    if canonical_sha256(payload) != envelope["payloadSha256"]:
        raise AuthenticatedEvidenceError("authenticated evidence payload hash differs")
    unhashed = dict(envelope)
    del unhashed["envelopeSha256"]
    if canonical_sha256(unhashed) != envelope["envelopeSha256"]:
        raise AuthenticatedEvidenceError("authenticated evidence envelope hash differs")
    if envelope["occurrenceId"] != payload.get("eventOccurrenceId"):
        raise AuthenticatedEvidenceError(
            "authenticated evidence occurrence and payload differ"
        )
    if envelope["evidenceKind"] == "AUDIO_CALLBACK":
        validate_audio_callback_payload(
            payload,
            event_occurrence_ids=event_occurrence_ids,
            receipts=receipts,
            asset_source_sha256_by_key=asset_source_sha256_by_key,
        )
    else:
        raise AuthenticatedEvidenceError("authenticated evidence kind is unsupported")
    for index, value, label in (
        (used_envelopes, envelope["envelopeSha256"], "envelope"),
        (used_payloads, envelope["payloadSha256"], "payload"),
        (used_occurrences, envelope["occurrenceId"], "occurrence"),
    ):
        if index is not None:
            if value in index:
                raise AuthenticatedEvidenceError(
                    f"authenticated evidence reuses {label}"
                )
            index.add(value)
    return record


def compare_records(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    """Compare already validated producer records without producer-specific fields."""

    left_envelope = left.get("envelope", {})
    right_envelope = right.get("envelope", {})
    identity_fields = (
        "evidenceKind", "edition", "claimId", "evidenceClass",
        "subjectSha256", "expectationSha256",
    )
    differences = [
        field for field in identity_fields
        if left_envelope.get(field) != right_envelope.get(field)
    ]
    def comparable_payload(record: dict[str, Any]) -> Any:
        payload = record.get("payload")
        if not isinstance(payload, dict):
            return payload
        return {
            key: value for key, value in payload.items()
            if key not in {"armedByEventOccurrenceId", "eventOccurrenceId"}
        }

    if comparable_payload(left) != comparable_payload(right):
        differences.append("payload")
    return {
        "schema": 1,
        "protocol": "miel-authenticated-evidence-differential",
        "result": "MATCH" if not differences else "DIFFER",
        "differences": differences,
        "parityEligible": False,
    }
