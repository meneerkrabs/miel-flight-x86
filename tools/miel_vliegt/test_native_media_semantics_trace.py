#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_media_semantics_trace as trace


def record(
    sequence: int,
    behaviour_id: str,
    phase: str,
    call_id: int,
    site_rva: str,
    values: dict,
    *,
    thread_id: int = 71,
) -> dict:
    return {
        "schema": 1,
        "protocol": trace.PROTOCOL,
        "sequence": sequence,
        "behaviour_id": behaviour_id,
        "phase": phase,
        "tick": sequence,
        "frame": sequence + 10,
        "call_id": call_id,
        "site_rva": site_rva,
        "values": values,
        "thread_id": thread_id,
    }


def valid_records(*, thread_id: int = 71) -> list[dict]:
    return [
        record(
            0, "audio_completion", "audio_start", 0,
            trace.AUDIO_START_SITE,
            {"accepted": True, "replaced_active": False},
            thread_id=thread_id,
        ),
        record(
            1, "audio_completion", "audio_poll", 0,
            trace.AUDIO_POLL_SITE,
            {"complete": False, "poll_ordinal": 0},
            thread_id=thread_id,
        ),
        record(
            2, "randomframe_cadence", "rng_draw", 0,
            "0x00000405",
            {"sampling_point": "initial", "value": 123},
            thread_id=thread_id,
        ),
        record(
            3, "audio_completion", "audio_poll", 0,
            trace.AUDIO_POLL_SITE,
            {"complete": True, "poll_ordinal": 1},
            thread_id=thread_id,
        ),
        record(
            4, "randomframe_cadence", "rng_draw", 1,
            "0x000005a2",
            {"sampling_point": "cadence", "value": 456},
            thread_id=thread_id,
        ),
    ]


def render(records: list[dict]) -> str:
    return "\n".join(
        ["ordinary projector output"]
        + ["MVD " + json.dumps(row, sort_keys=True) for row in records]
        + [
            'MVT {"schema":1,"record_type":"session"}',
            (
                'MVD {"schema":1,"protocol":'
                '"some-other-diagnostic","sequence":500}'
            ),
        ]
    )


class NativeMediaSemanticsTraceTest(unittest.TestCase):
    def test_valid_mixed_log_yields_non_promoting_deterministic_summary(self):
        records = trace.parse_observations(render(valid_records()))
        value = trace.build_observation_set(records)
        self.assertEqual(value["observationCount"], 5)
        self.assertEqual(value["behaviours"]["audio_completion"], {
            "starts": 1,
            "acceptedStarts": 1,
            "activeReplacements": 0,
            "polls": 2,
            "completedCalls": 1,
        })
        self.assertEqual(value["behaviours"]["randomframe_cadence"], {
            "draws": 2,
            "initialDraws": 1,
            "cadenceDraws": 1,
        })
        self.assertFalse(value["promotionEligible"])
        self.assertIsNone(value["promotionReceipt"])
        self.assertEqual(len(value["observationsSha256"]), 64)

    def test_thread_provenance_does_not_change_semantic_digest(self):
        left = trace.build_observation_set(
            trace.parse_observations(render(valid_records(thread_id=71)))
        )
        right = trace.build_observation_set(
            trace.parse_observations(render(valid_records(thread_id=99)))
        )
        self.assertEqual(
            left["observationsSha256"], right["observationsSha256"]
        )

    def test_consume_trace_reads_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native.log"
            path.write_text(render(valid_records()), encoding="utf-8")
            self.assertEqual(trace.consume_trace(path)["observationCount"], 5)

    def test_missing_records_fail_closed(self):
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError, "observations are absent"
        ):
            trace.parse_observations(
                'MVD {"protocol":"some-other-diagnostic"}'
            )

    def test_malformed_diagnostic_json_fails_closed(self):
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError, "malformed diagnostic JSON"
        ):
            trace.parse_observations("MVD {")

    def test_noncontiguous_sequence_fails_closed(self):
        records = valid_records()
        records[2]["sequence"] = 9
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError, "sequence is not contiguous"
        ):
            trace.parse_observations(render(records))

    def test_cross_thread_trace_fails_closed(self):
        records = valid_records()
        records[-1]["thread_id"] = 72
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError, "crossed engine threads"
        ):
            trace.parse_observations(render(records))

    def test_unknown_field_fails_closed(self):
        records = valid_records()
        records[0]["pointer"] = "0x12345678"
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError, "observation shape differs"
        ):
            trace.parse_observations(render(records))

    def test_site_and_sampling_point_are_bound_together(self):
        records = valid_records()
        records[-1]["values"]["sampling_point"] = "initial"
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError,
            "randomframe observation contract differs",
        ):
            trace.parse_observations(render(records))

    def test_orphan_or_rejected_audio_poll_fails_closed(self):
        orphan = valid_records()[1:]
        for sequence, row in enumerate(orphan):
            row["sequence"] = sequence
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError,
            "audio poll has no accepted start",
        ):
            trace.parse_observations(render(orphan))

        rejected = valid_records()
        rejected[0]["values"]["accepted"] = False
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError,
            "audio poll has no accepted start",
        ):
            trace.parse_observations(render(rejected))

    def test_poll_and_rng_ordinals_must_be_contiguous(self):
        bad_poll = copy.deepcopy(valid_records())
        bad_poll[3]["values"]["poll_ordinal"] = 2
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError,
            "audio poll ordinals are not contiguous",
        ):
            trace.parse_observations(render(bad_poll))

        bad_rng = copy.deepcopy(valid_records())
        bad_rng[-1]["call_id"] = 3
        with self.assertRaisesRegex(
            trace.NativeMediaSemanticsTraceError,
            "randomframe call ids are not contiguous",
        ):
            trace.parse_observations(render(bad_rng))

    def test_checked_in_schema_pins_protocol_sites_and_no_extra_fields(self):
        schema_path = (
            Path(__file__).with_name("native_media_semantics_trace_schema.json")
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]), trace.TOP_LEVEL_KEYS
        )
        self.assertEqual(
            schema["properties"]["protocol"]["const"], trace.PROTOCOL
        )
        self.assertEqual(
            set(schema["properties"]["site_rva"]["enum"]),
            {
                trace.AUDIO_START_SITE,
                trace.AUDIO_POLL_SITE,
                *trace.RANDOMFRAME_SITES,
            },
        )
        branches = {}
        for branch in schema["oneOf"]:
            properties = branch["properties"]
            key = (
                properties["behaviour_id"]["const"],
                properties["phase"]["const"],
                properties["site_rva"]["const"],
            )
            branches[key] = properties["values"]["$ref"]
        self.assertEqual(branches, {
            (
                "audio_completion",
                "audio_start",
                trace.AUDIO_START_SITE,
            ): "#/$defs/audio_start_values",
            (
                "audio_completion",
                "audio_poll",
                trace.AUDIO_POLL_SITE,
            ): "#/$defs/audio_poll_values",
            (
                "randomframe_cadence",
                "rng_draw",
                "0x00000405",
            ): "#/$defs/randomframe_initial_values",
            (
                "randomframe_cadence",
                "rng_draw",
                "0x000005a2",
            ): "#/$defs/randomframe_cadence_values",
        })
        expected_value_contracts = {
            "audio_start_values": {
                "accepted": {"type": "boolean"},
                "replaced_active": {"type": "boolean"},
            },
            "audio_poll_values": {
                "complete": {"type": "boolean"},
                "poll_ordinal": {"$ref": "#/$defs/uint32"},
            },
            "randomframe_initial_values": {
                "sampling_point": {"const": "initial"},
                "value": {"$ref": "#/$defs/uint32"},
            },
            "randomframe_cadence_values": {
                "sampling_point": {"const": "cadence"},
                "value": {"$ref": "#/$defs/uint32"},
            },
        }
        for name, properties in expected_value_contracts.items():
            definition = schema["$defs"][name]
            self.assertFalse(definition["additionalProperties"])
            self.assertEqual(set(definition["required"]), set(properties))
            self.assertEqual(definition["properties"], properties)


if __name__ == "__main__":
    unittest.main()
