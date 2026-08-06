#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.native_discovery import DiscoveryError, parse_log, summarize


def marker():
    return 'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook","status":"LOADED","thread_id":7}'


def record(sequence, channel, frame=0, snapshot="00"):
    return "MVT " + json.dumps({
        "record": "discovery", "sequence": sequence, "channel": channel,
        "frame": frame,
        "values": {
            "this_address": "0x00500000", "camera_address": "0x00600000",
            "flight_address": "0x00700000", "snapshot_size": len(snapshot) // 2,
            "snapshot_hex": snapshot,
        },
        "diagnostics": {"thread_id": 7},
    }, separators=(",", ":"))


class NativeDiscoveryTests(unittest.TestCase):
    def write(self, lines):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "observer.log"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_complete_log_is_summarized_but_never_promoted(self):
        channels = [
            "controls.sample.raw", "physics.entry.raw", "physics.leave.raw",
            "collision.entry.raw", "camera.entry.raw", "render.entry.raw",
        ]
        path = self.write([marker()] + [
            record(index, channel, int(channel == "render.entry.raw"), "0001")
            for index, channel in enumerate(channels)
        ])
        result = summarize(path, require_all=True)
        self.assertEqual(result["status"], "DISCOVERY_ONLY")
        self.assertEqual(result["record_count"], 6)
        self.assertEqual(result["channel_counts"]["physics.entry.raw"], 1)
        self.assertEqual(result["last_frame"], 1)

    def test_missing_channel_fails_when_complete_capture_is_requested(self):
        path = self.write([marker(), record(0, "physics.entry.raw")])
        with self.assertRaisesRegex(DiscoveryError, "channels incomplete"):
            parse_log(path, require_all=True)

    def test_sequence_snapshot_and_frame_tampering_fail_closed(self):
        path = self.write([marker(), record(1, "physics.entry.raw")])
        with self.assertRaisesRegex(DiscoveryError, "sequence"):
            parse_log(path)

        malformed = record(0, "physics.entry.raw").replace('"snapshot_size":1', '"snapshot_size":2')
        path = self.write([marker(), malformed])
        with self.assertRaisesRegex(DiscoveryError, "snapshot"):
            parse_log(path)

        path = self.write([
            marker(), record(0, "render.entry.raw", 2),
            record(1, "physics.entry.raw", 1),
        ])
        with self.assertRaisesRegex(DiscoveryError, "monotonic"):
            parse_log(path)


if __name__ == "__main__":
    unittest.main()
