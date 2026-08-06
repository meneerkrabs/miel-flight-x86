#!/usr/bin/env python3
import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_observer as observer


def map_value(executable_hash: str) -> dict:
    return {
        "schema": 1,
        "source": {"executable_sha256": executable_hash},
        "functions": [{"id": "fn_00401000", "address": "0x00401000"}],
        "basic_blocks": [
            {"id": "bb_00401000", "start": "0x00401000"},
            {"id": "bb_00401010", "start": "0x00401010"},
        ],
        "edges": [{
            "id": "edge_00401000_00401010",
            "source": "bb_00401000", "target": "bb_00401010",
        }],
    }


def events() -> list[dict]:
    registers = {name: index for index, name in enumerate(observer.REGISTER_NAMES)}
    return [
        {"type": "function", "id": "fn_00401000"},
        {"type": "block", "id": "bb_00401000"},
        {"type": "edge", "id": "edge_00401000_00401010"},
        {"type": "flight.step", "tick": 7, "phase": "enter", "dt_f32_bits": 0x3D23D70A},
        {"type": "deep.begin", "window_id": 3, "tick": 7, "reason_code": 9},
        {"type": "deep.instruction", "window_id": 3, "thread_id": 2, "ip": 0x401000, "eflags": 0x202, "registers": registers},
        {"type": "deep.memory", "window_id": 3, "thread_id": 2, "address": 0x500000, "access": "write", "data": b"abc"},
        {"type": "deep.end", "window_id": 3, "tick": 7, "reason_code": 9},
        {"type": "flight.step", "tick": 7, "phase": "leave", "dt_f32_bits": 0x3D23D70A},
    ]


class NativeObserverTests(unittest.TestCase):
    def setUp(self):
        self.executable_hash = "a" * 64
        self.coverage = observer.CoverageIndex.from_value(map_value(self.executable_hash))
        self.scenario_hash = "b" * 64

    def artifact(self, **kwargs) -> bytes:
        return observer.encode_artifact(
            events(), self.coverage, scenario_sha256=self.scenario_hash, **kwargs,
        )

    def test_round_trip_preserves_stable_ids_ticks_deep_trace_and_bitmaps(self):
        capture = observer.parse_artifact(self.artifact(), self.coverage)
        self.assertEqual(capture.capture_kind, "protocol_fixture")
        self.assertTrue(capture.complete)
        self.assertEqual(capture.events[0]["id"], "fn_00401000")
        self.assertEqual(capture.events[3]["type"], "flight.step")
        self.assertEqual(capture.events[6]["data"], b"abc")
        self.assertEqual(capture.coverage["function"], ("fn_00401000",))
        self.assertEqual(capture.coverage["edge"], ("edge_00401000_00401010",))

    def test_unknown_record_type_fails_before_payload_is_interpreted(self):
        artifact = bytearray(self.artifact())
        event_offset = observer.HEADER.size + 1 + 1 + 1
        artifact[event_offset] = 255
        with self.assertRaisesRegex(observer.ObserverError, "unknown observer record type"):
            observer.parse_artifact(bytes(artifact), self.coverage)

    def test_crc_truncation_sequence_and_provenance_tampering_fail(self):
        artifact = self.artifact()
        damaged = bytearray(artifact)
        damaged[-1] ^= 1
        with self.assertRaisesRegex(observer.ObserverError, "CRC mismatch"):
            observer.parse_artifact(bytes(damaged), self.coverage)
        with self.assertRaisesRegex(observer.ObserverError, "length does not match"):
            observer.parse_artifact(artifact[:-1], self.coverage)
        wrong_map = observer.CoverageIndex.from_value(map_value("c" * 64))
        with self.assertRaisesRegex(observer.ObserverError, "provenance"):
            observer.parse_artifact(artifact, wrong_map)

    def test_bitmap_claim_without_event_fails_for_unwrapped_capture(self):
        artifact = bytearray(observer.encode_artifact(
            [], self.coverage, scenario_sha256=self.scenario_hash,
        ))
        artifact[observer.HEADER.size] = 1
        with self.assertRaisesRegex(observer.ObserverError, "bitmap contains coverage"):
            observer.parse_artifact(bytes(artifact), self.coverage)

    def test_wrapped_ring_retains_accumulated_coverage_but_cannot_be_production(self):
        full = self.artifact(native_capture=True)
        header = observer.HEADER.unpack_from(full)
        event_capacity = header[4]
        first_record_size = observer.RECORD.size + observer.U32.size
        wrapped = observer.encode_artifact(
            events(), self.coverage, scenario_sha256=self.scenario_hash,
            native_capture=True, event_capacity=event_capacity - first_record_size,
        )
        capture = observer.parse_artifact(wrapped, self.coverage)
        self.assertTrue(capture.wrapped)
        self.assertEqual(capture.first_sequence, 1)
        self.assertEqual(capture.coverage["function"], ("fn_00401000",))

    def test_unknown_coverage_id_and_malformed_deep_window_fail_encoding(self):
        with self.assertRaisesRegex(observer.ObserverError, "unknown block ID"):
            observer.encode_artifact(
                [{"type": "block", "id": "bb_deadbeef"}], self.coverage,
                scenario_sha256=self.scenario_hash,
            )
        bad = events()
        del bad[4]
        with self.assertRaisesRegex(observer.ObserverError, "outside its window"):
            observer.encode_artifact(bad, self.coverage, scenario_sha256=self.scenario_hash)

    def test_in_process_hook_log_becomes_non_promoted_mvobsv1(self):
        map_data = map_value(self.executable_hash)
        map_data["functions"] = [{"id": "fn_0040e610", "address": "0x0040e610"}]
        coverage = observer.CoverageIndex.from_value(map_data)
        lines = [
            'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook","status":"LOADED","thread_id":7}',
            'MVT {"record":"behavior","sequence":0,"channel":"flight.step.enter","values":{"dt_f32_bits":"0x3d23d70a"},"diagnostics":{"this_address":"0x00500000","thread_id":7}}',
            'MVT {"record":"behavior","sequence":1,"channel":"flight.step.enter","values":{"dt_f32_bits":"0x3ca3d70a"},"diagnostics":{"this_address":"0x00500000","thread_id":7}}',
            'MVT {"record":"behavior","sequence":2,"channel":"flight.step.leave","values":{},"diagnostics":{"thread_id":7}}',
            'MVT {"record":"behavior","sequence":3,"channel":"flight.step.leave","values":{},"diagnostics":{"thread_id":7}}',
        ]
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "hook.log"
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            artifact = observer.import_hook_log(
                log, coverage, scenario_sha256=self.scenario_hash,
            )
        capture = observer.parse_artifact(artifact, coverage)
        self.assertEqual(capture.capture_kind, "protocol_fixture")
        self.assertEqual([event["type"] for event in capture.events], [
            "function", "flight.step", "flight.step",
        ])
        self.assertEqual(capture.events[1]["dt_f32_bits"], 0x3D23D70A)

    def test_incomplete_or_noncontiguous_flight_ticks_fail(self):
        bad = events()[:-1]
        with self.assertRaisesRegex(observer.ObserverError, "tick is incomplete"):
            observer.encode_artifact(bad, self.coverage, scenario_sha256=self.scenario_hash)
        bad = [
            {"type": "flight.step", "tick": 1, "phase": "enter", "dt_f32_bits": 1},
            {"type": "flight.step", "tick": 1, "phase": "leave", "dt_f32_bits": 1},
            {"type": "flight.step", "tick": 3, "phase": "enter", "dt_f32_bits": 1},
            {"type": "flight.step", "tick": 3, "phase": "leave", "dt_f32_bits": 1},
        ]
        with self.assertRaisesRegex(observer.ObserverError, "non-contiguous"):
            observer.encode_artifact(bad, self.coverage, scenario_sha256=self.scenario_hash)

    def test_fixture_receipt_cannot_make_a_production_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "game.exe"
            executable.write_bytes(b"native executable")
            executable_hash = observer.sha256_file(executable)
            coverage_path = root / "map.json"
            coverage_path.write_text(json.dumps(map_value(executable_hash)), encoding="utf-8")
            coverage = observer.CoverageIndex.from_path(coverage_path)
            scenario = root / "scenario.json"
            scenario.write_text("{}", encoding="utf-8")
            tool = root / "probe.dll"
            tool.write_bytes(b"probe")
            controller = root / "native-observer-launcher.exe"
            controller.write_bytes(b"controller")
            contract = root / "capture-contract.json"
            contract.write_text(json.dumps(self._host_contract(executable_hash)), encoding="utf-8")
            artifact = root / "capture.mvob"
            artifact.write_bytes(observer.encode_artifact(
                events(), coverage, scenario_sha256=observer.sha256_file(scenario),
            ))
            receipt = self._receipt(
                root, artifact, executable, coverage_path, scenario, tool, controller,
                contract,
            )
            receipt["production_claim"] = True
            receipt["evidence_status"] = "native-capture"
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(observer.ObserverError, "production capture is disabled"):
                observer.verify_receipt(receipt_path, root=root)

    def test_synthetic_native_receipts_cannot_enable_production(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "game.exe"
            executable.write_bytes(b"native executable")
            executable_hash = observer.sha256_file(executable)
            coverage_path = root / "map.json"
            coverage_path.write_text(json.dumps(map_value(executable_hash)), encoding="utf-8")
            coverage = observer.CoverageIndex.from_path(coverage_path)
            scenario = root / "scenario.json"
            scenario.write_text(json.dumps({
                "id": "taxi-straight", "native_scene": "mygghanget",
            }), encoding="utf-8")
            tool = root / "probe.dll"
            tool.write_bytes(b"probe")
            controller = root / "native-observer-launcher.exe"
            controller.write_bytes(b"controller")
            contract = root / "capture-contract.json"
            contract.write_text(json.dumps(self._host_contract(executable_hash)), encoding="utf-8")
            artifact = root / "capture.mvob"
            artifact.write_bytes(observer.encode_artifact(
                events(), coverage, scenario_sha256=observer.sha256_file(scenario),
                native_capture=True,
            ))
            receipt = self._receipt(
                root, artifact, executable, coverage_path, scenario, tool, controller,
                contract,
            )
            patched = root / "MulleMeck-scene.exe"
            patched.write_bytes(b"patched executable")
            patch_receipt = root / "native-scene-patch.json"
            patch_receipt.write_text(json.dumps({
                "schema": 1,
                "protocol": "miel-vliegt-native-scene-start-patch",
                "status": "PREPARED", "strategy": "startup-mode-argument",
                "marker_directory": None,
                "source_executable_sha256": executable_hash,
                "patched_executable_sha256": observer.sha256_file(patched),
                "scene": {"id": "mygghanget"},
                "changes": [{"kind": "startup-mode-argument"}],
            }), encoding="utf-8")
            launch = root / "launch.json"
            launch.write_text(json.dumps({
                "schema": 1,
                "protocol": "miel-vliegt-native-observer-launch",
                "status": "PASS", "phase": "cleanup",
                "detail": "observer-bootstrap-complete",
                "scene": "mygghanget",
                "original_executable_sha256": executable_hash,
                "patched_executable_sha256": observer.sha256_file(patched),
                "observer_dll_sha256": observer.sha256_file(tool),
                "patch_receipt_sha256": observer.sha256_file(patch_receipt),
                "checks": {name: True for name in (
                    "created_suspended", "entrypoint_signature_verified",
                    "entrypoint_barrier_installed", "loader_initialization_completed",
                    "entrypoint_barrier_reached", "entrypoint_bytes_restored",
                    "observer_loaded", "observer_initialized", "main_thread_resumed",
                    "projector_input_idle", "scenario_completion_event",
                    "observer_failure_event_clear", "observation_window_completed",
                    "target_terminated",
                )},
            }), encoding="utf-8")
            receipt.update({
                "capture_kind": "native", "evidence_status": "native-capture",
                "production_claim": True,
                "capture_host": {
                    "os": "Linux", "architecture": "aarch64",
                    "backend": "hangover-fex-suspended-process-hook",
                },
                "patched_executable": patched.name,
                "patched_executable_sha256": observer.sha256_file(patched),
                "patch_receipt": patch_receipt.name,
                "patch_receipt_sha256": observer.sha256_file(patch_receipt),
                "launch_receipt": launch.name,
                "launch_receipt_sha256": observer.sha256_file(launch),
                "capture_command": [
                    "native-observer-launcher.exe", "--source", "MulleMeck.exe",
                    "--target", "MulleMeck-scene.exe",
                    "--observer", "native-observer-hook.dll",
                    "--patch-receipt", "native-scene-patch.json",
                    "--receipt", "native-observer-launch.json", "--cwd", ".",
                    "--scene", "mygghanget",
                    "--observe-ms", "10000",
                ],
            })
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(
                observer.ObserverError, "production capture is disabled",
            ):
                observer.verify_receipt(receipt_path, root=root, require_production=True)

    @staticmethod
    def _receipt(
        root, artifact, executable, coverage, scenario, tool, controller=None,
        contract=None,
    ):
        if controller is None:
            controller = root / "controller.exe"
            controller.write_bytes(b"fixture controller")
        if contract is None:
            contract = root / "capture-contract.json"
            contract.write_text("{}", encoding="utf-8")
        paths = {
            "artifact": artifact, "executable": executable, "coverage_map": coverage,
            "scenario": scenario, "capture_tool": tool, "capture_controller": controller,
            "capture_contract": contract,
        }
        receipt = {
            "schema": 2, "protocol": observer.PROTOCOL,
            "capture_kind": "protocol_fixture", "evidence_status": "fixture-only",
            "production_claim": False, "capture_complete": True,
            "capture_command": ["probe.dll", "game.exe"],
            "capture_host": {"os": "Linux", "architecture": "aarch64", "backend": "hangover-fex"},
            "patched_executable": None, "patched_executable_sha256": None,
            "patch_receipt": None, "patch_receipt_sha256": None,
            "launch_receipt": None, "launch_receipt_sha256": None,
        }
        for field, path in paths.items():
            receipt[field] = str(path.relative_to(root))
            receipt[f"{field}_sha256"] = observer.sha256_file(path)
        return receipt

    @staticmethod
    def _host_contract(executable_hash):
        return {
            "schema": 1, "host_role": "EXPERIMENTAL_CAPTURE_HOST",
            "source": {"project": "AndreRH/hangover", "release": "hangover-11.9"},
            "target": {"executable_sha256": executable_hash},
            "probe_backends": [
                {"id": "box64", "hodll": "wowbox64.dll"},
                {"id": "fex", "hodll": "libwow64fex.dll"},
            ],
            "observer_strategy": {
                "selected": "startup-mode-patch+suspended-process-game-thread-hook",
            },
        }

    def test_schema_is_strict_and_documents_fail_closed_policy(self):
        schema = json.loads((Path(__file__).with_name("native_observer_schema.json")).read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["protocol"]["const"], observer.PROTOCOL)
        self.assertEqual(schema["properties"]["schema"]["const"], 2)
        self.assertIn("disabled until", schema["x-binary-artifact-contract"]["production_policy"])
        self.assertFalse(observer.PRODUCTION_CAPTURE_ENABLED)

    def test_receipt_duplicate_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "receipt.json"
            receipt.write_text('{"schema":1,"schema":1}', encoding="utf-8")
            with self.assertRaisesRegex(observer.ObserverError, "duplicate key"):
                observer.verify_receipt(receipt, root=Path(temporary))


if __name__ == "__main__":
    unittest.main()
