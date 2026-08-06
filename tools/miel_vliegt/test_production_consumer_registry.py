import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import production_consumer_registry as registry
from tools.miel_vliegt import run_production_consumer_receipt as runner


class ProductionConsumerRegistryTests(unittest.TestCase):
    def setUp(self):
        checked = json.loads(
            (registry.ROOT / registry.RECEIPT).read_text(encoding="utf-8")
        )
        self.required = checked["consumer_ids"]

    def _proof_root(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        spec = registry.proof_spec(self.required)
        paths = set(spec["runtime_paths"])
        for identifier in self.required:
            declaration = registry._declaration(identifier)
            paths.update(declaration["integration_tests"])
        for relative in paths:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(registry.ROOT / relative, target)

        checked = json.loads((registry.ROOT / registry.RECEIPT).read_text(encoding="utf-8"))
        identities = {(row["module"], row["export"]) for row in spec["handlers"]}
        call_identities = {
            (row["entrypoint"], row["module"], row["export"])
            for row in spec["entrypoint_calls"]
        }
        receipt = {
            **{key: spec[key] for key in (
                "schema", "protocol", "edition", "suite_id", "consumer_ids",
                "command", "tests", "handlers", "entrypoint_calls",
                "execution_functions", "pack_assertions",
            )},
            "result": "PASS",
            "exit_code": 0,
            "runtime_hashes": {
                relative: registry._sha256(root / relative)
                for relative in spec["runtime_paths"]
            },
            "handler_invocations": [
                copy.deepcopy(row) for row in checked["handler_invocations"]
                if (row["module"], row["export"]) in identities
            ],
            "function_invocations": copy.deepcopy(
                checked["function_invocations"]
            ),
            "pack_assertion_results": copy.deepcopy(
                checked["pack_assertion_results"]
            ),
            "entrypoint_invocations": [
                copy.deepcopy(row) for row in checked["entrypoint_invocations"]
                if (row["entrypoint"], row["module"], row["export"])
                in call_identities
            ],
        }
        receipt_path = root / registry.RECEIPT
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        return temporary, root, receipt

    @staticmethod
    def _consumer(document, identifier):
        return next(row for row in document["consumers"] if row["id"] == identifier)

    @staticmethod
    def _write_receipt(root, receipt):
        (root / registry.RECEIPT).write_text(json.dumps(receipt), encoding="utf-8")

    def test_fresh_machine_receipt_exports_invocations_and_state_registry_complete(self):
        temporary, root, _ = self._proof_root()
        self.addCleanup(temporary.cleanup)
        document = registry.build(self.required, root)
        self.assertTrue(all(row["status"] == "COMPLETE" for row in document["consumers"]))
        location = self._consumer(document, "location_presentation_consumer")
        self.assertGreater(
            location["integration"]["test_receipt"]["handler"]["invocation_count"], 0
        )
        self.assertEqual(
            location["integration"]["state_registrations"][0]["state_key"],
            "flight_location",
        )

    def test_empty_modules_or_tests_invalidate_the_executable_receipt(self):
        for relative in (
            "src/flight/browser/FlightPhaserLocationProjection.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ):
            with self.subTest(relative=relative):
                temporary, root, _ = self._proof_root()
                try:
                    (root / relative).write_text("// intentionally empty\n", encoding="utf-8")
                    document = registry.build(self.required, root)
                    self.assertEqual(
                        self._consumer(document, "location_presentation_consumer")["status"],
                        "BLOCKED",
                    )
                finally:
                    temporary.cleanup()

    def test_removed_export_blocks_even_when_source_hash_is_refreshed(self):
        temporary, root, receipt = self._proof_root()
        self.addCleanup(temporary.cleanup)
        relative = "src/flight/browser/FlightPhaserLocationProjection.js"
        path = root / relative
        source = path.read_text(encoding="utf-8")
        source = source.replace(
            "export function attachFlightPhaserLocationProjection",
            "function attachFlightPhaserLocationProjection",
            1,
        )
        path.write_text(source, encoding="utf-8")
        receipt["runtime_hashes"][relative] = registry._sha256(path)
        self._write_receipt(root, receipt)

        document = registry.build(self.required, root)
        self.assertEqual(
            self._consumer(document, "location_presentation_consumer")["status"],
            "BLOCKED",
        )

    def test_removed_handler_call_yields_zero_coverage_and_blocks(self):
        temporary, root, receipt = self._proof_root()
        self.addCleanup(temporary.cleanup)
        relative = "src/scenes/__tests__/flight-location-integration.test.js"
        path = root / relative
        path.write_text(
            "test('does not invoke the production handler', () => expect(true).toBe(true))\n",
            encoding="utf-8",
        )
        receipt["runtime_hashes"][relative] = registry._sha256(path)
        target = next(
            row for row in receipt["handler_invocations"]
            if row["export"] == "attachFlightPhaserLocationProjection"
        )
        target["invocation_count"] = 0
        self._write_receipt(root, receipt)

        document = registry.build(self.required, root)
        self.assertEqual(
            self._consumer(document, "location_presentation_consumer")["status"],
            "BLOCKED",
        )

    def test_removed_production_callsite_blocks_with_fresh_source_hash(self):
        temporary, root, receipt = self._proof_root()
        self.addCleanup(temporary.cleanup)
        relative = "src/scenes/flight_location.js"
        path = root / relative
        source = path.read_text(encoding="utf-8")
        source = source.replace("attachFlightPhaserLocationProjection(this)", "", 1)
        path.write_text(source, encoding="utf-8")
        receipt["runtime_hashes"][relative] = registry._sha256(path)
        self._write_receipt(root, receipt)

        document = registry.build(self.required, root)
        self.assertEqual(
            self._consumer(document, "location_presentation_consumer")["status"],
            "BLOCKED",
        )

    def test_receipt_builder_rejects_zero_handler_coverage(self):
        module = "src/flight/browser/FlightPhaserLocationProjection.js"
        export = "attachFlightPhaserLocationProjection"
        line = registry._exported_function_line(registry.ROOT, module, export)
        coverage = {
            str((registry.ROOT / module).resolve()): {
                "fnMap": {"0": {
                    "name": export,
                    "decl": {"start": {"line": line}},
                }},
                "f": {"0": 0},
            },
        }
        with self.assertRaisesRegex(ValueError, "did not invoke handler"):
            runner.handler_invocations(
                coverage, registry.ROOT, [{"module": module, "export": export}]
            )

    def test_presenter_opcode_requires_its_own_executed_method(self):
        cases = {
            "PLAY_CHARACTER_ANIMATION": "playCharacterAnimation",
            "PLAY_CHARACTER_SOUND": "playCharacterSound",
            "PLAY_MULLEBARNSOUND": "playMulleBarnSound",
            "POSITION_CHARACTER": "positionCharacter",
        }
        for opcode, function in cases.items():
            with self.subTest(opcode=opcode):
                temporary, root, receipt = self._proof_root()
                try:
                    target = next(
                        row for row in receipt["function_invocations"]
                        if row["function"] == function
                    )
                    target["invocation_count"] = 0
                    self._write_receipt(root, receipt)

                    document = registry.build(self.required, root)
                    self.assertEqual(
                        self._consumer(
                            document, f"presenter_opcode:{opcode}"
                        )["status"],
                        "BLOCKED",
                    )
                finally:
                    temporary.cleanup()

    def test_release_reachability_requires_executed_game_setup(self):
        temporary, root, receipt = self._proof_root()
        self.addCleanup(temporary.cleanup)
        target = next(
            row for row in receipt["function_invocations"]
            if row["module"] == registry.GAME_REGISTRY
            and row["function"] == "setup"
        )
        target["invocation_count"] = 0
        self._write_receipt(root, receipt)

        document = registry.build(self.required, root)
        self.assertEqual(
            self._consumer(document, "location_presentation_consumer")["status"],
            "BLOCKED",
        )

    def test_each_asset_pack_requires_its_named_runtime_assertion(self):
        temporary, root, receipt = self._proof_root()
        self.addCleanup(temporary.cleanup)
        title = "production pack receipt flight_scene_location_roy_mccoy"
        receipt["pack_assertion_results"] = [
            row for row in receipt["pack_assertion_results"]
            if row["title"] != title
        ]
        self._write_receipt(root, receipt)

        document = registry.build(self.required, root)
        self.assertEqual(
            self._consumer(
                document, "asset_pack:flight_scene_location_roy_mccoy"
            )["status"],
            "BLOCKED",
        )

    def test_removed_game_state_registration_blocks_with_fresh_hash(self):
        temporary, root, receipt = self._proof_root()
        self.addCleanup(temporary.cleanup)
        path = root / registry.GAME_REGISTRY
        source = path.read_text(encoding="utf-8")
        source = source.replace("flight_location: FlightLocationState,", "", 1)
        path.write_text(source, encoding="utf-8")
        receipt["runtime_hashes"][registry.GAME_REGISTRY] = registry._sha256(path)
        self._write_receipt(root, receipt)

        document = registry.build(self.required, root)
        self.assertEqual(
            self._consumer(document, "location_presentation_consumer")["status"],
            "BLOCKED",
        )


if __name__ == "__main__":
    unittest.main()
