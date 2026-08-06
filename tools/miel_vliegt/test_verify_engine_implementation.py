#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.engine_runtime_contract import (
    CANONICAL_GAMEPLAY_RUNTIMES,
    validate_gameplay_runtime_inventory,
)
from tools.miel_vliegt.verify_engine_implementation import (
    validate,
    validate_equivalence_receipt,
    validate_package_io_substitution,
    validate_substitution_receipt,
)


ROOT = Path(__file__).resolve().parents[2]
REGENERATE = ROOT / "tools/miel_vliegt/regenerate_flight_content.sh"


class EngineImplementationTests(unittest.TestCase):
    def test_regeneration_pipeline_validates_reviewed_substitutions(self):
        source = REGENERATE.read_text(encoding="utf-8")
        assets = source.index(
            'python3 "$ROOT/tools/miel_vliegt/flight_scene_assets.py"'
        )
        validator = source.index(
            'python3 "$ROOT/tools/miel_vliegt/verify_engine_implementation.py"'
        )
        completion = source.index(
            'python3 "$ROOT/tools/miel_vliegt/flight_cleanroom_completion.py"'
        )
        self.assertLess(assets, validator)
        self.assertLess(validator, completion)

    def write_equivalence_fixture(self, root: Path):
        for name, value in {
            "runtime.js": "runtime-v1\n",
            "runtime.test.js": "test-v1\n",
        }.items():
            (root / name).write_text(value)

        def identity(path):
            return {
                "path": path,
                "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest(),
            }

        native = {
            "schema": 1,
            "protocol": "miel-vliegt-engine-boundary-observation",
            "producer": "NATIVE",
            "boundary_id": "fixture",
            "source_sha256": "e" * 64,
            "observations": [{"sequence": 0, "state": {"value": 7}}],
        }
        web = {
            **native,
            "producer": "WEB",
            "source_sha256": identity("runtime.js")["sha256"],
        }
        for name, value in (("native.json", native), ("web.json", web)):
            (root / name).write_text(json.dumps(value))
        policy = {"ordered_observations": "EXACT_CANONICAL_JSON"}
        policy_sha256 = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        differential = {
            "schema": 1,
            "protocol": "miel-vliegt-engine-boundary-differential",
            "boundary_id": "fixture",
            "result": "PASS",
            "comparator": "exact-json-v1",
            "comparison_policy": policy,
            "comparison_policy_sha256": policy_sha256,
            "native_sha256": identity("native.json")["sha256"],
            "web_sha256": identity("web.json")["sha256"],
        }
        (root / "diff.json").write_text(json.dumps(differential))
        receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-engine-native-differential",
            "boundary_id": "fixture",
            "status": "PASS",
            "executable_sha256": "e" * 64,
            "runtime": identity("runtime.js"),
            "tests": [identity("runtime.test.js")],
            "evidence": {
                "native": identity("native.json"),
                "web": identity("web.json"),
                "differential": identity("diff.json"),
            },
        }
        (root / "receipt.json").write_text(json.dumps(receipt))
        row = {
            "id": "fixture", "runtime": "runtime.js",
            "tests": ["runtime.test.js"],
            "native_evidence_receipt": "receipt.json",
        }
        return row, receipt

    def test_every_native_engine_boundary_has_an_honest_implementation_disposition(self):
        counts = validate(ROOT)
        self.assertEqual(counts["MISSING"], 0)
        self.assertEqual(counts, {
            "PARTIAL": 17,
            "PLATFORM_SUBSTITUTION": 2,
        })

    def test_gameplay_runtime_inventory_cannot_shrink(self):
        implementation = json.loads(
            (ROOT / "content/miel_vliegt/engine_implementation.json").read_text()
        )
        rows = implementation["gameplay_runtimes"]
        self.assertEqual(
            set(validate_gameplay_runtime_inventory(rows)),
            set(CANONICAL_GAMEPLAY_RUNTIMES),
        )
        for identifier in CANONICAL_GAMEPLAY_RUNTIMES:
            with self.subTest(runtime=identifier):
                reduced = [row for row in copy.deepcopy(rows) if row["id"] != identifier]
                with self.assertRaisesRegex(ValueError, "coverage mismatch"):
                    validate_gameplay_runtime_inventory(reduced)

    def test_gameplay_runtime_owner_cannot_silently_move(self):
        implementation = json.loads(
            (ROOT / "content/miel_vliegt/engine_implementation.json").read_text()
        )
        rows = copy.deepcopy(implementation["gameplay_runtimes"])
        rows[0]["runtime"] = "src/flight/engine/NotTheCanonicalOwner.js"
        with self.assertRaisesRegex(ValueError, "canonical runtime owner drifted"):
            validate_gameplay_runtime_inventory(rows)

    def test_equivalent_rejects_an_arbitrary_existing_file_as_native_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("not a differential receipt\n")
            row = {
                "id": "fixture",
                "runtime": "README.md",
                "tests": ["README.md"],
                "native_evidence_receipt": "README.md",
            }
            with self.assertRaisesRegex(ValueError, "canonical JSON PASS receipt"):
                validate_equivalence_receipt(row, root, "e" * 64)

    def test_equivalent_receipt_is_bound_to_runtime_tests_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row, _receipt = self.write_equivalence_fixture(root)
            validated = validate_equivalence_receipt(row, root, "e" * 64)
            self.assertEqual(validated["status"], "PASS")
            (root / "runtime.js").write_text("runtime-v2\n")
            with self.assertRaisesRegex(ValueError, "runtime.*drifted"):
                validate_equivalence_receipt(row, root, "e" * 64)

    def test_equivalent_recomputes_differential_instead_of_trusting_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row, receipt = self.write_equivalence_fixture(root)
            web = json.loads((root / "web.json").read_text())
            web["observations"][0]["state"]["value"] = 8
            (root / "web.json").write_text(json.dumps(web))
            receipt["evidence"]["web"]["sha256"] = hashlib.sha256(
                (root / "web.json").read_bytes()
            ).hexdigest()
            differential = json.loads((root / "diff.json").read_text())
            differential["web_sha256"] = receipt["evidence"]["web"]["sha256"]
            (root / "diff.json").write_text(json.dumps(differential))
            receipt["evidence"]["differential"]["sha256"] = hashlib.sha256(
                (root / "diff.json").read_bytes()
            ).hexdigest()
            (root / "receipt.json").write_text(json.dumps(receipt))

            with self.assertRaisesRegex(ValueError, "recomputed differential differs"):
                validate_equivalence_receipt(row, root, "e" * 64)

    def test_equivalent_rejects_unknown_or_unhashed_comparison_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row, receipt = self.write_equivalence_fixture(root)
            differential = json.loads((root / "diff.json").read_text())
            differential["comparison_policy"]["ordered_observations"] = "IGNORE_ORDER"
            differential["comparison_policy_sha256"] = hashlib.sha256(
                json.dumps(
                    differential["comparison_policy"], sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            (root / "diff.json").write_text(json.dumps(differential))
            receipt["evidence"]["differential"]["sha256"] = hashlib.sha256(
                (root / "diff.json").read_bytes()
            ).hexdigest()
            (root / "receipt.json").write_text(json.dumps(receipt))

            with self.assertRaisesRegex(ValueError, "invalid boundary differential receipt"):
                validate_equivalence_receipt(row, root, "e" * 64)

    def test_platform_substitution_requires_a_reviewed_hash_bound_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = {
                "id": "platform", "runtime": "Browser APIs",
                "gap": "some prose", "substitution_receipt": None,
            }
            with self.assertRaisesRegex(ValueError, "reviewed substitution receipt"):
                validate_substitution_receipt(row, root, "f" * 64)

    def package_io_fixture(self):
        implementation = json.loads(
            (ROOT / "content/miel_vliegt/engine_implementation.json").read_text()
        )
        row = next(
            item for item in implementation["subsystems"]
            if item["id"] == "package_io"
        )
        receipt = json.loads(
            (ROOT / "content/miel_vliegt/substitutions/package_io.json").read_text()
        )
        source_identity = json.loads(
            (ROOT / "content/miel_vliegt/source_identity.json").read_text()
        )
        return row, receipt, source_identity["executable"]["sha256"]

    def test_package_io_is_explicitly_build_time_and_does_not_claim_streaming_equivalence(self):
        row, receipt, executable_sha256 = self.package_io_fixture()
        validated = validate_package_io_substitution(
            row, receipt, ROOT, executable_sha256,
        )
        self.assertEqual(validated["substitution_kind"], "BUILD_TIME_PLATFORM_SUBSTITUTION")
        self.assertEqual(validated["native_streaming_equivalence"], "NOT_CLAIMED")

    def test_package_io_rejects_a_forged_archive_identity(self):
        row, receipt, executable_sha256 = self.package_io_fixture()
        receipt["source"]["archives"][1]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "archive identities"):
            validate_package_io_substitution(row, receipt, ROOT, executable_sha256)

    def test_package_io_rejects_a_forged_runtime_identity(self):
        row, receipt, executable_sha256 = self.package_io_fixture()
        forged = receipt["runtime_boundary"]["sources"][0]
        forged["path"] = "src/flight/engine/FlightEngine.js"
        forged["sha256"] = hashlib.sha256((ROOT / forged["path"]).read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "runtime source mapping"):
            validate_package_io_substitution(row, receipt, ROOT, executable_sha256)

    def test_package_io_rejects_a_forged_native_import_mapping(self):
        row, receipt, executable_sha256 = self.package_io_fixture()
        key = "UdsPack.dll!?Read@UpFile@@QAEIPAXII@Z"
        receipt["native_boundary"]["import_mapping"][key] = "ResourceCatalog.get(path)"
        with self.assertRaisesRegex(ValueError, "native import mapping"):
            validate_package_io_substitution(row, receipt, ROOT, executable_sha256)


if __name__ == "__main__":
    unittest.main()
