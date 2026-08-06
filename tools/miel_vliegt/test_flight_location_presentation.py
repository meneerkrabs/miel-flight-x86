#!/usr/bin/env python3
import copy
import hashlib
import json
import struct
import unittest
from pathlib import Path

from tools.miel_vliegt.decode_gti import decode_gti
from tools.miel_vliegt.export_web_assets import encode_png
from tools.miel_vliegt.flight_location_presentation import (
    TILE_RE,
    _unique_rows,
    _source_fingerprint,
    _validate_asset_payload,
    _validate_location_asset_closure,
    build_flight_location_presentation_contract,
    generate_flight_location_presentation_contract,
    native_decoder_available,
)


ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / "content/miel_vliegt"
EXECUTABLE = ROOT / "tmp/miel-vliegt-native-local/MulleMeck.exe"
DATA_ARCHIVE = Path("/Volumes/Mielvliegt/data.up")
ASSET_OUTPUT = CONTENT
CHECKED = CONTENT / "flight_location_presentation_contract.json"
REGENERATE = ROOT / "tools/miel_vliegt/regenerate_flight_content.sh"


def load(name):
    return json.loads((CONTENT / name).read_text(encoding="utf-8"))


class FlightLocationPresentationForgeryTests(unittest.TestCase):
    def test_asset_payload_hash_dimensions_format_and_png_are_bound(self):
        pixels = b"\x03\x02\x01"
        source = (
            b"GtIm" + b"Imag" + struct.pack("<I", 20 + len(pixels))
            + struct.pack("<5I", 7, 1, 1, 0, 1) + pixels
        )
        output = encode_png(decode_gti(source))
        image = {
            "source": "data/Graphics/Locations/test/layer1_1_1.gti",
            "url": "assets/miel-vliegt/test.png",
            "sourceSha256": hashlib.sha256(source).hexdigest(),
            "outputSha256": hashlib.sha256(output).hexdigest(),
            "width": 1,
            "height": 1,
            "format": "RGB888",
        }
        _validate_asset_payload(image, source, output)
        for field, value, message in (
            ("sourceSha256", "0" * 64, "source asset receipt"),
            ("outputSha256", "0" * 64, "output asset receipt"),
            ("width", 2, "dimensions/format"),
        ):
            forged = {**image, field: value}
            with self.assertRaisesRegex(ValueError, message):
                _validate_asset_payload(forged, source, output)

        different_source = (
            b"GtIm" + b"Imag" + struct.pack("<I", 20 + len(pixels))
            + struct.pack("<5I", 7, 1, 1, 0, 1) + b"\x30\x20\x10"
        )
        different_output = encode_png(decode_gti(different_source))
        forged = {
            **image,
            "outputSha256": hashlib.sha256(different_output).hexdigest(),
        }
        with self.assertRaisesRegex(ValueError, "pixel content"):
            _validate_asset_payload(forged, source, different_output)

        with self.assertRaisesRegex(ValueError, "metadata type"):
            _validate_asset_payload({**image, "width": True}, source, output)

    def test_bidirectional_closure_rejects_ghost_keys_and_missing_archive_assets(self):
        image = {
            "key": "tile", "domainKind": "location", "domainId": "domain",
            "source": "data/Graphics/Locations/domain/layer1_1_1.gti",
        }

        class Evidence:
            def __init__(self, sources):
                self.sources = sources
                self.validated = []

            def location_sources(self, _domain):
                return self.sources

            def validate(self, row):
                self.validated.append(row["key"])

        assets = {"images": [image], "audio": []}
        packs = {"domain": {"assetKeys": ["tile"]}}
        evidence = Evidence({_source_key(image)})
        _validate_location_asset_closure(assets, {"domain"}, packs, evidence)
        self.assertEqual(evidence.validated, ["tile"])
        with self.assertRaisesRegex(ValueError, "pack closure"):
            _validate_location_asset_closure(
                assets, {"domain"}, {"domain": {"assetKeys": ["tile", "ghost"]}}, evidence
            )
        with self.assertRaisesRegex(ValueError, "archive asset closure"):
            _validate_location_asset_closure(
                assets, {"domain"}, packs, Evidence({_source_key(image), "extra.gti"})
            )

    def test_pack_closure_rejects_known_location_asset_owned_by_another_domain(self):
        own = {
            "key": "own", "domainKind": "location", "domainId": "domain",
            "source": "data/Graphics/Locations/domain/layer1_1_1.gti",
        }
        foreign = {
            "key": "foreign", "domainKind": "location", "domainId": "foreign_domain",
            "source": "data/Graphics/Locations/foreign_domain/layer1_1_1.gti",
        }

        class Evidence:
            def location_sources(self, _domain):
                return {_source_key(own)}

            def validate(self, _row):
                pass

        with self.assertRaisesRegex(ValueError, "pack closure"):
            _validate_location_asset_closure(
                {"images": [own, foreign], "audio": []},
                {"domain"},
                {"domain": {"assetKeys": ["own", "foreign"]}},
                Evidence(),
            )

    def test_authoritative_source_fingerprint_has_no_edition_label_input(self):
        executable = "01" * 32
        archive = "02" * 32
        expected = _source_fingerprint(executable, archive)
        self.assertEqual(expected, _source_fingerprint(executable, archive))
        self.assertNotEqual(expected, _source_fingerprint("03" * 32, archive))
        self.assertNotEqual(expected, _source_fingerprint(executable, "04" * 32))

    def test_duplicate_rows_are_rejected_without_native_fixture(self):
        with self.assertRaisesRegex(ValueError, "duplicate dispatch"):
            _unique_rows([{"id": "same"}, {"id": "same"}], "id", "dispatch")


def _source_key(image):
    return image["source"].replace("\\", "/").strip("/").lower()


class CheckedFlightLocationPresentationTruthfulnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CHECKED.read_text(encoding="utf-8"))

    def test_checked_claim_is_limited_to_source_asset_topology(self):
        contract = self.contract
        self.assertEqual(
            contract["claim"],
            "SOURCE_FINGERPRINTED_LOCATION_ASSET_TOPOLOGY_EXACT",
        )
        self.assertEqual(
            contract["editionLabelStatus"],
            "INFORMATIONAL_METADATA_NOT_SOURCE_IDENTITY",
        )
        self.assertIn("NATIVE_LAYOUT_SEMANTICS_UNPROVEN", contract["claimLimits"])
        self.assertIn(
            "INSTALL_MEDIA_ISO_AND_CAB_PROVENANCE_UNPROVEN",
            contract["claimLimits"],
        )
        self.assertTrue(all(
            location["layoutStatus"] == "NATIVE_LAYOUT_SEMANTICS_UNPROVEN"
            for location in contract["locations"]
        ))

    def test_checked_native_candidates_never_publish_exact_semantics(self):
        statuses = [
            row["evidenceStatus"] for row in self.contract["engine"].values()
        ]
        self.assertEqual(statuses.count("FUNCTION_BYTES_EXACT_CALL_TARGET_JOIN_EXACT"), 1)
        self.assertTrue(all(
            status == "FUNCTION_BYTES_EXACT_CALL_TARGET_JOIN_EXACT"
            or status.endswith("SEMANTICS_UNPROVEN")
            for status in statuses
        ))
        self.assertIsNone(self.contract["engine"]["gridRenderer"]["traversal"])

    def test_checked_source_fingerprint_is_derived_from_byte_receipts(self):
        source = self.contract["sourceFingerprint"]
        self.assertEqual(
            source["sha256"],
            _source_fingerprint(
                source["executableSha256"], source["dataArchiveSha256"]
            ),
        )
        self.assertEqual(
            source["executableSha256"], self.contract["sources"]["executable"]["sha256"]
        )
        self.assertEqual(
            source["dataArchiveSha256"], self.contract["sources"]["dataArchive"]["sha256"]
        )

    def test_checked_local_source_receipts_are_current(self):
        for receipt in self.contract["sources"].values():
            path = receipt.get("path")
            if path is None:
                continue
            self.assertEqual(
                receipt["sha256"],
                hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                path,
            )

    def test_regeneration_pipeline_rebuilds_presentation_after_assets(self):
        source = REGENERATE.read_text(encoding="utf-8")
        assets = source.index(
            'python3 "$ROOT/tools/miel_vliegt/flight_scene_assets.py"'
        )
        presentation = source.index(
            'python3 "$ROOT/tools/miel_vliegt/flight_location_presentation.py"'
        )
        visual = source.index(
            'python3 "$ROOT/tools/miel_vliegt/visual_checkpoint_inventory.py"'
        )
        self.assertLess(assets, presentation)
        self.assertLess(presentation, visual)
        invocation = source[presentation:visual]
        for argument in (
            '--executable "$SYS/MulleMeck.exe"',
            '--data-archive "$ISO_ROOT/data.up"',
            '--asset-output-root "$ROOT/content/miel_vliegt"',
        ):
            self.assertIn(argument, invocation)


@unittest.skipUnless(
    EXECUTABLE.is_file() and DATA_ARCHIVE.is_file() and ASSET_OUTPUT.is_dir()
    and native_decoder_available(),
    "pinned native executable, asset evidence, or decoder unavailable",
)
class FlightLocationPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = {
            "dispatch": load("scene_dispatch_contract.json"),
            "assets": load("flight_scene_asset_contract.json"),
            "probe": load("native_scene_probe.json"),
            "bodies": load("native_mode_bodies.json"),
            "functions": load("native_function_index.json"),
            "identity": load("source_identity.json"),
        }
        cls.generated = build_flight_location_presentation_contract(
            EXECUTABLE,
            data_archive=DATA_ARCHIVE,
            asset_output_root=ASSET_OUTPUT,
            **cls.inputs,
        )

    def build(self, inputs):
        return build_flight_location_presentation_contract(
            EXECUTABLE,
            data_archive=DATA_ARCHIVE,
            asset_output_root=ASSET_OUTPUT,
            **inputs,
        )

    def test_checked_contract_is_exact_generator_output(self):
        self.assertEqual(
            json.loads(CHECKED.read_text(encoding="utf-8")),
            generate_flight_location_presentation_contract(
                executable=EXECUTABLE,
                data_archive=DATA_ARCHIVE,
                asset_output_root=ASSET_OUTPUT,
                dispatch_path=CONTENT / "scene_dispatch_contract.json",
                assets_path=CONTENT / "flight_scene_asset_contract.json",
                probe_path=CONTENT / "native_scene_probe.json",
                bodies_path=CONTENT / "native_mode_bodies.json",
                functions_path=CONTENT / "native_function_index.json",
                identity_path=CONTENT / "source_identity.json",
            ),
        )

    def test_all_non_bespoke_domains_have_exact_asset_topology_and_unproven_native_layout(self):
        bespoke = {
            row["domainId"]
            for row in self.inputs["dispatch"]["expectedAbsences"]
            if row["kind"] == "LOCATION_SCRIPT_DOMAIN"
        }
        expected = {
            row["domainId"]
            for row in self.inputs["dispatch"]["locations"]
            if row["domainId"] not in bespoke
        }
        locations = self.generated["locations"]
        self.assertEqual({row["domainId"] for row in locations}, expected)
        self.assertEqual(len(locations), 17)
        self.assertEqual(
            self.generated["counts"], {"locations": 17, "layers": 51, "tiles": 679}
        )
        for row in locations:
            self.assertEqual(row["layoutStatus"], "NATIVE_LAYOUT_SEMANTICS_UNPROVEN")
            self.assertEqual(
                [layer["nativeRenderOrdinal"] for layer in row["layers"]],
                sorted(layer["nativeRenderOrdinal"] for layer in row["layers"]),
            )
            self.assertTrue(row["candidateVerticalOffsetWrites"])
            self.assertEqual(row["claimLimits"], [
                "NATIVE_LAYER_OFFSET_MAPPING_UNPROVEN",
                "NATIVE_CAMERA_BOUND_SEMANTICS_UNPROVEN",
                "NATIVE_RENDER_TRAVERSAL_UNPROVEN",
                "NATIVE_BACKGROUND_SELECTION_UNPROVEN",
                "NATIVE_ATTACHMENT_HELPER_SEMANTICS_UNPROVEN",
                "PHASER_PAINTER_ORDER_UNPROVEN",
                "FRAMEBUFFER_PARITY_UNPROVEN",
            ])

    def test_irregular_rows_and_partial_edge_tiles_are_data_not_exceptions(self):
        layers = [
            layer
            for location in self.generated["locations"]
            for layer in location["layers"]
        ]
        self.assertTrue(any(layer["topology"] == "SPARSE_EXACT" for layer in layers))
        tiles = [tile for layer in layers for tile in layer["tiles"]]
        self.assertTrue(any(tile["width"] < 256 for tile in tiles))
        expected = {}
        for image in self.inputs["assets"]["images"]:
            if image.get("domainKind") != "location":
                continue
            match = TILE_RE.search(image["source"].replace("\\", "/"))
            if match is not None:
                expected.setdefault(image["domainId"], set()).add(tuple(
                    int(match.group(name)) for name in ("layer", "row", "column")
                ))
        actual = {
            location["domainId"]: {
                (layer["nativeRenderOrdinal"], tile["row"], tile["column"])
                for layer in location["layers"] for tile in layer["tiles"]
            }
            for location in self.generated["locations"]
        }
        self.assertEqual(actual, {
            domain: coordinates for domain, coordinates in expected.items()
            if domain in actual
        })

    def test_unproven_selectors_and_attachment_candidates_are_typed(self):
        self.assertTrue(any(
            row["background"]["selectorStatus"]
            == "UNPROVEN_MULTI_ASSET_NATIVE_SELECTOR"
            for row in self.generated["locations"]
        ))
        static = next(
            row for row in self.generated["locations"]
            if row["attachments"]["status"]
            == "CALLSITE_ARGUMENT_CANDIDATES_HELPER_SEMANTICS_UNPROVEN"
        )
        self.assertTrue(static["attachments"]["candidatePlacements"])
        self.assertFalse(static["attachments"]["placements"])
        self.assertFalse(static["attachments"]["unplacedAssets"])

        ambiguous = copy.deepcopy(self.inputs)
        source_domain = static["domainId"]
        extra = copy.deepcopy(next(
            image for image in ambiguous["assets"]["images"]
            if image.get("domainId") == source_domain
            and "/attachments/" in image["source"].lower()
        ))
        extra["source"] = extra["source"].rsplit("/", 1)[0] + "/not_selected.gti"
        extra["key"] += "-not-selected"
        ambiguous["assets"]["images"].append(extra)
        next(
            section for section in ambiguous["assets"]["packSections"]
            if section.get("kind") == "location" and section["domainId"] == source_domain
        )["assetKeys"].append(extra["key"])
        with self.assertRaisesRegex(ValueError, "archive asset closure"):
            self.build(ambiguous)

    def test_synthetic_edition_relabel_cannot_override_independent_identity(self):
        relabeled = copy.deepcopy(self.inputs)
        rename = {
            domain: f"edition_x_{index}"
            for index, domain in enumerate(relabeled["assets"]["domains"]["locations"])
        }
        fixture = relabeled
        edition = "synthetic-alpha"
        for document in (fixture["dispatch"], fixture["assets"]):
            document["edition"] = edition
        fixture["probe"]["source"]["edition"] = edition
        for row in fixture["dispatch"]["locations"]:
            row["domainId"] = rename[row["domainId"]]
        for row in fixture["dispatch"]["expectedAbsences"]:
            if row["domainId"] in rename:
                row["domainId"] = rename[row["domainId"]]
        for row in fixture["probe"]["scenes"]:
            row["id"] = rename[row["id"]]
        for row in fixture["bodies"]["modes"]:
            if row["id"] in rename:
                row["id"] = rename[row["id"]]
        fixture["assets"]["domains"]["locations"] = [
            rename[value] for value in fixture["assets"]["domains"]["locations"]
        ]
        for section in fixture["assets"]["packSections"]:
            if section.get("kind") == "location" and section["domainId"] in rename:
                section["domainId"] = rename[section["domainId"]]
        for image in fixture["assets"]["images"]:
            if image.get("domainKind") == "location" and image["domainId"] in rename:
                image["domainId"] = rename[image["domainId"]]
        with self.assertRaisesRegex(ValueError, "edition label drift"):
            self.build(relabeled)

    def test_relabeling_every_metadata_document_cannot_change_source_fingerprint(self):
        relabeled = copy.deepcopy(self.inputs)
        for document in (relabeled["dispatch"], relabeled["assets"]):
            document["edition"] = "synthetic-alpha"
        relabeled["probe"]["source"]["edition"] = "synthetic-alpha"
        relabeled["identity"]["edition"] = "synthetic-alpha"
        result = self.build(relabeled)
        self.assertEqual(
            result["sourceFingerprint"]["sha256"],
            self.generated["sourceFingerprint"]["sha256"],
        )
        self.assertEqual(
            result["editionLabelStatus"],
            "INFORMATIONAL_METADATA_NOT_SOURCE_IDENTITY",
        )

    def test_duplicate_coordinate_and_domain_join_drift_fail_closed(self):
        duplicated = copy.deepcopy(self.inputs)
        tile = next(
            image for image in duplicated["assets"]["images"]
            if "/layer" in image["source"].lower()
        )
        duplicated["assets"]["images"].append(copy.deepcopy(tile))
        with self.assertRaisesRegex(ValueError, "duplicate keys"):
            self.build(duplicated)

        missing = copy.deepcopy(self.inputs)
        missing["probe"]["scenes"].pop(0)
        with self.assertRaisesRegex(ValueError, "domain join"):
            self.build(missing)

    def test_instruction_or_function_receipt_drift_fails_closed(self):
        drifted = copy.deepcopy(self.inputs)
        record = next(
            row for row in drifted["functions"]["functions"]
            if row["address"] == drifted["probe"]["engine"]["location_base_loader"]["address"]
        )
        record["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "receipt drift"):
            self.build(drifted)

    def test_function_index_string_and_import_labels_are_not_trusted(self):
        forged = copy.deepcopy(self.inputs)
        grid = next(
            row for row in forged["functions"]["functions"]
            if row["address"] == self.generated["engine"]["gridLoader"]["address"]
        )
        grid["strings"] = [{"address": "0x00400000", "value": "forged"}]
        grid["imports"] = ["forged.dll!forged"]
        attachment = next(
            row for row in forged["functions"]["functions"]
            if row["address"] == self.generated["engine"]["staticAttachmentHelper"]["address"]
        )
        attachment["imports"] = []
        self.assertEqual(self.build(forged)["engine"], self.generated["engine"])

    def test_duplicate_domain_location_id_and_mode_rows_fail_closed(self):
        duplicate = copy.deepcopy(self.inputs)
        duplicate["dispatch"]["locations"].append(
            copy.deepcopy(duplicate["dispatch"]["locations"][0])
        )
        with self.assertRaisesRegex(ValueError, "duplicate dispatch location"):
            self.build(duplicate)

        duplicate = copy.deepcopy(self.inputs)
        rows = duplicate["dispatch"]["locations"]
        rows[1]["locationId"] = rows[0]["locationId"]
        rows[1]["mode"] = rows[0]["mode"]
        duplicate["probe"]["scenes"][1]["location_id"] = rows[1]["locationId"]
        duplicate["probe"]["scenes"][1]["mode"] = rows[1]["mode"]
        body = next(row for row in duplicate["bodies"]["modes"] if row["id"] == rows[1]["domainId"])
        body["location_id"] = rows[1]["locationId"]
        body["mode"] = rows[1]["mode"]
        with self.assertRaisesRegex(ValueError, "duplicate location id or mode"):
            self.build(duplicate)


if __name__ == "__main__":
    unittest.main()
