#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import flight_cleanroom_completion as completion
from tools.miel_vliegt import production_consumer_registry


class FlightCleanroomCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.documents = completion.load_documents()
        cls.matrix = completion.build(copy.deepcopy(cls.documents))

    def dimensions(self, matrix=None):
        return {
            row["id"]: row for row in (matrix or self.matrix)["dimensions"]
        }

    def native_dimension(self, documents=None, root=None):
        return completion._build_native_functions(
            copy.deepcopy(documents or self.documents), root or completion.ROOT,
        )

    def write_native_boundary_receipt(
        self, directory, documents, identifiers, disposition, **payload,
    ):
        boundary_id = f"boundary:{disposition.lower()}:{identifiers[0]}"
        pipeline = {row["id"]: row for row in documents["native_pipeline"]["functions"]}
        claims = []
        for identifier in identifiers:
            identity = {
                "boundaryId": boundary_id,
                "disposition": disposition,
                "functionId": identifier,
                "nativeFunctionSha256": pipeline[identifier]["pe"]["sha256"],
            }
            claims.append({
                **identity,
                "membershipSha256": hashlib.sha256(
                    completion._canonical(identity)
                ).hexdigest(),
            })
        receipt = {
            "schema": 1,
            "protocol": completion.NATIVE_BOUNDARY_RECEIPT_PROTOCOL,
            "reviewStatus": "REVIEWED",
            "boundaryId": boundary_id,
            "disposition": disposition,
            "claims": claims,
            **payload,
        }
        receipt["boundarySha256"] = hashlib.sha256(
            completion._canonical(receipt)
        ).hexdigest()
        path = Path(directory) / "native-boundary.json"
        path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
        reference = {
            "path": path.relative_to(directory).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for identifier in identifiers:
            pipeline[identifier]["disposition"] = disposition
            pipeline[identifier]["boundary_evidence_receipt"] = reference
        return receipt, path

    def substitution_mapping(self, directory, documents, identifier):
        module = Path(directory) / f"replacement-{identifier}.js"
        export_name = f"replacement_{identifier}"
        module.write_text(
            f"export function {export_name} () {{ return true }}\n",
            encoding="utf-8",
        )
        native = next(
            row for row in documents["native_pipeline"]["functions"]
            if row["id"] == identifier
        )
        interfaces = native["native_interfaces"]["imports"] or [
            native["native_interfaces"]["fallback"]
        ]
        return {
            "functionId": identifier,
            "nativeInterfaces": interfaces,
            "replacementOwner": "web-runtime",
            "replacementModule": module.relative_to(directory).as_posix(),
            "replacementExport": export_name,
            "replacementSourceSha256": hashlib.sha256(module.read_bytes()).hexdigest(),
        }

    def test_every_inventory_total_is_derived_from_its_source(self):
        dimensions = self.dimensions()
        flight_editions = completion._flight_editions(self.documents["scene_coverage"])
        natural_edges = completion._natural_edges(self.documents["transitions"])
        self.assertEqual(
            dimensions["modes"]["required"],
            len(self.documents["mode_bodies"]["modes"]) * len(flight_editions),
        )
        self.assertEqual(
            dimensions["locations"]["required"],
            len(self.documents["scene_probe"]["scenes"]) * len(flight_editions),
        )
        self.assertEqual(
            dimensions["gameplay_runtimes"]["required"],
            len(completion.CANONICAL_GAMEPLAY_RUNTIMES),
        )
        self.assertEqual(
            dimensions["semantic_claims"]["required"],
            len(self.documents["semantic"]["records"]),
        )
        web_closure = dimensions["semantic_claims"]["web_slot_closure"]
        self.assertEqual(web_closure["jobs"], 631)
        self.assertEqual(web_closure["captured_candidate"], 261)
        self.assertEqual(web_closure["blocked"], 370)
        self.assertFalse(web_closure["parity_eligible"])
        self.assertFalse(web_closure["promotion_allowed"])
        self.assertEqual(web_closure["native_comparison"], "NOT_RUN")
        self.assertEqual(dimensions["semantic_claims"]["complete"], 0)
        self.assertEqual(
            dimensions["natural_edges"]["required"],
            len(natural_edges) * len(flight_editions),
        )
        self.assertEqual(
            dimensions["subsystems"]["required"],
            len(self.documents["engine"]["subsystems"]),
        )
        self.assertEqual(
            dimensions["native_functions"]["required"],
            len(self.documents["native_pipeline"]["functions"]),
        )

    def test_markdown_derives_web_semantic_counts_from_matrix(self):
        web_closure = self.dimensions()["semantic_claims"]["web_slot_closure"]
        markdown = completion.render_markdown(self.matrix)
        self.assertIn(
            f"{web_closure['captured_candidate']} captured candidates and "
            f"{web_closure['blocked']} explicit blockers",
            markdown,
        )

    def test_each_dimension_independently_blocks_release(self):
        complete = [
            {
                "id": identifier,
                "status": "COMPLETE",
                "required": 1,
                "complete": 1,
                "blocked": 0,
            }
            for identifier in completion.DIMENSION_IDS
        ]
        self.assertTrue(completion.release_decision(complete))
        for identifier in completion.DIMENSION_IDS:
            with self.subTest(dimension=identifier):
                candidate = copy.deepcopy(complete)
                row = next(item for item in candidate if item["id"] == identifier)
                row.update(status="BLOCKED", complete=0, blocked=1)
                self.assertFalse(completion.release_decision(candidate))

    def test_missing_dimension_and_empty_dimension_fail_closed(self):
        complete = [
            {"id": identifier, "status": "COMPLETE", "required": 1,
             "complete": 1, "blocked": 0}
            for identifier in completion.DIMENSION_IDS
        ]
        self.assertFalse(completion.release_decision(complete[:-1]))
        complete[0].update(required=0, complete=0)
        self.assertFalse(completion.release_decision(complete))

    def test_structural_semantic_inventory_cannot_claim_parity(self):
        documents = copy.deepcopy(self.documents)
        for row in documents["semantic"]["records"]:
            row["status"] = "PROVEN"
            row["evidence"] = []
        matrix = completion.build(documents)
        semantics = self.dimensions(matrix)["semantic_claims"]
        self.assertEqual(semantics["complete"], 0)
        self.assertEqual(semantics["blocked"], semantics["required"])

    def test_web_semantic_slot_closure_drift_cannot_enter_completion_matrix(self):
        mutations = []
        for field, value in (("captured", 198), ("blocked", 433), ("jobs", 630)):
            documents = copy.deepcopy(self.documents)
            documents["web_semantic_evidence"]["counts"][field] = value
            mutations.append(documents)

        missing_slot = copy.deepcopy(self.documents)
        missing_slot["web_semantic_evidence"]["records"].pop()
        mutations.append(missing_slot)

        promoted = copy.deepcopy(self.documents)
        promoted["web_semantic_evidence"]["parityEligible"] = True
        mutations.append(promoted)

        for index, documents in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaisesRegex(
                    completion.CompletionError, "web semantic slot closure"
                ):
                    completion.build(documents)

    def test_web_semantic_slot_closure_is_monotone_not_literal(self):
        documents = copy.deepcopy(self.documents)
        promoted = next(
            row for row in documents["web_semantic_evidence"]["records"]
            if row["status"] == "BLOCKED"
        )
        promoted["status"] = "CAPTURED_CANDIDATE"
        documents["web_semantic_evidence"]["counts"]["captured"] += 1
        documents["web_semantic_evidence"]["counts"]["blocked"] -= 1
        semantics = self.dimensions(completion.build(documents))["semantic_claims"]
        self.assertEqual(semantics["web_slot_closure"]["captured_candidate"], 262)
        self.assertEqual(semantics["web_slot_closure"]["blocked"], 369)

        regressed = copy.deepcopy(self.documents)
        demoted = [
            row for row in regressed["web_semantic_evidence"]["records"]
            if row["status"] == "CAPTURED_CANDIDATE"
        ][:1]
        demoted[0]["status"] = "BLOCKED"
        regressed["web_semantic_evidence"]["counts"]["captured"] -= 1
        regressed["web_semantic_evidence"]["counts"]["blocked"] += 1
        with self.assertRaisesRegex(
            completion.CompletionError, "web semantic slot closure"
        ):
            completion.build(regressed)

    def test_static_transition_topology_cannot_claim_edge_parity(self):
        edges = self.dimensions()["natural_edges"]
        self.assertTrue(all(
            row["status"] == "BLOCKED" and row["static_evidence"] in {
                "PROVEN_STATIC", "NATIVE_TRACE_REQUIRED",
            }
            for row in edges["items"]
        ))

    def test_source_asset_inventory_cannot_claim_pixel_parity(self):
        assets = self.dimensions()["assets"]
        inventory = next(row for row in assets["items"] if row["id"] == "source_inventory")
        referenced = next(row for row in assets["items"] if row["id"] == "referenced_media")
        pixels = next(row for row in assets["items"] if row["id"] == "native_pixels")
        self.assertEqual(inventory["status"], "COMPLETE")
        self.assertEqual(inventory["evidence_level"], "STATIC_PAYLOAD_DIFFERENTIAL")
        self.assertEqual(
            set(inventory["payload_differential"]["classes"]),
            {"sceneImages", "sceneAudio", "phaserPack"},
        )
        self.assertEqual(
            inventory["payload_differential"]["summary"]["files"],
            self.documents["assets"]["counts"]["images"]
            + self.documents["assets"]["counts"]["audioVariants"],
        )
        self.assertFalse(
            inventory["payload_differential"]["summary"]["framebufferParityClaimed"]
        )
        self.assertEqual(referenced["status"], "COMPLETE")
        self.assertEqual(
            referenced["absence_algebra"]["source_references"],
            referenced["absence_algebra"]["lowered_absences"],
        )
        self.assertEqual(pixels["status"], "BLOCKED")
        self.assertEqual(pixels["required_visual_checkpoints"], 78)
        self.assertEqual(pixels["complete_visual_checkpoints"], 0)
        self.assertEqual(
            sum(pixels["visual_by_kind"].values()),
            pixels["required_visual_checkpoints"],
        )
        self.assertEqual(assets["status"], "BLOCKED")

    def test_visual_checkpoint_inventory_cannot_be_bypassed_by_one_runtime_frame(self):
        documents = copy.deepcopy(self.documents)
        pixels = next(
            row for row in documents["runtime"]["checkpoints"]
            if row.get("id") == "rendering.native_pixels"
        )
        pixels["status"] = "PIXEL_EQUIVALENT"
        pixels["proofs"] = [{"status": "PASS"}]
        assets = self.dimensions(completion.build(documents))["assets"]
        visual = next(row for row in assets["items"] if row["id"] == "native_pixels")
        self.assertEqual(visual["status"], "BLOCKED")
        self.assertEqual(visual["complete_visual_checkpoints"], 0)

    def test_scene_payload_receipt_drift_blocks_source_inventory(self):
        mutations = []
        wrong_count = copy.deepcopy(self.documents)
        wrong_count["asset_payload_differential"]["summary"]["files"] -= 1
        mutations.append(wrong_count)

        false_pixel_claim = copy.deepcopy(self.documents)
        false_pixel_claim["asset_payload_differential"]["summary"][
            "framebufferParityClaimed"
        ] = True
        mutations.append(false_pixel_claim)

        missing_class = copy.deepcopy(self.documents)
        missing_class["asset_payload_differential"]["classes"].pop("sceneAudio")
        mutations.append(missing_class)

        for index, documents in enumerate(mutations):
            with self.subTest(mutation=index):
                assets = self.dimensions(completion.build(documents))["assets"]
                inventory = next(
                    row for row in assets["items"] if row["id"] == "source_inventory"
                )
                self.assertEqual(inventory["status"], "BLOCKED")
                self.assertIsNone(inventory["payload_differential"])

    def test_native_expected_absences_require_exact_three_way_identity(self):
        mutations = []

        wrong_status = copy.deepcopy(self.documents)
        absent = next(
            row for row in wrong_status["assets"]["media"]
            if row.get("status") == "ABSENT_NO_COMMAND_NODE"
        )
        absent["status"] = "UNRESOLVED_UNKNOWN"
        mutations.append(wrong_status)

        missing_lowering = copy.deepcopy(self.documents)
        missing_lowering["executable_scene_scripts"]["removedCommands"].pop()
        mutations.append(missing_lowering)

        wrong_reference = copy.deepcopy(self.documents)
        wrong_reference["assets"]["unresolvedReferencedMedia"][0]["owner"] = "other-owner"
        mutations.append(wrong_reference)

        for index, documents in enumerate(mutations):
            with self.subTest(mutation=index):
                assets = self.dimensions(completion.build(documents))["assets"]
                referenced = next(
                    row for row in assets["items"] if row["id"] == "referenced_media"
                )
                self.assertEqual(referenced["status"], "BLOCKED")

    def test_gameplay_runtime_dimension_cannot_shrink_with_the_ledger(self):
        documents = copy.deepcopy(self.documents)
        removed = documents["engine"]["gameplay_runtimes"].pop()
        runtime = self.dimensions(completion.build(documents))["gameplay_runtimes"]
        self.assertEqual(runtime["required"], len(completion.CANONICAL_GAMEPLAY_RUNTIMES))
        missing = next(row for row in runtime["items"] if row["id"] == removed["id"])
        self.assertEqual(missing["status"], "BLOCKED")
        self.assertIsNone(missing["disposition"])

    def test_only_typed_release_reachable_opcode_ports_count_as_production_wiring(self):
        wiring = self.dimensions()["production_wiring"]
        presenter_items = [
            row for row in wiring["items"] if row["id"].startswith("presenter_opcode:")
        ]
        self.assertEqual(
            {row["opcode"] for row in presenter_items},
            set(wiring["required_presenter_opcodes"]),
        )
        self.assertTrue(presenter_items)
        complete = {
            row["opcode"] for row in presenter_items if row["status"] == "COMPLETE"
        }
        self.assertEqual(
            complete,
            {
                "AWARD_DIPLOMA", "JUDGE_AIRPLANE",
                "PLAY_CHARACTER_ANIMATION", "PLAY_CHARACTER_SOUND",
                "PLAY_MULLEBARNSOUND", "POSITION_CHARACTER",
                "PLAY_RADIO", "PLAY_SOUND",
            },
        )
        blocked = {
            row["opcode"] for row in presenter_items if row["status"] == "BLOCKED"
        }
        self.assertEqual(
            blocked,
            set(wiring["required_presenter_opcodes"]) - complete,
        )
        for row in presenter_items:
            if row["status"] != "COMPLETE":
                continue
            consumer = row["consumer"]
            self.assertEqual(consumer["handler"]["type"], "function")
            expected_contract = (
                "miel-vliegt-native-udsp-service-port-registry"
                if row["opcode"] in {
                    "AWARD_DIPLOMA", "JUDGE_AIRPLANE",
                    "PLAY_RADIO", "PLAY_SOUND",
                }
                else "miel-vliegt-flight-phaser-presenter-registry"
            )
            self.assertEqual(consumer["typed_registry"]["contract"], expected_contract)
        mygghanget = next(
            row for row in wiring["items"]
            if row["id"] == "mygghanget_presentation_consumer"
        )
        self.assertEqual(mygghanget["status"], "COMPLETE")
        self.assertEqual(
            mygghanget["consumer"]["handler"]["export"],
            "attachFlightPhaserMygghangetProjection",
        )
        self.assertTrue(
            mygghanget["consumer"]["integration"]["release_reachable"]
        )
        location = next(
            row for row in wiring["items"]
            if row["id"] == "location_presentation_consumer"
        )
        self.assertEqual(location["status"], "COMPLETE")
        self.assertEqual(
            location["consumer"]["handler"]["export"],
            "attachFlightPhaserLocationProjection",
        )
        self.assertTrue(
            location["consumer"]["integration"]["release_reachable"]
        )
        self.assertEqual(wiring["status"], "COMPLETE")

    def test_comments_null_and_dead_code_never_create_an_unregistered_opcode_port(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake.js"
            fake.parent.mkdir(parents=True, exist_ok=True)
            fake.write_text(
                "// attachFlightStatePresenter(state, { INVENTED_OPCODE: () => {} })\n"
                "const dead = { INVENTED_OPCODE: null }\n",
                encoding="utf-8",
            )
            wiring = self.dimensions()["production_wiring"]
            required = sorted([
                *(f"presenter_opcode:{opcode}"
                  for opcode in wiring["required_presenter_opcodes"]),
                *(f"asset_pack:{key}" for key in wiring["required_asset_packs"]),
                "location_presentation_consumer",
                "mygghanget_presentation_consumer",
                "parity_observation_surface",
                "presenter_opcode:INVENTED_OPCODE",
            ])
            registry = production_consumer_registry.build(required, completion.ROOT)
            presenter = next(
                row for row in registry["consumers"]
                if row["id"] == "presenter_opcode:INVENTED_OPCODE"
            )
            self.assertEqual(presenter["status"], "BLOCKED")
            self.assertIsNone(presenter["handler"])

    def test_parity_observation_surface_is_release_reachable(self):
        wiring = self.dimensions()["production_wiring"]
        observation = next(
            row for row in wiring["items"]
            if row["id"] == "parity_observation_surface"
        )
        self.assertEqual(observation["status"], "COMPLETE")
        self.assertEqual(
            observation["consumer"]["handler"],
            {
                "module": "src/flight/runtime/FlightParityObservation.js",
                "export": "createFlightParityObservation",
                "type": "function",
                "source": observation["consumer"]["handler"]["source"],
            },
        )
        self.assertTrue(
            observation["consumer"]["integration"]["release_reachable"]
        )
        self.assertTrue(
            observation["consumer"]["integration"]["handler_invoked"]
        )

    def test_checked_in_production_consumer_registry_matches_completion_requirements(self):
        wiring = self.dimensions()["production_wiring"]
        metadata = {"player_route", "transition_producer_build", "runtime_owners"}
        required = sorted(
            row["id"] for row in wiring["items"] if row["id"] not in metadata
        )
        output = completion.ROOT / production_consumer_registry.OUTPUT
        document = json.loads(output.read_text(encoding="utf-8"))
        production_consumer_registry.validate(document, required, completion.ROOT)

    def test_completion_items_have_canonical_subject_and_proof_identities(self):
        for dimension in self.matrix["dimensions"]:
            for item in dimension["items"]:
                self.assertRegex(item["subject_sha256"], r"^[0-9a-f]{64}$")
                if item["status"] == "COMPLETE":
                    self.assertRegex(item["proof_sha256"], r"^[0-9a-f]{64}$")
                else:
                    self.assertIsNone(item["proof_sha256"])

    def test_every_canonical_asset_pack_has_a_release_reachable_consumer(self):
        wiring = self.dimensions()["production_wiring"]
        pack_items = [
            row for row in wiring["items"] if row["id"].startswith("asset_pack:")
        ]
        self.assertEqual(
            {row["pack"] for row in pack_items},
            set(wiring["required_asset_packs"]),
        )
        self.assertTrue(pack_items)
        self.assertTrue(all(row["status"] == "COMPLETE" for row in pack_items))

        presenter_items = [
            row for row in wiring["items"] if row["id"].startswith("presenter_opcode:")
        ]
        self.assertEqual(
            {
                row["opcode"] for row in presenter_items
                if row["status"] == "COMPLETE"
            },
            {
                "AWARD_DIPLOMA", "JUDGE_AIRPLANE",
                "PLAY_CHARACTER_ANIMATION", "PLAY_CHARACTER_SOUND",
                "PLAY_MULLEBARNSOUND", "POSITION_CHARACTER",
                "PLAY_RADIO", "PLAY_SOUND",
            },
        )
        mygghanget = next(
            row for row in wiring["items"]
            if row["id"] == "mygghanget_presentation_consumer"
        )
        self.assertEqual(mygghanget["status"], "COMPLETE")
        location = next(
            row for row in wiring["items"]
            if row["id"] == "location_presentation_consumer"
        )
        self.assertEqual(location["status"], "COMPLETE")

    def test_native_byte_coverage_does_not_erase_ownership_or_stage_debt(self):
        native = self.dimensions()["native_functions"]
        self.assertGreater(native["required"], native["complete"])
        self.assertGreater(sum(native["stage_debt"].values()), 0)
        self.assertGreater(
            sum(count for status, count in native["ownership"].items()
                if status != "reviewed"),
            0,
        )

    def test_native_function_inventory_is_preserved_and_defaults_to_unknown(self):
        native = self.native_dimension()
        self.assertEqual(native["required"], 1369)
        self.assertEqual(native["dispositions"], {
            "GAME_BEHAVIOR": 3, "UNKNOWN": 1366,
        })
        self.assertEqual(native["complete"], 3)
        self.assertEqual(
            {row["id"] for row in native["items"] if row["status"] == "COMPLETE"},
            {"fn_0040fe30", "fn_004102d0", "fn_004102f0"},
        )

    def test_hash_bound_substitution_receipt_can_cover_a_claim_bound_cluster(self):
        documents = copy.deepcopy(self.documents)
        identifiers = [
            row["id"] for row in documents["native_pipeline"]["functions"][:2]
        ]
        with tempfile.TemporaryDirectory() as directory:
            receipt, _ = self.write_native_boundary_receipt(
                directory, documents, identifiers, "PLATFORM_SUBSTITUTION",
                apiImportMapping=[
                    self.substitution_mapping(directory, documents, identifier)
                    for identifier in identifiers
                ],
            )
            native = self.native_dimension(documents, Path(directory))
        by_id = {row["id"]: row for row in native["items"]}
        self.assertTrue(all(by_id[identifier]["status"] == "COMPLETE"
                            for identifier in identifiers))
        self.assertEqual(
            {row["functionId"] for row in receipt["claims"]}, set(identifiers)
        )
        self.assertNotEqual(
            by_id[identifiers[0]]["proof_sha256"],
            by_id[identifiers[1]]["proof_sha256"],
        )

    def test_forged_or_unmapped_substitution_receipts_fail_closed(self):
        for mutation in (
            "native_hash", "disposition", "empty_mapping", "interface_drift",
            "source_hash_drift", "missing_export", "module_escape",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                documents = copy.deepcopy(self.documents)
                identifier = documents["native_pipeline"]["functions"][0]["id"]
                receipt, path = self.write_native_boundary_receipt(
                    directory, documents, [identifier], "IMPORT_BOUNDARY",
                    apiImportMapping=[self.substitution_mapping(
                        directory, documents, identifier,
                    )],
                )
                if mutation == "native_hash":
                    receipt["claims"][0]["nativeFunctionSha256"] = "0" * 64
                elif mutation == "disposition":
                    receipt["disposition"] = "COMPILER_SUBSTITUTION"
                elif mutation == "empty_mapping":
                    receipt["apiImportMapping"] = []
                elif mutation == "interface_drift":
                    receipt["apiImportMapping"][0]["nativeInterfaces"] = [
                        "KERNEL32.dll!NotTheNativeInterface"
                    ]
                elif mutation == "source_hash_drift":
                    receipt["apiImportMapping"][0]["replacementSourceSha256"] = "0" * 64
                elif mutation == "missing_export":
                    receipt["apiImportMapping"][0]["replacementExport"] = "absentExport"
                else:
                    receipt["apiImportMapping"][0]["replacementModule"] = "../outside.js"
                receipt_without_hash = dict(receipt)
                receipt_without_hash.pop("boundarySha256")
                receipt["boundarySha256"] = hashlib.sha256(
                    completion._canonical(receipt_without_hash)
                ).hexdigest()
                path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
                row = documents["native_pipeline"]["functions"][0]
                row["boundary_evidence_receipt"]["sha256"] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                native = self.native_dimension(documents, Path(directory))
                item = next(row for row in native["items"] if row["id"] == identifier)
                self.assertEqual(item["status"], "BLOCKED")

    def test_all_three_substitution_dispositions_use_the_same_strict_contract(self):
        for disposition in (
            "PLATFORM_SUBSTITUTION", "COMPILER_SUBSTITUTION", "IMPORT_BOUNDARY",
        ):
            with self.subTest(disposition=disposition), tempfile.TemporaryDirectory() as directory:
                documents = copy.deepcopy(self.documents)
                identifier = documents["native_pipeline"]["functions"][0]["id"]
                self.write_native_boundary_receipt(
                    directory, documents, [identifier], disposition,
                    apiImportMapping=[self.substitution_mapping(
                        directory, documents, identifier,
                    )],
                )
                native = self.native_dimension(documents, Path(directory))
                item = next(row for row in native["items"] if row["id"] == identifier)
                self.assertEqual(item["status"], "COMPLETE")

    def test_unreachable_requires_all_four_closed_graphs_and_no_unresolved_path(self):
        closures = {
            name: {
                "closed": True,
                "reviewedTargetsSha256": hashlib.sha256(name.encode()).hexdigest(),
                "unresolvedPaths": [],
            }
            for name in ("roots", "callbacks", "vtables", "indirectTargets")
        }
        for mutation in (
            None, "entrypoint_reachable", "root_open", "callback_path",
            "vtable_missing", "indirect_path",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                documents = copy.deepcopy(self.documents)
                code_row = next(
                    row for row in documents["native_code_map"]["functions"]
                    if row["entrypoint_reachable"] is False
                    and row["has_unresolved_direct_calls"] is False
                    and row["has_unresolved_indirect_calls"] is False
                )
                identifier = code_row["id"]
                receipt, path = self.write_native_boundary_receipt(
                    directory, documents, [identifier], "PROVEN_UNREACHABLE",
                    reachabilityClosure=copy.deepcopy(closures),
                )
                if mutation == "entrypoint_reachable":
                    code_row["entrypoint_reachable"] = True
                elif mutation == "root_open":
                    receipt["reachabilityClosure"]["roots"]["closed"] = False
                elif mutation == "callback_path":
                    receipt["reachabilityClosure"]["callbacks"]["unresolvedPaths"] = ["cb:unknown"]
                elif mutation == "vtable_missing":
                    receipt["reachabilityClosure"].pop("vtables")
                elif mutation == "indirect_path":
                    receipt["reachabilityClosure"]["indirectTargets"]["unresolvedPaths"] = ["call:*eax"]
                if mutation is not None:
                    receipt_without_hash = dict(receipt)
                    receipt_without_hash.pop("boundarySha256")
                    receipt["boundarySha256"] = hashlib.sha256(
                        completion._canonical(receipt_without_hash)
                    ).hexdigest()
                    path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
                    pipeline_row = next(
                        row for row in documents["native_pipeline"]["functions"]
                        if row["id"] == identifier
                    )
                    pipeline_row["boundary_evidence_receipt"]["sha256"] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                native = self.native_dimension(documents, Path(directory))
                item = next(row for row in native["items"] if row["id"] == identifier)
                self.assertEqual(
                    item["status"], "COMPLETE" if mutation is None else "BLOCKED"
                )

    def test_game_behavior_requires_reviewed_boundaries_and_all_monotonic_stages(self):
        documents = copy.deepcopy(self.documents)
        identifier = "fn_0040fe30"
        pipeline_row = next(
            row for row in documents["native_pipeline"]["functions"]
            if row["id"] == identifier
        )
        complete = self.native_dimension(documents)
        item = next(row for row in complete["items"] if row["id"] == identifier)
        self.assertEqual(item["status"], "COMPLETE")
        pipeline_row["stages"]["differential"] = "MISSING"
        blocked = self.native_dimension(documents)
        item = next(row for row in blocked["items"] if row["id"] == identifier)
        self.assertEqual(item["status"], "BLOCKED")

    def test_game_behavior_boundary_forged_membership_owner_effect_and_source_fail(self):
        mutations = {
            "membership": lambda receipt: receipt["claims"][0].update(
                membershipSha256="0" * 64
            ),
            "owner": lambda receipt: receipt["ownershipBoundary"].update(
                owner="forged-owner"
            ),
            "effect": lambda receipt: receipt["effectBoundary"].update(
                effects=["CONSERVATIVE_STATEFUL"]
            ),
            "source": lambda receipt: receipt["sourceEvidence"][0].update(
                differentialReceiptSha256="0" * 64
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                dir=completion.ROOT
            ) as directory:
                documents = copy.deepcopy(self.documents)
                receipt = json.loads((
                    completion.ROOT
                    / "content/miel_vliegt/native_function_game_behavior_boundary.json"
                ).read_text(encoding="utf-8"))
                mutate(receipt)
                unhashed = dict(receipt)
                unhashed.pop("boundarySha256")
                receipt["boundarySha256"] = hashlib.sha256(
                    completion._canonical(unhashed)
                ).hexdigest()
                path = Path(directory) / "forged-boundary.json"
                path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
                reference = {
                    "path": path.relative_to(completion.ROOT).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
                for row in documents["native_pipeline"]["functions"]:
                    if row.get("disposition") == "GAME_BEHAVIOR":
                        row["boundary_evidence_receipt"] = reference
                native = self.native_dimension(documents)
                self.assertEqual(native["complete"], 0)

    def test_generated_summary_is_derived_and_currently_fail_closed(self):
        dimensions = self.matrix["dimensions"]
        self.assertEqual(
            self.matrix["summary"]["complete_dimensions"],
            sum(row["status"] == "COMPLETE" for row in dimensions),
        )
        self.assertEqual(
            self.matrix["summary"]["blocked_dimensions"],
            sum(row["status"] == "BLOCKED" for row in dimensions),
        )
        self.assertFalse(self.matrix["summary"]["release_ready"])
        self.assertFalse(self.matrix["summary"]["complete"])

    def test_checked_in_json_and_markdown_are_generated_outputs(self):
        expected_json = completion.ROOT / completion.OUTPUT
        expected_docs = completion.ROOT / completion.DOCUMENTATION
        self.assertEqual(
            expected_json.read_text(encoding="utf-8"),
            json.dumps(self.matrix, indent=2, ensure_ascii=True) + "\n",
        )
        self.assertEqual(
            expected_docs.read_text(encoding="utf-8"),
            completion.render_markdown(self.matrix),
        )


if __name__ == "__main__":
    unittest.main()
