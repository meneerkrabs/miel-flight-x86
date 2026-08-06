import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tools.miel_vliegt import flight_trace_differential, natural_transition_trace, scene_coverage


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "tools/miel_vliegt/scene_coverage_ledger.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SceneCoverageTests(unittest.TestCase):
    def setUp(self):
        self.ledger = json.loads(LEDGER.read_text(encoding="utf-8"))

    def write_ledger(self, directory: str, document=None) -> Path:
        path = Path(directory) / "ledger.json"
        path.write_text(json.dumps(document or self.ledger), encoding="utf-8")
        return path

    def set_flight_body_claim(
        self, scene: str, status: str = "UNPROVEN", evidence=None,
    ) -> None:
        edition = next(
            record for record in self.ledger["editions"].values()
            if record["game"] == "flight"
        )
        claim = next(claim for claim in edition["claims"] if claim["scene"] == scene)
        claim["gates"]["BODY_PARITY"] = {
            "status": status,
            "evidence": list(evidence or []),
            "blocker": (
                scene_coverage.BODY_UNPROVEN_BLOCKER
                if status == "UNPROVEN" else None
            ),
        }

    def transition_claim(self, edge: str) -> dict:
        claims = self.ledger["flight_transition_claims"][
            "flight/nl/miel-vliegt-de-wereld-rond"
        ]
        return next(claim for claim in claims if claim["edge"] == edge)

    def add_body_triplet(
        self, directory: str, *, scene: str = "mode_login",
        evidence_prefix: str = "body",
    ) -> list[str]:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        phases = ["load", "open", "tick", "render", "close", "unload"]
        policy = {
            "lifecycle": "EXACT_ORDERED_STATES",
            "render_checkpoints": "EXACT_CANONICAL_RGBA_SHA256",
        }
        policy_sha256 = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        paths = {}
        for producer, kind, subject in (
            (
                "NATIVE", "native-trace",
                natural_transition_trace.NATIVE_EXECUTABLE_SHA256,
            ),
            ("WEB", "web-trace", natural_transition_trace.WEB_BUILD_SHA256),
        ):
            lifecycle = [
                {
                    "sequence": sequence,
                    "tick": sequence,
                    "phase": phase,
                    "state": {"active": phase not in {"load", "unload"}},
                }
                for sequence, phase in enumerate(phases)
            ]
            value = {
                "schema": 1,
                "protocol": "miel-vliegt-mode-body-trace",
                "producer": producer,
                "edition": "flight/nl/miel-vliegt-de-wereld-rond",
                "scene": scene,
                "capture_id": f"{producer.lower()}-{scene}",
                "subject_sha256": subject,
                "result": "PASS",
                "lifecycle": lifecycle,
                "render_checkpoints": [{
                    "id": f"{scene}:render:0",
                    "tick": 3,
                    "width": 640,
                    "height": 480,
                    "canonical_rgba_sha256": "a" * 64,
                }],
                "coverage": {
                    "required_lifecycle_phases": phases,
                    "observed_lifecycle_phases": phases,
                    "render_checkpoint_ids": [f"{scene}:render:0"],
                },
            }
            path = root / f"{producer.lower()}-body.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            paths[kind] = path
        receipt = {
            "schema": 2,
            "protocol": "miel-scene-differential",
            "edition": "flight/nl/miel-vliegt-de-wereld-rond",
            "scene": scene,
            "native_trace_sha256": sha256(paths["native-trace"]),
            "web_trace_sha256": sha256(paths["web-trace"]),
            "comparator": "mode-body-exact-v1",
            "comparison_policy": policy,
            "comparison_policy_sha256": policy_sha256,
            "result": "PASS",
        }
        receipt_path = root / "body-receipt.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        paths["differential-receipt"] = receipt_path
        refs = []
        for index, (kind, path) in enumerate(paths.items()):
            evidence_id = f"{evidence_prefix}-{index}"
            refs.append(evidence_id)
            self.ledger["parity_evidence"][evidence_id] = {
                "kind": kind,
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256(path),
            }
        return refs

    def add_transition_triplet(
        self, directory: str, *, edge: str, source_scene, scene: str,
        entry_path: str, native_capture_id: str | None = None,
        web_capture_id: str | None = None,
        evidence_prefix: str = "edge",
    ) -> list[str]:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        paths = {}
        for driver, kind in (
            ("native-gameplay", "native-transition-trace"),
            ("web-gameplay", "web-transition-trace"),
        ):
            capture_id = native_capture_id if driver == "native-gameplay" \
                and native_capture_id is not None else web_capture_id \
                if driver == "web-gameplay" and web_capture_id is not None \
                else f"{driver}-{edge}"
            event = flight_trace_differential.natural_transition_event(
                edge, driver, capture_id=capture_id, sequence=1, tick=0,
            )
            raw = root / f"{driver}.raw.ndjson"
            if driver == "native-gameplay":
                native_identity = {
                    "schema": 3,
                    "protocol": "miel-vliegt-native-natural-transition",
                    "scenario": edge,
                    "executable_sha256":
                        natural_transition_trace.NATIVE_EXECUTABLE_SHA256,
                    "hook_build": natural_transition_trace.NATIVE_HOOK_BUILD,
                    "observer_dll_sha256": "1" * 64,
                    "thread_id": 7,
                }
                raw.write_text(
                    'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
                    '"status":"LOADED","thread_id":7}\n'
                    + "MVD " + json.dumps({**native_identity,
                        "record": "natural_session_start", "result": "ACTIVE",
                    }, separators=(",", ":")) + "\n"
                    + "MVD " + json.dumps({**native_identity,
                        "record": "scene_transition_source", "edge": edge,
                        "transition_site": event["transition_site"], "sequence": 1,
                        "tick": 0,
                    }, separators=(",", ":")) + "\n"
                    + "MVD " + json.dumps({**native_identity,
                        "record": "natural_session_complete", "result": "PASS",
                    }, separators=(",", ":")) + "\n"
                    + "MVT " + json.dumps({
                        "record": "session", "channel": "session.complete",
                        "values": {"scenario": edge, "reason": "captured"},
                    }, separators=(",", ":")) + "\n"
                    + 'MVO {"schema":1,"protocol":"miel-vliegt-native-observer-hook",'
                    '"status":"SCENARIO_COMPLETE","thread_id":7}\n',
                    encoding="utf-8",
                )
                producer = "native-observer-hook"
                subject = natural_transition_trace.NATIVE_EXECUTABLE_SHA256
            else:
                subject = natural_transition_trace.WEB_BUILD_SHA256
                common = {
                    "schema": 1, "protocol": "miel-web-scene-transition-runtime",
                    "capture_id": capture_id, "scenario": edge,
                    "build_sha256": subject, "debug_entry": False,
                    "evidence_scope": "NATURAL_TRANSITION",
                }
                raw.write_text("\n".join(json.dumps(row) for row in (
                    {**common, "record": "session.start", "sequence": 0, "tick": 0},
                    {**common, "record": "scene_transition", "sequence": 1, "tick": 0,
                     "edge": edge, "source_scene": event["source_scene"],
                     "scene": event["scene"], "transition_site": event["transition_site"],
                     "transition_trigger": event["transition_trigger"],
                     "transition_predicate": event["transition_predicate"],
                     "native_edge": edge,
                     "native_transition_site": event["transition_site"],
                     "classification": "EXACT_NATIVE_CONTRACT_EDGE",
                     "parity_eligible": natural_transition_trace.EDGES[
                         edge
                     ]["parity_eligible"] is True},
                    {**common, "record": "session.complete", "sequence": 2, "tick": 0,
                     "result": "PASS"},
                )) + "\n", encoding="utf-8")
                producer = "web-scene-manager"
            path = root / f"{driver}.ndjson"
            start = {
                "schema": 3, "protocol": natural_transition_trace.PROTOCOL,
                "record": "capture_start", "edition": natural_transition_trace.EDITION,
                "entry_driver": driver, "capture_id": capture_id, "scenario": edge,
                "producer": producer, "subject_sha256": subject,
                "raw_trace": {"path": raw.name, "sha256": sha256(raw)},
                "debug_entry": False, "evidence_scope": natural_transition_trace.SCOPE,
            }
            complete = {
                "schema": 3, "protocol": natural_transition_trace.PROTOCOL,
                "record": "capture_complete", "edition": natural_transition_trace.EDITION,
                "entry_driver": driver, "capture_id": capture_id, "final_sequence": 2,
                "result": "PASS", "debug_entry": False,
                "evidence_scope": natural_transition_trace.SCOPE,
            }
            path.write_text("\n".join(json.dumps(row) for row in (start, event, complete))
                            + "\n", encoding="utf-8")
            paths[kind] = path
        receipt = root / "transition-receipt.json"
        receipt.write_text(json.dumps(natural_transition_trace.compare(
            paths["native-transition-trace"], paths["web-transition-trace"],
        )), encoding="utf-8")
        paths["transition-differential-receipt"] = receipt
        refs = []
        for index, (kind, path) in enumerate(paths.items()):
            evidence_id = f"{evidence_prefix}-{index}"
            refs.append(evidence_id)
            self.ledger["parity_evidence"][evidence_id] = {
                "kind": kind,
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256(path),
            }
        return refs

    def test_default_ledger_pins_all_three_game_inventories_without_claiming_parity(self):
        report = scene_coverage.validate_ledger(LEDGER)

        self.assertEqual(report.editions, 12)
        self.assertEqual(report.expectations, 390)
        self.assertEqual(report.proven, 0)
        self.assertEqual(report.unproven, 22)
        self.assertEqual(report.unknown, 368)
        self.assertEqual(report.inventory_unproven, 11)
        self.assertEqual(report.flight_expectations, 22)
        self.assertEqual(report.body_parity_proven, 0)
        self.assertEqual(report.body_parity_unproven, 22)
        self.assertEqual(report.body_parity_unknown, 0)
        self.assertEqual(report.natural_transition_parity_proven, 0)
        self.assertEqual(report.natural_transition_parity_unproven, 48)
        self.assertEqual(report.natural_transition_parity_unknown, 0)
        self.assertEqual(report.flight_transition_expectations, 48)
        self.assertFalse(report.release_ready)
        self.assertIn(
            "UNPROVEN_BODY_PARITY:flight/nl/miel-vliegt-de-wereld-rond:mode_login",
            report.gaps,
        )
        self.assertIn(
            "UNPROVEN_NATURAL_TRANSITION_PARITY:"
            "flight/nl/miel-vliegt-de-wereld-rond:credits.terminal",
            report.gaps,
        )
        self.assertIn("UNKNOWN:car/de/willy-werkel:00", report.gaps)
        self.assertIn("UNKNOWN:boat/no/mulle-mekk:showboat", report.gaps)
        self.assertIn("UNPROVEN_INVENTORY:car/en/gary-gadget-2006", report.gaps)

    def test_default_release_gate_fails_closed(self):
        with self.assertRaisesRegex(
            scene_coverage.SceneCoverageGap, "0/390 proven"
        ):
            scene_coverage.enforce_release_coverage(LEDGER)

    def test_failed_cli_gate_still_emits_machine_readable_debt(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = scene_coverage.main(["--ledger", str(LEDGER)])

        self.assertEqual(result, 1)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["unknown"], 368)
        self.assertEqual(payload["unproven"], 22)
        self.assertEqual(
            payload["flight_gates"]["BODY_PARITY"]["expectations"], 22
        )
        self.assertEqual(payload["flight_gates"]["BODY_PARITY"]["unknown"], 0)
        self.assertEqual(payload["flight_gates"]["BODY_PARITY"]["unproven"], 22)
        self.assertEqual(
            payload["flight_gates"]["NATURAL_TRANSITION_PARITY"]["expectations"], 48
        )
        self.assertEqual(
            payload["flight_gates"]["NATURAL_TRANSITION_PARITY"]["unproven"], 48
        )
        self.assertIn("0/390 proven", stderr.getvalue())

    def test_inventory_contains_exact_22_native_modes(self):
        modes = self.ledger["inventories"]["flight"]["ids"]

        self.assertEqual(len(modes), 22)
        self.assertIn("mode_login", modes)
        self.assertIn("mode_barn", modes)
        self.assertIn("mode_mygghanget", modes)
        self.assertIn("mode_fly", modes)
        self.assertIn("mode_credits", modes)

    def flight_claims(self):
        edition = next(
            record for record in self.ledger["editions"].values()
            if record["game"] == "flight"
        )
        return edition["claims"]

    def test_generated_negative_body_claims_exactly_cover_native_mode_inventory(self):
        claims = self.flight_claims()
        modes = self.ledger["inventories"]["flight"]["ids"]
        body_contract = json.loads(
            (ROOT / self.ledger["sources"]["flight_native_mode_bodies"]["path"])
            .read_text(encoding="utf-8")
        )

        self.assertEqual(
            scene_coverage.generate_negative_body_claims(
                self.ledger, body_contract,
            ),
            self.ledger,
        )
        self.assertEqual([claim["scene"] for claim in claims], modes)
        self.assertEqual(len(claims), 22)
        for claim in claims:
            self.assertEqual(
                claim["coverage"]["required_lifecycle_phases"],
                ["load", "open", "tick", "render", "close", "unload"],
            )
            self.assertEqual(
                claim["gates"]["BODY_PARITY"]["status"], "UNPROVEN",
            )
            self.assertTrue(claim["gates"]["BODY_PARITY"]["blocker"])

    def test_write_refreshes_only_generated_dependency_source_pins(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            ledger = self.write_ledger(directory)
            value = json.loads(ledger.read_text(encoding="utf-8"))
            value["sources"]["edition_registry"]["sha256"] = "0" * 64
            value["sources"]["flight_native_mode_bodies"]["sha256"] = "0" * 64
            value["sources"]["flight_web_transition_build"]["sha256"] = "0" * 64
            value["sources"]["director_scene_graph"]["sha256"] = "1" * 64
            ledger.write_text(json.dumps(value), encoding="utf-8")

            generated = scene_coverage.regenerate_negative_body_claims(ledger)

            for name in (
                "edition_registry", "flight_native_mode_bodies",
                "flight_web_transition_build",
            ):
                source = generated["sources"][name]
                self.assertEqual(source["sha256"], sha256(ROOT / source["path"]))
            self.assertEqual(
                generated["sources"]["director_scene_graph"]["sha256"],
                "1" * 64,
            )

    def test_missing_generated_body_claim_fails_closed(self):
        self.flight_claims().pop()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "body claim matrix is missing",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_duplicate_generated_body_claim_fails_closed(self):
        self.flight_claims().append(dict(self.flight_claims()[0]))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "duplicate scene claim",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_foreign_generated_body_claim_fails_closed(self):
        self.flight_claims()[0]["scene"] = "mode_foreign"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "unknown scene claim",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_generated_body_claim_requires_six_phase_coverage_vector(self):
        self.flight_claims()[0]["coverage"]["required_lifecycle_phases"] = []
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "BODY coverage vector differs",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_generated_body_claim_rejects_source_hash_drift(self):
        self.flight_claims()[0]["subject"]["source"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "BODY subject identity differs",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_transition_matrix_ratchets_exact_48_edges_and_terminal(self):
        claims = self.ledger["flight_transition_claims"][
            "flight/nl/miel-vliegt-de-wereld-rond"
        ]
        edges = [claim["edge"] for claim in claims]

        self.assertEqual(len(edges), 48)
        self.assertEqual(len(set(edges)), 48)
        self.assertEqual(edges, sorted(edges))
        self.assertIn("credits.terminal", edges)
        terminal = next(
            edge for edge in json.loads(
                (ROOT / "content/miel_vliegt/native_scene_transitions.json")
                .read_text(encoding="utf-8")
            )["edges"]
            if edge["id"] == "credits.terminal"
        )
        self.assertEqual(terminal["source"], "mode_credits")
        self.assertEqual(terminal["target"], "__terminal__")

    def test_missing_transition_edge_claim_is_rejected(self):
        claims = self.ledger["flight_transition_claims"][
            "flight/nl/miel-vliegt-de-wereld-rond"
        ]
        claims[:] = [row for row in claims if row["edge"] != "credits.terminal"]

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "flight transition claim matrix is missing edges.*credits.terminal",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_duplicate_transition_edge_claim_is_rejected(self):
        claims = self.ledger["flight_transition_claims"][
            "flight/nl/miel-vliegt-de-wereld-rond"
        ]
        claims.append(dict(claims[0]))

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "duplicate flight transition claim",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_unknown_transition_edge_claim_is_rejected(self):
        self.ledger["flight_transition_claims"][
            "flight/nl/miel-vliegt-de-wereld-rond"
        ][0]["edge"] = "invented.edge"

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "flight transition claim names an unknown edge",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_transition_evidence_for_unknown_edge_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            self.add_transition_triplet(
                directory,
                edge="startup.login",
                source_scene=None,
                scene="mode_login",
                entry_path="startup",
            )
            native = Path(directory) / "native-gameplay.ndjson"
            records = [json.loads(line) for line in native.read_text(encoding="utf-8").splitlines()]
            records[1]["edge"] = "invented.edge"
            native.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                              encoding="utf-8")
            self.ledger["parity_evidence"]["edge-0"]["sha256"] = sha256(native)
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "invalid natural transition trace",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_legacy_transition_schema_cannot_enter_the_edge_ratchet(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            self.add_transition_triplet(
                directory,
                edge="startup.login",
                source_scene=None,
                scene="mode_login",
                entry_path="startup",
            )
            native = Path(directory) / "native-gameplay.ndjson"
            records = [json.loads(line) for line in native.read_text(encoding="utf-8").splitlines()]
            records[0]["schema"] = 1
            native.write_text("\n".join(json.dumps(row) for row in records) + "\n",
                              encoding="utf-8")
            self.ledger["parity_evidence"]["edge-0"]["sha256"] = sha256(native)

            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "invalid natural transition trace",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_legacy_transition_receipt_cannot_enter_the_edge_ratchet(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            self.add_transition_triplet(
                directory,
                edge="startup.login",
                source_scene=None,
                scene="mode_login",
                entry_path="startup",
            )
            receipt = Path(directory) / "transition-receipt.json"
            value = json.loads(receipt.read_text(encoding="utf-8"))
            value["schema"] = 1
            receipt.write_text(json.dumps(value), encoding="utf-8")
            self.ledger["parity_evidence"]["edge-2"]["sha256"] = sha256(receipt)

            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "natural transition differential receipt is not PASS",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_credits_terminal_has_an_explicit_edge_bound_proof_shape(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_transition_triplet(
                directory,
                edge="credits.terminal",
                source_scene="mode_credits",
                scene="__terminal__",
                entry_path="gameplay-transition",
            )
            claim = self.transition_claim("credits.terminal")
            claim["status"] = "PARITY_PROVEN"
            claim["evidence"] = refs

            report = scene_coverage.validate_ledger(self.write_ledger(directory))

        self.assertEqual(report.natural_transition_parity_proven, 1)
        self.assertEqual(report.natural_transition_parity_unproven, 47)

    def test_proven_transition_edge_cannot_omit_evidence(self):
        claim = self.transition_claim("credits.terminal")
        claim["status"] = "PARITY_PROVEN"

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "NATURAL_TRANSITION_PARITY requires natural native, web",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_transition_evidence_cannot_be_reused_for_another_edge(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_transition_triplet(
                directory,
                edge="login.barn.keyboard",
                source_scene="mode_login",
                scene="mode_barn",
                entry_path="gameplay-transition",
            )
            first = self.transition_claim("login.barn.keyboard")
            first["status"] = "PARITY_PROVEN"
            first["evidence"] = refs
            second = self.transition_claim("login.barn.deferred")
            second["status"] = "PARITY_PROVEN"
            second["evidence"] = refs

            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "duplicate flight transition evidence reference",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_native_capture_id_cannot_be_relabelled_as_two_distinct_edges(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            first_refs = self.add_transition_triplet(
                str(root / "first"), edge="login.barn.keyboard",
                source_scene="mode_login", scene="mode_barn",
                entry_path="gameplay-transition", native_capture_id="shared-native-capture",
                evidence_prefix="first",
            )
            second_refs = self.add_transition_triplet(
                str(root / "second"), edge="login.barn.deferred",
                source_scene="mode_login", scene="mode_barn",
                entry_path="gameplay-transition", native_capture_id="shared-native-capture",
                evidence_prefix="second",
            )
            for edge, refs in (
                ("login.barn.keyboard", first_refs),
                ("login.barn.deferred", second_refs),
            ):
                claim = self.transition_claim(edge)
                claim["status"] = "PARITY_PROVEN"
                claim["evidence"] = refs
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "native capture cannot prove multiple natural edges",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_web_capture_id_cannot_be_relabelled_as_two_distinct_edges(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            first_refs = self.add_transition_triplet(
                str(root / "first"), edge="login.barn.keyboard",
                source_scene="mode_login", scene="mode_barn",
                entry_path="gameplay-transition", web_capture_id="shared-web-capture",
                evidence_prefix="first",
            )
            second_refs = self.add_transition_triplet(
                str(root / "second"), edge="login.barn.deferred",
                source_scene="mode_login", scene="mode_barn",
                entry_path="gameplay-transition", web_capture_id="shared-web-capture",
                evidence_prefix="second",
            )
            for edge, refs in (
                ("login.barn.keyboard", first_refs),
                ("login.barn.deferred", second_refs),
            ):
                claim = self.transition_claim(edge)
                claim["status"] = "PARITY_PROVEN"
                claim["evidence"] = refs
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "web capture cannot prove multiple natural edges",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_ledger_uses_same_utf8_bom_transition_parser_as_differential(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_transition_triplet(
                directory, edge="startup.login", source_scene=None,
                scene="mode_login", entry_path="startup",
            )
            native = Path(directory) / "native-gameplay.ndjson"
            native.write_bytes(b"\xef\xbb\xbf" + native.read_bytes())
            self.ledger["parity_evidence"][refs[0]]["sha256"] = sha256(native)
            receipt = Path(directory) / "transition-receipt.json"
            value = natural_transition_trace.compare(
                native, Path(directory) / "web-gameplay.ndjson",
            )
            receipt.write_text(json.dumps(value), encoding="utf-8")
            self.ledger["parity_evidence"][refs[2]]["sha256"] = sha256(receipt)
            claim = self.transition_claim("startup.login")
            claim["status"] = "PARITY_PROVEN"
            claim["evidence"] = refs
            report = scene_coverage.validate_ledger(self.write_ledger(directory))
            self.assertEqual(report.natural_transition_parity_proven, 1)

    def test_flight_inventory_is_bound_to_body_and_transition_contracts(self):
        sources = self.ledger["sources"]

        self.assertEqual(
            sources["flight_native_mode_bodies"]["path"],
            "content/miel_vliegt/native_mode_bodies.json",
        )
        self.assertEqual(
            sources["flight_native_scene_transitions"]["path"],
            "content/miel_vliegt/native_scene_transitions.json",
        )
        self.assertEqual(
            sources["flight_web_transition_build"]["path"],
            "content/miel_vliegt/web_transition_build.json",
        )
        report = scene_coverage.validate_ledger(LEDGER)
        self.assertEqual(report.flight_expectations, 22)

    def test_web_transition_build_source_cannot_lie_about_its_inputs(self):
        source = ROOT / self.ledger["sources"]["flight_web_transition_build"]["path"]
        value = json.loads(source.read_text(encoding="utf-8"))
        value["inputs"] = []
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            replacement = Path(directory) / "web_transition_build.json"
            replacement.write_text(json.dumps(value), encoding="utf-8")
            self.ledger["sources"]["flight_web_transition_build"] = {
                "path": str(replacement.relative_to(ROOT)),
                "sha256": sha256(replacement),
                "authority": "web-parity-build",
            }
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "unsupported web transition build contract",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_body_contract_cannot_claim_runtime_parity_without_trace_evidence(self):
        body_source = ROOT / self.ledger["sources"]["flight_native_mode_bodies"]["path"]
        body_contract = json.loads(body_source.read_text(encoding="utf-8"))
        body_contract["modes"][0]["runtime_body_equivalence"] = "PARITY_PROVEN"
        body_contract["modes"][0]["parity_eligible"] = True

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            contract_path = Path(directory) / "native_mode_bodies.json"
            contract_path.write_text(json.dumps(body_contract), encoding="utf-8")
            self.ledger["sources"]["flight_native_mode_bodies"] = {
                "path": str(contract_path.relative_to(ROOT)),
                "sha256": sha256(contract_path),
                "authority": "inventory",
            }
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "mode body contract contains an unearned runtime claim",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_source_hash_drift_is_rejected(self):
        self.ledger["sources"]["director_scene_graph"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "source hash drifted"
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_new_registry_edition_cannot_be_omitted(self):
        del self.ledger["editions"]["car/en/gary-gadget-2006"]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "edition coverage matrix drifted"
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_unknown_scene_claim_is_rejected(self):
        self.ledger["editions"]["car/nl/mielauto"]["claims"].append({
            "scene": "invented",
            "status": "UNPROVEN",
            "evidence": [],
        })
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "unknown scene claim"
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_explicit_unproven_scene_remains_release_debt(self):
        with tempfile.TemporaryDirectory() as directory:
            report = scene_coverage.validate_ledger(self.write_ledger(directory))

        self.assertEqual(report.unproven, 22)
        self.assertEqual(report.unknown, 368)
        self.assertEqual(report.body_parity_unproven, 22)
        self.assertEqual(report.natural_transition_parity_unproven, 48)
        self.assertIn(
            "UNPROVEN_BODY_PARITY:flight/nl/miel-vliegt-de-wereld-rond:mode_login",
            report.gaps,
        )

    def test_legacy_positive_flight_claim_is_rejected_as_ambiguous(self):
        claims = self.flight_claims()
        index = next(
            index for index, claim in enumerate(claims)
            if claim["scene"] == "mode_login"
        )
        claims[index] = {
            "scene": "mode_login",
            "status": "PARITY_PROVEN",
            "evidence": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "flight BODY claim fields differ",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_parity_proven_requires_all_three_evidence_kinds(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_body_triplet(directory)
            self.set_flight_body_claim("mode_login", "PARITY_PROVEN", refs[:1])
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "BODY_PARITY requires native, web and PASS differential evidence",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_protocol_only_files_cannot_promote_a_mode_body(self):
        trace = ROOT / "tools/miel_vliegt/fixtures/native_trace_protocol_fixture.ndjson"
        web_trace = ROOT / "tools/miel_vliegt/fixtures/web_scene_trace_protocol_fixture.ndjson"
        receipt = ROOT / "tools/miel_vliegt/fixtures/scene_differential_pass_fixture.json"
        self.ledger["parity_evidence"] = {
            "native": {"kind": "native-trace", "path": str(trace.relative_to(ROOT)),
                       "sha256": sha256(trace)},
            "web": {"kind": "web-trace", "path": str(web_trace.relative_to(ROOT)),
                    "sha256": sha256(web_trace)},
            "diff": {"kind": "differential-receipt",
                     "path": str(receipt.relative_to(ROOT)), "sha256": sha256(receipt)},
        }
        self.set_flight_body_claim(
            "mode_login", "PARITY_PROVEN", ["native", "web", "diff"],
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "invalid mode BODY trace",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_mode_body_requires_all_six_lifecycle_phases(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_body_triplet(directory)
            native_path = Path(directory) / "native-body.json"
            native = json.loads(native_path.read_text())
            native["lifecycle"] = [
                row for row in native["lifecycle"] if row["phase"] != "close"
            ]
            native["coverage"]["observed_lifecycle_phases"] = [
                row["phase"] for row in native["lifecycle"]
            ]
            native_path.write_text(json.dumps(native))
            self.ledger["parity_evidence"][refs[0]]["sha256"] = sha256(native_path)
            receipt_path = Path(directory) / "body-receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["native_trace_sha256"] = sha256(native_path)
            receipt_path.write_text(json.dumps(receipt))
            self.ledger["parity_evidence"][refs[2]]["sha256"] = sha256(receipt_path)
            self.set_flight_body_claim("mode_login", "PARITY_PROVEN", refs)
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "all six lifecycle phases",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_mode_body_recomputes_differential_after_refreshed_hashes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_body_triplet(directory)
            web_path = Path(directory) / "web-body.json"
            web = json.loads(web_path.read_text())
            web["lifecycle"][2]["state"]["active"] = False
            web_path.write_text(json.dumps(web))
            self.ledger["parity_evidence"][refs[1]]["sha256"] = sha256(web_path)
            receipt_path = Path(directory) / "body-receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["web_trace_sha256"] = sha256(web_path)
            receipt_path.write_text(json.dumps(receipt))
            self.ledger["parity_evidence"][refs[2]]["sha256"] = sha256(receipt_path)
            self.set_flight_body_claim("mode_login", "PARITY_PROVEN", refs)

            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "recomputed mode BODY differential differs",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_mode_body_requires_a_render_checkpoint(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_body_triplet(directory)
            native_path = Path(directory) / "native-body.json"
            native = json.loads(native_path.read_text())
            native["render_checkpoints"] = []
            native["coverage"]["render_checkpoint_ids"] = []
            native_path.write_text(json.dumps(native))
            self.ledger["parity_evidence"][refs[0]]["sha256"] = sha256(native_path)
            receipt_path = Path(directory) / "body-receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["native_trace_sha256"] = sha256(native_path)
            receipt_path.write_text(json.dumps(receipt))
            self.ledger["parity_evidence"][refs[2]]["sha256"] = sha256(receipt_path)
            self.set_flight_body_claim("mode_login", "PARITY_PROVEN", refs)

            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "lacks a render checkpoint",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_candidate_language_inventory_can_never_be_called_complete(self):
        self.ledger["editions"]["car/de/willy-werkel"]["claims"].append({
            "scene": "00",
            "status": "PARITY_PROVEN",
            "evidence": [],
        })
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "requires an exact edition inventory"
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_body_pass_does_not_promote_flight_scene_without_natural_transition(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_body_triplet(directory)
            self.set_flight_body_claim("mode_login", "PARITY_PROVEN", refs)
            report = scene_coverage.validate_ledger(self.write_ledger(directory))

        self.assertEqual(report.proven, 0)
        self.assertEqual(report.unproven, 22)
        self.assertEqual(report.unknown, 368)
        self.assertEqual(report.body_parity_proven, 1)
        self.assertEqual(report.body_parity_unproven, 21)
        self.assertEqual(report.natural_transition_parity_unproven, 48)
        self.assertFalse(report.release_ready)

    def test_debug_style_body_evidence_cannot_satisfy_natural_transition_gate(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            refs = self.add_body_triplet(directory)
            claim = self.transition_claim("startup.login")
            claim["status"] = "PARITY_PROVEN"
            claim["evidence"] = refs
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "NATURAL_TRANSITION_PARITY requires natural native, web",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_body_and_exact_edge_proofs_are_counted_but_matrix_stays_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            body_refs = self.add_body_triplet(directory)
            self.set_flight_body_claim("mode_login", "PARITY_PROVEN", body_refs)
            refs = self.add_transition_triplet(
                str(Path(directory) / "transition"),
                edge="startup.login",
                source_scene=None,
                scene="mode_login",
                entry_path="startup",
            )
            claim = self.transition_claim("startup.login")
            claim["status"] = "PARITY_PROVEN"
            claim["evidence"] = refs
            report = scene_coverage.validate_ledger(self.write_ledger(directory))

        self.assertEqual(report.proven, 0)
        self.assertEqual(report.unproven, 22)
        self.assertEqual(report.unknown, 368)
        self.assertEqual(report.body_parity_proven, 1)
        self.assertEqual(report.body_parity_unproven, 21)
        self.assertEqual(report.natural_transition_parity_proven, 1)
        self.assertEqual(report.natural_transition_parity_unproven, 47)

    def test_transition_trace_explicitly_rejects_debug_entry(self):
        debug_path = ROOT / "tools/miel_vliegt/fixtures/debug_transition_fixture.ndjson"
        self.ledger["parity_evidence"] = {
            "debug": {
                "kind": "native-transition-trace",
                "path": str(debug_path.relative_to(ROOT)),
                "sha256": sha256(debug_path),
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError,
                "invalid natural transition trace",
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))

    def test_subsystem_checkpoints_cannot_be_promoted_to_inventory_authority(self):
        self.ledger["sources"]["flight_checkpoints"]["authority"] = "inventory"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                scene_coverage.SceneCoverageError, "must remain subsystem-only"
            ):
                scene_coverage.validate_ledger(self.write_ledger(directory))


if __name__ == "__main__":
    unittest.main()
