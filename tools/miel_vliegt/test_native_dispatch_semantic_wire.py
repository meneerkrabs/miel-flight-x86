import copy
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
import os
from pathlib import Path

from tools.miel_vliegt import scene_semantic_coverage as coverage
from tools.miel_vliegt import scene_semantic_evidence_batches as batches
from tools.miel_vliegt import udsp_semantic_oracle as oracle
from tools.miel_vliegt.native_dispatch_hook_contract import EXECUTABLE_SHA256
from tools.miel_vliegt.native_dispatch_hook_contract import producer_build_sha256
from tools.miel_vliegt.native_dispatch_hook_contract import SELECTORS
from tools.miel_vliegt import native_dispatch_semantic_wire as wire
from tools.miel_vliegt import native_dispatch_capture_job as capture_jobs


ROOT = Path(__file__).resolve().parents[2]
C_SOURCE = ROOT / "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.c"
HARNESS_SOURCE = ROOT / "tools/miel_vliegt/hangover/native_dispatch_semantic_wire_harness.c"
BINDING = {}
CAPABILITY_TARGETS = {}


def f32_bits(value):
    return f"0x{struct.unpack('<I', struct.pack('<f', value))[0]:08x}"


def capability(*, binding=None, **changes):
    binding = BINDING if binding is None else binding
    if binding["capturePlanJobId"] not in CAPABILITY_TARGETS:
        CAPABILITY_TARGETS.update({
            target["jobId"]: target
            for target in capture_jobs.compile_targets()["targets"]
        })
    target = CAPABILITY_TARGETS[binding["capturePlanJobId"]]
    hooks = wire.required_semantic_hooks(target)
    routes = wire.forwarded_route_hooks_for_target(target)
    value = {
        "schema": 1,
        "protocol": wire.WIRE_PROTOCOL,
        "record": "CAPABILITY",
        "executableSha256": EXECUTABLE_SHA256,
        "producerBuildSha256": producer_build_sha256(),
        "runtimeCapture": True,
        "routeForwarding": bool(routes),
        "engineThread": 37,
        "nativeProcessId": 4242,
        "captureSessionId": "mvds-" + "ab" * 16,
        "installedHookCount": len(hooks),
        "installedHookMask": wire.semantic_hook_mask(hooks),
        "installedHooks": list(hooks),
        "forwardedRouteHooks": list(routes),
        "capabilities": {
            name: (bool(routes) if name == "route" else True)
            for name in wire.DISPATCH_CAPABILITIES
        },
        **{field: binding[field] for field in wire.CAPABILITY_PROVENANCE_FIELDS},
        **{field: target[field] for field in wire.TARGET_CAPABILITY_FIELDS},
    }
    value.update(changes)
    return value


def receipt_for(record, sequence):
    expectation = record["expectation"]
    before = {
        "sequence": sequence - 1,
        "finalMissionState": 0,
        "grotte": {"refuelArmed": False, "refuelConsumed": False},
        "raymond": {"firstChallenge": True, "challengeResult": 0},
        "exhibition": {"outroRequested": False, "projectedMapXBits": f32_bits(0)},
    }
    if record["evidenceClass"] == "MISSION_DISPATCH":
        route = expectation["route"]
        event = {
            "trigger": "MISSION_ACTION",
            "missionKey": expectation["missionKey"],
            "missionPhase": expectation["missionPhase"],
            "nativeActionOrdinal": expectation["nativeActionOrdinal"],
        }
        result = {
            "schema": 1,
            "sequence": sequence,
            "trigger": "MISSION_ACTION",
            "action": {
                "GROUND": "PREPENDED", "BARN": "STARTED", "FLIGHT": "STARTED",
                "LOCATION_POLICY": "ARMED",
            }[route],
            "route": route,
            "locationId": None,
            "artifactKey": expectation["artifactKey"],
            "duplicate": False,
        }
        key = (
            f"{expectation['missionKey']}|{expectation['missionPhase']}|"
            f"{expectation['nativeActionOrdinal']}"
        )
        after = {
            "sequence": sequence,
            "appliedMissionActions": {
                key: {
                    name: value for name, value in result.items()
                    if name not in {"schema", "sequence", "trigger"}
                }
            },
        }
    else:
        selector = expectation["selector"]
        location = expectation["locationId"]
        if "FINAL_MISSION_STATE_EQ_3" in selector:
            before["finalMissionState"] = 3
        if "SUBSEQUENT_CHALLENGE" in selector:
            before["raymond"]["firstChallenge"] = False
        if "RESULT_EQ_2" in selector:
            before["raymond"]["challengeResult"] = 2
        elif "RESULT_NE_2" in selector:
            before["raymond"]["challengeResult"] = 1
        if "REFUEL_ARMED" in selector:
            before["grotte"] = {"refuelArmed": True, "refuelConsumed": False}
        if "OUTRO_REQUESTED" in selector:
            before["exhibition"]["outroRequested"] = True
        if "900_LTE_PROJECTED_X_LT_2200" in selector:
            before["exhibition"]["projectedMapXBits"] = f32_bits(900)
        elif "PROJECTED_X_GTE_2200" in selector:
            before["exhibition"]["projectedMapXBits"] = f32_bits(2200)
        elif "PROJECTED_X_LT_900" in selector:
            before["exhibition"]["projectedMapXBits"] = f32_bits(899.5)
        completion = selector.startswith(("ROOT_COMPLETE_", "CHALLENGE_ROOT_COMPLETE_"))
        event = (
            {"trigger": "DERIVED_STATE", "kind": "ROOT_COMPLETE", "route": "GROUND", "locationId": location}
            if completion else {"trigger": "LOCATION_ENTER", "locationId": location}
        )
        artifact = expectation["artifactKey"]
        result = {
            "schema": 1,
            "sequence": sequence,
            "trigger": event["trigger"],
            "action": "EXPECTED_ABSENCE" if artifact is None else "ADVANCED" if completion else "STARTED",
            "route": "GROUND",
            "locationId": location,
            "artifactKey": artifact,
        }
        after = {"sequence": sequence, "locations": {str(location): {"activeRoot": artifact}}}
    return {
        "schema": 1,
        "sequence": sequence,
        "semanticStatus": "UNPROVEN",
        "event": event,
        "before": before,
        "result": result,
        "after": after,
    }


def event_for(record, sequence):
    value = {
        "schema": 1,
        "protocol": wire.WIRE_PROTOCOL,
        "record": "EVENT",
        "executableSha256": EXECUTABLE_SHA256,
        "thread": 37,
        "nativeProcessId": 4242,
        "captureSessionId": "mvds-" + "ab" * 16,
        "evidenceClass": record["evidenceClass"],
        "receipt": receipt_for(record, sequence),
    }
    if record["evidenceClass"] == "LOCATION_POLICY":
        value["selector"] = record["expectation"]["selector"]
    return value


def line(value):
    return wire.WIRE_PREFIX + json.dumps(value, separators=(",", ":"), allow_nan=False)


class NativeDispatchSemanticWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = json.loads(coverage.DEFAULT_LEDGER.read_bytes())
        cls.records = [
            row for row in cls.ledger["records"]
            if row["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}
        ]
        cls.temp = tempfile.TemporaryDirectory(dir=ROOT / "tmp")
        cls.temp_root = Path(cls.temp.name)
        plan = batches.generate()
        cls.plan_path = cls.temp_root / "capture-plan.json"
        cls.plan_path.write_text(
            json.dumps(plan, sort_keys=True, separators=(",", ":")), encoding="ascii",
        )
        cls.plan_sha = hashlib.sha256(cls.plan_path.read_bytes()).hexdigest()
        cls.binary_path = cls.temp_root / "native-observer-hook.dll"
        cls.binary_path.write_bytes(b"MZ\x90\x00unit-native-dispatch-observer")
        cls.binary_sha = hashlib.sha256(cls.binary_path.read_bytes()).hexdigest()
        cls.jobs = {
            job["claimId"]: job
            for batch in plan["batches"] for job in batch["jobs"]
            if job["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}
        }
        compilation = capture_jobs.compile_targets(cls.plan_path)
        global CAPABILITY_TARGETS
        CAPABILITY_TARGETS = {
            target["jobId"]: target for target in compilation["targets"]
        }
        cls.bindings = {}
        for record in cls.records:
            job = cls.jobs[record["id"]]
            native_slice = next(
                row for row in job["captureSlices"] if row["producer"] == "NATIVE"
            )
            native_sha = native_slice["sliceId"].split(":", 1)[1]
            receipt = {
                "schema": 1,
                "protocol": wire.BUILD_RECEIPT_PROTOCOL,
                "capturePlanJobId": job["id"],
                "nativeSliceSha256": native_sha,
                "observerBinarySha256": cls.binary_sha,
                "producerBuildSha256": producer_build_sha256(),
            }
            receipt_path = cls.temp_root / f"build-{job['jobSha256']}.json"
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            cls.bindings[record["id"]] = {
                "capturePlanJobId": job["id"],
                "nativeSliceSha256": native_sha,
                "observerBinarySha256": cls.binary_sha,
                "observerBuildReceiptSha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                "capturePlanPath": cls.plan_path.relative_to(ROOT).as_posix(),
                "capturePlanSha256": cls.plan_sha,
                "observerBinaryPath": cls.binary_path.relative_to(ROOT).as_posix(),
                "observerBuildReceiptPath": receipt_path.relative_to(ROOT).as_posix(),
            }
        global BINDING
        BINDING = cls.bindings[cls.records[0]["id"]]

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def binding_for(self, record=None):
        return self.bindings[(record or self.records[0])["id"]]

    def parser(self, record=None):
        return wire.NativeDispatchWireParser(capture_binding=self.binding_for(record))

    def test_every_dispatch_expectation_round_trips_through_native_oracle(self):
        documents = []
        for record in self.records:
            parser = self.parser(record)
            parser.feed_line("observer noise")
            parser.feed_line(line(capability(binding=self.binding_for(record))))
            document = parser.feed_line(line(event_for(record, 1)))
            self.assertEqual(document["evidenceMode"], "UNTRUSTED_CANDIDATE")
            self.assertEqual(document["supportStatus"], "NATIVE_TRACE_REQUIRED")
            self.assertIs(document["parityEligible"], False)
            self.assertTrue(all(document["hookCapabilities"].values()))
            self.assertEqual(parser.finish(), [document])
            documents.append(document)
        self.assertEqual(len(documents), 155)
        self.assertEqual(
            {document["evidenceClass"] for document in documents},
            {"MISSION_DISPATCH", "LOCATION_POLICY"},
        )

    def test_fake_mz_and_self_authored_receipt_never_promote_to_production(self):
        record = self.records[0]
        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        document = parser.feed_line(line(event_for(record, 1)))
        self.assertEqual(self.binary_path.read_bytes()[:2], b"MZ")
        self.assertNotEqual(document["evidenceMode"], "PRODUCTION")
        self.assertNotEqual(document["supportStatus"], "SUPPORTED_HOOK_FACTS")
        self.assertEqual(document["supportStatus"], "NATIVE_TRACE_REQUIRED")
        self.assertIs(document["parityEligible"], False)
        with self.assertRaises(oracle.SemanticOracleError):
            oracle.normalize_native_trace(
                document, parser.executable,
                wire._expected_identity(parser.ledger, record),
                executable_source_bytes=parser.executable_bytes,
                expected_expectation=record["expectation"],
                expected_capture_provenance=document["captureProvenance"],
            )

    def test_play_outro_is_a_source_bound_policy_arm_without_route_callback(self):
        record = next(
            row for row in self.records
            if row["expectation"].get("opcode") == "PLAY_OUTRO"
        )
        event = event_for(record, 1)
        self.assertEqual(event["receipt"]["result"]["route"], "LOCATION_POLICY")
        self.assertEqual(event["receipt"]["result"]["action"], "ARMED")
        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        document = parser.feed_line(line(event))
        self.assertEqual(document["claimId"], record["id"])

    def test_raymond_root_complete_keeps_location_20(self):
        record = next(
            row for row in self.records
            if row["expectation"].get("selector") == "CHALLENGE_ROOT_COMPLETE_RESULT_EQ_2"
        )
        event = event_for(record, 1)
        self.assertEqual(event["receipt"]["event"]["locationId"], 20)
        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        self.assertEqual(parser.feed_line(line(event))["claimId"], record["id"])

    def test_raymond_first_challenge_uses_branch_observation_receipt(self):
        record = next(
            row for row in self.records
            if row["expectation"].get("selector") == "LOCATION_ENTER_FIRST_CHALLENGE"
        )
        event = event_for(record, 1)
        self.assertIs(event["receipt"]["before"]["raymond"]["firstChallenge"], True)
        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        self.assertEqual(parser.feed_line(line(event))["claimId"], record["id"])

    def test_no_runtime_capability_can_never_claim_support(self):
        parser = self.parser()
        with self.assertRaisesRegex(wire.NativeDispatchWireUnsupported, "CAPABILITY_NOT_OBSERVED"):
            parser.finish()
        with self.assertRaisesRegex(wire.NativeDispatchWireUnsupported, "CAPABILITY_NOT_OBSERVED"):
            self.parser().feed_line(line(event_for(self.records[0], 1)))

    def test_binary_build_binding_is_mandatory_and_exact(self):
        parser = wire.NativeDispatchWireParser()
        with self.assertRaisesRegex(
            wire.NativeDispatchWireUnsupported, "BINARY_BUILD_RECEIPT_REQUIRED",
        ):
            parser.feed_line(line(capability()))
        changed = capability(observerBinarySha256="4" * 64)
        with self.assertRaisesRegex(
            wire.NativeDispatchWireUnsupported, "CAPTURE_PROVENANCE_DIFFERS",
        ):
            self.parser().feed_line(line(changed))

    def test_binding_opens_and_hashes_plan_binary_and_build_receipt(self):
        for field in (
            "capturePlanSha256", "observerBinarySha256",
            "observerBuildReceiptSha256",
        ):
            binding = copy.deepcopy(BINDING)
            binding[field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(
                wire.NativeDispatchWireUnsupported,
            ):
                wire.NativeDispatchWireParser(capture_binding=binding)

        mutated_receipt = self.temp_root / "mutated-build-receipt.json"
        mutated = json.loads(
            (ROOT / BINDING["observerBuildReceiptPath"]).read_text(encoding="ascii")
        )
        mutated["observerBinarySha256"] = "f" * 64
        mutated_receipt.write_text(
            json.dumps(mutated, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        binding = copy.deepcopy(BINDING)
        binding["observerBuildReceiptPath"] = mutated_receipt.relative_to(ROOT).as_posix()
        binding["observerBuildReceiptSha256"] = hashlib.sha256(
            mutated_receipt.read_bytes()
        ).hexdigest()
        with self.assertRaisesRegex(
            wire.NativeDispatchWireUnsupported, "BUILD_RECEIPT_INVALID",
        ):
            wire.NativeDispatchWireParser(capture_binding=binding)

    def test_binding_paths_cannot_be_absolute_escape_or_symlink_escape(self):
        for path in (str(self.plan_path), "../capture-plan.json", "tmp\\capture-plan.json"):
            binding = copy.deepcopy(BINDING)
            binding["capturePlanPath"] = path
            with self.subTest(path=path), self.assertRaises(
                wire.NativeDispatchWireUnsupported,
            ):
                wire.NativeDispatchWireParser(capture_binding=binding)
        link = self.temp_root / "outside-link"
        try:
            link.symlink_to(Path("/tmp"), target_is_directory=True)
        except OSError:
            return
        binding = copy.deepcopy(BINDING)
        binding["capturePlanPath"] = (link / "capture-plan.json").relative_to(ROOT).as_posix()
        with self.assertRaisesRegex(
            wire.NativeDispatchWireUnsupported, "ESCAPES_REPOSITORY",
        ):
            wire.NativeDispatchWireParser(capture_binding=binding)

    def test_one_checked_job_accepts_exactly_one_matching_event(self):
        record = self.records[0]
        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        with self.assertRaisesRegex(
            wire.NativeDispatchWireUnsupported, "EXACTLY_ONE_JOB_EVENT_REQUIRED",
        ):
            parser.finish()

        other = self.records[1]
        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        with self.assertRaisesRegex(
            wire.NativeDispatchWireUnsupported, "EVENT_JOB_IDENTITY_DIFFERS",
        ):
            parser.feed_line(line(event_for(other, 1)))

        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        parser.feed_line(line(event_for(record, 1)))
        with self.assertRaisesRegex(wire.NativeDispatchWireError, "exactly one EVENT"):
            parser.feed_line(line(event_for(record, 2)))

    def test_capability_mutations_fail_closed(self):
        mutations = []
        short_hooks = capability()
        short_hooks["installedHooks"] = short_hooks["installedHooks"][:-1]
        mutations.append(short_hooks)
        short_routes = capability()
        short_routes["forwardedRouteHooks"] = short_routes["forwardedRouteHooks"][:-1]
        mutations.append(short_routes)
        mutations.append(capability(installedHookCount=23))
        mutations.append(capability(installedHookMask="0x00000000"))
        mutations.append(capability(runtimeCapture=False))
        mutations.append(capability(routeForwarding=False))
        false_fact = capability()
        false_fact["capabilities"]["selectorPredicates"] = False
        mutations.append(false_fact)
        mutations.append(capability(executableSha256="0" * 64))
        mutations.append(capability(producerBuildSha256="0" * 64))
        mutations.append(capability(nativeProcessId=0))
        mutations.append(capability(captureSessionId="runner-supplied"))
        for field in wire.TARGET_CAPABILITY_FIELDS:
            changed = capability()
            changed[field] = (
                "0" * 64 if field.endswith("Sha256") else
                "LOCATION_POLICY" if field == "evidenceClass" else "wrong"
            )
            mutations.append(changed)
        for value in mutations:
            with self.subTest(value=value):
                with self.assertRaises(wire.NativeDispatchWireUnsupported):
                    self.parser().feed_line(line(value))

    def test_every_compiled_target_has_a_bounded_exact_hook_closure(self):
        targets = capture_jobs.compile_targets(self.plan_path)["targets"]
        self.assertEqual(len(targets), 155)
        for target in targets:
            hooks = wire.required_semantic_hooks(target)
            mask = int(wire.semantic_hook_mask(hooks), 16)
            with self.subTest(job=target["jobId"]):
                self.assertEqual(mask.bit_count(), len(hooks))
                self.assertTrue(set(hooks).issubset(wire.HOOK_NAMES))
                if target["evidenceClass"] == "MISSION_DISPATCH":
                    self.assertIn("MISSION_ACTION_EXECUTE", hooks)
                    self.assertIn(target["trigger"]["actionHookFamily"], hooks)
                else:
                    self.assertNotIn("MISSION_ACTION_EXECUTE", hooks)
                    expected = {
                        name for name in SELECTORS[target["trigger"]["selector"]]["probes"]
                        if name in wire.HOOK_NAMES
                    }
                    self.assertEqual(set(hooks), expected)

    def test_c_capability_serializes_only_the_required_hook_set(self):
        source = C_SOURCE.read_text(encoding="utf-8")
        begin = source[
            source.index("BOOL mvds_begin_capture_window"):
            source.index("BOOL mvds_end_capture_window")
        ]
        self.assertIn("if (!mvds_hook_required(g_specs[index].id)) continue", begin)
        self.assertIn("installed_mask = mvds_required_hook_mask()", begin)
        self.assertIn("installedHookMask", begin)
        self.assertIn("(unsigned long)emitted", begin)
        self.assertIn('g_route_forwarding ? "true" : "false"', begin)
        self.assertIn('g_route_forwarding ?\n            "[\\\"SCENE_DISPATCH_GROUND', begin)

    def test_event_mutations_are_rejected_before_supported_document_escapes(self):
        base_record = next(row for row in self.records if row["evidenceClass"] == "MISSION_DISPATCH")
        route = event_for(base_record, 1)
        route["receipt"]["result"]["route"] = "FLIGHT"
        wrong_thread = event_for(base_record, 1)
        wrong_thread["thread"] = 38
        wrong_process = event_for(base_record, 1)
        wrong_process["nativeProcessId"] += 1
        wrong_session = event_for(base_record, 1)
        wrong_session["captureSessionId"] = "mvds-" + "cd" * 16
        sequence = event_for(base_record, 2)
        for value in (route, wrong_thread, wrong_process, wrong_session, sequence):
            with self.subTest(value=value):
                parser = self.parser(base_record)
                parser.feed_line(line(capability(binding=self.binding_for(base_record))))
                with self.assertRaises(wire.NativeDispatchWireError):
                    parser.feed_line(line(value))

    def test_oracle_rejects_forged_selector_predicate(self):
        record = next(
            row for row in self.records
            if row["expectation"].get("selector", "").endswith("PROJECTED_X_LT_900")
        )
        event = event_for(record, 1)
        event["receipt"]["before"]["exhibition"]["projectedMapXBits"] = f32_bits(2200)
        parser = self.parser(record)
        parser.feed_line(line(capability(binding=self.binding_for(record))))
        with self.assertRaisesRegex(oracle.SemanticOracleError, "selector predicates differ"):
            parser.feed_line(line(event))

    def test_duplicate_capability_is_rejected(self):
        parser = self.parser()
        parser.feed_line(line(capability()))
        with self.assertRaisesRegex(wire.NativeDispatchWireError, "exactly once"):
            parser.feed_line(line(capability()))

    def test_wire_rejects_non_ascii_nonfinite_and_noncanonical_f32(self):
        with self.assertRaisesRegex(wire.NativeDispatchWireError, "ASCII"):
            self.parser().feed_line(wire.WIRE_PREFIX + '{"schema":1,"x":"é"}')
        with self.assertRaisesRegex(wire.NativeDispatchWireError, "constant"):
            self.parser().feed_line(wire.WIRE_PREFIX + '{"schema":NaN}')
        record = next(
            row for row in self.records
            if row["expectation"].get("selector", "").endswith("PROJECTED_X_LT_900")
        )
        for bits in ("0X00000000", "0x7f800000", "0x7fc00000"):
            parser = self.parser(record)
            parser.feed_line(line(capability(binding=self.binding_for(record))))
            event = event_for(record, 1)
            event["receipt"]["before"]["exhibition"]["projectedMapXBits"] = bits
            with self.subTest(bits=bits), self.assertRaises(wire.NativeDispatchWireError):
                parser.feed_line(line(event))

    def test_c_producer_has_no_dependency_on_active_observer_source(self):
        source = C_SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("native_observer_hook.c", source)
        self.assertIn("0x00436789", source)
        self.assertIn("0x00443db4", source)
        self.assertIn("read_u8(completed.node + 0x18) == 1", source)
        self.assertIn('"EXHIBITION_LT_900"', source)
        self.assertIn('"EXHIBITION_LT_900_SELECTED"', source)
        self.assertIn("exhibition setter lacks matching location-14 entry interval", source)
        self.assertIn("completed.final_predicate_observed", source)
        self.assertIn("queued_root = read_u32(object + 0x8c8)", source)
        self.assertIn("default_root = read_u32(object + 0x8d0)", source)
        self.assertIn("active_root = read_u32(object + 0x8d4)", source)
        self.assertIn("mygghanget_absence_is_proven(&completed", source)
        self.assertIn("if (!copied || !bound)", source)
        self.assertIn("g_selector.root_without_provenance = TRUE", source)
        self.assertIn("g_capture_window_consumed ||", source)
        arm_body = source[source.index("BOOL mvds_arm("):source.index("BOOL mvds_bind_engine_thread(")]
        self.assertNotIn("g_capture_window_consumed = FALSE", arm_body)
        self.assertIn("static BOOL emitf", source)
        self.assertIn("semantic wire record was not durably accepted by host", source)
        self.assertIn("if (emitf(", source)
        self.assertIn("(BYTE *)0x004254d3", source)
        self.assertNotIn("(BYTE *)0x004254cf", source)
        self.assertIn("emit_location_event(selector,14", source)
        self.assertIn("projectedMapXBits", source)
        self.assertNotIn('"MYGGHANGET_STATE_SETTER"', source)

    def test_c_producer_derives_an_exact_hook_plan_from_the_capture_target(self):
        source = C_SOURCE.read_text(encoding="utf-8")
        plan = source[
            source.index("static DWORD capture_target_hook_mask"):
            source.index("BOOL mvds_configure_capture_target")
        ]
        self.assertIn("MVDS_EVIDENCE_MISSION_DISPATCH", plan)
        self.assertIn("MVDS_CAPTURE_HOOK_GENERIC_LOCATION_ENTER", plan)
        self.assertIn("MVDS_HOOK_ROOT_FACTORY", plan)
        for hook in (
            "MVDS_HOOK_GENERIC_ENTER",
            "MVDS_HOOK_GENERIC_FINAL_MISSION_PRESENT",
            "MVDS_HOOK_GENERIC_FINAL_TRUE",
        ):
            self.assertIn(hook, plan)
        self.assertIn("MVDS_CAPTURE_HOOK_GROTTE_STATE_SETTER", plan)
        self.assertIn("MVDS_CAPTURE_HOOK_RAYMOND_LOCATION_LOAD", plan)
        self.assertIn("MVDS_CAPTURE_HOOK_RAYMOND_STATE_SETTER", plan)
        self.assertIn("MVDS_CAPTURE_HOOK_EXHIBITION_STATE_SETTER", plan)
        self.assertIn("MVDS_CAPTURE_HOOK_MYGGHANGET_ENTER", plan)

        arm = source[
            source.index("BOOL mvds_arm("):
            source.index("BOOL mvds_bind_engine_thread(")
        ]
        self.assertIn("mvds_hook_required(g_specs[index].id)", arm)
        self.assertIn("required != (*g_specs[index].trampoline_slot != NULL)", arm)
        self.assertIn(
            "g_capture_target.evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH",
            arm,
        )
        self.assertIn("route_forwarding", arm)

    def test_c_emitter_harness_covers_every_selector_and_negatives(self):
        source = HARNESS_SOURCE.read_text(encoding="ascii")
        emitted = {
            selector for selector in SELECTORS
            if f'"{selector}"' in source
        }
        self.assertEqual(emitted, set(SELECTORS))
        self.assertIn('"wrong-object"', source)
        self.assertIn('"duplicate-route"', source)
        self.assertIn('"stale-source"', source)
        self.assertIn('"unreadable-source"', source)
        self.assertIn('"unterminated-source"', source)
        self.assertIn('"nested-source"', source)
        self.assertIn('"duplicate-action"', source)
        self.assertIn('"duplicate-outro-commit"', source)
        self.assertIn('"wrong-outro-object"', source)
        for family in (
            "generic", "grotte", "raymond-entry", "raymond-result", "exhibition",
        ):
            self.assertIn(f'"wrong-{family}-probe-object"', source)
        self.assertIn('"wrong-selector-kind"', source)
        self.assertIn('"unreadable-semantic-object"', source)
        self.assertIn('"capability-drop"', source)
        self.assertIn('"event-drop"', source)
        self.assertIn('"reuse-window"', source)
        for mode in ("hook-plan-exact", "hook-plan-missing", "hook-plan-extra"):
            self.assertIn(f'"{mode}"', source)
        for field in ("queued", "default", "active"):
            self.assertIn(f'"mygghanget-{field}-root"', source)
        self.assertIn('"mygghanget-new-root"', source)
        self.assertIn('"mygghanget-factory-provenance"', source)
        self.assertIn("g_root_factory_trampoline = harness_root_factory", source)
        self.assertIn('"mygghanget-observed-route"', source)
        for selector in SELECTORS:
            if selector.startswith("LOCATION_ENTER_OUTRO_"):
                marker = source.index(f'"{selector}"')
                self.assertIn(", 14,", source[marker:marker + 300])

    def test_compile_only_with_mingw_when_available(self):
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if compiler is None:
            self.skipTest("i686-w64-mingw32-gcc is unavailable on this host")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native_dispatch_semantic_hook.o"
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-c", str(C_SOURCE), "-o", str(output)],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertTrue(output.is_file())

    def test_c_emitter_harness_links_with_mingw_when_available(self):
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if compiler is None:
            self.skipTest("i686-w64-mingw32-gcc is unavailable on this host")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native_dispatch_semantic_wire_harness.exe"
            subprocess.run(
                [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-O2", "-I", str(C_SOURCE.parent), str(HARNESS_SOURCE),
                    "-o", str(output),
                ],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertTrue(output.is_file())
            self.assertEqual(output.read_bytes()[:2], b"MZ")

    def test_c_emitter_harness_executes_all_selectors_and_negatives_when_available(self):
        compiler = shutil.which("i686-w64-mingw32-gcc")
        wine = shutil.which("wine")
        if compiler is None or wine is None:
            self.skipTest("MinGW plus Wine are unavailable on this host")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "harness.exe"
            subprocess.run(
                [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-O2", "-I", str(C_SOURCE.parent), str(HARNESS_SOURCE),
                    "-o", str(output),
                ],
                check=True, cwd=ROOT, capture_output=True, text=True,
            )
            environment = {**os.environ, "WINEDEBUG": "-all", "WINEPREFIX": str(root / "prefix")}
            completed = subprocess.run(
                [wine, str(output)], check=True, capture_output=True, text=True,
                env=environment, timeout=60,
            )
            records = [
                json.loads(row[len(wire.WIRE_PREFIX):])
                for row in completed.stdout.splitlines()
                if row.startswith(wire.WIRE_PREFIX)
            ]
            events = [row for row in records if row.get("record") == "EVENT"]
            self.assertEqual({row.get("selector") for row in events}, set(SELECTORS))
            exhibition = [row for row in events if row.get("selector", "").startswith("LOCATION_ENTER_OUTRO_")]
            self.assertTrue(exhibition)
            self.assertTrue(all(row["receipt"]["result"]["locationId"] == 14 for row in exhibition))
            self.assertTrue(all(
                "projectedMapXBits" in row["receipt"]["before"]["exhibition"]
                for row in exhibition
            ))
            for mode in ("hook-plan-exact", "hook-plan-missing", "hook-plan-extra"):
                contract = subprocess.run(
                    [wine, str(output), mode], capture_output=True, text=True,
                    env=environment, timeout=30,
                )
                with self.subTest(mode=mode):
                    self.assertEqual(contract.returncode, 0)
            for mode in (
                "wrong-object", "duplicate-route", "stale-source",
                "unreadable-source", "unterminated-source", "nested-source",
                "duplicate-action", "duplicate-outro-commit", "wrong-outro-object",
                "wrong-generic-probe-object", "wrong-grotte-probe-object",
                "wrong-raymond-entry-probe-object", "wrong-raymond-result-probe-object",
                "wrong-exhibition-probe-object", "wrong-selector-kind",
                "unreadable-semantic-object",
                "capability-drop", "event-drop",
                "reuse-window", "mygghanget-queued-root",
                "mygghanget-default-root", "mygghanget-active-root",
                "mygghanget-new-root",
                "mygghanget-factory-provenance",
                "mygghanget-observed-route",
            ):
                negative = subprocess.run(
                    [wine, str(output), mode], capture_output=True, text=True,
                    env=environment, timeout=30,
                )
                with self.subTest(mode=mode):
                    self.assertEqual(negative.returncode, 0)
                    self.assertIn("FAIL ", negative.stderr)


if __name__ == "__main__":
    unittest.main()
