#!/usr/bin/env python3
import copy
import unittest

from tools.miel_vliegt import native_udsp_scene_commands as scene_commands


class NativeUdspSceneCommandTests(unittest.TestCase):
    def setUp(self):
        self.contract = scene_commands.load_contract()

    def validate_structure(self, contract):
        return scene_commands.validate_contract(contract, verify_artifacts=False)

    def test_inventory_maps_all_registered_ids_without_name_promotion(self):
        self.assertEqual([row["id"] for row in self.contract["commands"]], list(range(1, 16)))
        actual = {
            row["id"]: (
                row["name"], row["parser_behavior"], row["handler_case_address"]
            )
            for row in self.contract["commands"]
        }
        expected = {
            command_id: (values[0], values[3], values[5])
            for command_id, values in scene_commands.EXPECTED_COMMANDS.items()
        }
        self.assertEqual(actual, expected)
        self.assertTrue(all(not row["parity_eligible"] for row in self.contract["commands"]))
        self.assertTrue(all(row["runtime_equivalence"] == "UNPROVEN" for row in self.contract["commands"]))

    def test_parser_constructs_eleven_and_synthesizes_random_sound(self):
        constructed = {
            row["id"] for row in self.contract["commands"]
            if row["parser_behavior"] == "CONSTRUCT_NODE"
        }
        discarded = {
            row["id"] for row in self.contract["commands"]
            if row["parser_behavior"] in {
                "DISCARD_OPCODE", "DISCARD_DIRECT_TOKEN_SYNTHESIZED_BY_OPCODE_5"
            }
        }
        self.assertEqual(discarded, {2, 6, 7, 8})
        self.assertEqual(constructed, set(range(1, 16)) - discarded)
        self.assertEqual(len(constructed), 11)
        self.assertEqual(self.contract["policy"]["parser_synthesized_runtime_ids"], [6])
        lowering = self.contract["engine"]["sound_lowering"]
        self.assertEqual(lowering, scene_commands.EXPECTED_SOUND_LOWERING)
        self.assertEqual(lowering["zero_take"]["result"], "NO_COMMAND_NODE")
        self.assertEqual(lowering["one_take"]["runtime_opcode"], 5)
        self.assertEqual(lowering["multiple_takes"]["runtime_opcode"], 6)
        self.assertEqual(
            lowering["multiple_takes"]["take_order"],
            "ASCENDING_EXISTING_TAKES_IN_SCAN_RANGE_1_TO_99",
        )

    def test_pinned_dutch_def_observes_exact_ten_commands_and_arities(self):
        observed = {
            row["name"]: (
                row["def_observation"]["occurrences"],
                row["def_observation"]["arities"],
            )
            for row in self.contract["commands"]
            if row["def_observation"]["occurrences"]
        }
        self.assertEqual(observed, scene_commands.EXPECTED_DEF)
        self.assertEqual(sum(count for count, _ in observed.values()), 2320)

    def test_unobserved_registered_commands_remain_explicit(self):
        unobserved = {
            row["id"] for row in self.contract["commands"]
            if row["def_observation"]["evidence"] == "NOT_OBSERVED_IN_PINNED_DEF"
        }
        self.assertEqual(unobserved, {2, 4, 6, 7, 8})
        random_sound = self.contract["commands"][5]
        self.assertEqual(random_sound["id"], 6)
        self.assertEqual(
            random_sound["parser_behavior"],
            "DISCARD_DIRECT_TOKEN_SYNTHESIZED_BY_OPCODE_5",
        )
        self.assertEqual(random_sound["handler_case_address"], "0x0043ca3e")
        self.assertEqual(
            random_sound["runtime"]["parsed_def_reachability"],
            "REACHABLE_VIA_OPCODE_5_LOWERING",
        )

    def test_unknown_and_allocation_paths_are_fail_closed_and_recorded(self):
        self.assertEqual(self.contract["engine"]["error_paths"], {
            "unknown_name_id": 0,
            "unknown_or_out_of_range_parser_action": "DISCARD_AND_CONTINUE",
            "node_allocation_failure": "SKIP_NODE_AND_CONTINUE",
            "structural_or_file_failure_addresses": ["0x0043d63d", "0x0043d646"],
            "structural_or_file_failure_result": 0,
        })

    def test_parser_grammar_and_scheduler_are_exact_and_source_ordered(self):
        engine = self.contract["engine"]
        self.assertEqual(engine["parser_tokens"], scene_commands.EXPECTED_PARSER_TOKENS)
        self.assertEqual(engine["composite_layout"], scene_commands.EXPECTED_COMPOSITE_LAYOUT)
        self.assertEqual(engine["command_layout"], scene_commands.EXPECTED_COMMAND_LAYOUT)
        self.assertEqual(engine["scheduler"], scene_commands.EXPECTED_SCHEDULER)
        self.assertEqual(engine["scheduler"]["append_policy"], "TAIL_IN_SOURCE_ORDER")
        self.assertEqual(
            engine["scheduler"]["command_policy"],
            "AT_MOST_ONE_COMMAND_NODE_PER_COMPOSITE_UPDATE",
        )
        self.assertEqual(
            engine["scheduler"]["parallel_policy"],
            "UPDATE_ALL_CONSECUTIVE_TYPE_4_CHILDREN_BEFORE_ADVANCING",
        )

    def test_wait_random_formula_and_strict_timer_boundary_are_pinned(self):
        wait_random = self.contract["engine"]["modifier_execution"]["WAIT_RANDOM"]
        self.assertEqual(wait_random["duration_scale_address"], "0x0044ca40")
        self.assertEqual(wait_random["duration_scale_bits"], "0x3f19999a")
        self.assertEqual(wait_random["rand_normalizer_address"], "0x00454050")
        self.assertEqual(wait_random["rand_normalizer_bits"], "0x38000100")
        self.assertEqual(wait_random["lower_offset_address"], "0x0044c6c0")
        self.assertEqual(wait_random["lower_offset_bits"], "0x3e99999a")
        self.assertEqual(
            wait_random["formula"],
            "duration * (0.7 + 0.6 * rand_result / 32767)",
        )
        self.assertEqual(wait_random["initial_update"], "INITIALIZE_THEN_SUBTRACT_DELTA")
        self.assertEqual(wait_random["completion_predicate"], "timer < 0.0")
        runtime = self.contract["observed_runtime_contracts"]
        self.assertEqual(runtime["15"]["completion_predicate"], "timer < 0.0")
        for command_id in ("5", "10", "14"):
            self.assertEqual(runtime[command_id]["fallback_completion_predicate"], "timer < 0.0")

    def test_finishdirect_loop_and_native_completion_ports_remain_distinct(self):
        modifiers = self.contract["engine"]["modifier_execution"]
        self.assertEqual(
            modifiers["FINISHDIRECT"]["PLAY_CHARACTER_SCRIPT"],
            "START_THEN_COMPLETE_SAME_UPDATE",
        )
        self.assertEqual(
            modifiers["LOOP"]["parser_token"],
            "COMPOSITE_REPEAT_RESET_AFTER_COMPLETION",
        )
        self.assertEqual(
            modifiers["LOOP"]["animation_modifier"],
            "START_WITH_LOOP_FLAG_WITHOUT_COMPLETION_CALLBACK",
        )
        runtime = self.contract["observed_runtime_contracts"]
        self.assertEqual(set(runtime), {"1", "3", "5", "6", "9", "10", "11", "12", "13", "14", "15"})
        self.assertEqual(runtime["6"]["index_formula"], "rand_result % node+0x48")
        self.assertEqual(runtime["3"]["callback_predicate"], "event == 1 AND opcode == 3")
        self.assertEqual(runtime["13"]["timer_fallback"], "NONE")
        self.assertEqual(
            runtime["13"]["completion_predicate"],
            "service == null OR poll_result == false",
        )

    def test_external_service_static_contracts_are_exact_but_not_promoted(self):
        runtime = self.contract["observed_runtime_contracts"]
        judge = runtime["10"]
        self.assertEqual(judge["half_policy"], "EXACT_0.5_ROUNDS_DOWN")
        self.assertEqual(judge["media_identity"], {
            "owner": "domaren", "bank": "f", "take": 1,
            "clip_formula": "score + 3", "clip_domain": [4, 5, 6, 7, 8],
        })

        award = runtime["11"]
        self.assertEqual(award["valid_index_domain"], "int32 0..5")
        self.assertEqual(award["award_clip_table"], [451, 452, 453, 456, 454, 455])
        self.assertEqual(award["award_asset_table"], [
            "water", "snow", "rejser", "cirkus", "mecci", "map",
        ])
        self.assertEqual(award["media_identity"], {
            "owner": "mulle", "bank": "y", "take": 1,
            "clip": "award_clip_table[index]",
        })
        self.assertIn("save chunk id DIPL", award["bank_pointer_guard"])

        sound = runtime["12"]
        self.assertEqual(sound["take_policy"], "BUILDER_CLAMPS_TO_TAKE_1_WITHOUT_RNG")
        self.assertEqual(sound["rng_draws"], 0)
        self.assertEqual(
            sound["start_policy"],
            "REUSE_PLAYING_CASE_INSENSITIVE_EQUAL_PATH_ELSE_RELEASE_AND_PREEMPT",
        )

        radio = runtime["13"]
        self.assertEqual(radio["queue_policy"], "FIFO_NO_DEDUPLICATION")
        self.assertEqual(
            radio["queue_gap"],
            "float32(elapsed-last_primary_end) > float32(2.0)",
        )
        self.assertEqual(radio["requested_rng_draws"], 0)
        self.assertEqual(radio["path_equality"], {
            "comparator": "MSVCRT _stricmp",
            "iat_address": "0x0044c480",
            "equal_result": 0,
        })
        self.assertEqual(radio["service_constructor"], {
            "address": "0x0041f010",
            "alert_eligible": "this+0x4c=1",
            "alert_pending": "this+0x4d=0",
            "alert_active": "this+0x4e=0",
        })
        self.assertEqual(
            radio["enqueue_order"],
            "ARM_ALERT_PENDING_IF_ELIGIBLE_BEFORE_REQUEST_NODE_ALLOCATION",
        )
        self.assertEqual(radio["alert_storage"], "SEPARATE_BOOLEAN_STATE_NOT_A_FIFO_NODE")
        self.assertEqual(
            radio["alert_reset_policy"],
            "ONLY_A_NEW_SERVICE_INSTANCE_RESETS_ELIGIBILITY",
        )
        self.assertEqual(
            radio["clock_policy"]["finish_detection"],
            "RETURN_FROM_TICK_AFTER_STAMP_WITHOUT_STARTING_NEXT_ITEM",
        )
        self.assertEqual(
            radio["clock_policy"]["failed_primary_start"],
            "POP_REQUEST_AND_RESTART_STRICT_GAP_FROM_PRE_ATTEMPT_STAMP",
        )
        self.assertEqual(radio["first_alert"]["rng_draws"], 2)
        self.assertEqual(radio["first_alert"]["ordering"], "BEFORE_QUEUED_REQUEST")
        self.assertEqual(
            radio["first_alert"]["tick_sequence"],
            "RAND_CLIP_THEN_COUNT_TAKES_THEN_UNCONDITIONAL_RAND_TAKE_THEN_SIGNED_IDIV",
        )
        self.assertEqual(
            radio["first_alert"]["zero_take_count"],
            "CPU_SIGNED_DIVIDE_ERROR_AFTER_SECOND_RNG_DRAW",
        )

        for command_id in (10, 11, 12, 13):
            command = self.contract["commands"][command_id - 1]
            self.assertEqual(command["runtime_equivalence"], "UNPROVEN")
            self.assertFalse(command["parity_eligible"])

    def test_judge_score_presentation_and_failure_chronology_are_static_exact(self):
        judge = self.contract["observed_runtime_contracts"]["10"]
        self.assertEqual(judge["score_presentation"], {
            "render_function": "0x004440c0",
            "render_span_sha256": "5eaf0f7be981d8e1d35db3ebb7d0e4cf0660f657fa208231df094f52ccc2a90b",
            "font_load_function": "0x00443770",
            "font_load_span_sha256": "b9b13d8a118e3a8f6ad5c7e8647dc7c06626428961c0043ef27bc1aeceb86eab",
            "font_path": "Data\\Graphics\\Fonts\\fontmulle_small.fnt",
            "font_field": "mode+0x48b0",
            "render_gate": "mode_state == 6 AND active_script == judge_script AND score > 0",
            "text_conversion": "MSVCRT _itoa(score, buffer, 10)",
            "print": {
                "x": 396.0, "x_bits": "0x43c60000",
                "y": 233.0, "y_bits": "0x43690000",
            },
            "parity_eligible": False,
        })
        self.assertEqual(judge["media_failure_chronology"], {
            "handler_owner_function": "0x0043c580",
            "handler_owner_span_sha256": "965eaeeaadee18393019afbbea3b4ce5892cf843beb9c3960ba0d4ab9117fea5",
            "score_write": "BEFORE_MEDIA_CONTEXT_AND_LOAD_CHECKS",
            "fallback_cases": [
                "MISSING_MEDIA_CONTEXT",
                "MEDIA_CREATE_RETURNS_NULL",
                "PLAYBACK_INSTANCE_RETURNS_NULL",
            ],
            "fallback_duration": 5.0,
            "fallback_duration_bits": "0x40a00000",
            "fallback_tick": "SUBTRACT_DELTA_THEN_COMPLETE_ONLY_WHEN_TIMER_LT_ZERO",
            "score_clear": "ONLY_ON_MEDIA_INACTIVE_OR_FALLBACK_TIMER_LT_ZERO",
            "runtime_differential": "BLOCKED",
            "parity_eligible": False,
        })

    def test_diploma_ui_timing_input_boundary_and_resource_close_are_static_exact(self):
        diploma = self.contract["observed_runtime_contracts"]["11"]
        ui = diploma["manager_ui_contract"]
        self.assertEqual(ui["activation"], {
            "function": "0x0041c300",
            "function_span_sha256": "43786af43e8ca369dfec8acf2fbf6c8ec4c68d4987dfb8ee7beb7e1399918770",
            "writes": [
                "manager+0x10d0=-1", "manager+0x10c8=0",
                "manager+0x10f0=0", "manager+0x2c=0", "manager+0x15=1",
            ],
        })
        self.assertEqual(ui["input"], {
            "function": "0x0041c3a0",
            "function_span_sha256": "2c487d4787c7f5759ede70735c6546974671a0b786c7a126e4422270d3b37972",
            "raw_event_gate": "event+0x0c == 5 AND event+0x10 == 0",
            "dismiss_outside_inclusive_bounds": {
                "x": [140.0, 500.0], "y": [167.0, 427.0],
            },
            "event_semantics": "UNPROVEN",
            "parity_eligible": False,
        })
        self.assertEqual(ui["update"], {
            "entry": "0x0041c810",
            "owner_function": "0x0041c3a0",
            "owner_span_sha256": "2c487d4787c7f5759ede70735c6546974671a0b786c7a126e4422270d3b37972",
            "elapsed_update": "manager+0x10ec=float32(manager+0x10ec+delta)",
            "close_predicate": "manager+0x2c == 1 AND elapsed > float32(0.25) AND manager+0x10f0 < 0",
            "threshold": 0.25,
            "threshold_bits": "0x3e800000",
        })
        self.assertEqual(ui["resource_close"], {
            "function": "0x0041c340",
            "function_span_sha256": "43786af43e8ca369dfec8acf2fbf6c8ec4c68d4987dfb8ee7beb7e1399918770",
            "order": [
                "STOP_MANAGER_MEDIA_IF_PRESENT(manager+0x10f4)",
                "RELEASE_AWARD_MEDIA_IF_PRESENT(manager+0x10f8,manager+0x10fc)",
                "CLEAR_AWARD_MEDIA_FIELDS",
                "CLEAR_ACTIVE_BYTE(manager+0x15)",
                "RUN_OWNER_CLOSE_HOOKS",
            ],
            "manager_media_playback_lifecycle": "UNPROVEN",
            "parity_eligible": False,
        })
        self.assertEqual(
            diploma["ui_lifecycle"],
            "award mode closes only after elapsed > float32(0.25) and dismiss phase becomes negative",
        )

    def test_external_service_semantic_mutations_fail_closed(self):
        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["10"]["half_policy"] = (
            "EXACT_0.5_ROUNDS_UP"
        )
        with self.assertRaisesRegex(ValueError, "JUDGE_AIRPLANE score"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["11"]["award_clip_table"] = list(
            range(451, 457)
        )
        with self.assertRaisesRegex(ValueError, "AWARD_DIPLOMA clip table"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["11"]["bank_pointer_guard"] = (
            "DIPL is the media bank"
        )
        with self.assertRaisesRegex(ValueError, "AWARD_DIPLOMA clip table"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["10"]["media_identity"] = {
            "actor": "domaren", "bank": "f", "variant": 1,
            "take_formula": "score + 3",
        }
        with self.assertRaisesRegex(ValueError, "JUDGE_AIRPLANE score"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["10"]["score_presentation"]["print"]["x"] = 395.0
        with self.assertRaisesRegex(ValueError, "JUDGE_AIRPLANE presentation"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["10"]["media_failure_chronology"][
            "fallback_tick"
        ] = "COMPLETE_WHEN_TIMER_LTE_ZERO"
        with self.assertRaisesRegex(ValueError, "JUDGE_AIRPLANE presentation"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["11"]["media_identity"] = {
            "owner": "mulle", "bank": "y", "variant": 1, "take": 456,
        }
        with self.assertRaisesRegex(ValueError, "AWARD_DIPLOMA clip table"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["11"]["manager_ui_contract"]["update"][
            "close_predicate"
        ] = "manager+0x2c == 1 AND elapsed >= float32(0.25)"
        with self.assertRaisesRegex(ValueError, "AWARD_DIPLOMA UI lifecycle"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["11"]["manager_ui_contract"][
            "resource_close"
        ]["order"].reverse()
        with self.assertRaisesRegex(ValueError, "AWARD_DIPLOMA UI lifecycle"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["11"]["manager_media_identity"] = {
            "owner": "doris", "bank": "x", "take": 38, "clip": 1,
        }
        with self.assertRaisesRegex(ValueError, "AWARD_DIPLOMA clip table"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["11"]["manager_media_load"][
            "playback_lifecycle"
        ] = "PROVEN"
        broken["observed_runtime_contracts"]["11"]["manager_media_load"][
            "parity_eligible"
        ] = True
        with self.assertRaisesRegex(ValueError, "AWARD_DIPLOMA clip table"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["12"]["rng_draws"] = 1
        with self.assertRaisesRegex(ValueError, "PLAY_SOUND take-1"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["13"]["queue_gap"] = (
            "float32(elapsed-last_primary_end) >= float32(2.0)"
        )
        with self.assertRaisesRegex(ValueError, "PLAY_RADIO queue"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["13"]["enqueue_order"] = (
            "ALLOCATE_REQUEST_NODE_THEN_ARM_ALERT"
        )
        with self.assertRaisesRegex(ValueError, "PLAY_RADIO service lifecycle"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["13"]["scheduler_order"][
            "scene_relation"
        ] = "BEFORE_ACTIVE_MODE"
        with self.assertRaisesRegex(ValueError, "PLAY_RADIO scheduler order"):
            self.validate_structure(broken)

    def test_pinned_dutch_service_media_inventory_is_exact_and_fail_closed(self):
        expected = {
            "data/Sound/Voices/x/DD010038X.WAV": "11a0755765a780c8aa1da71b81d04e66d43088d06c06e2e06f81f473d81ad9c8",
            "data/Sound/Voices/f/JU010004F.WAV": "47b2ea941dd18c0e4d8d42b7fb3faed9632d5df0b81b51b741d647b9f005a833",
            "data/Sound/Voices/f/JU010005F.WAV": "84688070af12f833449fb9ee11d8b950f31151370c3d77fed0d750764185220f",
            "data/Sound/Voices/f/JU010006F.WAV": "5909a8d2fdc5d7d5540b49c0dfe46d98787c8e58b99a39789fd734c1be0f9840",
            "data/Sound/Voices/f/JU010007F.WAV": "8d2f0a3ca384b53b58fa0edf46720c814fdce61e1a5c05a209d6bea8fd7e7148",
            "data/Sound/Voices/f/JU010008F.WAV": "31151b13453401f4b1161e5c0e6b21d7c8c8749fcc5c462b923be4132b5534ba",
            "data/Sound/Voices/y/MM010451Y.WAV": "9356afbbceda4fd45af1c136eb5b729a272d29cc3f8de2f0c2760a854ae50470",
            "data/Sound/Voices/y/MM010452Y.WAV": "5d1b7cfa6f48579d4458256e327db463ef040733b8972f387dc476ff88f2f040",
            "data/Sound/Voices/y/MM010453Y.WAV": "5ef55425e4a776844277b6a153cd8f88ca429dfbc1a90f61d6357b6a5e1c01f3",
            "data/Sound/Voices/y/MM010456Y.WAV": "e2b7d2a9c31a55975fbfad1ade4862667a3a9267792ab836c5eec349a1409a54",
            "data/Sound/Voices/y/MM010454Y.WAV": "b634fa9c061fa2bc305c0b8816dff5cc31daeeb83a4ae88987d4e02210153212",
            "data/Sound/Voices/y/MM010455Y.WAV": "dcca99200451628c671fe1cd09987e02ea33103f7c0f541a4a0a117093fa111f",
            "data/Sound/Voices/b/MM010043B.WAV": "a6885143feb328a3757f79c55f6f3ca4a8216e2f09a636c14d7b8687ba20cd47",
            "data/Sound/Voices/b/MM020043B.WAV": "4c8c8cac84215aff11a2047422ee92019c37a9222f3ef941aa86978804f7eaa5",
            "data/Sound/Voices/b/MM010044B.WAV": "09ee2d6053362b349700ecacac35ade4d8ed2846f07e70b4dcef81d94c2eb98b",
            "data/Sound/Voices/b/MM020044B.WAV": "2adbd30fa6a5cc176e0957121ec867024b3a435127ad961267e0f47e371fd2fa",
        }
        self.assertEqual(scene_commands.NL_SERVICE_MEDIA_SHA256, expected)
        self.assertEqual(
            scene_commands.validate_nl_service_media_inventory(
                "7d1fe9a6adcfee26fd91fbf98d78110e5df42f5ddce52568d27548983decf676",
                expected,
            ),
            expected,
        )
        with self.assertRaisesRegex(ValueError, "sounds.up hash"):
            scene_commands.validate_nl_service_media_inventory("0" * 64, expected)
        broken = dict(expected)
        broken["data/Sound/Voices/f/JU010004F.WAV"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "media inventory"):
            scene_commands.validate_nl_service_media_inventory(
                scene_commands.NL_SOUNDS_ARCHIVE_SHA256, broken
            )

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["13"]["clock_policy"][
            "failed_primary_start"
        ] = "KEEP_LAST_END_STAMP"
        with self.assertRaisesRegex(ValueError, "PLAY_RADIO clock"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["13"]["first_alert"][
            "zero_take_count"
        ] = "GRACEFUL_FAIL_CLOSED"
        with self.assertRaisesRegex(ValueError, "PLAY_RADIO alert ordering"):
            self.validate_structure(broken)

    def test_proven_semantics_cannot_be_softened_by_editing_json(self):
        broken = copy.deepcopy(self.contract)
        broken["engine"]["modifier_execution"]["WAIT_RANDOM"]["completion_predicate"] = (
            "timer <= 0.0"
        )
        with self.assertRaisesRegex(ValueError, "WAIT_RANDOM completion boundary"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["observed_runtime_contracts"]["13"]["timer_fallback"] = "DECREMENT_5_SECONDS"
        with self.assertRaisesRegex(ValueError, "nonexistent timer fallback"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["engine"]["scheduler"]["command_policy"] = "DRAIN_ALL_COMMANDS"
        with self.assertRaisesRegex(ValueError, "scheduler drifted"):
            self.validate_structure(broken)

    def test_command_cannot_be_promoted_by_editing_json(self):
        broken = copy.deepcopy(self.contract)
        broken["commands"][0]["runtime_equivalence"] = "EQUIVALENT"
        broken["commands"][0]["parity_eligible"] = True
        with self.assertRaisesRegex(ValueError, "escaped fail-closed parity"):
            self.validate_structure(broken)

    def test_claim_and_schema_extensions_cannot_self_promote(self):
        broken = copy.deepcopy(self.contract)
        broken["claim_limit"] = "runtime equivalence proven"
        with self.assertRaisesRegex(ValueError, "claim limit drifted"):
            self.validate_structure(broken)

        for path in (("runtime_parity",), ("source", "runtime_parity"),
                     ("engine", "runtime_parity")):
            broken = copy.deepcopy(self.contract)
            target = broken
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = "PROVEN"
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "fields drifted"):
                    self.validate_structure(broken)

    def test_parser_behavior_or_reachability_drift_fails(self):
        broken = copy.deepcopy(self.contract)
        broken["commands"][5]["parser_behavior"] = "CONSTRUCT_NODE"
        broken["commands"][5]["runtime"]["parsed_def_reachability"] = "REACHABLE_IF_PARSED"
        with self.assertRaisesRegex(ValueError, "mapping drifted"):
            self.validate_structure(broken)

        broken = copy.deepcopy(self.contract)
        broken["commands"][1]["runtime"]["parsed_def_reachability"] = "REACHABLE_IF_PARSED"
        with self.assertRaisesRegex(ValueError, "marked reachable"):
            self.validate_structure(broken)

    def test_reviewed_runtime_summary_cannot_drift_unnoticed(self):
        broken = copy.deepcopy(self.contract)
        broken["commands"][14]["runtime"]["completion"] = "Complete immediately."
        with self.assertRaisesRegex(ValueError, "runtime summary drifted"):
            self.validate_structure(broken)

    def test_artifact_hash_drift_fails(self):
        broken = copy.deepcopy(self.contract)
        broken["source"]["artifacts"]["uds_scene_scripts"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned artifact drifted"):
            scene_commands.validate_contract(broken)


if __name__ == "__main__":
    unittest.main()
