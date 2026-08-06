#!/usr/bin/env python3
"""Validate the fail-closed native UDSP scene-command control-flow map.

The checked-in contract contains no executable bytes.  It binds reviewed
addresses to the pinned native analysis artifacts and independently checks the
commands and arities harvested from the proprietary archive.  Static handler
discovery is deliberately not treated as runtime-equivalence evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.extract_udsp import UdspArchive
except ModuleNotFoundError:  # Direct script execution.
    from extract_udsp import UdspArchive


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = ROOT / "content/miel_vliegt/native_udsp_scene_commands.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ADDRESS = re.compile(r"^0x[0-9a-f]{8}$")

TOP_LEVEL_FIELDS = {
    "schema", "claim", "claim_limit", "source", "policy", "engine",
    "observed_runtime_contracts", "commands", "unresolved",
}
SOURCE_FIELDS = {"executable_sha256", "artifacts"}
ENGINE_FIELDS = {
    "addresses", "registration_order", "modifiers", "node_layout",
    "error_paths", "parser_tokens", "composite_layout", "command_layout",
    "scheduler", "sound_lowering", "modifier_execution",
}
CLAIM_LIMIT = (
    "All 15 native name-to-ID registrations, parser cases and runtime dispatch "
    "cases are mapped for the pinned executable. DEF arities are corpus "
    "observations, not inferred native signatures. Static control flow is not "
    "runtime equivalence."
)

EXECUTABLE_SHA256 = "a84550b46612dc326177a67a84d6fd1e35aae3dc74361254611d1b03eda559a2"
NL_SOUNDS_ARCHIVE_SHA256 = "7d1fe9a6adcfee26fd91fbf98d78110e5df42f5ddce52568d27548983decf676"
NL_SERVICE_MEDIA_SHA256 = {
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
REQUIRED_ARTIFACTS = {
    "native_function_index",
    "native_code_map",
    "uds_scene_scripts",
    "uds_scene_harvester",
    "uds_script_parser",
}

EXPECTED_ENGINE = {
    "command_parser": "0x0043cd70",
    "command_normalizer": "0x0043d900",
    "command_name_mapper": "0x0043ddb0",
    "modifier_name_mapper": "0x0043d980",
    "parser_token_mapper": "0x0043d6d0",
    "node_constructor": "0x0043c240",
    "command_reset": "0x0043c480",
    "composite_constructor": "0x0043c490",
    "composite_reset": "0x0043cc60",
    "node_update_dispatcher": "0x0043c580",
    "script_start": "0x0043cd60",
    "script_update": "0x0043cd20",
    "animation_completion_callback": "0x0043c460",
    "parser_dispatch_table": "0x0043d694",
    "payload_copy_table": "0x0043c328",
    "runtime_dispatch_table": "0x0043cbfc",
    "complete_case": "0x0043cb7b",
    "keep_active_case": "0x0043cb7f",
}

# id: (name, string, parser case, parser behavior, payload slots, runtime case)
EXPECTED_COMMANDS = {
    1: ("PLAY_CHARACTER_SCRIPT", "0x0045cd00", "0x0043d478", "CONSTRUCT_NODE", 2, "0x0043c680"),
    2: ("STOP_CHARACTER_SCRIPT", "0x0045cc1c", "0x0043d0e4", "DISCARD_OPCODE", 0, "0x0043cb7f"),
    3: ("PLAY_CHARACTER_ANIMATION", "0x0045cce4", "0x0043d02f", "CONSTRUCT_NODE", 5, "0x0043c718"),
    4: ("STOP_CHARACTER_ANIMATION", "0x0045cc4c", "0x0043cf81", "CONSTRUCT_NODE", 2, "0x0043c856"),
    5: ("PLAY_CHARACTER_SOUND", "0x0045cc98", "0x0043d1f1", "CONSTRUCT_NODE", 2, "0x0043c880"),
    6: ("PLAY_CHARACTER_SOUND_RANDOM", "0x0045cc68", "0x0043d0e4", "DISCARD_DIRECT_TOKEN_SYNTHESIZED_BY_OPCODE_5", 3, "0x0043ca3e"),
    7: ("STOP_CHARACTER_SOUND", "0x0045cc34", "0x0043d0e4", "DISCARD_OPCODE", 0, "0x0043cb7f"),
    8: ("MOVE_CHARACTER", "0x0045cc0c", "0x0043d0e4", "DISCARD_OPCODE", 0, "0x0043cb7f"),
    9: ("POSITION_CHARACTER", "0x0045ccd0", "0x0043ced1", "CONSTRUCT_NODE", 2, "0x0043c6cd"),
    10: ("JUDGE_AIRPLANE", "0x0045ccc0", "0x0043cfce", "CONSTRUCT_NODE", 0, "0x0043cac1"),
    11: ("AWARD_DIPLOMA", "0x0045ccb0", "0x0043cff6", "CONSTRUCT_NODE", 1, "0x0043c632"),
    12: ("PLAY_SOUND", "0x0045c860", "0x0043d340", "CONSTRUCT_NODE", 2, "0x0043c974"),
    13: ("PLAY_RADIO", "0x0045c840", "0x0043d3d3", "CONSTRUCT_NODE", 2, "0x0043c9d6"),
    14: ("PLAY_MULLEBARNSOUND", "0x0045cc84", "0x0043d0fe", "CONSTRUCT_NODE", 3, "0x0043c8fa"),
    15: ("WAIT", "0x0045cba4", "0x0043d524", "CONSTRUCT_NODE", 1, "0x0043c5c9"),
}

EXPECTED_REGISTRATION_ORDER = [1, 3, 9, 15, 10, 11, 12, 13, 5, 14, 6, 4, 7, 2, 8]
EXPECTED_MODIFIERS = {
    "NONE": 0,
    "LOOP": 1,
    "LOOP_TIMES": 2,
    "LOOP_RANDOMTIMES": 3,
    "WAIT_RANDOM": 4,
    "WAIT": 5,
    "FINISHDIRECT": 6,
}
EXPECTED_NODE_LAYOUT = {
    "complete": "0x08",
    "next": "0x10",
    "opcode": "0x1c",
    "context": "0x20",
    "modifier": "0x24",
    "timer": "0x28",
    "started": "0x50",
}
EXPECTED_PARSER_TOKENS = {
    "CLOSE_BRACE": {"id": 1, "string_address": "0x0045608c", "case_address": "0x0043d5b0", "action": "ASCEND_TO_PARENT"},
    "CHARACTER_SCRIPT": {"id": 2, "string_address": "0x0045cb64", "case_address": "0x0043d61b", "action": "ROOT_HEADER_ONLY"},
    "LOCATION_SCRIPT": {"id": 3, "string_address": "0x0045cb54", "case_address": "0x0043d61b", "action": "ROOT_HEADER_ONLY"},
    "NODE": {"id": 4, "string_address": "0x0045cb4c", "case_address": "0x0043d569", "action": "APPEND_COMPOSITE_AND_DESCEND"},
    "LOOP": {"id": 5, "string_address": "0x0045cb3c", "case_address": "0x0043d5fe", "action": "SET_CURRENT_COMPOSITE_REPEAT"},
    "COMM": {"id": 6, "string_address": "0x0045cb44", "case_address": "0x0043ceb3", "action": "PARSE_AND_APPEND_COMMAND"},
    "NAME": {"id": 7, "string_address": "0x00456084", "case_address": "0x0043d5ca", "action": "REPLACE_SCRIPT_NAME"},
}
EXPECTED_COMPOSITE_LAYOUT = {
    "type": "0x04", "repeat": "0x18", "first_child": "0x1c",
    "last_child": "0x20", "current_child": "0x24",
}
EXPECTED_COMMAND_LAYOUT = {
    "type": "0x06", "callback_vtable": "0x18", "payload_0": "0x3c",
    "payload_1": "0x40", "payload_2": "0x44", "payload_3": "0x48",
    "payload_4": "0x4c",
}
EXPECTED_SCHEDULER = {
    "append_policy": "TAIL_IN_SOURCE_ORDER",
    "reset_policy": "RESET_ALL_DESCENDANTS_THEN_CURRENT_TO_FIRST_CHILD",
    "command_policy": "AT_MOST_ONE_COMMAND_NODE_PER_COMPOSITE_UPDATE",
    "parallel_policy": "UPDATE_ALL_CONSECUTIVE_TYPE_4_CHILDREN_BEFORE_ADVANCING",
    "incomplete_policy": "CLEAR_PARENT_COMPLETE_AND_KEEP_CURRENT_CHILD",
    "complete_command_policy": "ADVANCE_CURRENT_TO_NEXT_SIBLING",
    "complete_composite_policy": "ADVANCE_ONLY_WHEN_ALL_CONSECUTIVE_TYPE_4_CHILDREN_COMPLETE",
    "repeat_policy": "CLEAR_PARENT_COMPLETE_AND_RESET_COMPLETED_REPEAT_CHILD",
    "script_stop_policy": "CLEAR_RUNNING_WHEN_ROOT_COMPLETES_WITHOUT_REPEAT",
}
EXPECTED_SOUND_LOWERING = {
    "source_opcode": 5,
    "parser_case_address": "0x0043d1f1",
    "take_scan_address": "0x0041b240",
    "count_decision_address": "0x0043d24c",
    "zero_take": {"result": "NO_COMMAND_NODE", "branch_address": "0x0043d469"},
    "one_take": {
        "runtime_opcode": 5,
        "lowering_span": ["0x0043d251", "0x0043d2a7"],
    },
    "multiple_takes": {
        "runtime_opcode": 6,
        "lowering_span": ["0x0043d2ac", "0x0043d33b"],
        "array_fill_span": ["0x0043d2ce", "0x0043d2f5"],
        "take_order": "ASCENDING_EXISTING_TAKES_IN_SCAN_RANGE_1_TO_99",
    },
    "direct_opcode_6_token": "DISCARD_AND_CONTINUE",
}
EXPECTED_MODIFIER_OBSERVATIONS = {
    "PLAY_CHARACTER_ANIMATION": {"LOOP": 61, "LOOP_RANDOMTIMES": 1, "LOOP_TIMES": 1, "WAIT": 308},
    "PLAY_CHARACTER_SCRIPT": {"FINISHDIRECT": 778, "WAIT": 150},
    "PLAY_CHARACTER_SOUND": {"WAIT": 310},
    "PLAY_MULLEBARNSOUND": {"WAIT": 3},
    "PLAY_RADIO": {"WAIT": 4},
    "PLAY_SOUND": {"WAIT": 7},
    "WAIT": {"WAIT": 161, "WAIT_RANDOM": 92},
}
# Canonical hash of engine.modifier_execution plus observed_runtime_contracts.
# The validator also checks high-risk predicates explicitly below so this is
# not an opaque substitute for semantic validation.
EXPECTED_PROVEN_SEMANTICS_SHA256 = "cb774d77882433f720bce818cb1f41acae7818980c06e6996eae1a9ccc14c7a0"
EXPECTED_RADIO_SERVICE_SHA256 = "282d2fc4bfb1b49039e4aeb5a9159df22e64afc97762d700e5dcb197ad791010"
EXPECTED_JUDGE_PRESENTATION = {
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
}
EXPECTED_JUDGE_FAILURE_CHRONOLOGY = {
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
}
EXPECTED_DIPLOMA_UI_CONTRACT = {
    "activation": {
        "function": "0x0041c300",
        "function_span_sha256": "43786af43e8ca369dfec8acf2fbf6c8ec4c68d4987dfb8ee7beb7e1399918770",
        "writes": [
            "manager+0x10d0=-1", "manager+0x10c8=0", "manager+0x10f0=0",
            "manager+0x2c=0", "manager+0x15=1",
        ],
    },
    "input": {
        "function": "0x0041c3a0",
        "function_span_sha256": "2c487d4787c7f5759ede70735c6546974671a0b786c7a126e4422270d3b37972",
        "raw_event_gate": "event+0x0c == 5 AND event+0x10 == 0",
        "dismiss_outside_inclusive_bounds": {
            "x": [140.0, 500.0], "y": [167.0, 427.0],
        },
        "event_semantics": "UNPROVEN",
        "parity_eligible": False,
    },
    "update": {
        "entry": "0x0041c810",
        "owner_function": "0x0041c3a0",
        "owner_span_sha256": "2c487d4787c7f5759ede70735c6546974671a0b786c7a126e4422270d3b37972",
        "elapsed_update": "manager+0x10ec=float32(manager+0x10ec+delta)",
        "close_predicate": (
            "manager+0x2c == 1 AND elapsed > float32(0.25) AND manager+0x10f0 < 0"
        ),
        "threshold": 0.25,
        "threshold_bits": "0x3e800000",
    },
    "resource_close": {
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
    },
}
PROVEN_CODE_ADDRESSES = {
    "0x004013e0", "0x00405a20", "0x00409910", "0x00409fc0",
    "0x00408730", "0x004087c9", "0x00408890", "0x00408940", "0x004089c0",
    "0x00406f70", "0x0040a280", "0x0040a650", "0x00413890", "0x004191a0",
    "0x0041a130", "0x0041ac10", "0x0041ac60", "0x0041afa0", "0x0041b0c0",
    "0x0041b180", "0x0041b1d0", "0x0041bce0", "0x0041bf80",
    "0x0041c2a0", "0x0041c300", "0x0041c340", "0x0041c3a0",
    "0x0041c520", "0x0041c810", "0x0041cb90", "0x0041e410",
    "0x0041cd80", "0x0041cf88", "0x0041d990", "0x0041da29", "0x0041dbae",
    "0x0041f010",
    "0x0041f110", "0x0041f150", "0x0041f210", "0x0041f320",
    "0x0041f6d0", "0x0042c4d0", "0x0042c500", "0x0042c630",
    "0x004440c0", "0x00444169",
    "0x0043c460", "0x0043c5c9", "0x0043d5b0", "0x0043d61b",
    "0x0043d569", "0x0043d5fe", "0x0043ceb3", "0x0043d5ca",
    "0x0041b240", "0x0043d24c", "0x0043d469", "0x0043d251",
    "0x0043d2a7", "0x0043d2ac", "0x0043d33b", "0x0043d2ce",
    "0x0043d2f5", "0x0043ca46", "0x0043ca4c", "0x0043ca56",
    "0x0043ca63", "0x0043ca89",
}
PROVEN_DATA_ADDRESSES = {
    "0x0044c46c", "0x0044ca40", "0x00454050", "0x0044c6c0",
    "0x0044cb98", "0x00454f00", "0x00455adc", "0x00455bd0",
    "0x0044c480", "0x00456350", "0x00456358", "0x004564e0", "0x004564e4",
}
EXPECTED_DEF = {
    "AWARD_DIPLOMA": (3, [1]),
    "JUDGE_AIRPLANE": (1, [0]),
    "PLAY_CHARACTER_ANIMATION": (371, [5, 6]),
    "PLAY_CHARACTER_SCRIPT": (928, [3]),
    "PLAY_CHARACTER_SOUND": (310, [4]),
    "PLAY_MULLEBARNSOUND": (3, [2]),
    "PLAY_RADIO": (6, [3, 4]),
    "PLAY_SOUND": (7, [4]),
    "POSITION_CHARACTER": (438, [3]),
    "WAIT": (253, [2]),
}
EXPECTED_ARGUMENT_SCHEMAS = {
    "AWARD_DIPLOMA": {"1": ["number"]},
    "JUDGE_AIRPLANE": {"0": []},
    "PLAY_CHARACTER_ANIMATION": {
        "5": ["number", "number", "number", "identifier", "identifier"],
        "6": ["number", "number", "number", "identifier", "identifier", "number"],
    },
    "PLAY_CHARACTER_SCRIPT": {"3": ["character_id", "script_id", "identifier"]},
    "PLAY_CHARACTER_SOUND": {"4": ["character_id", "number", "media_bank", "identifier"]},
    "PLAY_MULLEBARNSOUND": {"2": ["number", "identifier"]},
    "PLAY_RADIO": {
        "3": ["media_owner", "number", "media_bank"],
        "4": ["media_owner", "number", "media_bank", "identifier"],
    },
    "PLAY_SOUND": {"4": ["media_owner", "number", "media_bank", "identifier"]},
    "POSITION_CHARACTER": {"3": ["character_id", "number", "number"]},
    "WAIT": {"2": ["number", "identifier"]},
}
EXPECTED_RUNTIME_SHA256 = {
    1: "156171a4becf046c88d05785652e202c7610cc6ca6f2d813ac7c4e6a496f16ba",
    2: "c53a1ca74ba6cfe1b14a45e64ce901459eccc5e2af3549b691ff1b857f5a6b8f",
    3: "d666775a6395ac4b003fb67a5681d9807d49ffd4e8199224b66d238cfdfaed42",
    4: "1671a217fa75a05f1187737f5182aba25453fae5f385ed8a52241e636e921836",
    5: "4fd35349adb84d47f09fa4e0078f88cacc41a71659ef2528553df3fc56381b1e",
    6: "4e3112a98707a6ad2cfbe4cc7e61047da5dc71dae37e458bc38aff41df5b4ea2",
    7: "6d0945f76efa36ef529575d4ad9c7c9ab3aa6c841de437572b0a5cf6f4a16c8d",
    8: "6d0945f76efa36ef529575d4ad9c7c9ab3aa6c841de437572b0a5cf6f4a16c8d",
    9: "6556cf3ae56a6745ebf1048c4aa7caf45f3315c3ae54b73ce14309ca720bb40e",
    10: "4627a4258fec5f8fdf251abefe6ce5aa389d966f9f70259509d87be899fc0c22",
    11: "ac188b1e45a42715b753d88ea4413e926a05ce63cad66f686d29846097f2dc72",
    12: "3837aeeb0bffc763ceee7a7770a407a98ed0ee376d107e5108deb59b8eaf2c0c",
    13: "91d9a2acf2e7914d5d62d7bf85c0b4d2b00fec3f7fb412384fb0e83e858bd824",
    14: "8d403c864c0be60fd03427e15f2abe31f36899fd0ca184c90784eacc3359be0b",
    15: "680438519103610cde02ac54d4243deb011e598254fe53a78f587779b1dc1833",
}
COMMAND_FIELDS = {
    "id", "name", "name_string_address", "registration_evidence",
    "parser_case_address", "parser_behavior", "constructor_payload_slots",
    "handler_case_address", "runtime_equivalence", "parity_eligible",
    "def_observation", "runtime",
}
RUNTIME_FIELDS = {
    "evidence", "parsed_def_reachability", "start", "completion", "calls",
    "state_writes", "unresolved",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"artifact escapes repository root: {relative}") from error
    return candidate


def _validate_policy(contract: dict[str, Any]) -> None:
    expected = {
        "registered_command_count": 15,
        "parser_constructed_count": 11,
        "parser_discarded_ids": [2, 6, 7, 8],
        "parser_synthesized_runtime_ids": [6],
        "observed_def_command_count": 10,
        "unobserved_registered_ids": [2, 4, 6, 7, 8],
        "semantic_equivalence_status": "UNPROVEN",
        "parity_promotion_requires": "REVIEWED_NATIVE_TRACE_DIFFERENTIAL",
    }
    if contract.get("policy") != expected:
        raise ValueError("native scene-command fail-closed policy drifted")


def _validate_engine(contract: dict[str, Any]) -> None:
    engine = contract.get("engine", {})
    if set(engine) != ENGINE_FIELDS:
        raise ValueError("native scene-command engine fields drifted")
    if engine.get("addresses") != EXPECTED_ENGINE:
        raise ValueError("native scene-command engine addresses drifted")
    if engine.get("registration_order") != EXPECTED_REGISTRATION_ORDER:
        raise ValueError("native command registration order drifted")
    if engine.get("modifiers") != EXPECTED_MODIFIERS:
        raise ValueError("native command modifier table drifted")
    if engine.get("node_layout") != EXPECTED_NODE_LAYOUT:
        raise ValueError("native command node layout drifted")
    if engine.get("parser_tokens") != EXPECTED_PARSER_TOKENS:
        raise ValueError("native parser token grammar drifted")
    if engine.get("composite_layout") != EXPECTED_COMPOSITE_LAYOUT:
        raise ValueError("native composite layout drifted")
    if engine.get("command_layout") != EXPECTED_COMMAND_LAYOUT:
        raise ValueError("native command payload layout drifted")
    if engine.get("scheduler") != EXPECTED_SCHEDULER:
        raise ValueError("native scene scheduler drifted")
    if engine.get("sound_lowering") != EXPECTED_SOUND_LOWERING:
        raise ValueError("native character-sound lowering drifted")
    error_paths = engine.get("error_paths", {})
    if error_paths != {
        "unknown_name_id": 0,
        "unknown_or_out_of_range_parser_action": "DISCARD_AND_CONTINUE",
        "node_allocation_failure": "SKIP_NODE_AND_CONTINUE",
        "structural_or_file_failure_addresses": ["0x0043d63d", "0x0043d646"],
        "structural_or_file_failure_result": 0,
    }:
        raise ValueError("native parser error-path contract drifted")


def _validate_proven_semantics(contract: dict[str, Any]) -> None:
    engine = contract.get("engine", {})
    modifiers = engine.get("modifier_execution")
    runtime = contract.get("observed_runtime_contracts")
    if not isinstance(modifiers, dict) or not isinstance(runtime, dict):
        raise ValueError("reviewed native scene semantics missing")
    expected_runtime_ids = {"1", "3", "5", "6", "9", "10", "11", "12", "13", "14", "15"}
    if set(runtime) != expected_runtime_ids:
        raise ValueError("observed native runtime contract coverage drifted")
    if modifiers.get("WAIT_RANDOM", {}).get("formula") != (
        "duration * (0.7 + 0.6 * rand_result / 32767)"
    ):
        raise ValueError("WAIT_RANDOM formula drifted")
    if modifiers["WAIT_RANDOM"].get("completion_predicate") != "timer < 0.0":
        raise ValueError("WAIT_RANDOM completion boundary drifted")
    if modifiers.get("FINISHDIRECT", {}).get("PLAY_CHARACTER_SCRIPT") != (
        "START_THEN_COMPLETE_SAME_UPDATE"
    ):
        raise ValueError("FINISHDIRECT ordering drifted")
    if modifiers.get("LOOP", {}).get("parser_token") != (
        "COMPOSITE_REPEAT_RESET_AFTER_COMPLETION"
    ):
        raise ValueError("LOOP composite behavior drifted")
    if runtime["13"].get("timer_fallback") != "NONE":
        raise ValueError("PLAY_RADIO acquired a nonexistent timer fallback")
    if runtime["10"].get("half_policy") != "EXACT_0.5_ROUNDS_DOWN" or (
        runtime["10"].get("media_identity") != {
            "owner": "domaren", "bank": "f", "take": 1,
            "clip_formula": "score + 3", "clip_domain": [4, 5, 6, 7, 8],
        }
    ):
        raise ValueError("JUDGE_AIRPLANE score or media contract drifted")
    if runtime["10"].get("score_presentation") != EXPECTED_JUDGE_PRESENTATION or (
        runtime["10"].get("media_failure_chronology")
        != EXPECTED_JUDGE_FAILURE_CHRONOLOGY
    ):
        raise ValueError("JUDGE_AIRPLANE presentation or failure chronology drifted")
    if runtime["11"].get("award_clip_table") != [451, 452, 453, 456, 454, 455] or (
        runtime["11"].get("media_identity") != {
            "owner": "mulle", "bank": "y", "take": 1,
            "clip": "award_clip_table[index]",
        }
    ) or (
        runtime["11"].get("manager_media_identity") != {
            "owner": "doris", "bank": "x", "take": 1, "clip": 38,
        }
    ) or (
        runtime["11"].get("manager_media_load") != {
            "function": "0x0041bf80",
            "function_span_sha256": (
                "3acf05fd033cb9fd98b10c80c3dfff4338d774a502954d4f391f8819bd062412"
            ),
            "builder_callsite": "0x0041c1f8",
            "requested_take": 0,
            "resource_field": "manager+0x10f4",
            "timing": "shared diploma manager initialization before any award",
            "playback_lifecycle": "UNPROVEN",
            "parity_eligible": False,
        }
    ) or (
        runtime["11"].get("bank_pointer_guard") != (
            "0x004564e0 is y; adjacent 0x004564e4 is save chunk id DIPL, never a media bank"
        )
    ):
        raise ValueError("AWARD_DIPLOMA clip table or bank identity drifted")
    if runtime["11"].get("manager_ui_contract") != EXPECTED_DIPLOMA_UI_CONTRACT or (
        runtime["11"].get("ui_lifecycle") != (
            "award mode closes only after elapsed > float32(0.25) "
            "and dismiss phase becomes negative"
        )
    ):
        raise ValueError("AWARD_DIPLOMA UI lifecycle contract drifted")
    if runtime["12"].get("take_policy") != "BUILDER_CLAMPS_TO_TAKE_1_WITHOUT_RNG" or (
        runtime["12"].get("rng_draws") != 0
    ):
        raise ValueError("PLAY_SOUND take-1 or RNG contract drifted")
    radio = runtime["13"]
    alert = radio.get("first_alert", {})
    if radio.get("take_policy") != (
        "BUILDER_CLAMPS_TO_TAKE_1_WITHOUT_REQUEST_RNG"
    ) or radio.get("requested_rng_draws") != 0 or alert.get("rng_draws") != 2 or (
        radio.get("queue_gap") != (
            "float32(elapsed-last_primary_end) > float32(2.0)"
        )
    ):
        raise ValueError("PLAY_RADIO queue, take or RNG contract drifted")
    if radio.get("path_equality") != {
        "comparator": "MSVCRT _stricmp",
        "iat_address": "0x0044c480",
        "equal_result": 0,
    } or radio.get("service_constructor") != {
        "address": "0x0041f010",
        "alert_eligible": "this+0x4c=1",
        "alert_pending": "this+0x4d=0",
        "alert_active": "this+0x4e=0",
    } or radio.get("enqueue_order") != (
        "ARM_ALERT_PENDING_IF_ELIGIBLE_BEFORE_REQUEST_NODE_ALLOCATION"
    ) or radio.get("alert_storage") != "SEPARATE_BOOLEAN_STATE_NOT_A_FIFO_NODE" or (
        radio.get("alert_reset_policy") != "ONLY_A_NEW_SERVICE_INSTANCE_RESETS_ELIGIBILITY"
    ):
        raise ValueError("PLAY_RADIO service lifecycle contract drifted")
    if radio.get("scheduler_order") != {
        "manager_tick": "0x0041d990",
        "child_scheduler": "manager+0x144",
        "scheduler_update": "0x00408730",
        "category": 1,
        "registration_callsite": "0x0041cf88",
        "insertion_policy": "HEAD_INSERT",
        "category_callsite": "0x004087c9",
        "scene_relation": "AFTER_ACTIVE_MODE_AND_UDSP_ROOT_SAME_MANAGER_TICK",
        "normal_dt_callsite": "0x0041dbae",
        "zero_dt_callsite": "0x0041da29",
        "zero_dt_policy": "TICK_SCENE_AND_RADIO_WITH_LITERAL_F32_ZERO",
        "runtime_trace": "UNPROVEN",
        "parity_eligible": False,
    }:
        raise ValueError("PLAY_RADIO scheduler order drifted")
    if radio.get("clock_policy") != {
        "accumulator": "elapsed = float32(elapsed + dt)",
        "last_primary_end_stamp": (
            "STAMP_ELAPSED_AT_ACTIVE_DISAPPEARANCE_AND_BEFORE_EVERY_PRIMARY_START_ATTEMPT"
        ),
        "finish_detection": "RETURN_FROM_TICK_AFTER_STAMP_WITHOUT_STARTING_NEXT_ITEM",
        "failed_primary_start": (
            "POP_REQUEST_AND_RESTART_STRICT_GAP_FROM_PRE_ATTEMPT_STAMP"
        ),
    } or radio.get("queue_pop_on_start_failure") is not True:
        raise ValueError("PLAY_RADIO clock or failed-start chronology drifted")
    if alert.get("ordering") != "BEFORE_QUEUED_REQUEST" or alert.get(
        "tick_sequence"
    ) != "RAND_CLIP_THEN_COUNT_TAKES_THEN_UNCONDITIONAL_RAND_TAKE_THEN_SIGNED_IDIV" or (
        alert.get("failure_policy") != (
            "GRACEFUL_START_FAILURE_CONSUMES_ELIGIBILITY_AND_RETURNS; "
            "NEXT_TICK_CLEANS_UP_AND_RETURNS; PRIMARY_EARLIEST_ON_FOLLOWING_TICK"
        )
    ) or alert.get("zero_take_count") != "CPU_SIGNED_DIVIDE_ERROR_AFTER_SECOND_RNG_DRAW":
        raise ValueError("PLAY_RADIO alert ordering or failure contract drifted")
    radio_payload = json.dumps(
        radio, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    if hashlib.sha256(radio_payload).hexdigest() != EXPECTED_RADIO_SERVICE_SHA256:
        raise ValueError("reviewed PLAY_RADIO service semantics drifted")
    for command_id in ("5", "10", "14", "15"):
        key = "completion_predicate" if command_id == "15" else "fallback_completion_predicate"
        if runtime[command_id].get(key) != "timer < 0.0":
            raise ValueError(f"strict timer boundary drifted: id={command_id}")
    payload = json.dumps(
        {"modifier_execution": modifiers, "observed_runtime_contracts": runtime},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if hashlib.sha256(payload).hexdigest() != EXPECTED_PROVEN_SEMANTICS_SHA256:
        raise ValueError("reviewed native scene semantics drifted")


def _validate_commands(contract: dict[str, Any]) -> None:
    commands = contract.get("commands")
    if not isinstance(commands, list) or len(commands) != 15:
        raise ValueError("native command inventory must contain exactly 15 rows")
    ids = [row.get("id") for row in commands]
    names = [row.get("name") for row in commands]
    if ids != list(range(1, 16)) or len(names) != len(set(names)):
        raise ValueError("native command IDs/names must be unique and ID-sorted")

    observed_names = set(EXPECTED_DEF)
    for row in commands:
        command_id = row["id"]
        if set(row) != COMMAND_FIELDS:
            raise ValueError(f"native command fields drifted: id={command_id}")
        expected = EXPECTED_COMMANDS[command_id]
        actual = (
            row.get("name"),
            row.get("name_string_address"),
            row.get("parser_case_address"),
            row.get("parser_behavior"),
            row.get("constructor_payload_slots"),
            row.get("handler_case_address"),
        )
        if actual != expected:
            raise ValueError(f"native command mapping drifted: id={command_id}")
        if row.get("registration_evidence") != "PROVEN_STATIC":
            raise ValueError(f"command lacks static registration evidence: id={command_id}")
        if row.get("runtime_equivalence") != "UNPROVEN" or row.get("parity_eligible") is not False:
            raise ValueError(f"command escaped fail-closed parity policy: id={command_id}")
        runtime = row.get("runtime")
        if not isinstance(runtime, dict) or runtime.get("evidence") != "PARTIAL_STATIC":
            raise ValueError(f"command runtime map lacks bounded static evidence: id={command_id}")
        if set(runtime) != RUNTIME_FIELDS:
            raise ValueError(f"command runtime fields drifted: id={command_id}")
        if not isinstance(runtime.get("start"), str) or not runtime["start"]:
            raise ValueError(f"command runtime start contract missing: id={command_id}")
        if not isinstance(runtime.get("completion"), str) or not runtime["completion"]:
            raise ValueError(f"command runtime completion contract missing: id={command_id}")
        for key in ("calls", "state_writes", "unresolved"):
            if not isinstance(runtime.get(key), list):
                raise ValueError(f"command runtime {key} must be an array: id={command_id}")

        observation = row.get("def_observation")
        name = row["name"]
        expected_count, expected_arities = EXPECTED_DEF.get(name, (0, []))
        expected_schemas = EXPECTED_ARGUMENT_SCHEMAS.get(name, {})
        if observation != {
            "evidence": "OBSERVED_DEF" if name in observed_names else "NOT_OBSERVED_IN_PINNED_DEF",
            "occurrences": expected_count,
            "arities": expected_arities,
            "argument_schemas": expected_schemas,
        }:
            raise ValueError(f"DEF observation drifted: {name}")
        if row["parser_behavior"] == "DISCARD_OPCODE" and runtime.get("parsed_def_reachability") != "UNREACHABLE_STATIC":
            raise ValueError(f"discarded parser command marked reachable: id={command_id}")
        if row["parser_behavior"] == "DISCARD_DIRECT_TOKEN_SYNTHESIZED_BY_OPCODE_5" and runtime.get("parsed_def_reachability") != "REACHABLE_VIA_OPCODE_5_LOWERING":
            raise ValueError(f"synthesized parser command marked unreachable: id={command_id}")
        if row["parser_behavior"] == "CONSTRUCT_NODE" and runtime.get("parsed_def_reachability") != "REACHABLE_IF_PARSED":
            raise ValueError(f"constructed parser command marked unreachable: id={command_id}")
        runtime_payload = json.dumps(
            runtime, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        if hashlib.sha256(runtime_payload).hexdigest() != EXPECTED_RUNTIME_SHA256[command_id]:
            raise ValueError(f"reviewed static runtime summary drifted: id={command_id}")


def _validate_artifacts(contract: dict[str, Any], root: Path) -> None:
    source = contract.get("source", {})
    if set(source) != SOURCE_FIELDS:
        raise ValueError("native scene-command source fields drifted")
    if source.get("executable_sha256") != EXECUTABLE_SHA256:
        raise ValueError("native scene-command contract belongs to another executable")
    artifacts = source.get("artifacts", {})
    if set(artifacts) != REQUIRED_ARTIFACTS:
        raise ValueError("native scene-command artifact pins drifted")
    loaded: dict[str, Any] = {}
    for name, pin in artifacts.items():
        if set(pin) != {"path", "sha256"} or not SHA256.fullmatch(pin.get("sha256", "")):
            raise ValueError(f"invalid artifact pin: {name}")
        path = _artifact_path(root, pin["path"])
        if not path.is_file() or sha256_file(path) != pin["sha256"]:
            raise ValueError(f"pinned artifact drifted: {name}")
        if path.suffix == ".json":
            loaded[name] = json.loads(path.read_text(encoding="utf-8"))
    for name in ("native_function_index", "native_code_map"):
        if loaded[name].get("source", {}).get("sha256") != EXECUTABLE_SHA256:
            raise ValueError(f"{name} belongs to another executable")

    uds = loaded["uds_scene_scripts"]
    if uds.get("coverage", {}).get("all_archive_def_files_covered") != 264:
        raise ValueError("UDSP DEF coverage must remain complete")
    if uds.get("counts", {}).get("commands") != sum(count for count, _ in EXPECTED_DEF.values()):
        raise ValueError("UDSP command total drifted")
    vocabulary = uds.get("command_vocabulary", {})
    counts = {name: value[0] for name, value in EXPECTED_DEF.items()}
    arities = {name: value[1] for name, value in EXPECTED_DEF.items()}
    if vocabulary != {"counts": counts, "arities": arities}:
        raise ValueError("UDSP command vocabulary/arities drifted")
    known_modifiers = set(EXPECTED_MODIFIERS)
    observed_modifiers: dict[str, dict[str, int]] = {}
    for script in uds.get("scripts", []):
        for command in script.get("commands", []):
            found = [
                argument for argument in command.get("arguments", [])
                if isinstance(argument, str) and argument in known_modifiers
            ]
            for modifier in found:
                command_counts = observed_modifiers.setdefault(command["opcode"], {})
                command_counts[modifier] = command_counts.get(modifier, 0) + 1
    if observed_modifiers != EXPECTED_MODIFIER_OBSERVATIONS:
        raise ValueError("UDSP command modifier observations drifted")

    index = loaded["native_function_index"]
    functions_by_address = {
        function["address"]: function for function in index.get("functions", [])
    }
    runtime = contract["observed_runtime_contracts"]
    pinned_spans = {
        "diploma manager media load": (
            runtime["11"]["manager_media_load"]["function"],
            runtime["11"]["manager_media_load"]["function_span_sha256"],
        ),
        "judge score render": (
            runtime["10"]["score_presentation"]["render_function"],
            runtime["10"]["score_presentation"]["render_span_sha256"],
        ),
        "judge font load": (
            runtime["10"]["score_presentation"]["font_load_function"],
            runtime["10"]["score_presentation"]["font_load_span_sha256"],
        ),
        "judge failure chronology": (
            runtime["10"]["media_failure_chronology"]["handler_owner_function"],
            runtime["10"]["media_failure_chronology"]["handler_owner_span_sha256"],
        ),
        "diploma activation and close": (
            runtime["11"]["manager_ui_contract"]["activation"]["function"],
            runtime["11"]["manager_ui_contract"]["activation"]["function_span_sha256"],
        ),
        "diploma input and update": (
            runtime["11"]["manager_ui_contract"]["input"]["function"],
            runtime["11"]["manager_ui_contract"]["input"]["function_span_sha256"],
        ),
    }
    for label, (address, expected_sha256) in pinned_spans.items():
        function = functions_by_address.get(address)
        if not isinstance(function, dict) or function.get("sha256") != expected_sha256:
            raise ValueError(f"{label} span drifted from native function index")
    spans = [
        (int(function["address"], 16), int(function["end"], 16))
        for function in index.get("functions", [])
    ]
    sections = [
        (int(section["address"], 16), int(section["address"], 16) + section["virtual_size"], section["executable"])
        for section in index.get("sections", [])
    ]
    code_addresses = list(EXPECTED_ENGINE.values())
    code_addresses.extend(["0x0043d63d", "0x0043d646"])
    code_addresses.extend(PROVEN_CODE_ADDRESSES)
    for command in EXPECTED_COMMANDS.values():
        code_addresses.extend((command[2], command[5]))
    for value in code_addresses:
        address = int(value, 16)
        if not any(start <= address < end for start, end in spans):
            raise ValueError(f"contract address is outside native function index: {value}")
    for value in (command[1] for command in EXPECTED_COMMANDS.values()):
        address = int(value, 16)
        if not any(start <= address < end and not executable for start, end, executable in sections):
            raise ValueError(f"command name address is outside native data sections: {value}")
    for token in EXPECTED_PARSER_TOKENS.values():
        address = int(token["string_address"], 16)
        if not any(start <= address < end and not executable for start, end, executable in sections):
            raise ValueError(f"parser token string is outside native data sections: {token['string_address']}")
    for value in PROVEN_DATA_ADDRESSES:
        address = int(value, 16)
        if not any(start <= address < end and not executable for start, end, executable in sections):
            raise ValueError(f"semantic constant is outside native data sections: {value}")


def validate_contract(
    contract: dict[str, Any], *, root: Path = ROOT, verify_artifacts: bool = True
) -> dict[str, Any]:
    if not isinstance(contract, dict) or set(contract) != TOP_LEVEL_FIELDS:
        raise ValueError("native scene-command top-level fields drifted")
    if contract.get("schema") != 1:
        raise ValueError("unsupported native UDSP scene-command schema")
    if contract.get("claim") != "STATIC_CONTROL_FLOW_COMPLETE_SEMANTICS_PARTIAL":
        raise ValueError("native UDSP scene-command claim drifted")
    if contract.get("claim_limit") != CLAIM_LIMIT:
        raise ValueError("native scene-command claim limit drifted")
    source = contract.get("source")
    if not isinstance(source, dict) or set(source) != SOURCE_FIELDS:
        raise ValueError("native scene-command source fields drifted")
    _validate_policy(contract)
    _validate_engine(contract)
    _validate_proven_semantics(contract)
    _validate_commands(contract)
    if contract.get("unresolved") != [
        "Native accepted arities for commands absent from the pinned DEF corpus.",
        "Semantic names and side effects of unresolved external/virtual calls.",
        "Runtime timing and completion parity until reviewed native trace differentials exist.",
        "Whether other language editions exercise registered commands absent from the pinned Dutch corpus.",
    ]:
        raise ValueError("native scene-command unresolved boundary drifted")
    if verify_artifacts:
        _validate_artifacts(contract, root)
    return contract


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    return validate_contract(json.loads(path.read_text(encoding="utf-8")))


def validate_nl_service_media_inventory(
    archive_sha256: str, inventory: dict[str, str]
) -> dict[str, str]:
    """Fail closed on pinned Dutch judge/diploma-manager/award/radio media.

    Prefixes remain edition-specific; these hashes prove only that the pinned
    Dutch archive realizes the executable's clip/owner/bank/take contract.
    """
    if archive_sha256 != NL_SOUNDS_ARCHIVE_SHA256:
        raise ValueError("Dutch sounds.up hash differs from the reviewed archive")
    if inventory != NL_SERVICE_MEDIA_SHA256:
        raise ValueError("Dutch judge/diploma/radio media inventory drifted")
    return dict(inventory)


def validate_nl_service_media_archive(path: Path) -> dict[str, str]:
    payload = path.read_bytes()
    archive_sha256 = hashlib.sha256(payload).hexdigest()
    archive = UdspArchive(path)
    expected_casefold = {name.casefold(): name for name in NL_SERVICE_MEDIA_SHA256}
    inventory: dict[str, str] = {}
    for entry in archive.files:
        normalized = entry.path.replace("\\", "/")
        canonical = expected_casefold.get(normalized.casefold())
        if canonical is None:
            continue
        if canonical in inventory:
            raise ValueError(f"duplicate Dutch service media path: {canonical}")
        inventory[canonical] = hashlib.sha256(archive.payload(entry)).hexdigest()
    return validate_nl_service_media_inventory(archive_sha256, inventory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract", nargs="?", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument(
        "--sounds-archive", type=Path,
        help="also verify the exact pinned Dutch JUDGE/AWARD/radio media",
    )
    parser.add_argument("--check", action="store_true", help="validate without printing the summary")
    args = parser.parse_args()
    contract = load_contract(args.contract)
    if args.sounds_archive is not None:
        validate_nl_service_media_archive(args.sounds_archive)
    if not args.check:
        observed = sum(1 for row in contract["commands"] if row["def_observation"]["occurrences"])
        print(json.dumps({
            "registered": len(contract["commands"]),
            "parser_constructed": sum(row["parser_behavior"] == "CONSTRUCT_NODE" for row in contract["commands"]),
            "def_observed": observed,
            "parity_eligible": sum(row["parity_eligible"] for row in contract["commands"]),
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
