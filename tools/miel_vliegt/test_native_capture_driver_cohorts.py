#!/usr/bin/env python3
"""Exact tests for the shared native capture driver cohort table."""

import json
import unittest
from pathlib import Path

try:
    from tools.miel_vliegt import native_capture_driver_cohorts as cohorts
    from tools.miel_vliegt import native_dispatch_capture_job as capture_job
    from tools.miel_vliegt import native_dispatch_capture_runner as runner
    from tools.miel_vliegt import (
        native_dispatch_capture_target_header as header,
    )
    from tools.miel_vliegt import native_observer_build as observer_build
except ModuleNotFoundError:  # Direct execution from tools/miel_vliegt.
    import native_capture_driver_cohorts as cohorts
    import native_dispatch_capture_job as capture_job
    import native_dispatch_capture_runner as runner
    import native_dispatch_capture_target_header as header
    import native_observer_build as observer_build

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "content/miel_vliegt/uds_flight_contracts.json"
DISPATCH = ROOT / "content/miel_vliegt/scene_dispatch_contract.json"


def _ne3_target(mode="mode_roymccoy"):
    return {
        "evidenceClass": "LOCATION_POLICY",
        "trigger": {
            "selector": "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3",
            "selectorHookFamily": "GENERIC_LOCATION_ENTER",
            "mode": mode,
        },
    }


class CohortTableTest(unittest.TestCase):
    def test_declared_cohorts_are_disjoint_and_exact(self):
        versions = [c["version"] for c in cohorts.COHORTS]
        self.assertEqual(len(versions), len(set(versions)))
        macros = [c["cMacro"] for c in cohorts.COHORTS]
        self.assertEqual(len(macros), len(set(macros)))
        location_keys = [
            (c["evidenceClass"], c["selector"], c["selectorHookFamily"])
            for c in cohorts.COHORTS if c["kind"] == "location"
        ]
        self.assertEqual(len(location_keys), len(set(location_keys)))
        mission_rows = [
            row
            for c in cohorts.COHORTS if c["kind"] == "mission"
            for row in c["allowlist"]
        ]
        self.assertEqual(len(mission_rows), len(set(mission_rows)))

    def test_ne3_cohort_matches(self):
        selected = cohorts.cohort_for_target(_ne3_target())
        self.assertEqual(selected, {
            "version": "GENERIC_LOCATION_CLEAN_V2",
            "mode": "mode_roymccoy",
            "cMacro": "MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2",
        })

    def test_non_matching_targets_select_nothing(self):
        for target in (
            {},
            {"trigger": None},
            {"evidenceClass": "LOCATION_POLICY", "trigger": {}},
            {
                "evidenceClass": "MISSION_DISPATCH",
                "trigger": _ne3_target()["trigger"],
            },
            {
                "evidenceClass": "LOCATION_POLICY",
                "trigger": {
                    "selector": "LOCATION_ENTER_FINAL_MISSION_STATE_EQ_3",
                    "selectorHookFamily": "GENERIC_LOCATION_ENTER",
                    "mode": "mode_roymccoy",
                },
            },
            {
                "evidenceClass": "MISSION_DISPATCH",
                "trigger": {
                    "actionHookFamily": "ACTION_GROUND",
                    "missionPhase": "reward",
                    "missionKey": "1:data/Missions/camera.txt",
                    "nativeActionOrdinal": 0,
                    "domainId": "roy_mccoy",
                },
            },
            {
                "evidenceClass": "MISSION_DISPATCH",
                "trigger": {
                    "actionHookFamily": "ACTION_GROUND",
                    "missionPhase": "activate",
                    "missionKey": "34:data/Missions/photo.txt",
                    "nativeActionOrdinal": 0,
                    "domainId": "roy_mccoy",
                },
            },
        ):
            self.assertIsNone(cohorts.cohort_for_target(target))

    def test_invalid_mode_fails_closed(self):
        for mode in (None, 7, "", "flight", "mode_\r", "mode_é"):
            with self.assertRaises(cohorts.DriverCohortError):
                cohorts.cohort_for_target(_ne3_target(mode))

    def test_mission_ground_cohort_resolves_domain_mode(self):
        selected = cohorts.cohort_for_target({
            "evidenceClass": "MISSION_DISPATCH",
            "trigger": {
                "actionHookFamily": "ACTION_GROUND",
                "missionPhase": "activate",
                "missionKey": "1:data/Missions/camera.txt",
                "nativeActionOrdinal": 0,
                "domainId": "roy_mccoy",
            },
        })
        self.assertEqual(selected, {
            "version": "MISSION_LOCATION_ENTER_V1",
            "mode": "mode_roymccoy",
            "cMacro": "MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1",
        })

    def test_mission_barn_cohort_uses_barn_mode(self):
        selected = cohorts.cohort_for_target({
            "evidenceClass": "MISSION_DISPATCH",
            "trigger": {
                "actionHookFamily": "ACTION_BARN",
                "missionPhase": "activate",
                "missionKey": "5001:data/Missions/randomdoris.txt",
                "nativeActionOrdinal": 1,
                "domainId": "barn",
            },
        })
        self.assertEqual(selected, {
            "version": "MISSION_BARN_TRAVERSAL_V1",
            "mode": "mode_barn",
            "cMacro": "MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1",
        })

    def test_mode_by_domain_matches_scene_dispatch_contract(self):
        dispatch = json.loads(DISPATCH.read_text(encoding="utf-8"))
        contract_map = {
            location["domainId"]: location["mode"]
            for location in dispatch["locations"]
            if location["domainId"] in cohorts.MODE_BY_DOMAIN
        }
        self.assertEqual(contract_map, dict(cohorts.MODE_BY_DOMAIN))

    def test_mission_allowlists_match_arrive_only_activate_contracts(self):
        contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))
        dispatch = json.loads(DISPATCH.read_text(encoding="utf-8"))
        location_by_domain = {
            location["domainId"]: location["locationId"]
            for location in dispatch["locations"]
        }
        missions = {
            f"{mission['id']}:{mission['source']}": mission
            for mission in contracts["missions"]
        }
        derived_ground = set()
        derived_barn = set()
        for target in capture_job.compile_targets()["targets"]:
            trigger = target["trigger"]
            if target["evidenceClass"] != "MISSION_DISPATCH" \
                    or trigger["missionPhase"] != "activate" \
                    or trigger["actionHookFamily"] not in (
                        "ACTION_GROUND", "ACTION_BARN",
                    ):
                continue
            mission = missions[trigger["missionKey"]]
            dependencies = [
                dependency for dependency in mission["dependencies"]
                if dependency["state"] == "activate"
            ]
            if not dependencies or any(
                dependency["type"] != "arrive" for dependency in dependencies
            ):
                continue
            if trigger["actionHookFamily"] == "ACTION_BARN":
                # The barn is not a flight location; its arrive id is 1.
                own_location = 1
                collection = derived_barn
            else:
                own_location = location_by_domain[trigger["domainId"]]
                collection = derived_ground
            if {int(d["data"]) for d in dependencies} != {own_location}:
                continue
            collection.add(
                (trigger["missionKey"], trigger["nativeActionOrdinal"])
            )
        self.assertEqual(derived_ground, set(cohorts.MISSION_GROUND_ALLOWLIST))
        self.assertEqual(derived_barn, set(cohorts.MISSION_BARN_ALLOWLIST))

    def test_compiled_population_matches_expected_counts(self):
        compilation = capture_job.compile_targets()
        counts = {}
        for target in compilation["targets"]:
            selected = cohorts.cohort_for_target(target)
            if selected is not None:
                counts[selected["version"]] = \
                    counts.get(selected["version"], 0) + 1
        self.assertEqual(counts, {
            c["version"]: c["expectedTargetCount"] for c in cohorts.COHORTS
        })
        self.assertEqual(
            sum(counts.values()), cohorts.EXPECTED_DRIVEN_TARGET_COUNT,
        )
        self.assertEqual(cohorts.EXPECTED_DRIVEN_TARGET_COUNT, 32)

    def test_runner_and_header_agree_with_table(self):
        compilation = capture_job.compile_targets()
        for target in compilation["targets"]:
            selected = cohorts.cohort_for_target(target)
            driver = runner.capture_driver_for_target(target)
            macro = header.capture_driver(target)
            if selected is None:
                self.assertIsNone(driver)
                self.assertEqual(macro, header.DRIVER_NONE)
            else:
                self.assertEqual(driver, {
                    "version": selected["version"],
                    "mode": selected["mode"],
                })
                self.assertEqual(macro, selected["cMacro"])

    def test_foundation_constants_are_single_sourced(self):
        self.assertEqual(
            runner.DRIVER_BOOTSTRAP_PROFILE, cohorts.DRIVER_BOOTSTRAP_PROFILE,
        )
        self.assertEqual(
            runner.DRIVER_BOOTSTRAP_PROFILE_SHA256,
            cohorts.DRIVER_BOOTSTRAP_PROFILE_SHA256,
        )
        self.assertEqual(
            runner.DRIVER_SCENARIO_SHA256, cohorts.DRIVER_SCENARIO_SHA256,
        )
        self.assertEqual(
            runner.DRIVER_INITIAL_USER_SHA256,
            cohorts.DRIVER_INITIAL_USER_SHA256,
        )
        self.assertEqual(observer_build.CAPTURE_DRIVER_FOUNDATION, {
            "profile": cohorts.DRIVER_BOOTSTRAP_PROFILE,
            "profile_sha256": cohorts.DRIVER_BOOTSTRAP_PROFILE_SHA256,
            "scenario_sha256": cohorts.DRIVER_SCENARIO_SHA256,
            "initial_user_sha256": cohorts.DRIVER_INITIAL_USER_SHA256,
        })


if __name__ == "__main__":
    unittest.main()
