#!/usr/bin/env python3
"""Single source of truth for deterministic native-dispatch driver cohorts.

A cohort binds one compiled-target predicate to one observer driver version.
Three boundaries must agree on that binding: the capture runner (process
orchestration and receipt validation), the generated C allowlist
(:mod:`native_dispatch_capture_target_header`), and the observer DLL gate
(``configure_native_capture_driver``).  This table is the only place a cohort
is declared on the Python side; the observer DLL still re-enforces every
predicate independently, so the table can never relax that check — it only
removes predicate duplication.

Mission cohorts are pinned to an explicit allowlist of (missionKey, phase,
ordinal) rows whose activate dependencies are arrive-only at the action's own
location, so the canonical fresh save satisfies them by navigation alone.
``test_native_capture_driver_cohorts`` recomputes that allowlist from
``uds_flight_contracts.json`` and ``scene_dispatch_contract.json``; any drift
fails the build.

Adding a cohort here does not make it runnable: the observer DLL needs the
matching ``MVDS_CAPTURE_DRIVER_*`` state machine and the generated header must
be regenerated, which changes the observer build identity.
"""

from __future__ import annotations

from typing import Any, Mapping

DRIVER_BOOTSTRAP_PROFILE = "NATIVE_DISPATCH_DRIVER_V2"
DRIVER_BOOTSTRAP_PROFILE_SHA256 = (
    "72925be976520350aec44c45861e5f0af1bcaaef0f33fe605f42d6d415c0cd68"
)
DRIVER_SCENARIO_SHA256 = (
    "1435350feab7bfe92840bc8be305f13a6daf539173674e0b1bab8553c7b9b165"
)
DRIVER_INITIAL_USER_SHA256 = (
    "7019275a9489a2d078f2cb38425f852dd2c019295e401ba4a58cbd67566555d6"
)

GENERIC_LOCATION_CLEAN_V2 = "GENERIC_LOCATION_CLEAN_V2"
BOOTSTRAP_TRAVERSAL_V1 = "BOOTSTRAP_TRAVERSAL_V1"
MISSION_LOCATION_ENTER_V1 = "MISSION_LOCATION_ENTER_V1"
MISSION_BARN_TRAVERSAL_V1 = "MISSION_BARN_TRAVERSAL_V1"

#: domainId -> mode, pinned from scene_dispatch_contract.json locations[].
MODE_BY_DOMAIN = {
    "roy_mccoy": "mode_roymccoy",
    "sam_scribbler": "mode_samscribbler",
    "ture_tapp": "mode_turetapp",
    "atle_artillerist": "mode_atleartillerist",
    "viola_wallmark": "mode_violawallmark",
    "sampo_sanna": "mode_samposanna",
    "brejton_bord": "mode_brejtonbord",
    "grotte_grundlig": "mode_grottegrundlig",
    "gabriella_gourmet": "mode_gabriellagourmet",
    "richard_revers": "mode_richardrevers",
    "victor_vulcan": "mode_victorvulcan",
    "varldsutstallning": "mode_varldsutstallning",
    "vermont_vrak": "mode_vermontvrak",
    "fiona_falk": "mode_fionafalk",
    "doris_digital": "mode_dorisdigital",
    "ernst_eremit": "mode_ernsteremit",
}

#: Activate-phase mission actions whose dependencies are arrive-only at the
#: action's own location (verified against uds_flight_contracts.json).
MISSION_GROUND_ALLOWLIST = frozenset({
    ("1:data/Missions/camera.txt", 0),
    ("3:data/Missions/tent.txt", 0),
    ("6:data/Missions/crops.txt", 0),
    ("9:data/Missions/ggcollect.txt", 0),
    ("14:data/Missions/vacuumcleaner.txt", 0),
    ("20:data/Missions/bbstuff.txt", 0),
    ("21:data/Missions/seismograph.txt", 0),
    ("28:data/Missions/enrstbuild.txt", 0),
    ("28:data/Missions/ernstbuild.txt", 0),
    ("38:data/Missions/reindeer.txt", 0),
    ("39:data/Missions/ddstuff.txt", 0),
    ("2000:data/Missions/mecchistory.txt", 0),
    ("2001:data/Missions/mecchistory.txt", 0),
    ("2002:data/Missions/mecchistory.txt", 0),
})

MISSION_BARN_ALLOWLIST = frozenset({
    ("5001:data/Missions/randomdoris.txt", 1),
    ("6001:data/Missions/randommia.txt", 1),
})

#: Declaration order is the match order; predicates must stay disjoint.
COHORTS: tuple[Mapping[str, Any], ...] = (
    {
        "version": GENERIC_LOCATION_CLEAN_V2,
        "cMacro": "MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2",
        "kind": "location",
        "evidenceClass": "LOCATION_POLICY",
        "selector": "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3",
        "selectorHookFamily": "GENERIC_LOCATION_ENTER",
        "expectedTargetCount": 15,
    },
    {
        # The observer only performs the login bootstrap; the original
        # input-driven barn -> mygghanget path then reaches the target hook
        # naturally, so no engine_mode dispatch ever happens in this cohort.
        "version": BOOTSTRAP_TRAVERSAL_V1,
        "cMacro": "MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1",
        "kind": "location",
        "evidenceClass": "LOCATION_POLICY",
        "selector": "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE",
        "selectorHookFamily": "MYGGHANGET_ENTER",
        "expectedTargetCount": 1,
    },
    {
        # NE_3-style navigation (login -> flight -> engine_mode dispatch into
        # the mission's own location); the activate-phase action then fires
        # on arrival and the action hook opens the capture window.
        "version": MISSION_LOCATION_ENTER_V1,
        "cMacro": "MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1",
        "kind": "mission",
        "evidenceClass": "MISSION_DISPATCH",
        "actionHookFamily": "ACTION_GROUND",
        "missionPhase": "activate",
        "allowlist": MISSION_GROUND_ALLOWLIST,
        "expectedTargetCount": 14,
    },
    {
        # Barn missions 5001/6001 activate on arrive-at-barn, which the
        # natural login -> barn bootstrap reaches without any dispatch.
        "version": MISSION_BARN_TRAVERSAL_V1,
        "cMacro": "MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1",
        "kind": "mission",
        "evidenceClass": "MISSION_DISPATCH",
        "actionHookFamily": "ACTION_BARN",
        "missionPhase": "activate",
        "allowlist": MISSION_BARN_ALLOWLIST,
        "expectedTargetCount": 2,
        "mode": "mode_barn",
    },
)

EXPECTED_DRIVEN_TARGET_COUNT = sum(
    cohort["expectedTargetCount"] for cohort in COHORTS
)


class DriverCohortError(ValueError):
    """A compiled target matched a cohort but violated its mode contract."""


def _checked_mode(mode: Any) -> str:
    if not isinstance(mode, str) or not mode.startswith("mode_") \
            or not mode.isascii() or any(char in mode for char in "\0\r\n"):
        raise DriverCohortError(
            "compiled capture driver target mode is invalid"
        )
    return mode


def _location_match(
    cohort: Mapping[str, Any], target: Mapping[str, Any],
    trigger: Mapping[str, Any],
) -> dict[str, Any] | None:
    if (
        target.get("evidenceClass") == cohort["evidenceClass"]
        and trigger.get("selector") == cohort["selector"]
        and trigger.get("selectorHookFamily") == cohort["selectorHookFamily"]
    ):
        return {
            "version": cohort["version"],
            "mode": _checked_mode(trigger.get("mode")),
            "cMacro": cohort["cMacro"],
        }
    return None


def _mission_match(
    cohort: Mapping[str, Any], target: Mapping[str, Any],
    trigger: Mapping[str, Any],
) -> dict[str, Any] | None:
    if (
        target.get("evidenceClass") != cohort["evidenceClass"]
        or trigger.get("actionHookFamily") != cohort["actionHookFamily"]
        or trigger.get("missionPhase") != cohort["missionPhase"]
    ):
        return None
    row = (trigger.get("missionKey"), trigger.get("nativeActionOrdinal"))
    if row not in cohort["allowlist"]:
        return None
    if "mode" in cohort:
        mode = cohort["mode"]
    else:
        mode = MODE_BY_DOMAIN.get(trigger.get("domainId"))
        if mode is None:
            raise DriverCohortError(
                "compiled mission capture target domain has no pinned mode"
            )
    return {
        "version": cohort["version"],
        "mode": _checked_mode(mode),
        "cMacro": cohort["cMacro"],
    }


def cohort_for_target(target: Mapping[str, Any]) -> dict[str, Any] | None:
    """Match ``target`` against the declared cohorts; never accept a mode."""

    trigger = target.get("trigger")
    if not isinstance(trigger, Mapping):
        return None
    for cohort in COHORTS:
        if cohort["kind"] == "location":
            selected = _location_match(cohort, target, trigger)
        else:
            selected = _mission_match(cohort, target, trigger)
        if selected is not None:
            return selected
    return None
