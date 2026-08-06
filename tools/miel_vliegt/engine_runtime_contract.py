"""Canonical, edition-independent gameplay runtime inventory for flight.

This is deliberately code-owned rather than copied from
``engine_implementation.json``: deleting a ledger row must create a coverage
error, never redefine the required implementation surface.
"""

from __future__ import annotations

from typing import Any


CANONICAL_GAMEPLAY_RUNTIMES = {
    "aircraft_graph": "src/flight/engine/aircraft/AircraftGraph.js",
    "character_script_host": "src/flight/engine/scene/CharacterScriptHost.js",
    "flight_game_session": "src/flight/engine/session/FlightGameSession.js",
    "flight_scene_asset_catalog": "src/flight/engine/resources/FlightSceneAssetCatalog.js",
    "flight_scene_runtime": "src/flight/engine/scene/FlightSceneRuntime.js",
    "mission_runtime": "src/flight/engine/mission/MissionRuntime.js",
    "mygghanget_runtime": "src/flight/engine/scene/MygghangetRuntime.js",
    "scene_dispatch_runtime": "src/flight/engine/scene/SceneDispatchRuntime.js",
    "udsp_scene_runtime": "src/flight/engine/scene/UdspSceneRuntime.js",
}


def validate_gameplay_runtime_inventory(rows: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        raise ValueError("engine gameplay runtimes must be an array")
    identifiers = [row.get("id") if isinstance(row, dict) else None for row in rows]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise ValueError("engine gameplay runtime ids must be unique and sorted")
    actual = set(identifiers)
    required = set(CANONICAL_GAMEPLAY_RUNTIMES)
    if actual != required:
        raise ValueError(
            "engine gameplay runtime coverage mismatch: "
            f"missing={sorted(required - actual)} extra={sorted(actual - required)}"
        )
    result = {row["id"]: row for row in rows}
    for identifier, runtime in CANONICAL_GAMEPLAY_RUNTIMES.items():
        if result[identifier].get("runtime") != runtime:
            raise ValueError(f"{identifier}: canonical runtime owner drifted")
    return result
