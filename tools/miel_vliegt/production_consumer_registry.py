#!/usr/bin/env python3
"""Generate the typed, fail-closed browser production-consumer registry.

Only consumers with a code-owned declaration and an executable integration
test enter this registry. Source tokens, comments and test-only pack names are
never discovery inputs. Missing consumers remain explicit BLOCKED rows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = "content/miel_vliegt/flight_production_consumers.json"
PROTOCOL = "miel-vliegt-flight-production-consumers"
RECEIPT = "content/miel_vliegt/flight_production_consumer_test_receipt.json"
RECEIPT_PROTOCOL = "miel-vliegt-production-consumer-jest-receipt"
RECEIPT_SUITE = "jest.flight.production-consumers"
EDITION = "miel-vliegt-de-wereld-rond-nl"
GAME_REGISTRY = "src/game.js"
GAME_REGISTRATION_TEST = "src/__tests__/game-users22-lingo-parity.test.js"
REGISTRY_SOURCE = "tools/miel_vliegt/production_consumer_registry.py"
RECEIPT_RUNNER = "tools/miel_vliegt/run_production_consumer_receipt.py"
COVERAGE_DIRECTORY = "tmp/miel-vliegt-production-consumer-coverage"
JEST_RESULT = f"{COVERAGE_DIRECTORY}/jest-results.json"

PRODUCTION_STATES = {
    "src/scenes/flight_hangar.js": {
        "state_key": "flight_hangar",
        "binding": "FlightHangarState",
        "import_source": "scenes/flight_hangar",
    },
    "src/scenes/flight_location.js": {
        "state_key": "flight_location",
        "binding": "FlightLocationState",
        "import_source": "scenes/flight_location",
    },
    "src/scenes/flight_mygghanget.js": {
        "state_key": "flight_mygghanget",
        "binding": "FlightMygghangetState",
        "import_source": "scenes/flight_mygghanget",
    },
    "src/scenes/flight_world.js": {
        "state_key": "flight_world",
        "binding": "FlightWorldState",
        "import_source": "scenes/flight_world",
    },
}

# These declarations are deliberately narrow. Adding one is a reviewed code
# change and requires a test which imports and invokes the callable handler at
# the production state boundary.
REGISTERED_CONSUMERS = {
    "parity_observation_surface": {
        "kind": "render-boundary-observation",
        "handler": {
            "module": "src/flight/runtime/FlightParityObservation.js",
            "export": "createFlightParityObservation",
            "type": "function",
        },
        "production_entrypoints": ["src/scenes/flight_world.js"],
        "integration_tests": [
            "src/flight/runtime/__tests__/FlightParityObservation.test.js",
            "src/scenes/__tests__/flight-world-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "flight_world invokes the canonical observation after simulation "
                "and WebGL render and emits it through flightFrameTraceSink"
            ),
        },
    },
    "mygghanget_presentation_consumer": {
        "kind": "static-presentation",
        "handler": {
            "module": "src/flight/browser/FlightPhaserMygghangetProjection.js",
            "export": "attachFlightPhaserMygghangetProjection",
            "type": "function",
        },
        "production_entrypoints": ["src/scenes/flight_mygghanget.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserMygghangetProjection.test.js",
            "src/scenes/__tests__/flight-mygghanget-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "openMygghanget feeds its frozen edition receipt and loaded closure "
                "to the transactional 47-local/8-sky static projection"
            ),
        },
    },
    "location_presentation_consumer": {
        "kind": "candidate-presentation",
        "handler": {
            "module": "src/flight/browser/FlightPhaserLocationProjection.js",
            "export": "attachFlightPhaserLocationProjection",
            "type": "function",
        },
        "production_entrypoints": ["src/scenes/flight_location.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserLocationProjection.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "flight_location binds the frozen runtime arrival and catalog closure "
                "to the source-topology-exact, layout-and-framebuffer-unproven projection"
            ),
        },
    },
    "presenter_opcode:PLAY_CHARACTER_SOUND": {
        "kind": "presenter-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "attachFlightPhaserPresenter",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "function": "playCharacterSound",
        },
        "typed_registry": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "flightPhaserPresenterRegistry",
            "schema": 1,
            "contract": "miel-vliegt-flight-phaser-presenter-registry",
            "record": {
                "opcode": "PLAY_CHARACTER_SOUND",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": [
            "src/scenes/flight_hangar.js",
            "src/scenes/flight_location.js",
        ],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserPresenter.test.js",
            "src/scenes/__tests__/flight-hangar-integration.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": "typed PLAY_CHARACTER_SOUND port plays the runtime-bound catalog asset",
        },
    },
    "presenter_opcode:PLAY_MULLEBARNSOUND": {
        "kind": "presenter-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "attachFlightPhaserPresenter",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "function": "playMulleBarnSound",
        },
        "typed_registry": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "flightPhaserPresenterRegistry",
            "schema": 1,
            "contract": "miel-vliegt-flight-phaser-presenter-registry",
            "record": {
                "opcode": "PLAY_MULLEBARNSOUND",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": ["src/scenes/flight_hangar.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserPresenter.test.js",
            "src/scenes/__tests__/flight-hangar-integration.test.js",
        ],
        "integration": {
            "assertion": "typed PLAY_MULLEBARNSOUND port plays the runtime-bound barn asset",
        },
    },
    "presenter_opcode:PLAY_CHARACTER_ANIMATION": {
        "kind": "presenter-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "attachFlightPhaserPresenter",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "function": "playCharacterAnimation",
        },
        "typed_registry": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "flightPhaserPresenterRegistry",
            "schema": 1,
            "contract": "miel-vliegt-flight-phaser-presenter-registry",
            "record": {
                "opcode": "PLAY_CHARACTER_ANIMATION",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": [
            "src/scenes/flight_hangar.js",
            "src/scenes/flight_location.js",
        ],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserPresenter.test.js",
            "src/scenes/__tests__/flight-hangar-integration.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "typed PLAY_CHARACTER_ANIMATION port executes the source-bound actor runtime; "
                "native callback timing and framebuffer parity remain separately UNPROVEN"
            ),
        },
    },
    "presenter_opcode:POSITION_CHARACTER": {
        "kind": "presenter-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "attachFlightPhaserPresenter",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "function": "positionCharacter",
        },
        "typed_registry": {
            "module": "src/flight/browser/FlightPhaserPresenter.js",
            "export": "flightPhaserPresenterRegistry",
            "schema": 1,
            "contract": "miel-vliegt-flight-phaser-presenter-registry",
            "record": {
                "opcode": "POSITION_CHARACTER",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": [
            "src/scenes/flight_hangar.js",
            "src/scenes/flight_location.js",
        ],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserPresenter.test.js",
            "src/scenes/__tests__/flight-hangar-integration.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "typed POSITION_CHARACTER port performs the transactional actor-root projection; "
                "native coordinate-space and framebuffer parity remain separately UNPROVEN"
            ),
        },
    },
    "presenter_opcode:AWARD_DIPLOMA": {
        "kind": "engine-service-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserSession.js",
            "export": "ensureFlightGameSession",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "function": "awardDiploma",
        },
        "typed_registry": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "export": "nativeUdspServicePortRegistry",
            "schema": 1,
            "contract": "miel-vliegt-native-udsp-service-port-registry",
            "record": {
                "opcode": "AWARD_DIPLOMA",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": ["src/scenes/flight_location.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserSession.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "session-owned AWARD_DIPLOMA persists the exact DIPL slot before "
                "returning its source-bound award and manager media contract"
            ),
        },
    },
    "presenter_opcode:JUDGE_AIRPLANE": {
        "kind": "engine-service-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserSession.js",
            "export": "ensureFlightGameSession",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "function": "judgeAirplane",
        },
        "typed_registry": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "export": "nativeUdspServicePortRegistry",
            "schema": 1,
            "contract": "miel-vliegt-native-udsp-service-port-registry",
            "record": {
                "opcode": "JUDGE_AIRPLANE",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": ["src/scenes/flight_location.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserSession.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "session-owned JUDGE_AIRPLANE evaluates the current active-aircraft "
                "graph and returns its exact score, media and presentation contract"
            ),
        },
    },
    "presenter_opcode:PLAY_SOUND": {
        "kind": "engine-service-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserSession.js",
            "export": "ensureFlightGameSession",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "function": "playSound",
        },
        "typed_registry": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "export": "nativeUdspServicePortRegistry",
            "schema": 1,
            "contract": "miel-vliegt-native-udsp-service-port-registry",
            "record": {
                "opcode": "PLAY_SOUND",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": ["src/scenes/flight_location.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserSession.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "session-owned PLAY_SOUND resolves the edition asset and executes "
                "the pinned UDSP script through the Phaser native-audio adapter"
            ),
        },
    },
    "presenter_opcode:PLAY_RADIO": {
        "kind": "engine-service-opcode",
        "handler": {
            "module": "src/flight/browser/FlightPhaserSession.js",
            "export": "ensureFlightGameSession",
            "type": "function",
        },
        "execution_target": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "function": "playRadio",
        },
        "typed_registry": {
            "module": "src/flight/engine/session/NativeUdspServicePortCoordinator.js",
            "export": "nativeUdspServicePortRegistry",
            "schema": 1,
            "contract": "miel-vliegt-native-udsp-service-port-registry",
            "record": {
                "opcode": "PLAY_RADIO",
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            },
        },
        "production_entrypoints": ["src/scenes/flight_location.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightPhaserSession.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ],
        "integration": {
            "assertion": (
                "session-owned PLAY_RADIO enqueues the edition asset and advances "
                "the native service after the scene on the same session tick"
            ),
        },
    },
    "asset_pack:flight_scene_location_mygghanget": {
        "kind": "asset-pack",
        "handler": {
            "module": "src/flight/browser/FlightScenePackPreloader.js",
            "export": "preloadFlightSceneAssetClosure",
            "type": "function",
        },
        "production_entrypoints": ["src/scenes/flight_mygghanget.js"],
        "integration_tests": [
            "src/flight/browser/__tests__/FlightScenePackPreloader.test.js",
            "src/scenes/__tests__/flight-mygghanget-integration.test.js",
        ],
        "integration": {
            "assertion": "exact catalog closure is passed to Phaser loader.pack",
        },
    },
}


def _asset_pack_declaration(identifier: str) -> dict[str, Any]:
    if identifier == "asset_pack:flight_scene_barn":
        entrypoints = ["src/scenes/flight_hangar.js"]
        tests = [
            "src/flight/browser/__tests__/FlightScenePackPreloader.test.js",
            "src/scenes/__tests__/flight-hangar-integration.test.js",
        ]
        assertion = "barn catalog closure is passed to Phaser loader.pack"
    elif identifier == "asset_pack:flight_scene_shared":
        entrypoints = [
            "src/scenes/flight_hangar.js",
            "src/scenes/flight_location.js",
            "src/scenes/flight_mygghanget.js",
        ]
        tests = [
            "src/flight/browser/__tests__/FlightScenePackPreloader.test.js",
            "src/scenes/__tests__/flight-hangar-integration.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
            "src/scenes/__tests__/flight-mygghanget-integration.test.js",
        ]
        assertion = "shared dependency precedes each catalog-owned scene pack"
    elif identifier == "asset_pack:flight_scene_location_mygghanget":
        return REGISTERED_CONSUMERS[identifier]
    else:
        entrypoints = ["src/scenes/flight_location.js"]
        tests = [
            "src/flight/browser/__tests__/FlightScenePackPreloader.test.js",
            "src/scenes/__tests__/flight-location-integration.test.js",
        ]
        assertion = "location catalog closure is passed to Phaser loader.pack"
    return {
        "kind": "asset-pack",
        "handler": {
            "module": "src/flight/browser/FlightScenePackPreloader.js",
            "export": "preloadFlightSceneAssetClosure",
            "type": "function",
        },
        "production_entrypoints": entrypoints,
        "integration_tests": tests,
        "integration": {
            "assertion": assertion,
        },
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identity(root: Path, relative: str) -> dict[str, str]:
    path = (root / relative).resolve()
    path.relative_to(root.resolve())
    if not path.is_file():
        raise ValueError(f"production consumer source is missing: {relative}")
    return {"path": relative, "sha256": _sha256(path)}


def _declaration(identifier: str) -> dict[str, Any] | None:
    declaration = REGISTERED_CONSUMERS.get(identifier)
    if declaration is None and identifier.startswith("asset_pack:"):
        declaration = _asset_pack_declaration(identifier)
    return declaration


def _release_tests(declaration: dict[str, Any]) -> list[str]:
    return sorted(
        path for path in declaration["integration_tests"]
        if path.startswith("src/scenes/__tests__/")
        and path.endswith("-integration.test.js")
    )


def _entrypoint_call_lines(
    root: Path, entrypoint: str, module: str, export: str,
) -> list[int]:
    path = root / entrypoint
    if not path.is_file():
        return []
    source = _strip_js_comments(path.read_text(encoding="utf-8"))
    import_source = os.path.relpath(
        module.removesuffix(".js"), Path(entrypoint).parent.as_posix(),
    ).replace(os.sep, "/")
    if not import_source.startswith("."):
        import_source = f"./{import_source}"
    imports = re.findall(
        rf"\bimport[ \t\r\n]*\{{(.*?)\}}[ \t\r\n]*from[ \t]+"
        rf"['\"]{re.escape(import_source)}['\"]",
        source,
        re.DOTALL,
    )
    if len(imports) != 1 or len(re.findall(rf"\b{re.escape(export)}\b", imports[0])) != 1:
        return []
    matches = list(re.finditer(rf"\b{re.escape(export)}[ \t\r\n]*\(", source))
    return [source.count("\n", 0, match.start()) + 1 for match in matches]


def proof_spec(required_ids: list[str], root: Path = ROOT) -> dict[str, Any]:
    """Return the one deterministic Jest/coverage proof required by the registry."""
    declarations = {
        identifier: _declaration(identifier)
        for identifier in required_ids
    }
    proven = {
        identifier: declaration
        for identifier, declaration in declarations.items()
        if declaration is not None
    }
    handlers = sorted({
        (declaration["handler"]["module"], declaration["handler"]["export"])
        for declaration in proven.values()
    })
    tests = sorted({
        path for declaration in proven.values()
        for path in declaration["integration_tests"]
    } | {GAME_REGISTRATION_TEST})
    entrypoints = sorted({
        path for declaration in proven.values()
        for path in declaration["production_entrypoints"]
    })
    if not tests or any(not _release_tests(declaration) for declaration in proven.values()):
        raise ValueError("every production consumer requires a scene-bound integration test")
    unknown_entrypoints = set(entrypoints) - set(PRODUCTION_STATES)
    if unknown_entrypoints:
        raise ValueError(f"production states lack registry identities: {sorted(unknown_entrypoints)}")
    execution_functions = sorted({
        (target["module"], target["function"])
        for declaration in proven.values()
        for target in [declaration.get("execution_target")]
        if target is not None
    } | {(GAME_REGISTRY, "setup")})
    pack_assertions = sorted(
        f"production pack receipt {identifier.split(':', 1)[1]}"
        for identifier in proven
        if identifier.startswith("asset_pack:")
    )
    modules = sorted(
        {module for module, _ in handlers}
        | {module for module, _ in execution_functions}
    )
    entrypoint_calls = []
    for declaration in proven.values():
        handler = declaration["handler"]
        for entrypoint in declaration["production_entrypoints"]:
            row = {
                "entrypoint": entrypoint,
                "module": handler["module"],
                "export": handler["export"],
                "call_lines": _entrypoint_call_lines(
                    root, entrypoint, handler["module"], handler["export"]
                ),
            }
            if row not in entrypoint_calls:
                entrypoint_calls.append(row)
    entrypoint_calls.sort(key=lambda row: (
        row["entrypoint"], row["module"], row["export"]
    ))
    command = [
        "./node_modules/.bin/jest",
        "--runInBand",
        "--runTestsByPath",
        *tests,
        "--coverage",
        "--coverageProvider=babel",
        "--coverageReporters=json",
        f"--coverageDirectory={COVERAGE_DIRECTORY}",
        "--json",
        f"--outputFile={JEST_RESULT}",
        *(f"--collectCoverageFrom={module}" for module in sorted({*modules, *entrypoints})),
    ]
    return {
        "schema": 1,
        "protocol": RECEIPT_PROTOCOL,
        "edition": EDITION,
        "suite_id": RECEIPT_SUITE,
        "consumer_ids": sorted(proven),
        "command": command,
        "tests": tests,
        "handlers": [
            {"module": module, "export": export}
            for module, export in handlers
        ],
        "execution_functions": [
            {"module": module, "function": function}
            for module, function in execution_functions
        ],
        "pack_assertions": pack_assertions,
        "entrypoint_calls": entrypoint_calls,
        "runtime_paths": sorted({
            GAME_REGISTRY, REGISTRY_SOURCE, RECEIPT_RUNNER,
            *modules, *entrypoints, *tests,
        }),
    }


def _strip_js_comments(source: str) -> str:
    """Remove comments while preserving strings and line numbers."""
    output: list[str] = []
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if quote is not None:
            output.append(current)
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
            index += 1
            continue
        if current in {"'", '"', "`"}:
            quote = current
            output.append(current)
            index += 1
            continue
        if current == "/" and following == "/":
            output.extend("  ")
            index += 2
            while index < len(source) and source[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        if current == "/" and following == "*":
            output.extend("  ")
            index += 2
            while index < len(source):
                if source[index:index + 2] == "*/":
                    output.extend("  ")
                    index += 2
                    break
                output.append("\n" if source[index] == "\n" else " ")
                index += 1
            continue
        output.append(current)
        index += 1
    return "".join(output)


def _exported_function_line(root: Path, module: str, export: str) -> int | None:
    path = root / module
    if not path.is_file():
        return None
    source = _strip_js_comments(path.read_text(encoding="utf-8"))
    pattern = re.compile(
        rf"^[ \t]*export[ \t]+function[ \t]+{re.escape(export)}[ \t]*\(",
        re.MULTILINE,
    )
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        return None
    return source.count("\n", 0, matches[0].start()) + 1


def _function_line(root: Path, module: str, function: str) -> int | None:
    path = root / module
    if not path.is_file():
        return None
    source = _strip_js_comments(path.read_text(encoding="utf-8"))
    patterns = (
        re.compile(
            rf"^[ \t]*export[ \t]+function[ \t]+{re.escape(function)}[ \t]*\(",
            re.MULTILINE,
        ),
        re.compile(
            rf"^[ \t]+(?:async[ \t]+)?{re.escape(function)}[ \t]*\(",
            re.MULTILINE,
        ),
    )
    matches = [match for pattern in patterns for match in pattern.finditer(source)]
    if len(matches) != 1:
        return None
    return source.count("\n", 0, matches[0].start()) + 1


def _has_named_export(root: Path, module: str, export: str) -> bool:
    path = root / module
    if not path.is_file():
        return False
    source = _strip_js_comments(path.read_text(encoding="utf-8"))
    declaration = re.compile(
        rf"^[ \t]*export[ \t]+(?:const|let|var|class|function)[ \t]+{re.escape(export)}\b",
        re.MULTILINE,
    )
    return len(declaration.findall(source)) == 1


def _state_registration(root: Path, entrypoint: str) -> dict[str, Any] | None:
    expected = PRODUCTION_STATES[entrypoint]
    path = root / GAME_REGISTRY
    if not path.is_file():
        return None
    source = _strip_js_comments(path.read_text(encoding="utf-8"))
    binding = re.escape(expected["binding"])
    import_source = re.escape(expected["import_source"])
    state_key = re.escape(expected["state_key"])
    imports = re.findall(
        rf"\bimport[ \t]+{binding}[ \t]+from[ \t]+['\"]{import_source}['\"]",
        source,
    )
    state_blocks = re.findall(
        r"\bthis\.mulle\.states[ \t]*=[ \t]*\{(.*?)^[ \t]{4}\}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    registrations = re.findall(
        rf"\b{state_key}[ \t]*:[ \t]*{binding}\b",
        state_blocks[0] if len(state_blocks) == 1 else "",
    )
    installers = re.findall(
        r"\bthis\.state\.add\([ \t]*i[ \t]*,[ \t]*this\.mulle\.states\[i\][ \t]*\)",
        source,
    )
    if len(imports) != 1 or len(registrations) != 1 or len(installers) != 1:
        return None
    return {
        "entrypoint": _identity(root, entrypoint),
        "game_registry": _identity(root, GAME_REGISTRY),
        **expected,
    }


def _load_receipt(root: Path) -> dict[str, Any] | None:
    path = root / RECEIPT
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _receipt_proof(
    required_ids: list[str], root: Path,
) -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, Any]],
    dict[str, Any] | None,
]:
    spec = proof_spec(required_ids, root)
    receipt = _load_receipt(root)
    if receipt is None:
        return {}, {}, {}, None
    expected_hashes = {
        relative: _sha256(root / relative)
        for relative in spec["runtime_paths"]
        if (root / relative).is_file()
    }
    static_fields = {
        key: spec[key]
        for key in (
            "schema", "protocol", "edition", "suite_id", "consumer_ids",
            "command", "tests", "handlers", "entrypoint_calls",
            "execution_functions",
            "pack_assertions",
        )
    }
    if any(receipt.get(key) != value for key, value in static_fields.items()) \
            or expected_hashes.keys() != set(spec["runtime_paths"]) \
            or receipt.get("runtime_hashes") != expected_hashes \
            or receipt.get("result") != "PASS" or receipt.get("exit_code") != 0:
        return {}, {}, {}, receipt
    invocations = receipt.get("handler_invocations")
    if not isinstance(invocations, list):
        return {}, {}, {}, receipt
    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for row in invocations:
        if not isinstance(row, dict):
            return {}, {}, {}, receipt
        identity = (row.get("module"), row.get("export"))
        line = _exported_function_line(root, *identity) \
            if all(isinstance(value, str) for value in identity) else None
        if identity in by_identity or line is None or row != {
            "module": identity[0],
            "export": identity[1],
            "function_line": line,
            "invocation_count": row.get("invocation_count"),
        } or not isinstance(row.get("invocation_count"), int) \
                or isinstance(row.get("invocation_count"), bool) \
                or row["invocation_count"] <= 0:
            return {}, {}, {}, receipt
        by_identity[identity] = row
    expected_identities = {
        (row["module"], row["export"])
        for row in spec["handlers"]
    }
    if set(by_identity) != expected_identities:
        return {}, {}, {}, receipt
    function_rows = receipt.get("function_invocations")
    if not isinstance(function_rows, list):
        return {}, {}, {}, receipt
    by_function: dict[tuple[str, str], dict[str, Any]] = {}
    expected_functions = {
        (row["module"], row["function"]): row
        for row in spec["execution_functions"]
    }
    for row in function_rows:
        if not isinstance(row, dict):
            return {}, {}, {}, receipt
        identity = (row.get("module"), row.get("function"))
        expected = expected_functions.get(identity)
        line = _function_line(root, *identity) \
            if all(isinstance(value, str) for value in identity) else None
        if expected is None or identity in by_function or line is None or row != {
            **expected,
            "function_line": line,
            "invocation_count": row.get("invocation_count"),
        } or not isinstance(row.get("invocation_count"), int) \
                or isinstance(row.get("invocation_count"), bool) \
                or row["invocation_count"] <= 0:
            return {}, {}, {}, receipt
        by_function[identity] = row
    if set(by_function) != set(expected_functions):
        return {}, {}, {}, receipt
    expected_pack_results = [
        {"title": title, "status": "passed"}
        for title in spec["pack_assertions"]
    ]
    if receipt.get("pack_assertion_results") != expected_pack_results:
        return {}, {}, {}, receipt
    call_rows = receipt.get("entrypoint_invocations")
    if not isinstance(call_rows, list):
        return {}, {}, {}, receipt
    by_callsite: dict[tuple[str, str, str], dict[str, Any]] = {}
    expected_calls = {
        (row["entrypoint"], row["module"], row["export"]): row
        for row in spec["entrypoint_calls"]
    }
    for row in call_rows:
        if not isinstance(row, dict):
            return {}, {}, {}, receipt
        identity = (row.get("entrypoint"), row.get("module"), row.get("export"))
        expected = expected_calls.get(identity)
        if expected is None or identity in by_callsite or row != {
            **expected,
            "invocation_count": row.get("invocation_count"),
        } or not isinstance(row.get("invocation_count"), int) \
                or isinstance(row.get("invocation_count"), bool) \
                or row["invocation_count"] <= 0:
            return {}, {}, {}, receipt
        by_callsite[identity] = row
    if set(by_callsite) != set(expected_calls):
        return {}, {}, {}, receipt
    return by_identity, by_callsite, by_function, receipt


def build(required_ids: list[str], root: Path = ROOT) -> dict[str, Any]:
    if required_ids != sorted(set(required_ids)) or not required_ids:
        raise ValueError("production consumer requirements must be unique and sorted")
    unknown = set(REGISTERED_CONSUMERS) - set(required_ids)
    if unknown:
        raise ValueError(f"production consumer registry has unknown declarations: {sorted(unknown)}")
    invocation_proofs, entrypoint_proofs, function_proofs, receipt = _receipt_proof(
        required_ids, root
    )
    consumers = []
    for identifier in required_ids:
        declaration = _declaration(identifier)
        if declaration is None:
            consumers.append({
                "id": identifier,
                "status": "BLOCKED",
                "handler": None,
                "production_entrypoints": [],
                "integration_tests": [],
                "integration": None,
            })
            continue
        handler = declaration["handler"]
        integration = declaration["integration"]
        typed_registry = declaration.get("typed_registry")
        if handler.get("type") != "function" \
                or not isinstance(integration.get("assertion"), str) \
                or not integration["assertion"]:
            raise ValueError(f"production consumer is not callable and integration-proven: {identifier}")
        opcode_registry_contracts = {
            "presenter-opcode": "miel-vliegt-flight-phaser-presenter-registry",
            "engine-service-opcode": "miel-vliegt-native-udsp-service-port-registry",
        }
        expected_registry_contract = opcode_registry_contracts.get(declaration["kind"])
        if expected_registry_contract is not None and (
            not isinstance(typed_registry, dict)
            or typed_registry.get("schema") != 1
            or typed_registry.get("contract")
            != expected_registry_contract
            or not isinstance(typed_registry.get("export"), str)
            or typed_registry.get("record") != {
                "opcode": identifier.split(":", 1)[1],
                "status": "COMPLETE",
                "handlerType": "function",
                "blocker": None,
            }
        ):
            raise ValueError(f"presenter consumer lacks its typed registry contract: {identifier}")
        invocation = invocation_proofs.get((handler["module"], handler["export"]))
        execution_target = declaration.get("execution_target")
        execution = function_proofs.get((
            execution_target["module"], execution_target["function"]
        )) if execution_target else invocation
        setup_invocation = function_proofs.get((GAME_REGISTRY, "setup"))
        callsites = [
            entrypoint_proofs.get((entrypoint, handler["module"], handler["export"]))
            for entrypoint in declaration["production_entrypoints"]
        ]
        registrations = [
            _state_registration(root, entrypoint)
            for entrypoint in declaration["production_entrypoints"]
        ]
        release_tests = _release_tests(declaration)
        handler_invoked = invocation is not None and invocation["invocation_count"] > 0 \
            and execution is not None and execution["invocation_count"] > 0
        release_reachable = bool(registrations) and all(registrations) \
            and bool(callsites) and all(callsites) and setup_invocation is not None
        test_passed = receipt is not None and receipt.get("result") == "PASS" \
            and receipt.get("exit_code") == 0
        proof_complete = handler_invoked and release_reachable and test_passed \
            and receipt is not None \
            and set(release_tests).issubset(receipt.get("tests", [])) \
            and _has_named_export(root, handler["module"], handler["export"])
        if identifier.startswith("asset_pack:"):
            title = f"production pack receipt {identifier.split(':', 1)[1]}"
            proof_complete = proof_complete and {
                "title": title, "status": "passed"
            } in receipt.get("pack_assertion_results", [])
        if typed_registry:
            proof_complete = proof_complete and _has_named_export(
                root, typed_registry["module"], typed_registry["export"]
            )
        if not proof_complete:
            consumers.append({
                "id": identifier,
                "kind": declaration["kind"],
                "status": "BLOCKED",
                "handler": None,
                "typed_registry": None,
                "production_entrypoints": [],
                "integration_tests": [],
                "integration": None,
                "blocker": (
                    "fresh executable Jest invocation, named export, or game-state "
                    "registration proof is missing"
                ),
            })
            continue
        consumers.append({
            "id": identifier,
            "kind": declaration["kind"],
            "status": "COMPLETE",
            "handler": {
                **handler,
                "source": _identity(root, handler["module"]),
            },
            "typed_registry": {
                **typed_registry,
                "source": _identity(root, typed_registry["module"]),
            } if typed_registry else None,
            "production_entrypoints": [
                _identity(root, path) for path in declaration["production_entrypoints"]
            ],
            "integration_tests": [
                _identity(root, path) for path in declaration["integration_tests"]
            ],
            "integration": {
                "status": receipt["result"],
                "release_reachable": release_reachable,
                "handler_invoked": handler_invoked,
                "assertion": integration["assertion"],
                "test_receipt": {
                    "source": _identity(root, RECEIPT),
                    "suite_id": receipt["suite_id"],
                    "handler": invocation,
                    "execution": execution,
                    "game_setup": setup_invocation,
                    "asset_pack_assertion": (
                        f"production pack receipt {identifier.split(':', 1)[1]}"
                        if identifier.startswith("asset_pack:") else None
                    ),
                    "production_callsites": callsites,
                    "release_tests": [
                        _identity(root, path) for path in release_tests
                    ],
                },
                "state_registrations": registrations,
            },
        })
    return {
        "schema": 1,
        "protocol": PROTOCOL,
        "policy": {
            "source_tokens_are_evidence": False,
            "callable_handler_required": True,
            "release_reachable_integration_required": True,
            "executable_jest_receipt_required": True,
            "positive_handler_coverage_required": True,
            "game_state_registration_required": True,
            "edition_scope": EDITION,
        },
        "consumers": consumers,
    }


def validate(document: dict[str, Any], required_ids: list[str], root: Path = ROOT) -> None:
    expected = build(required_ids, root)
    if document != expected:
        raise ValueError("flight production consumer registry drifted")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    requirements = json.loads(args.requirements.read_text(encoding="utf-8"))
    if not isinstance(requirements, list):
        raise SystemExit("production consumer requirements must be a JSON array")
    value = build(requirements, root)
    output = root / OUTPUT
    encoded = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    if args.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != encoded:
            raise SystemExit("flight production consumer registry drifted")
    else:
        output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
