#!/usr/bin/env python3
"""Fail unless every tracked flight contract reproduces from the Dutch ISO sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

try:
    from tools.miel_vliegt.classify_native_graph import (
        build as build_native_map,
        verify_resource_sources,
    )
    from tools.miel_vliegt.map_engine_subsystems import build as build_engine_subsystems
    from tools.miel_vliegt.native_analysis_receipt import build as build_native_receipt
    from tools.miel_vliegt.harvest_ccf_materials import check_assets as check_ccf_assets
    from tools.miel_vliegt.harvest_ccf_materials import write_assets as write_ccf_assets
    from tools.miel_vliegt.harvest_ccf_materials import harvest as harvest_ccf_materials
    from tools.miel_vliegt.harvest_ccf_parts import harvest as harvest_parts
    from tools.miel_vliegt.harvest_ccf_attachments import project_attachments
    from tools.miel_vliegt.harvest_flight_contracts import harvest as harvest_flight
    from tools.miel_vliegt.harvest_hangar_masks import harvest as harvest_masks
    from tools.miel_vliegt.harvest_dutch_help_contract import harvest as harvest_help
    from tools.miel_vliegt.harvest_part_components import harvest as harvest_components
    from tools.miel_vliegt.harvest_uds_contracts import harvest as harvest_barn
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from classify_native_graph import build as build_native_map, verify_resource_sources
    from map_engine_subsystems import build as build_engine_subsystems
    from native_analysis_receipt import build as build_native_receipt
    from harvest_ccf_materials import check_assets as check_ccf_assets
    from harvest_ccf_materials import write_assets as write_ccf_assets
    from harvest_ccf_materials import harvest as harvest_ccf_materials
    from harvest_ccf_parts import harvest as harvest_parts
    from harvest_ccf_attachments import project_attachments
    from harvest_flight_contracts import harvest as harvest_flight
    from harvest_hangar_masks import harvest as harvest_masks
    from harvest_dutch_help_contract import harvest as harvest_help
    from harvest_part_components import harvest as harvest_components
    from harvest_uds_contracts import harvest as harvest_barn

try:
    from tools.parity.binary_sources import analyze_executable_tree
except ModuleNotFoundError:
    parity_root = Path(__file__).resolve().parents[1] / "parity"
    sys.path.insert(0, str(parity_root))
    from binary_sources import analyze_executable_tree


# Imported lazily so unit tests for the remaining source gate do not require
# Capstone. Production parity runs must install tools/parity/requirements.txt.
PeImage = None
analyze_native = None


def _native_analyzer():
    global PeImage, analyze_native
    if PeImage is None or analyze_native is None:
        try:
            from tools.miel_vliegt.analyze_native import PeImage as pe_image, analyze
        except ModuleNotFoundError as error:
            if error.name == "capstone":
                raise ValueError(
                    "native parity requires Capstone from tools/parity/requirements.txt"
                ) from error
            if error.name != "tools":
                raise
            try:
                from analyze_native import PeImage as pe_image, analyze
            except ModuleNotFoundError as direct_error:
                if direct_error.name == "capstone":
                    raise ValueError(
                        "native parity requires Capstone from tools/parity/requirements.txt"
                    ) from direct_error
                raise
        PeImage = pe_image
        analyze_native = analyze
    return PeImage, analyze_native


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
IDENTITY_PATH = REPOSITORY_ROOT / "content/miel_vliegt/source_identity.json"
CONTRACT_ROOT = REPOSITORY_ROOT / "content/miel_vliegt"
FUNCTION_SEEDS_PATH = CONTRACT_ROOT / "native_function_seeds.json"
CCF_TEXTURE_ASSET_ROOT = CONTRACT_ROOT / "ccf-textures"

# Deze afgeleiden staan bewust NIET in git (ISO-/executable-afgeleide
# payloads); ze bestaan alleen lokaal na tools/miel_vliegt/
# regenerate_flight_content.sh. Zonder lokale kopie slaat de gate ze over.
GITIGNORED_CONTRACTS = {
    "uds_flight_parts.json",
    "native_function_index.json",
    "native_code_map.json",
}
WRITE_MODE = False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise ValueError(f"missing {label}: {path}")


def _verify_identity(
    iso: Path, executable: Path, launcher: Path, help_file: Path, cc_dll: Path, udspack_dll: Path
) -> dict[str, object]:
    _require_file(IDENTITY_PATH, "tracked flight source identity")
    identity = json.loads(IDENTITY_PATH.read_text(encoding="utf-8"))
    inputs = {
        "iso": iso,
        "executable": executable,
        "launcher": launcher,
        "help_file": help_file,
        "cc_dll": cc_dll,
        "udspack_dll": udspack_dll,
    }
    for key, path in inputs.items():
        _require_file(path, key.replace("_", " "))
        expected = identity[key]["sha256"]
        actual = _sha256(path)
        if actual != expected:
            raise ValueError(
                f"wrong Miel Vliegt {key.replace('_', ' ')}: {path} "
                f"(sha256 {actual}, expected {expected})"
            )
    return identity


def _assert_contract(name: str, fresh: dict[str, object], *, compact: bool = False) -> None:
    path = CONTRACT_ROOT / name
    separators = (",", ":") if compact else None
    encoded = json.dumps(fresh, indent=None if compact else 2, separators=separators) + "\n"
    if WRITE_MODE:
        path.write_text(encoded, encoding="utf-8")
        return
    if name in GITIGNORED_CONTRACTS and not path.is_file():
        print(f"skip {name}: gitignored payload niet lokaal aanwezig (draai regenerate_flight_content.sh)")
        return
    _require_file(path, f"tracked {name} contract")
    current = path.read_text(encoding="utf-8")
    if current != encoded:
        raise ValueError(
            f"flight source parity drifted for {name}; regenerate it only from the pinned Dutch ISO"
        )


def check(
    source: Path, iso: Path, executable: Path, launcher: Path, help_file: Path,
    cc_dll: Path, udspack_dll: Path, shipped_root: Path | None = None,
) -> dict[str, object]:
    """Run the complete source gate and return a small machine-readable summary."""
    identity = _verify_identity(iso, executable, launcher, help_file, cc_dll, udspack_dll)
    if not (source / "data").is_dir():
        raise ValueError(f"missing extracted Miel Vliegt data directory: {source / 'data'}")

    barn = harvest_barn(source)
    masks = harvest_masks(source)
    flight = harvest_flight(source, executable=executable, help_file=help_file)
    help_contract = harvest_help(help_file)
    parts = harvest_parts(source)
    attachments = project_attachments(parts)
    materials = harvest_ccf_materials(source, parts)
    components = harvest_components(source, parts)
    seeds = json.loads(FUNCTION_SEEDS_PATH.read_text(encoding="utf-8"))
    if seeds.get("image_sha256") != identity["executable"]["sha256"]:
        raise ValueError("native function seeds do not target the pinned executable")
    pe_image, analyze = _native_analyzer()
    native_index = analyze(pe_image(executable), seeds)
    native_map = build_native_map(native_index, seeds)
    native_receipt = build_native_receipt(native_index, native_map)
    verify_resource_sources(source, native_map["resources"])
    engine_subsystems = build_engine_subsystems(native_index, native_map)
    executable_inventory = analyze_executable_tree(shipped_root or executable.parent)
    _assert_contract("uds_barn_contracts.json", barn)
    _assert_contract("uds_hangar_masks.json", masks)
    _assert_contract("uds_flight_contracts.json", flight)
    _assert_contract("dutch_help_contract.json", help_contract)
    _assert_contract("uds_flight_parts.json", parts, compact=True)
    _assert_contract("uds_flight_attachment_targets.json", attachments, compact=True)
    _assert_contract("ccf_material_contract.json", materials)
    if WRITE_MODE:
        write_ccf_assets(materials, source, CCF_TEXTURE_ASSET_ROOT)
    if CCF_TEXTURE_ASSET_ROOT.is_dir():
        check_ccf_assets(materials, CCF_TEXTURE_ASSET_ROOT)
    else:
        print("skip ccf-textures: gitignored assets niet lokaal aanwezig (draai regenerate_flight_content.sh)")
    _assert_contract("uds_flight_part_components.json", components)
    _assert_contract("native_function_index.json", native_index, compact=True)
    _assert_contract("native_code_map.json", native_map, compact=True)
    _assert_contract("native_analysis_receipt.json", native_receipt, compact=True)
    _assert_contract("native_engine_subsystems.json", engine_subsystems, compact=True)
    _assert_contract("shipped_executable_inventory.json", executable_inventory)
    return {
        "edition": "miel-vliegt-de-wereld-rond-nl",
        "iso_sha256": _sha256(iso),
        "contracts": 13,
        "parts": parts["counts"]["parts"],
        "missions": flight["counts"]["mission_declarations"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, required=True, help="original Dutch Mielvliegt.iso")
    parser.add_argument("--source", type=Path, required=True, help="root of decoded UDSP archives")
    parser.add_argument("--executable", type=Path, required=True, help="installed MulleMeck.exe")
    parser.add_argument("--launcher", type=Path, required=True, help="installed Start_Mulle.exe Director launcher")
    parser.add_argument(
        "--shipped-root", type=Path, required=True,
        help="staging root containing both the extracted ISO and installed files; every .exe is inventoried",
    )
    parser.add_argument("--help-file", type=Path, required=True, help="installed Dutch MIELMONTEUR.HLP")
    parser.add_argument("--cc-dll", type=Path, required=True, help="installed Dutch Cc.dll")
    parser.add_argument("--udspack-dll", type=Path, required=True, help="installed Dutch UdsPack.dll")
    parser.add_argument("--write", action="store_true",
                        help="schrijf alle contracten opnieuw i.p.v. asserten (regeneratie)")
    args = parser.parse_args()
    if args.write:
        global WRITE_MODE
        WRITE_MODE = True
    try:
        summary = check(
            args.source, args.iso, args.executable, args.launcher, args.help_file,
            args.cc_dll, args.udspack_dll, args.shipped_root,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(1, f"flight source parity failed: {error}\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
