#!/usr/bin/env python3
"""Harvest compact gameplay semantics from the pinned Dutch WinHelp source.

The WinHelp topic stream stores its Dutch text as Latin-1 byte runs separated
by formatting records.  This harvester deliberately does not pretend to be a
general WinHelp renderer: it locates a reviewed set of short, exact source
fragments and records their byte positions.  A changed, translated or guessed
fragment is therefore a hard parity failure.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path


WINHELP_MAGIC = bytes.fromhex("3f5f0300")

# Claims are normalized contracts for the web port. Evidence remains concise
# Dutch source text; multi-fragment rules preserve lists split by HLP formatting.
RULES = (
    ("controls", "turn_left", "left turns left", ("Druk de linkerpijltoets in als je naar links wil draaien.",)),
    ("controls", "turn_right", "right turns right", ("Druk de rechterpijltoets in als je naar rechts wil draaien.",)),
    ("controls", "descend", "up descends", ("Druk de vooruit-pijltoets in als je met het vliegtuig wilt dalen, d.w.z. lager vliegen.",)),
    ("controls", "ascend", "down ascends", ("Druk de achteruit-pijltoets in je met het vliegtuig wilt dalen, d.w.z. hoger vliegen.",)),
    ("controls", "accelerate", "shift increases speed", ("Verhoog de snelheid door de shift-toets in te drukken.",)),
    ("controls", "decelerate", "control decreases speed", ("Verminder de snelheid door de ctrl-toets in te drukken.",)),
    ("aircraft_build", "snap_feedback", "compatible attachment points show red arrows and snap on release", ("Als je een onderdeel in de buurt van een plaats op het vliegtuig houdt waar het past, zie je rode pijltjes.", "Laat je de muisknop los, dan zet het onderdeel zich vast op het vliegtuig.")),
    ("aircraft_build", "weight", "excess weight can prevent takeoff and slows flight", ("Het vliegtuig kan misschien niet opstijgen als je het te zwaar maakt.", "Hoe zwaarder het vleigtuig, hoe langzamer het zal vliegen.")),
    ("aircraft_build", "balance", "uneven wing load makes the aircraft unstable", ("Een ongelijkmatige belasting tussen bijvoorbeeld de vleugels maakt het vliegtuig wankel.",)),
    ("aircraft_build", "required_parts", "airworthiness requires motor, fuel tank, fuselage, propeller, wings, nose and tail", ("Opdat een vliegtuig zou werken moet het ten minste bestaan uit volgende onderdelen:", "Motor", "Benzinetank", "Vliegtuigromp", "Propeller", "Vleugels", "Neus", "Staart")),
    ("aircraft_build", "topmost_removal", "covered parts must be removed from the top first", ("Als je het vliegtuig wilt veranderen en onderdelen wilt verwisselen moet je altijd eerst het onderdeel wegnemen dat bovenaan zit.",)),
    ("flight_safety", "takeoff_gate", "the takeoff control drives to the runway and missing required parts block departure", ("Als je klikt op het beeld met vliegtuigje dan rijdt je vliegtuig uit naar de startbaan.", "Als er iets belangrijks ontbreekt aan het vliegtuig dat je heb gebouwd, dan zegt Miel je dit.")),
    ("flight_safety", "landing_and_crash", "landing sites constrain aircraft design and rapid descent risks a crash and ejection", ("anderen kunnen minder goede landingsbanen hebben.", "Vermijd ook het te snel dalen.", "Miel zich met schietstoel en valscherm moet redden.")),
    ("flight_safety", "damage_return", "all damage lamps broken forces a return to the hangar", ("Wanneer alle groene lampjes gebroken zijn moet je naar de vliegtuighangar terug keren",)),
    ("flight_safety", "fuel", "empty fuel requires refuelling at a station", ("Wanneer de benzine op is moet je vullen bij een tankstation.",)),
    ("navigation", "map", "the dashboard map is opened by clicking it and may have unexplored gaps", ("Klik op de kaart in de linkerhoek van het instrumentenbord, zo krijg je een kaart.", "Het kan gebeuren dat niet de hele wereld kon gefotografeerd worden, en dat er delen van de kaart ontbreken.")),
    ("navigation", "compass", "compass red points north and white points south", ("De rode pijl wijst altijd het noorden aan en de witte wijst altijd naar het zuiden",)),
    ("navigation", "radio", "radio reports weather and calls from friends", ("Hier hoor je welk weer het wordt en kan je oproepen van Miel", "s vrienden krijgen.")),
    ("hangar_tools", "part_storage", "parts move between shelves, hangar floor and outdoor build area", ("De vliegtuigonderdelen kan je in de rekken sorteren, ze op de vloer van de hangar leggen of op de bouwplaats erbuiten.",)),
    ("hangar_tools", "door_drag", "dragging a part to the doorway transfers it", ("sleep je het naar de deuropening.",)),
    ("hangar_tools", "toolbox", "the bottom-right toolbox follows the player and exposes contextual choices", ("In de rechter benedenhoek staat Miel", "s gereedschapskist om je te helpen. Die volgt je doorheen het hele spel.")),
    ("hangar_tools", "trash", "the toolbox trash can dismantles the aircraft", ("Klik op de vuilnisbak. Het vliegtuig wordt dan afgebroken.",)),
    ("album_save", "photograph", "camera photographs the aircraft for album storage", ("Door op de camera te klikken kan je een foto van je vliegtuig nemen.", "Dat beeld kan je in het fotoalbum kleven en zo kan je je vliegtuig opslaan.")),
    ("album_save", "album_store", "album page plus left arrow stores a named aircraft", ("Klik op de pagina van het fotoalbum waar je het vliegtuig wil opslaan.", "Klik op de grote rode pijl links.", "Geef je vliegtuig een naam.")),
    ("album_save", "album_load", "right arrow restores the selected aircraft after dismantling the current one", ("Klik op de grote rode pijl rechts.", "Denk er wel aan dat het vliegtuig dat op de bouwsteunen ligt, wordt afgebroken.", "Nu wordt het bewaarde vliegtuig automatisch opnieuw gemonteerd!")),
    ("album_save", "external_file", "green-folder control stores a shareable aircraft file", ("Klik op de map met de groene pijl die in de map staat als je je vliegtuig op de harde schijf wil opslaan.",)),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _locate_fragments(data: bytes, fragments: tuple[str, ...], rule_id: str) -> list[dict[str, object]]:
    evidence = []
    cursor = 0
    first_offset = None
    for fragment in fragments:
        encoded = fragment.encode("latin-1")
        offset = data.find(encoded, cursor)
        if offset < 0:
            raise ValueError(f"Dutch help rule {rule_id} lost exact fragment: {fragment!r}")
        if first_offset is None:
            first_offset = offset
        # Formatting records may separate list entries, but a semantic rule
        # must still remain a local topic-sized run rather than matching text
        # elsewhere in the help corpus.
        if offset - first_offset > 2048:
            raise ValueError(f"Dutch help rule {rule_id} fragments no longer share one topic")
        evidence.append({
            "text": fragment,
            "byte_offset": offset,
            "sha256": _sha256(encoded),
        })
        cursor = offset + len(encoded)
    return evidence


def harvest(help_file: Path) -> dict[str, object]:
    data = help_file.read_bytes()
    if not data.startswith(WINHELP_MAGIC):
        raise ValueError(f"not a Windows 3.x help file: {help_file}")

    categories: dict[str, list[dict[str, object]]] = {}
    for category, rule_id, claim, fragments in RULES:
        categories.setdefault(category, []).append({
            "id": rule_id,
            "claim": claim,
            "evidence": _locate_fragments(data, fragments, f"{category}.{rule_id}"),
        })
    return {
        "schema": 1,
        "source": {
            "filename": help_file.name,
            "format": "MS Windows 3.1 Help",
            "size": len(data),
            "sha256": _sha256(data),
            "encoding": "latin-1 topic text with binary formatting records",
        },
        "policy": {
            "authority": "Dutch player-facing behavior documentation",
            "limit": "Documents intended behavior; executable and extracted data remain authoritative for implementation constants and runtime traces.",
        },
        "counts": {
            "categories": len(categories),
            "rules": len(RULES),
            "evidence_fragments": sum(len(rule[3]) for rule in RULES),
        },
        "categories": categories,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("help_file", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(harvest(args.help_file), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(difflib.unified_diff(
                current.splitlines(keepends=True), encoded.splitlines(keepends=True),
                fromfile=str(args.output), tofile="fresh Dutch help harvest",
            ))
            raise SystemExit(f"Dutch help parity contract drifted:\n{diff}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
