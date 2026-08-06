#!/usr/bin/env python3
"""Build the edition-specific web asset pack for every Miel Vliegt scene.

The scene and character domains come from the checked-in dispatch/UDSP
contracts. Voice files are resolved by combining the edition executable's
native owner-prefix table and filename-builder contract with the actual sound
archive. Nothing here guesses locale paths or speaker initials: ambiguous
native evidence stops generation and exact zero matches remain explicit
``ABSENT_NO_COMMAND_NODE`` records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Callable, Iterable, Protocol

try:
    from tools.miel_vliegt import native_udsp_scene_commands
    from tools.miel_vliegt.decode_gti import decode_gti
    from tools.miel_vliegt.export_web_assets import encode_png
    from tools.miel_vliegt.extract_udsp import UdspArchive
    from tools.miel_vliegt.native_mygghanget_contract import (
        extract_native_mygghanget_contract,
    )
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    import native_udsp_scene_commands
    from decode_gti import decode_gti
    from export_web_assets import encode_png
    from extract_udsp import UdspArchive
    from native_mygghanget_contract import extract_native_mygghanget_contract


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DISPATCH = ROOT / "content/miel_vliegt/scene_dispatch_contract.json"
DEFAULT_SCRIPTS = ROOT / "content/miel_vliegt/uds_scene_scripts.json"
DEFAULT_NATIVE_UDSP = ROOT / "content/miel_vliegt/native_udsp_scene_commands.json"
VOICE_RE = re.compile(
    r"^(?P<prefix>[a-z]{2})(?P<take>\d{2})(?P<clip>\d{4})(?P<bank>[a-z]{1,2})\.wav$",
    re.IGNORECASE,
)
VOICE_OPCODES = {"PLAY_CHARACTER_SOUND", "PLAY_SOUND", "PLAY_RADIO"}
BARN_OPCODE = "PLAY_MULLEBARNSOUND"
MYGGHANGET_OPCODE = "NATIVE_MYGGHANGET_VOICE"
RADIO_ALERT_OPCODE = "NATIVE_RADIO_ALERT"
JUDGE_AUDIO_OPCODE = "NATIVE_JUDGE_AIRPLANE_AUDIO"
AWARD_AUDIO_OPCODE = "NATIVE_AWARD_DIPLOMA_AUDIO"
DIPLOMA_MANAGER_AUDIO_OPCODE = "NATIVE_DIPLOMA_MANAGER_AUDIO"
EXACT_NATIVE_SERVICE_AUDIO_OPCODES = frozenset({
    JUDGE_AUDIO_OPCODE,
    AWARD_AUDIO_OPCODE,
    DIPLOMA_MANAGER_AUDIO_OPCODE,
})
RADIO_ALERT_CLIPS = (43, 44)
SKY_TILE_RE = re.compile(
    r"^(?P<bank>[a-z]+)(?P<row>\d+)_(?P<column>\d+)\.gti$", re.IGNORECASE
)
VOICE_FORMATS = (
    b"data\\sound\\voices\\%s%02u%04u.wav",
    b"data\\sound\\voices\\%s\\%s%02u%04u%s.wav",
)
TAKE_SCAN_SIGNATURE = bytes.fromhex("4383fb640f8c")
NO_NODE_SIGNATURE = bytes.fromhex("83ff01755b33ff")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path_key(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def _slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not result:
        raise ValueError(f"cannot derive asset key from {value!r}")
    return result


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


@dataclass(frozen=True)
class SourceEntry:
    path: str
    read: Callable[[], bytes]


class AssetSource(Protocol):
    provenance: dict[str, object]

    def entries(self) -> list[SourceEntry]: ...


class DirectorySource:
    """Case-insensitive view of one extracted UDSP source tree."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        if not self.root.is_dir():
            raise ValueError(f"missing extracted UDSP source root: {root}")
        self._entries = [
            SourceEntry(path.relative_to(self.root).as_posix(), path.read_bytes)
            for path in sorted(self.root.rglob("*"))
            if path.is_file()
        ]
        digest = hashlib.sha256()
        for entry in sorted(self._entries, key=lambda item: _path_key(item.path)):
            digest.update(_path_key(entry.path).encode())
            digest.update(b"\0")
            digest.update(hashlib.sha256(entry.read()).digest())
        self.provenance = {
            "kind": "extracted-directory",
            "tree_sha256": digest.hexdigest(),
            "file_count": len(self._entries),
        }

    def entries(self) -> list[SourceEntry]:
        return self._entries


class ArchiveSource:
    """Read-only decoded view of a single UDSP archive."""

    def __init__(self, path: Path):
        self.archive = UdspArchive(path)
        self._entries = [
            SourceEntry(
                entry.path.replace("\\", "/"),
                lambda entry=entry: self.archive.payload(entry),
            )
            for entry in self.archive.files
        ]
        self.provenance = {
            "kind": "udsp-archive",
            "archive": path.name,
            "sha256": _sha256(path.read_bytes()),
            "udsp_version": (
                f"{self.archive.header.version_major}.{self.archive.header.version_minor}"
            ),
            "file_count": len(self._entries),
        }

    def entries(self) -> list[SourceEntry]:
        return self._entries


class SourceIndex:
    def __init__(self, sources: Iterable[AssetSource]):
        self.sources = []
        seen_sources: set[int] = set()
        for source in sources:
            if id(source) not in seen_sources:
                self.sources.append(source)
                seen_sources.add(id(source))
        self._entries: dict[str, SourceEntry] = {}
        for source in self.sources:
            source_paths: set[str] = set()
            for entry in source.entries():
                key = _path_key(entry.path)
                if key in source_paths:
                    raise ValueError(
                        f"duplicate case-insensitive source path: {entry.path}"
                    )
                source_paths.add(key)
                previous = self._entries.get(key)
                if previous is not None:
                    if previous.read() != entry.read():
                        raise ValueError(
                            "conflicting case-insensitive source path: "
                            f"{previous.path} / {entry.path}"
                        )
                    continue
                self._entries[key] = entry

    def under(self, prefix: str, *, suffix: str | None = None) -> list[SourceEntry]:
        normalized = _path_key(prefix).rstrip("/") + "/"
        entries = [
            entry
            for key, entry in self._entries.items()
            if key.startswith(normalized) and (suffix is None or key.endswith(suffix.lower()))
        ]
        return sorted(entries, key=lambda entry: _path_key(entry.path))


class _PeImage:
    """Small dependency-free PE32 mapper for native asset provenance."""

    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError(f"{path}: native voice contract requires a PE executable")
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise ValueError(f"{path}: invalid PE signature")
        coff = pe + 4
        machine, count, _, _, _, optional_size, _ = struct.unpack_from(
            "<HHIIIHH", self.data, coff
        )
        optional = coff + 20
        if machine != 0x14C or struct.unpack_from("<H", self.data, optional)[0] != 0x10B:
            raise ValueError(f"{path}: native voice contract requires PE32 i386")
        self.image_base = struct.unpack_from("<I", self.data, optional + 28)[0]
        section_offset = optional + optional_size
        self.sections = []
        for index in range(count):
            offset = section_offset + index * 40
            name, _, virtual_address, raw_size, raw_offset, _, _, _, _, _ = struct.unpack_from(
                "<8sIIIIIIHHI", self.data, offset
            )
            self.sections.append({
                "name": name.rstrip(b"\0").decode("ascii"),
                "address": self.image_base + virtual_address,
                "rawSize": raw_size,
                "rawOffset": raw_offset,
            })

    def offset_to_address(self, offset: int) -> int:
        for section in self.sections:
            delta = offset - section["rawOffset"]
            if 0 <= delta < section["rawSize"]:
                return section["address"] + delta
        raise ValueError(f"file offset {offset:#x} is not inside a PE section")


def _all_offsets(data: bytes, needle: bytes) -> list[int]:
    offsets = []
    cursor = 0
    while True:
        cursor = data.find(needle, cursor)
        if cursor < 0:
            return offsets
        offsets.append(cursor)
        cursor += 1


def extract_native_voice_contract(
    executable: Path, required_owners: Iterable[str]
) -> dict[str, object]:
    """Extract the native owner table and exact WAV-builder evidence."""
    image = _PeImage(executable)
    required = set(required_owners) | {"mulle"}
    candidates = []
    for offset in range(len(image.data) - 35):
        records = []
        cursor = offset
        while cursor + 35 <= len(image.data):
            raw = image.data[cursor:cursor + 35]
            name_field, prefix_field = raw[:32], raw[32:]
            if b"\0" not in name_field:
                break
            name = name_field.split(b"\0", 1)[0]
            prefix = prefix_field[:2]
            if (
                not name
                or any(
                    byte not in range(ord("a"), ord("z") + 1)
                    and byte not in range(ord("0"), ord("9") + 1)
                    and byte != ord("_")
                    for byte in name
                )
                or len(prefix) != 2
                or any(byte not in range(ord("a"), ord("z") + 1) for byte in prefix)
                or prefix_field[2:] != b"\0"
                or any(name_field[len(name) + 1:])
            ):
                break
            records.append({"owner": name.decode("ascii"), "prefix": prefix.decode("ascii")})
            cursor += 35
        names = {record["owner"] for record in records}
        if required.issubset(names):
            candidates.append((offset, records))
    if len(candidates) != 1:
        raise ValueError(
            f"native executable exposes {len(candidates)} voice-prefix tables for owners "
            f"{sorted(required)}"
        )
    table_offset, table = candidates[0]
    if len({record["owner"] for record in table}) != len(table):
        raise ValueError("native voice-prefix table repeats an owner")

    format_offsets = []
    for value in VOICE_FORMATS:
        matches = _all_offsets(image.data, value + b"\0")
        if len(matches) != 1:
            raise ValueError(f"native voice filename format occurs {len(matches)} times")
        format_offsets.append(matches[0])
    scan_offsets = _all_offsets(image.data, TAKE_SCAN_SIGNATURE)
    if len(scan_offsets) != 1:
        raise ValueError(f"native voice take scan signature occurs {len(scan_offsets)} times")
    scan_offset = scan_offsets[0]
    function_starts = []
    prologue = bytes.fromhex("64a1000000006aff68")
    for offset in _all_offsets(image.data, prologue):
        if offset < scan_offset < offset + 512:
            function_starts.append(offset)
    if len(function_starts) != 1:
        raise ValueError("cannot uniquely bound the native voice filename builder")
    builder_offset = function_starts[0]
    for format_offset in format_offsets:
        pointer = struct.pack("<I", image.offset_to_address(format_offset))
        if not _all_offsets(image.data[builder_offset:builder_offset + 512], pointer):
            raise ValueError("native voice builder no longer references its filename formats")
    no_node_offsets = _all_offsets(image.data, NO_NODE_SIGNATURE)
    if len(no_node_offsets) != 1:
        raise ValueError(f"native zero-match node signature occurs {len(no_node_offsets)} times")
    no_node_offset = no_node_offsets[0]

    table_raw = image.data[table_offset:table_offset + len(table) * 35]
    return {
        "schema": 1,
        "contract": "miel-vliegt-native-voice-filename",
        "source": {
            "filename": executable.name,
            "sha256": _sha256(image.data),
            "imageBase": f"0x{image.image_base:08x}",
        },
        "ownerPrefixTable": {
            "address": f"0x{image.offset_to_address(table_offset):08x}",
            "recordSize": 35,
            "recordCount": len(table),
            "sha256": _sha256(table_raw),
            "entries": table,
        },
        "filenameBuilder": {
            "address": f"0x{image.offset_to_address(builder_offset):08x}",
            "sha256First512Bytes": _sha256(image.data[builder_offset:builder_offset + 512]),
            "formats": [value.decode("ascii") for value in VOICE_FORMATS],
            "takeScan": {
                "address": f"0x{image.offset_to_address(scan_offset):08x}",
                "startInclusive": 1,
                "endExclusive": 100,
                "signature": TAKE_SCAN_SIGNATURE.hex(),
            },
            "zeroMatch": {
                "result": "ABSENT_NO_COMMAND_NODE",
                "nodeDecisionAddress": f"0x{image.offset_to_address(no_node_offset):08x}",
                "signature": NO_NODE_SIGNATURE.hex(),
            },
        },
    }


@dataclass(frozen=True)
class VoiceFile:
    entry: SourceEntry
    prefix: str
    take: int
    clip: int
    bank: str


def _voice_files(index: SourceIndex) -> tuple[list[VoiceFile], list[dict[str, str]]]:
    voices: list[VoiceFile] = []
    ignored: list[dict[str, str]] = []
    for entry in index.under("data/Sound/Voices", suffix=".wav"):
        name = PureWindowsPath(entry.path).name
        match = VOICE_RE.fullmatch(name)
        if match is None:
            ignored.append({"path": entry.path, "reason": "filename-structure-mismatch"})
            continue
        bank_dir = PureWindowsPath(entry.path).parent.name.lower()
        bank = match.group("bank").lower()
        if bank_dir != bank:
            ignored.append({"path": entry.path, "reason": "bank-directory-name-mismatch"})
            continue
        voices.append(VoiceFile(
            entry=entry,
            prefix=match.group("prefix").lower(),
            take=int(match.group("take")),
            clip=int(match.group("clip")),
            bank=bank,
        ))
    if not voices:
        raise ValueError("source contains no native voice WAVs")
    return voices, ignored


def _clip_candidates(number: int) -> tuple[int, ...]:
    if type(number) is not int or number < 0 or number > 9999:
        raise ValueError(f"invalid native media number: {number!r}")
    return (number,)


def _validate_inputs(dispatch: dict[str, object], scripts: dict[str, object]) -> None:
    if dispatch.get("schema") != 1 or dispatch.get("contract") != "miel-vliegt-scene-dispatch":
        raise ValueError("unsupported flight scene dispatch contract")
    if scripts.get("schema") != 2 or scripts.get("claim") != "SOURCE_STRUCTURE_EXACT":
        raise ValueError("unsupported flight UDSP scene artifact")
    domains = [location.get("domainId") for location in dispatch.get("locations", [])]
    if not domains or any(type(domain) is not str or not domain for domain in domains):
        raise ValueError("dispatch contract has invalid location domains")
    if len(domains) != len(set(domains)):
        raise ValueError("dispatch contract repeats a location domain")
    scene_ids = {scene.get("id") for scene in scripts.get("scenes", [])}
    if not scene_ids or not scene_ids.issubset(set(domains) | {"barn"}):
        raise ValueError("UDSP scene domains drifted from dispatch locations")
    characters = scripts.get("referenced_character_ids")
    definitions = {item.get("character_id") for item in scripts.get("character_definitions", [])}
    if (
        not isinstance(characters, list)
        or any(type(item) is not str or not item for item in characters)
        or len(characters) != len(set(characters))
        or set(characters) != definitions
    ):
        raise ValueError("referenced character domains drifted from their definitions")


def _raw_media_references(scripts: dict[str, object]) -> list[dict[str, object]]:
    references: list[dict[str, object]] = []
    for script in scripts.get("scripts", []):
        if script.get("type") != "LOCATION_SCRIPT":
            continue
        path = script.get("path")
        for command in script.get("commands", []):
            opcode = command.get("opcode")
            if opcode not in VOICE_OPCODES | {BARN_OPCODE}:
                continue
            arguments = command.get("arguments")
            if not isinstance(arguments, list):
                raise ValueError(f"invalid media command in {path!r}: {command!r}")
            node = command.get("node")
            loop = command.get("loop")
            if (
                type(loop) is not bool
                or (node is not None and (type(node) is not int or node < 0))
            ):
                raise ValueError(f"invalid media command site in {path!r}: {command!r}")
            reference = {
                "path": path,
                "node": node,
                "loop": loop,
                "opcode": opcode,
            }
            if opcode == BARN_OPCODE:
                if len(arguments) < 1 or type(arguments[0]) is not int:
                    raise ValueError(f"invalid barn media command in {path!r}: {command!r}")
                reference.update({"owner": "barn", "id": arguments[0]})
            else:
                if (
                    len(arguments) < 3
                    or type(arguments[0]) is not str
                    or not arguments[0]
                    or type(arguments[1]) is not int
                    or type(arguments[2]) is not str
                    or not arguments[2]
                ):
                    raise ValueError(f"invalid voice media command in {path!r}: {command!r}")
                reference.update({
                    "owner": arguments[0], "id": arguments[1], "bank": arguments[2]
                })
            references.append(reference)
    harvested = scripts.get("media_references")
    if not isinstance(harvested, list):
        raise ValueError("UDSP scene artifact has no harvested media references")
    canonical = lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
    if sorted(map(canonical, references)) != sorted(map(canonical, harvested)):
        raise ValueError("harvested media references drifted from raw scene commands")
    return references


def _native_command_domains(
    scripts: dict[str, object], opcode: str
) -> list[dict[str, str]]:
    sites: list[dict[str, str]] = []
    for script in scripts.get("scripts", []):
        if script.get("type") != "LOCATION_SCRIPT":
            continue
        path = script.get("path")
        domain = script.get("domain_id")
        for command in script.get("commands", []):
            if command.get("opcode") != opcode:
                continue
            if type(path) is not str or not path or type(domain) is not str or not domain:
                raise ValueError(f"{opcode} occurs outside a typed location domain")
            site = {"domainId": domain, "path": path}
            if site not in sites:
                sites.append(site)
    return sorted(sites, key=lambda item: (item["domainId"], item["path"]))


def _native_implicit_media_references(
    scripts: dict[str, object], native_contract: dict[str, object]
) -> list[dict[str, object]]:
    """Lower source-proven service media without guessing edition prefixes."""
    runtime = native_contract.get("observed_runtime_contracts", {})
    judge = runtime.get("10", {})
    award = runtime.get("11", {})
    judge_media = judge.get("media_identity")
    award_media = award.get("media_identity")
    manager_media = award.get("manager_media_identity")
    manager_load = award.get("manager_media_load")
    if judge_media != {
        "owner": "domaren", "bank": "f", "take": 1,
        "clip_formula": "score + 3", "clip_domain": [4, 5, 6, 7, 8],
    }:
        raise ValueError("JUDGE_AIRPLANE implicit media identity drifted")
    clip_table = award.get("award_clip_table")
    if clip_table != [451, 452, 453, 456, 454, 455] or award_media != {
        "owner": "mulle", "bank": "y", "take": 1,
        "clip": "award_clip_table[index]",
    }:
        raise ValueError("AWARD_DIPLOMA implicit media identity drifted")
    if manager_media != {
        "owner": "doris", "bank": "x", "take": 1, "clip": 38,
    } or manager_load != {
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
    }:
        raise ValueError("diploma manager implicit media identity drifted")

    references: list[dict[str, object]] = []
    specifications = (
        (
            "JUDGE_AIRPLANE", JUDGE_AUDIO_OPCODE, judge_media,
            judge_media["clip_domain"], "native-udsp-command-runtime",
        ),
        (
            "AWARD_DIPLOMA", AWARD_AUDIO_OPCODE, award_media, clip_table,
            "native-udsp-command-runtime",
        ),
        (
            "AWARD_DIPLOMA", DIPLOMA_MANAGER_AUDIO_OPCODE, manager_media,
            [manager_media["clip"]], "native-diploma-manager-initialization",
        ),
    )
    for source_opcode, asset_opcode, media, clips, source in specifications:
        sites = _native_command_domains(scripts, source_opcode)
        for clip in clips:
            for site in sites:
                references.append({
                    "opcode": asset_opcode,
                    "owner": media["owner"],
                    "id": clip,
                    "bank": media["bank"],
                    "domainId": site["domainId"],
                    "path": site["path"],
                    "source": source,
                    "sourceOpcode": source_opcode,
                    "requiredTake": media["take"],
                    "loop": False,
                    "placement": "SHARED_NATIVE_SERVICE_MEDIA",
                    "semanticStatus": "UNPROVEN",
                    "parityEligible": False,
                })
    return references


def _select_voice_variants(
    reference: dict[str, object], voices: list[VoiceFile], prefix: str, bank: str
) -> tuple[int | None, list[VoiceFile]]:
    groups = []
    for clip in _clip_candidates(reference["id"]):
        matches = [
            voice for voice in voices
            if voice.prefix == prefix and voice.bank == bank.lower() and voice.clip == clip
        ]
        if matches:
            groups.append((clip, matches))
    if not groups:
        return None, []
    if len(groups) != 1:
        raise ValueError(
            f"media reference {reference!r} resolved to {len(groups)} native clip groups"
        )
    clip, matches = groups[0]
    takes = [voice.take for voice in matches]
    if len(takes) != len(set(takes)):
        raise ValueError(f"duplicate native voice take for {reference!r}")
    return clip, sorted(matches, key=lambda voice: voice.take)


def _select_exact_voice_variant(
    reference: dict[str, object], voices: list[VoiceFile], prefix: str, bank: str
) -> tuple[int, list[VoiceFile]]:
    take = reference.get("requiredTake")
    clip = reference.get("id")
    if type(take) is not int or not 1 <= take < 100 or type(clip) is not int:
        raise ValueError(f"invalid native implicit media identity: {reference!r}")
    matches = [
        voice for voice in voices
        if voice.prefix == prefix and voice.bank == bank.lower()
        and voice.clip == clip and voice.take == take
    ]
    if len(matches) != 1:
        raise ValueError(
            "native implicit media requires exactly one archive entry: "
            f"opcode={reference['sourceOpcode']} owner={reference['owner']} "
            f"clip={clip} bank={bank.lower()} take={take}; matches={len(matches)}"
        )
    voice = matches[0]
    expected_path = (
        f"data/Sound/Voices/{bank.lower()}/"
        f"{prefix.upper()}{take:02d}{clip:04d}{bank.upper()}.WAV"
    )
    if _path_key(voice.entry.path) != _path_key(expected_path):
        raise ValueError(
            f"native implicit media archive path is not canonical: {voice.entry.path}"
        )
    return clip, matches


def _resolve_barn_bank(
    references: list[dict[str, object]], voices: list[VoiceFile], mulle_prefix: str
) -> str:
    possible: set[str] | None = None
    for reference in references:
        banks = {
            voice.bank
            for voice in voices
            if voice.prefix == mulle_prefix and voice.clip in _clip_candidates(reference["id"])
        }
        possible = banks if possible is None else possible & banks
    if possible is None or len(possible) != 1:
        raise ValueError(
            f"Mulle barn media resolves to banks {sorted(possible or ())}; expected exactly one"
        )
    return next(iter(possible))


def _script_dependency_closures(
    dispatch: dict[str, object],
    scripts: dict[str, object],
    native_mygghanget_contract: dict[str, object] | None,
) -> dict[str, dict[str, object]]:
    """Derive scene dependencies from commands, never from presentation guesses."""
    script_items = scripts.get("scripts", [])
    script_by_path: dict[str, dict[str, object]] = {}
    character_scripts: dict[tuple[str, str], str] = {}
    location_scripts: dict[str, list[dict[str, object]]] = {}
    for script in script_items:
        if not isinstance(script, dict):
            raise ValueError(f"invalid UDSP script record: {script!r}")
        path = script.get("path")
        script_type = script.get("type")
        domain = script.get("domain_id")
        dispatch_id = script.get("dispatch_id")
        if (
            type(path) is not str
            or not path
            or path in script_by_path
            or script_type not in {"LOCATION_SCRIPT", "CHARACTER_SCRIPT"}
            or type(domain) is not str
            or not domain
            or type(dispatch_id) is not str
            or not dispatch_id
            or not isinstance(script.get("commands"), list)
        ):
            raise ValueError(f"invalid or duplicate UDSP script record: {script!r}")
        expected_prefix = (
            f"data/Scripts/Locations/{domain}/"
            if script_type == "LOCATION_SCRIPT"
            else f"data/Scripts/Characters/{domain}/"
        )
        if not path.startswith(expected_prefix) or not path.lower().endswith(".def"):
            raise ValueError(f"UDSP script crosses its declared domain: {path!r}")
        script_by_path[path] = script
        if script_type == "LOCATION_SCRIPT":
            location_scripts.setdefault(domain, []).append(script)
        else:
            key = (domain, dispatch_id)
            if key in character_scripts:
                raise ValueError(f"duplicate character script dispatch: {key!r}")
            character_scripts[key] = path

    scene_by_id: dict[str, dict[str, object]] = {}
    for scene in scripts.get("scenes", []):
        if not isinstance(scene, dict) or type(scene.get("id")) is not str:
            raise ValueError(f"invalid UDSP scene record: {scene!r}")
        domain = scene["id"]
        if domain in scene_by_id:
            raise ValueError(f"duplicate UDSP scene domain: {domain}")
        declared_paths = scene.get("script_paths")
        actual_paths = sorted(item["path"] for item in location_scripts.get(domain, []))
        if (
            not isinstance(declared_paths, list)
            or any(type(path) is not str for path in declared_paths)
            or sorted(declared_paths) != actual_paths
        ):
            raise ValueError(f"scene {domain!r} does not close over its location scripts")
        scene_by_id[domain] = scene

    dispatch_locations = dispatch.get("locations", [])
    dispatch_domains = [location["domainId"] for location in dispatch_locations]
    allowed_scene_domains = set(dispatch_domains) | {"barn"}
    if set(scene_by_id) - allowed_scene_domains:
        raise ValueError(
            f"UDSP scenes cross dispatch domains: {sorted(set(scene_by_id) - allowed_scene_domains)}"
        )
    definition_ids = {
        definition["character_id"] for definition in scripts.get("character_definitions", [])
    }
    closures: dict[str, dict[str, object]] = {}
    for location in dispatch_locations:
        domain = location["domainId"]
        scene = scene_by_id.get(domain)
        if scene is None:
            if location.get("policy") != "BESPOKE_NO_UDSP":
                raise ValueError(
                    f"location {domain!r} has no UDSP scene and is not proven bespoke"
                )
            if domain == "mygghanget" and native_mygghanget_contract is not None:
                closures[domain] = {
                    "dependencyState": "PROVEN_NATIVE_BESPOKE_STATIC_CLOSURE",
                    "locationScripts": [],
                    "characterScripts": [],
                    "characters": [],
                    "mediaReferencePaths": [],
                    "unresolvedDependencies": [],
                    "claimLimit": native_mygghanget_contract["claimLimit"],
                }
            else:
                closures[domain] = {
                    "dependencyState": "UNRESOLVED_BESPOKE_NO_UDSP_SCENE",
                    "locationScripts": [],
                    "characterScripts": [],
                    "characters": [],
                    "mediaReferencePaths": [],
                    "unresolvedDependencies": [
                        "native bespoke mode has no harvested dependency contract"
                    ],
                    "claimLimit": [],
                }
            continue
        closures[domain] = _scene_dependency_closure(
            domain, scene, script_by_path, character_scripts, definition_ids
        )

    barn_scene = scene_by_id.get("barn")
    if barn_scene is not None:
        closures["barn"] = _scene_dependency_closure(
            "barn", barn_scene, script_by_path, character_scripts, definition_ids
        )
    return closures


def _scene_dependency_closure(
    domain: str,
    scene: dict[str, object],
    script_by_path: dict[str, dict[str, object]],
    character_scripts: dict[tuple[str, str], str],
    definition_ids: set[str],
) -> dict[str, object]:
    characters: set[str] = set()
    required_character_scripts: set[str] = set()
    media_reference_paths: set[str] = set()
    paths = sorted(scene["script_paths"])
    for path in paths:
        script = script_by_path.get(path)
        if script is None or script.get("type") != "LOCATION_SCRIPT":
            raise ValueError(f"scene {domain!r} references missing location script {path!r}")
        if script.get("domain_id") != domain:
            raise ValueError(f"scene {domain!r} references cross-domain script {path!r}")
        for command in script["commands"]:
            if not isinstance(command, dict) or not isinstance(command.get("arguments"), list):
                raise ValueError(f"invalid command in {path!r}: {command!r}")
            opcode = command.get("opcode")
            arguments = command["arguments"]
            if opcode in VOICE_OPCODES | {BARN_OPCODE}:
                media_reference_paths.add(path)
            if opcode in {"POSITION_CHARACTER", "PLAY_CHARACTER_SCRIPT", "PLAY_CHARACTER_SOUND"}:
                if not arguments or type(arguments[0]) is not str or not arguments[0]:
                    raise ValueError(f"invalid character dependency in {path!r}: {command!r}")
                characters.add(arguments[0])
            if opcode == "PLAY_CHARACTER_SCRIPT":
                if len(arguments) < 2 or type(arguments[1]) is not str:
                    raise ValueError(f"invalid character-script dependency in {path!r}: {command!r}")
                target = (arguments[0], arguments[1])
                target_path = character_scripts.get(target)
                if target_path is None:
                    raise ValueError(
                        f"scene {domain!r} references missing character script {target!r}"
                    )
                required_character_scripts.add(target_path)
    missing_definitions = characters - definition_ids
    if missing_definitions:
        raise ValueError(
            f"scene {domain!r} references missing character definitions "
            f"{sorted(missing_definitions)}"
        )
    declared_characters = scene.get("characters")
    if not isinstance(declared_characters, list) or set(declared_characters) != characters:
        raise ValueError(f"scene {domain!r} character summary drifted from raw commands")
    return {
        "dependencyState": "PROVEN_UDSP_SCRIPT_CLOSURE",
        "locationScripts": paths,
        "characterScripts": sorted(required_character_scripts),
        "characters": sorted(characters),
        "mediaReferencePaths": sorted(media_reference_paths),
        "unresolvedDependencies": [],
        "claimLimit": [],
    }


def _asset_counts(keys: list[str], assets: dict[str, dict[str, object]]) -> dict[str, int]:
    counts = {"assets": len(keys), "images": 0, "audio": 0}
    for key in keys:
        asset_type = assets[key]["type"]
        if asset_type == "image":
            counts["images"] += 1
        elif asset_type == "audio":
            counts["audio"] += 1
        else:
            raise ValueError(f"unsupported Phaser asset type: {asset_type!r}")
    return counts


def _build_pack_sections(
    dispatch: dict[str, object],
    scripts: dict[str, object],
    image_records: list[dict[str, object]],
    media_groups: dict[tuple[object, ...], dict[str, object]],
    audio_records: dict[str, dict[str, object]],
    native_mygghanget_contract: dict[str, object] | None,
) -> list[dict[str, object]]:
    closures = _script_dependency_closures(
        dispatch, scripts, native_mygghanget_contract
    )
    assets_list = image_records + [audio_records[key] for key in sorted(audio_records)]
    assets: dict[str, dict[str, object]] = {}
    for asset in assets_list:
        key = asset["key"]
        if key in assets:
            raise ValueError(f"duplicate Phaser asset key across inventories: {key}")
        assets[key] = asset

    consumers: dict[str, set[str]] = {key: set() for key in assets}
    location_image_keys: dict[str, list[str]] = {}
    character_image_keys: dict[str, list[str]] = {}
    forced_shared_keys: set[str] = set()
    for image in image_records:
        if image["domainKind"] in {"shared", "presentation-boundary"}:
            forced_shared_keys.add(image["key"])
            for domain in image["consumerDomains"]:
                if domain not in closures:
                    raise ValueError(
                        f"shared image references unknown scene domain {domain!r}"
                    )
                consumers[image["key"]].add(domain)
            continue
        mapping = (
            location_image_keys
            if image["domainKind"] == "location"
            else character_image_keys
        )
        mapping.setdefault(image["domainId"], []).append(image["key"])

    for domain, closure in closures.items():
        if domain != "barn":
            own_images = location_image_keys.get(domain, [])
            if not own_images:
                raise ValueError(f"location pack {domain!r} has no location image assets")
            for key in own_images:
                consumers[key].add(domain)
        for character in closure["characters"]:
            keys = character_image_keys.get(character, [])
            if not keys:
                raise ValueError(
                    f"scene {domain!r} references missing character image domain {character!r}"
                )
            for key in keys:
                consumers[key].add(domain)

    for logical, group in media_groups.items():
        native_implicit = group.get("nativeImplicit")
        if native_implicit is not None:
            if native_implicit.get("placement") != "SHARED_NATIVE_SERVICE_MEDIA":
                raise ValueError(
                    f"native implicit media has invalid placement: {logical!r}"
                )
            forced_shared_keys.update(
                variant["key"] for variant in group["variants"]
            )
        for reference in group["references"]:
            if "domainId" in reference:
                script_domain = reference["domainId"]
                if script_domain not in closures:
                    raise ValueError(
                        f"native media references unknown scene domain: {script_domain!r}"
                    )
            else:
                path = reference["path"]
                script_domain = None
                for domain, closure in closures.items():
                    if path in closure["locationScripts"]:
                        if script_domain is not None:
                            raise ValueError(
                                f"media reference belongs to multiple scene domains: {path!r}"
                            )
                        script_domain = domain
                if script_domain is None:
                    raise ValueError(
                        f"media reference is outside every scene closure: {path!r}"
                    )
            for variant in group["variants"]:
                key = variant["key"]
                if key not in audio_records:
                    raise ValueError(f"logical media {logical!r} references missing audio key {key!r}")
                consumers[key].add(script_domain)

    unused = sorted(key for key, domains in consumers.items() if not domains)
    if unused:
        raise ValueError(f"asset inventory contains assets outside every scene closure: {unused}")
    shared_keys = sorted(
        forced_shared_keys
        | {key for key, domains in consumers.items() if len(domains) > 1}
    )
    sections: list[dict[str, object]] = []
    if shared_keys:
        sections.append({
            "key": "flight_scene_shared",
            "kind": "shared",
            "assetKeys": shared_keys,
            "counts": _asset_counts(shared_keys, assets),
        })

    dispatch_domains = [location["domainId"] for location in dispatch["locations"]]
    for domain in dispatch_domains + (["barn"] if "barn" in closures else []):
        required_shared = sorted(
            key for key in shared_keys if domain in consumers[key]
        )
        local_keys = sorted(
            key
            for key, domains in consumers.items()
            if domains == {domain} and key not in forced_shared_keys
        )
        closure_keys = sorted(local_keys + required_shared)
        closure = closures[domain]
        section = {
            "key": (
                "flight_scene_barn"
                if domain == "barn"
                else f"flight_scene_location_{_slug(domain).replace('-', '_')}"
            ),
            "kind": "barn" if domain == "barn" else "location",
            "domainId": domain,
            "dependencyState": closure["dependencyState"],
            "dependencies": ["flight_scene_shared"] if required_shared else [],
            "assetKeys": local_keys,
            "requiredSharedAssetKeys": required_shared,
            "closureAssetKeys": closure_keys,
            "counts": _asset_counts(local_keys, assets),
            "closureCounts": _asset_counts(closure_keys, assets),
            "locationScripts": closure["locationScripts"],
            "characterScripts": closure["characterScripts"],
            "characters": closure["characters"],
            "mediaReferencePaths": closure["mediaReferencePaths"],
            "unresolvedDependencies": closure["unresolvedDependencies"],
            "claimLimit": closure["claimLimit"],
        }
        sections.append(section)

    assigned = [key for section in sections for key in section["assetKeys"]]
    if len(assigned) != len(set(assigned)):
        raise ValueError("Phaser pack sections assign a duplicate asset key")
    if set(assigned) != set(assets):
        raise ValueError("Phaser pack sections do not partition the asset inventory")
    return sections


def _image_records(
    index: SourceIndex,
    domains: list[str],
    characters: list[str],
) -> tuple[list[dict[str, object]], dict[str, Callable[[], bytes]]]:
    records: list[dict[str, object]] = []
    payloads: dict[str, Callable[[], bytes]] = {}
    used_keys: set[str] = set()
    groups = [
        ("location", domain, f"data/Graphics/Locations/{domain}") for domain in domains
    ] + [
        ("character", character, f"data/Graphics/Characters/{character}")
        for character in characters
    ]
    for kind, domain, prefix in groups:
        entries = index.under(prefix, suffix=".gti")
        if not entries:
            raise ValueError(f"required {kind} graphic domain has no GTI images: {prefix}")
        prefix_key = _path_key(prefix).rstrip("/") + "/"
        for entry in entries:
            relative = _path_key(entry.path)[len(prefix_key):]
            stem = relative[:-4]
            key = f"flight-scene-{kind}-{_slug(domain)}-{_slug(stem)}"
            if key in used_keys:
                raise ValueError(f"generated Phaser image key collision: {key}")
            used_keys.add(key)
            raw = entry.read()
            image = decode_gti(raw)
            output_relative = f"scenes/{kind}s/{_slug(domain)}/{_slug(stem)}.png"
            png = encode_png(image)
            if output_relative in payloads:
                raise ValueError(f"generated image path collision: {output_relative}")
            payloads[output_relative] = lambda entry=entry: encode_png(decode_gti(entry.read()))
            records.append({
                "type": "image",
                "key": key,
                "url": f"assets/miel-vliegt/{output_relative}",
                "domainKind": kind,
                "domainId": domain,
                "source": entry.path.replace("\\", "/"),
                "sourceSha256": _sha256(raw),
                "outputSha256": _sha256(png),
                "width": image.width,
                "height": image.height,
                "format": image.format_name,
            })
    return records, payloads


def _validate_native_mygghanget_contract(
    contract: dict[str, object], native_voice_contract: dict[str, object]
) -> None:
    if (
        contract.get("schema") != 1
        or contract.get("contract") != "miel-vliegt-native-mygghanget"
        or contract.get("claim") != "STATIC_CODE_EXACT"
        or set(contract.get("claimLimit", []))
        != {"RUNTIME_EXECUTION_UNPROVEN", "FRAMEBUFFER_PARITY_UNPROVEN"}
    ):
        raise ValueError("invalid native Mygghanget contract or claim boundary")
    source = contract.get("source", {})
    generator = contract.get("generator", {})
    if (
        not isinstance(source, dict)
        or source.get("sha256") != native_voice_contract.get("source", {}).get("sha256")
        or not isinstance(generator, dict)
        or generator.get("path") != "tools/miel_vliegt/native_mygghanget_contract.py"
        or generator.get("sha256") != _sha256(Path(__file__).with_name("native_mygghanget_contract.py").read_bytes())
    ):
        raise ValueError("native Mygghanget provenance does not match this build")
    mode = contract.get("mode", {})
    sky = contract.get("assets", {}).get("sky", {})
    presentation = contract.get("assets", {}).get("presentationBoundary", {})
    bootstrap = contract.get("bootstrapInputContract", {})
    voice = contract.get("voice", {})
    takes = voice.get("takeDomain")
    if (
        not isinstance(mode, dict)
        or mode.get("id") != "mygghanget"
        or mode.get("locationId") != 22
        or not isinstance(sky, dict)
        or type(sky.get("condition")) is not str
        or not sky["condition"]
        or type(sky.get("bank")) is not str
        or re.fullmatch(r"[a-z]+", sky["bank"]) is None
        or sky.get("discoveryPolicy") != "contiguous-rectangular-grid"
        or not isinstance(voice, dict)
        or voice.get("owner") != "mulle"
        or type(voice.get("scriptNumber")) is not int
        or type(voice.get("bank")) is not str
        or re.fullmatch(r"[a-z]+", voice["bank"]) is None
        or voice.get("selection")
        != "one-native-rand-modulo-take-count-plus-one"
        or not isinstance(takes, list)
        or any(type(take) is not int for take in takes)
        or takes != list(range(1, len(takes) + 1))
        or not takes
    ):
        raise ValueError("native Mygghanget asset/voice policy is malformed")
    resources = presentation.get("resources") if isinstance(presentation, dict) else None
    renderer = presentation.get("renderer") if isinstance(presentation, dict) else None
    expected_roles = {
        "loading": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
        "start-engine": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
        "land": "PRESENTATION_OVERLAY_STATIC_RENDER_ONLY",
    }
    if (
        type(presentation.get("directory")) is not str
        or not _path_key(presentation["directory"]).startswith("data/graphics/")
        or ".." in _path_key(presentation["directory"]).split("/")
        or not isinstance(presentation.get("loaderReceipt"), dict)
        or type(presentation["loaderReceipt"].get("address")) is not str
        or type(presentation["loaderReceipt"].get("size")) is not int
        or presentation["loaderReceipt"]["size"] <= 0
        or not isinstance(presentation.get("generalSiblings"), list)
        or len(presentation["generalSiblings"]) != 2
        or any(
            type(name) is not str or re.fullmatch(r"[a-z0-9_]+", name) is None
            for name in presentation["generalSiblings"]
        )
        or len(set(presentation["generalSiblings"])) != 2
        or not isinstance(renderer, dict)
        or renderer.get("inputSemantics") != "NONE_STATIC_RENDER_ONLY"
        or renderer.get("selectorHandleBase") != "0x1d4"
        or renderer.get("selectorToHandleField") != {
            "1": "0x1d8", "2": "0x1dc", "3": "0x1e0",
            "4": "0x1e4", "5": "0x1e8",
        }
        or re.fullmatch(r"0x[0-9a-f]{8}", renderer.get("entry", "")) is None
        or not isinstance(renderer.get("receipt"), dict)
        or not isinstance(resources, list)
        or [item.get("role") for item in resources if isinstance(item, dict)]
        != list(expected_roles)
    ):
        raise ValueError("native Mygghanget presentation boundary is malformed")
    for item in resources:
        if (
            set(item) != {
                "role", "assetName", "handleField", "loadAddress", "classification"
            }
            or item["classification"] != expected_roles[item["role"]]
            or type(item["assetName"]) is not str
            or re.fullmatch(r"[a-z0-9_]+", item["assetName"]) is None
            or re.fullmatch(r"0x[0-9a-f]+", item["handleField"]) is None
            or re.fullmatch(r"0x[0-9a-f]{8}", item["loadAddress"]) is None
        ):
            raise ValueError("native Mygghanget presentation resource is malformed")
    asset_names = [item["assetName"] for item in resources]
    if len(set(asset_names + presentation["generalSiblings"])) != 5:
        raise ValueError("native Mygghanget presentation resource names are ambiguous")
    bootstrap_input = bootstrap.get("input") if isinstance(bootstrap, dict) else None
    bootstrap_dispatch = bootstrap.get("dispatch") if isinstance(bootstrap, dict) else None
    start_engine = bootstrap.get("startEngine") if isinstance(bootstrap, dict) else None
    start_engine_input = (
        start_engine.get("input") if isinstance(start_engine, dict) else None
    )
    start_engine_sample = (
        start_engine.get("sample") if isinstance(start_engine, dict) else None
    )
    start_engine_gate = (
        start_engine.get("gate") if isinstance(start_engine, dict) else None
    )
    direct_departure = (
        start_engine.get("directDeparture")
        if isinstance(start_engine, dict) else None
    )
    if (
        bootstrap.get("policy")
        != "REAL_INPUT_ONLY_NO_DIRECT_HANDLER_OR_STATE_MODE_WRITE"
        or not isinstance(bootstrap_input, dict)
        or bootstrap_input != {
            "api": "SendInput", "kind": "keyboard-scan-code",
            "scanCode": "0x01", "nativeKeyCode": 1, "name": "DIK_ESCAPE",
        }
        or not isinstance(bootstrap_dispatch, dict)
        or bootstrap_dispatch.get("lookupIndex") != 0
        or any(
            re.fullmatch(r"0x[0-9a-f]{8}", bootstrap_dispatch.get(key, "")) is None
            for key in ("entry", "lookupAddress", "lookupTable", "jumpTable",
                        "action", "outsideViewBranch", "handler")
        )
        or start_engine_input != {
            "api": "SendInput",
            "kind": "keyboard-scan-code-held-until-departure",
            "scanCode": "0x2a",
            "nativeScanCodes": [42, 54, 78],
            "name": "DIK_LSHIFT_OR_EQUIVALENT_FASTER",
        }
        or not isinstance(start_engine_sample, dict)
        or start_engine_sample.get("managerNodeField") != "0x74"
        or start_engine_sample.get("throttleAdjust") != "0x0040f8d0"
        or not isinstance(start_engine_sample.get("receipt"), dict)
        or not isinstance(start_engine_gate, dict)
        or start_engine_gate.get("sharedFlightField") != "0x5c"
        or start_engine_gate.get("throttleField") != "0x148"
        or start_engine_gate.get("latchField") != "0x8b4"
        or start_engine_gate.get("thresholdF32") != 0.5
        or not isinstance(start_engine_gate.get("receipt"), dict)
        or not isinstance(direct_departure, dict)
        or direct_departure.get("targetMode") != "mode_fly"
        or not isinstance(direct_departure.get("receipt"), dict)
        or any(
            re.fullmatch(r"0x[0-9a-f]{8}", direct_departure.get(key, "")) is None
            for key in ("offscreenTestEntry", "modeSetCallsite")
        )
        or bootstrap.get("preconditions") != [
            "current-mode-is-mode_barn", "pending-mode-is-null",
            "barn-view-field-0x190-is-zero",
            "airplane-complete-predicate-is-true",
        ]
        or not isinstance(bootstrap.get("postconditions"), list)
        or bootstrap["postconditions"][:4] != [
            "mode_mygghanget-field-0x999-set-to-one",
            "mode_mygghanget-open-selects-state-five",
            "native-faster-sample-field-0x74-becomes-one",
            "shared-flight-throttle-field-0x148-reaches-at-least-0.5",
        ]
        or len(bootstrap["postconditions"]) != 6
        or re.fullmatch(
            r"state-five-callsite-0x[0-9a-f]{8}-requests-mode_fly-after-offscreen-test",
            bootstrap["postconditions"][4],
        ) is None
        or re.fullmatch(
            r"alternate-state-zero-callsite-0x[0-9a-f]{8}-requests-mode_fly-after-offscreen-test",
            bootstrap["postconditions"][5],
        ) is None
    ):
        raise ValueError("native Mygghanget bootstrap input contract is malformed")


def _mygghanget_sky_records(
    index: SourceIndex, contract: dict[str, object]
) -> tuple[list[dict[str, object]], dict[str, Callable[[], bytes]]]:
    sky = contract["assets"]["sky"]
    condition = sky["condition"].lower()
    bank = sky["bank"].lower()
    prefix = f"data/Graphics/Locations/sky/{condition}"
    coordinates: dict[tuple[int, int], SourceEntry] = {}
    for entry in index.under(prefix, suffix=".gti"):
        match = SKY_TILE_RE.fullmatch(PureWindowsPath(entry.path).name)
        if match is None or match.group("bank").lower() != bank:
            continue
        coordinate = (int(match.group("row")), int(match.group("column")))
        if coordinate in coordinates:
            raise ValueError(f"duplicate Mygghanget sky tile coordinate: {coordinate}")
        coordinates[coordinate] = entry
    if not coordinates:
        raise ValueError(
            f"Mygghanget sky grid is absent for edition tuple {condition}/{bank}"
        )
    max_row = max(row for row, _ in coordinates)
    max_column = max(column for _, column in coordinates)
    expected = {
        (row, column)
        for row in range(1, max_row + 1)
        for column in range(1, max_column + 1)
    }
    if set(coordinates) != expected:
        missing = sorted(expected - set(coordinates))
        extra = sorted(set(coordinates) - expected)
        raise ValueError(
            f"Mygghanget sky grid is not contiguous; missing={missing}, extra={extra}"
        )

    records: list[dict[str, object]] = []
    payloads: dict[str, Callable[[], bytes]] = {}
    for (row, column), entry in sorted(coordinates.items()):
        raw = entry.read()
        image = decode_gti(raw)
        key = f"flight-scene-shared-sky-{_slug(condition)}-{_slug(bank)}{row}-{column}"
        output_relative = f"scenes/shared/sky/{_slug(condition)}/{_slug(bank)}{row}-{column}.png"
        png = encode_png(image)
        payloads[output_relative] = lambda entry=entry: encode_png(decode_gti(entry.read()))
        records.append({
            "type": "image",
            "key": key,
            "url": f"assets/miel-vliegt/{output_relative}",
            "domainKind": "shared",
            "domainId": f"sky/{condition}/{bank}",
            "consumerDomains": ["mygghanget"],
            "source": entry.path.replace("\\", "/"),
            "sourceSha256": _sha256(raw),
            "outputSha256": _sha256(png),
            "width": image.width,
            "height": image.height,
            "format": image.format_name,
            "row": row,
            "column": column,
        })
    return records, payloads


def _mygghanget_presentation_records(
    index: SourceIndex, contract: dict[str, object]
) -> tuple[list[dict[str, object]], dict[str, Callable[[], bytes]]]:
    boundary = contract["assets"]["presentationBoundary"]
    directory = boundary["directory"]
    available: dict[str, SourceEntry] = {}
    for entry in index.under(directory, suffix=".gti"):
        name = PureWindowsPath(entry.path).stem.lower()
        if name in available:
            raise ValueError(f"duplicate Mygghanget presentation resource: {name}")
        available[name] = entry

    records: list[dict[str, object]] = []
    payloads: dict[str, Callable[[], bytes]] = {}
    for resource in boundary["resources"]:
        name = resource["assetName"].lower()
        entry = available.get(name)
        if entry is None:
            raise ValueError(f"Mygghanget presentation resource is missing: {name}")
        raw = entry.read()
        image = decode_gti(raw)
        role = resource["role"]
        key = f"flight-scene-presentation-mygghanget-{_slug(role)}"
        output_relative = f"scenes/shared/presentation/mygghanget/{_slug(name)}.png"
        if output_relative in payloads:
            raise ValueError(f"generated Mygghanget presentation path collision: {output_relative}")
        png = encode_png(image)
        payloads[output_relative] = lambda entry=entry: encode_png(decode_gti(entry.read()))
        records.append({
            "type": "image",
            "key": key,
            "url": f"assets/miel-vliegt/{output_relative}",
            "domainKind": "presentation-boundary",
            "domainId": "mygghanget/presentation",
            "consumerDomains": ["mygghanget"],
            "source": entry.path.replace("\\", "/"),
            "sourceSha256": _sha256(raw),
            "outputSha256": _sha256(png),
            "width": image.width,
            "height": image.height,
            "format": image.format_name,
            "role": role,
            "classification": resource["classification"],
            "loadAddress": resource["loadAddress"],
            "handleField": resource["handleField"],
        })
    return records, payloads


def build_scene_asset_contract(
    dispatch_path: Path,
    scripts_path: Path,
    data_source: AssetSource,
    sound_source: AssetSource,
    native_voice_contract: dict[str, object],
    native_mygghanget_contract: dict[str, object],
    native_udsp_path: Path = DEFAULT_NATIVE_UDSP,
) -> tuple[dict[str, object], dict[str, Callable[[], bytes]]]:
    dispatch_raw = dispatch_path.read_bytes()
    scripts_raw = scripts_path.read_bytes()
    dispatch = json.loads(dispatch_raw)
    scripts = json.loads(scripts_raw)
    native_udsp_raw = native_udsp_path.read_bytes()
    native_udsp_contract = native_udsp_scene_commands.validate_contract(
        json.loads(native_udsp_raw), root=ROOT
    )
    native_udsp_executable = native_udsp_contract.get("source", {}).get(
        "executable_sha256"
    )
    native_voice_executable = native_voice_contract.get("source", {}).get("sha256")
    if (
        not isinstance(native_udsp_executable, str)
        or native_udsp_executable != native_voice_executable
    ):
        raise ValueError(
            "native UDSP implicit-media semantics and edition voice-prefix executable differ"
        )
    _validate_inputs(dispatch, scripts)
    expected_udsp_sha = dispatch["sources"]["udsp"]["sha256"]
    if expected_udsp_sha != _sha256(scripts_raw):
        raise ValueError("scene dispatch contract does not pin this UDSP scene artifact")
    if data_source.provenance.get("kind") == "udsp-archive":
        expected_data_sha = scripts.get("source", {}).get("sha256")
        if data_source.provenance.get("sha256") != expected_data_sha:
            raise ValueError("data archive identity drifted from the UDSP scene artifact")

    index = SourceIndex([data_source, sound_source])
    domains = [location["domainId"] for location in dispatch["locations"]]
    characters = list(scripts["referenced_character_ids"])
    image_records, payloads = _image_records(index, domains, characters)
    has_mygghanget = "mygghanget" in domains
    if has_mygghanget:
        _validate_native_mygghanget_contract(
            native_mygghanget_contract, native_voice_contract
        )
        sky_records, sky_payloads = _mygghanget_sky_records(
            index, native_mygghanget_contract
        )
        image_records.extend(sky_records)
        presentation_records, presentation_payloads = _mygghanget_presentation_records(
            index, native_mygghanget_contract
        )
        image_records.extend(presentation_records)
        combined_payloads = {**sky_payloads, **presentation_payloads}
        if len(combined_payloads) != len(sky_payloads) + len(presentation_payloads):
            raise ValueError("generated Mygghanget presentation/sky path collision")
        overlap = set(payloads).intersection(combined_payloads)
        if overlap:
            raise ValueError(f"generated shared Mygghanget path collision: {sorted(overlap)}")
        payloads.update(combined_payloads)

    references = _raw_media_references(scripts)
    if not references:
        raise ValueError("UDSP scene artifact contains no media references")
    known_scripts = {script["path"] for script in scripts.get("scripts", [])}
    voice_keys = {"path", "node", "loop", "opcode", "owner", "id", "bank"}
    barn_keys = voice_keys - {"bank"}
    for reference in references:
        if not isinstance(reference, dict):
            raise ValueError(f"invalid UDSP media reference shape: {reference!r}")
        expected_keys = barn_keys if reference.get("opcode") == BARN_OPCODE else voice_keys
        if set(reference) != expected_keys:
            raise ValueError(f"invalid UDSP media reference shape: {reference!r}")
        if reference.get("path") not in known_scripts:
            raise ValueError(f"media reference points outside the harvested scripts: {reference!r}")
        if reference.get("opcode") not in VOICE_OPCODES | {BARN_OPCODE}:
            raise ValueError(f"unsupported scene media opcode: {reference!r}")
        if (
            type(reference.get("owner")) is not str
            or not reference["owner"]
            or type(reference.get("id")) is not int
            or type(reference.get("loop")) is not bool
            or (
                reference.get("node") is not None
                and (type(reference["node"]) is not int or reference["node"] < 0)
            )
            or (
                reference["opcode"] != BARN_OPCODE
                and (type(reference.get("bank")) is not str or not reference["bank"])
            )
        ):
            raise ValueError(f"invalid scene media reference scalar: {reference!r}")

    if (
        native_voice_contract.get("schema") != 1
        or native_voice_contract.get("contract") != "miel-vliegt-native-voice-filename"
        or native_voice_contract.get("filenameBuilder", {}).get("zeroMatch", {}).get("result")
        != "ABSENT_NO_COMMAND_NODE"
    ):
        raise ValueError("invalid native voice filename contract")
    prefix_entries = native_voice_contract.get("ownerPrefixTable", {}).get("entries", [])
    owner_prefixes = {
        entry["owner"]: entry["prefix"]
        for entry in prefix_entries
        if isinstance(entry, dict) and set(entry) == {"owner", "prefix"}
    }
    if len(owner_prefixes) != len(prefix_entries):
        raise ValueError("native voice-prefix contract has duplicate or malformed records")
    if any(
        type(owner) is not str
        or not owner
        or type(prefix) is not str
        or re.fullmatch(r"[a-z]{2}", prefix) is None
        for owner, prefix in owner_prefixes.items()
    ):
        raise ValueError("native voice-prefix contract has invalid owner/prefix scalars")
    implicit_references = _native_implicit_media_references(
        scripts, native_udsp_contract
    )
    required_owners = {
        reference["owner"] for reference in references if reference["opcode"] in VOICE_OPCODES
    } | {reference["owner"] for reference in implicit_references} | {"mulle"}
    missing_owners = required_owners - set(owner_prefixes)
    if missing_owners:
        raise ValueError(
            f"native executable has no voice-prefix records for {sorted(missing_owners)}"
        )
    voices, ignored_voices = _voice_files(index)
    barn_refs = [reference for reference in references if reference["opcode"] == BARN_OPCODE]
    if barn_refs and "mulle" not in owner_prefixes:
        raise ValueError("barn media cannot prove the native Mulle filename prefix")
    barn_bank = _resolve_barn_bank(barn_refs, voices, owner_prefixes["mulle"]) if barn_refs else None

    resolution_references = list(references) + implicit_references
    script_domains = {
        script["path"]: script["domain_id"]
        for script in scripts.get("scripts", [])
        if script.get("type") == "LOCATION_SCRIPT"
    }
    radio_domains = sorted({
        script_domains[reference["path"]]
        for reference in references
        if reference["opcode"] == "PLAY_RADIO"
    })
    for clip in RADIO_ALERT_CLIPS:
        for domain in radio_domains:
            resolution_references.append({
                "opcode": RADIO_ALERT_OPCODE,
                "owner": "mulle",
                "id": clip,
                "bank": "b",
                "domainId": domain,
                "source": "native-play-radio-alert",
                "loop": False,
            })
    if has_mygghanget:
        native_voice = native_mygghanget_contract["voice"]
        resolution_references.append({
            "opcode": MYGGHANGET_OPCODE,
            "owner": native_voice["owner"],
            "id": native_voice["scriptNumber"],
            "bank": native_voice["bank"],
            "domainId": "mygghanget",
            "source": "native-mygghanget-update",
            "loop": False,
        })

    media_groups: dict[tuple[object, ...], dict[str, object]] = {}
    audio_records: dict[str, dict[str, object]] = {}
    unresolved_media: list[dict[str, object]] = []
    for reference in resolution_references:
        opcode = reference["opcode"]
        owner = "mulle" if opcode == BARN_OPCODE else reference["owner"]
        bank = barn_bank if opcode == BARN_OPCODE else reference["bank"].lower()
        prefix = owner_prefixes[owner]
        if opcode in EXACT_NATIVE_SERVICE_AUDIO_OPCODES:
            clip, variants = _select_exact_voice_variant(
                reference, voices, prefix, bank
            )
        else:
            clip, variants = _select_voice_variants(reference, voices, prefix, bank)
        logical = (opcode, reference["owner"], reference["id"], bank)
        group = media_groups.setdefault(logical, {
            "opcode": opcode,
            "owner": reference["owner"],
            "scriptNumber": reference["id"],
            "resolvedPrefix": prefix,
            "resolvedClip": clip,
            "bank": bank,
            "variants": [],
            "references": [],
        })
        if opcode in EXACT_NATIVE_SERVICE_AUDIO_OPCODES:
            implicit_identity = {
                "sourceOpcode": reference["sourceOpcode"],
                "requiredTake": reference["requiredTake"],
                "placement": reference["placement"],
                "semanticStatus": reference["semanticStatus"],
                "parityEligible": reference["parityEligible"],
            }
            previous_identity = group.get("nativeImplicit")
            if previous_identity is not None and previous_identity != implicit_identity:
                raise ValueError(f"inconsistent native implicit media identity {logical!r}")
            group["nativeImplicit"] = implicit_identity
        reference_site = (
            {
                "domainId": reference["domainId"],
                "source": reference["source"],
                "loop": reference["loop"],
            }
            if opcode in {
                MYGGHANGET_OPCODE, RADIO_ALERT_OPCODE,
                *EXACT_NATIVE_SERVICE_AUDIO_OPCODES,
            }
            else {
                "path": reference["path"],
                "node": reference["node"],
                "loop": reference["loop"],
            }
        )
        if reference_site not in group["references"]:
            group["references"].append(reference_site)
        if clip is None:
            if opcode == MYGGHANGET_OPCODE:
                raise ValueError("Mygghanget native take domain is absent from this edition")
            if opcode == RADIO_ALERT_OPCODE:
                raise ValueError(
                    f"native PLAY_RADIO alert {reference['id']} is absent from this edition"
                )
            group["status"] = "ABSENT_NO_COMMAND_NODE"
            unresolved = {
                "opcode": opcode,
                "owner": reference["owner"],
                "scriptNumber": reference["id"],
                "resolvedPrefix": prefix,
                "bank": bank,
                "reference": reference_site,
            }
            if unresolved not in unresolved_media:
                unresolved_media.append(unresolved)
            continue
        if opcode == MYGGHANGET_OPCODE:
            expected_takes = native_mygghanget_contract["voice"]["takeDomain"]
            actual_takes = [voice.take for voice in variants]
            if actual_takes != expected_takes:
                raise ValueError(
                    "Mygghanget native take domain differs from the edition archive: "
                    f"native={expected_takes}, archive={actual_takes}"
                )
        if opcode == RADIO_ALERT_OPCODE:
            actual_takes = [voice.take for voice in variants]
            expected_takes = list(range(1, len(actual_takes) + 1))
            if not actual_takes or actual_takes != expected_takes:
                raise ValueError(
                    "native PLAY_RADIO alert take domain is empty or non-contiguous: "
                    f"clip={reference['id']}, archive={actual_takes}"
                )
        if opcode in EXACT_NATIVE_SERVICE_AUDIO_OPCODES:
            actual_takes = [voice.take for voice in variants]
            if actual_takes != [reference["requiredTake"]]:
                raise ValueError(
                    f"native implicit media take identity drifted: {reference!r}"
                )
        group["status"] = "RESOLVED"
        variant_items = []
        for voice in variants:
            voice_raw = voice.entry.read()
            if not voice_raw.startswith(b"RIFF") or voice_raw[8:12] != b"WAVE":
                raise ValueError(f"referenced voice is not a RIFF/WAVE asset: {voice.entry.path}")
            if (
                opcode in EXACT_NATIVE_SERVICE_AUDIO_OPCODES
                and sound_source.provenance.get("sha256")
                == native_udsp_scene_commands.NL_SOUNDS_ARCHIVE_SHA256
            ):
                expected_hashes = {
                    _path_key(path): digest
                    for path, digest in
                    native_udsp_scene_commands.NL_SERVICE_MEDIA_SHA256.items()
                }
                expected_hash = expected_hashes.get(_path_key(voice.entry.path))
                actual_hash = _sha256(voice_raw)
                if expected_hash is None or actual_hash != expected_hash:
                    raise ValueError(
                        "pinned Dutch native implicit media differs from its audit: "
                        f"{voice.entry.path}"
                    )
            source_name = PureWindowsPath(voice.entry.path).name
            key = f"flight-voice-{voice.prefix}-{voice.take:02d}-{voice.clip:04d}-{voice.bank}"
            output_relative = f"scenes/audio/{voice.bank}/{source_name.lower()}"
            record = {
                "type": "audio",
                "key": key,
                "urls": [f"assets/miel-vliegt/{output_relative}"],
                "source": voice.entry.path.replace("\\", "/"),
                "sourceSha256": _sha256(voice_raw),
                "prefix": voice.prefix,
                "take": voice.take,
                "clip": voice.clip,
                "bank": voice.bank,
            }
            previous = audio_records.get(key)
            if previous is not None and previous != record:
                raise ValueError(f"generated Phaser audio key collision: {key}")
            audio_records[key] = record
            if output_relative in payloads and previous is None:
                raise ValueError(f"generated audio path collision: {output_relative}")
            payloads[output_relative] = voice.entry.read
            variant_items.append({
                "key": key,
                "take": voice.take,
                "sourceSha256": record["sourceSha256"],
            })
        if group["variants"] and group["variants"] != variant_items:
            raise ValueError(f"inconsistent variants for logical media {logical!r}")
        group["variants"] = variant_items

    assets = image_records + [audio_records[key] for key in sorted(audio_records)]
    pack_sections = _build_pack_sections(
        dispatch,
        scripts,
        image_records,
        media_groups,
        audio_records,
        native_mygghanget_contract if has_mygghanget else None,
    )
    contract = {
        "schema": 1,
        "contract": "miel-vliegt-flight-scene-assets",
        "edition": dispatch["edition"],
        "claim": "EDITION_SOURCE_ASSET_INVENTORY",
        "sources": {
            "dispatch": {"path": _display_path(dispatch_path), "sha256": _sha256(dispatch_raw)},
            "scripts": {"path": _display_path(scripts_path), "sha256": _sha256(scripts_raw)},
            "nativeUdspCommands": {
                "path": _display_path(native_udsp_path),
                "sha256": _sha256(native_udsp_raw),
                "claim": native_udsp_contract["claim"],
                "executableSha256": native_udsp_executable,
            },
            "generator": {
                "path": _display_path(Path(__file__)),
                "sha256": _sha256(Path(__file__).read_bytes()),
            },
            "data": data_source.provenance,
            "sounds": sound_source.provenance,
            "nativeVoice": native_voice_contract,
            "nativeMygghanget": native_mygghanget_contract,
        },
        "resolution": {
            "voiceFilename": "<prefix:2><take:2><clip:4><bank:1-2>.wav",
            "ownerPrefixes": owner_prefixes,
            "barnBank": barn_bank,
            "selectorPolicy": "exact-script-number",
            "variants": "all-native-takes-for-the-resolved-prefix-clip-bank",
            "ignoredUnreferencedVoiceFiles": ignored_voices,
        },
        "domains": {
            "locations": domains,
            "characters": characters,
        },
        "counts": {
            "locationDomains": len(domains),
            "characterDomains": len(characters),
            "images": len(image_records),
            "logicalMedia": len(media_groups),
            "audioVariants": len(audio_records),
            "unresolvedMedia": len(unresolved_media),
        },
        "images": image_records,
        "media": [media_groups[key] for key in sorted(media_groups, key=lambda item: tuple(map(str, item)))],
        "unresolvedReferencedMedia": sorted(
            unresolved_media,
            key=lambda item: (
                item["owner"], item["scriptNumber"], item["bank"], item["reference"]["path"]
            ),
        ),
        "audio": [audio_records[key] for key in sorted(audio_records)],
        "packSections": pack_sections,
    }
    return contract, payloads


def export_scene_assets(
    contract: dict[str, object], payloads: dict[str, Callable[[], bytes]], output: Path
) -> None:
    asset_root = output / "miel-vliegt"
    for relative, load_payload in sorted(payloads.items()):
        destination = asset_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(load_payload())
    assets: dict[str, dict[str, object]] = {}
    for image in contract["images"]:
        record = {key: image[key] for key in ("type", "key", "url")}
        if record["key"] in assets:
            raise ValueError(f"duplicate exported Phaser asset key: {record['key']}")
        assets[record["key"]] = record
    for audio in contract["audio"]:
        record = {key: audio[key] for key in ("type", "key", "urls")}
        if record["key"] in assets:
            raise ValueError(f"duplicate exported Phaser asset key: {record['key']}")
        assets[record["key"]] = record
    pack: dict[str, list[dict[str, object]]] = {}
    assigned: set[str] = set()
    for section in contract.get("packSections", []):
        section_key = section.get("key")
        keys = section.get("assetKeys")
        if (
            type(section_key) is not str
            or not section_key
            or section_key in pack
            or not isinstance(keys, list)
            or any(type(key) is not str for key in keys)
            or keys != sorted(keys)
        ):
            raise ValueError(f"invalid or duplicate Phaser pack section: {section!r}")
        duplicates = assigned.intersection(keys)
        if duplicates:
            raise ValueError(f"asset keys assigned to multiple Phaser sections: {sorted(duplicates)}")
        missing = set(keys) - set(assets)
        if missing:
            raise ValueError(f"Phaser pack section references missing assets: {sorted(missing)}")
        assigned.update(keys)
        pack[section_key] = [assets[key] for key in keys]
    if assigned != set(assets):
        raise ValueError("Phaser pack sections do not export the complete asset inventory")
    output.mkdir(parents=True, exist_ok=True)
    (output / "flight_scene_assets.json").write_text(
        json.dumps(pack, indent=2) + "\n", encoding="utf-8"
    )
    (output / "flight_scene_asset_contract.json").write_text(
        json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-root", type=Path, help="extracted root containing data/")
    source.add_argument("--data-archive", type=Path, help="edition data.up archive")
    parser.add_argument("--sounds-archive", type=Path, help="edition sounds.up archive")
    parser.add_argument(
        "--executable", type=Path, required=True,
        help="installed edition MulleMeck.exe used to prove native voice filenames",
    )
    parser.add_argument("--dispatch", type=Path, default=DEFAULT_DISPATCH)
    parser.add_argument("--scripts", type=Path, default=DEFAULT_SCRIPTS)
    parser.add_argument(
        "--native-udsp-commands", type=Path, default=DEFAULT_NATIVE_UDSP,
        help="corrected native opcode/runtime contract for implicit service media",
    )
    parser.add_argument("--output", type=Path, help="generated Phaser asset directory")
    parser.add_argument("--contract-output", type=Path, help="write provenance contract only")
    parser.add_argument("--inventory-only", action="store_true", help="validate without asset writes")
    args = parser.parse_args()
    if args.source_root is not None:
        if args.sounds_archive is not None:
            raise ValueError("--sounds-archive cannot be combined with --source-root")
        data_source = sound_source = DirectorySource(args.source_root)
    else:
        if args.sounds_archive is None:
            raise ValueError("--data-archive requires --sounds-archive")
        data_source = ArchiveSource(args.data_archive)
        sound_source = ArchiveSource(args.sounds_archive)
    scripts = json.loads(args.scripts.read_text(encoding="utf-8"))
    owners = {
        reference["owner"]
        for reference in scripts.get("media_references", [])
        if reference.get("opcode") in VOICE_OPCODES
    }
    native_voice_contract = extract_native_voice_contract(args.executable, owners)
    native_mygghanget_contract = extract_native_mygghanget_contract(args.executable)
    contract, payloads = build_scene_asset_contract(
        args.dispatch,
        args.scripts,
        data_source,
        sound_source,
        native_voice_contract,
        native_mygghanget_contract,
        args.native_udsp_commands,
    )
    if args.contract_output:
        args.contract_output.parent.mkdir(parents=True, exist_ok=True)
        args.contract_output.write_text(
            json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    if not args.inventory_only:
        if args.output is None:
            raise ValueError("--output is required unless --inventory-only is used")
        export_scene_assets(contract, payloads, args.output)
    print(json.dumps(contract["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
