#!/usr/bin/env python3
"""Harvest the pinned Dutch Cc.dll API and reconcile secondary symbol notes.

The PE export table is authoritative.  A secondary declaration list can add
independent discovery evidence, but it can never rename an export or promote a
runtime parity claim.  Reconciliation intentionally stops at owner/member
identity because overload signatures require a verified MSVC demangler.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

try:
    from tools.miel_vliegt.map_engine_subsystems import classify_import
except ModuleNotFoundError:
    from map_engine_subsystems import classify_import


WILLYWERKEL_COMMIT = "ac37fa19a468143df58864986ccfe5384a48d339"
WILLYWERKEL_SYMBOL_SHA256 = (
    "2ea66a3483210663a35c5a1a7340daca5572ab42e13b5a6bdab6051b4de92c1a"
)
WILLYWERKEL_URL = (
    "https://github.com/Yepoleb/willywerkel/blob/"
    f"{WILLYWERKEL_COMMIT}/Cc_symbols.txt"
)

_OPERATORS = {
    "2": "operator new",
    "3": "operator delete",
    "4": "operator=",
    "5": "operator>>",
    "6": "operator<<",
    "7": "operator!",
    "8": "operator==",
    "9": "operator!=",
    "A": "operator[]",
    "B": "operator conversion",
    "C": "operator->",
    "D": "operator*",
    "E": "operator++",
    "F": "operator--",
    "G": "operator-",
    "H": "operator+",
    "I": "operator&",
    "J": "operator->*",
    "K": "operator/",
    "L": "operator%",
    "M": "operator<",
    "N": "operator<=",
    "O": "operator>",
    "P": "operator>=",
    "Q": "operator,",
    "R": "operator()",
    "S": "operator~",
    "T": "operator^",
    "U": "operator|",
    "V": "operator&&",
    "W": "operator||",
    "X": "operator*=",
    "Y": "operator+=",
    "Z": "operator-=",
    "_0": "operator/=",
    "_1": "operator%=",
    "_2": "operator>>=",
    "_3": "operator<<=",
    "_4": "operator&=",
    "_5": "operator|=",
    "_6": "operator^=",
    "_7": "`vftable'",
}

_TEXT_OPERATORS = {
    "new", "delete", "=", ">>", "<<", "!", "==", "!=", "[]", "->",
    "*", "++", "--", "-", "+", "&", "->*", "/", "%", "<", "<=",
    ">", ">=", ",", "()", "~", "^", "|", "&&", "||", "*=", "+=",
    "-=", "/=", "%=", ">>=", "<<=", "&=", "|=", "^=",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def msvc_api_id(symbol: str) -> str:
    """Return an overload-neutral identity from a VC6 decorated export."""

    if symbol.startswith("??0"):
        owner = symbol[3:].split("@@", 1)[0]
        return f"{owner}::{owner}"
    if symbol.startswith("??1"):
        owner = symbol[3:].split("@@", 1)[0]
        return f"{owner}::~{owner}"
    if symbol.startswith("??"):
        tail = symbol[2:]
        for code in sorted(_OPERATORS, key=len, reverse=True):
            if not tail.startswith(code):
                continue
            owner = tail[len(code):].split("@@", 1)[0]
            prefix = f"{owner}::" if owner else ""
            return prefix + _OPERATORS[code]
        raise ValueError(f"unsupported MSVC operator export: {symbol}")
    if not symbol.startswith("?") or "@@" not in symbol:
        raise ValueError(f"unsupported decorated Cc export: {symbol}")
    components = symbol[1:].split("@@", 1)[0].split("@")
    member, owners = components[0], components[1:]
    prefix = "::".join(reversed(owners))
    return f"{prefix}::{member}" if prefix else member


def declaration_api_id(line: str) -> str | None:
    """Normalize one undname-style declaration without retaining its text."""

    line = line.strip()
    if not line:
        return None
    vftable = re.search(r"\b([A-Za-z_]\w*)::(`vftable')", line)
    if vftable:
        return f"{vftable.group(1)}::{vftable.group(2)}"
    data = re.search(r"\b([A-Za-z_]\w*)::([A-Za-z_]\w*)\s*$", line)
    if data:
        return f"{data.group(1)}::{data.group(2)}"
    method = re.search(r"\b([A-Za-z_]\w*)::([^:(]+?)\s*\(", line)
    if method:
        owner, member = method.groups()
        member = member.strip()
        if member.startswith("operator"):
            spelling = member[len("operator"):].strip()
            if spelling in {"new", "delete"}:
                member = f"operator {spelling}"
            elif spelling in _TEXT_OPERATORS:
                member = f"operator{spelling}"
            else:
                member = "operator conversion"
        return f"{owner}::{member}"
    prefix = line.split("(", 1)[0]
    function = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
    return function.group(1) if function else None


def parse_secondary_declarations(lines: Iterable[str]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for line in lines:
        api_id = declaration_api_id(line)
        if api_id is not None:
            counts[api_id] += 1
    return dict(sorted(counts.items()))


def build_contract(
    exports: dict[str, int],
    *,
    image_base: int,
    cc_sha256: str,
    secondary_lines: list[str],
    secondary_sha256: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", cc_sha256):
        raise ValueError("Cc.dll identity must be a lowercase SHA-256")
    if secondary_sha256 != WILLYWERKEL_SYMBOL_SHA256:
        raise ValueError("secondary Cc declaration list identity drifted")
    if len(exports) != len(set(exports)):
        raise ValueError("Cc export names are not unique")
    if any(address < image_base for address in exports.values()):
        raise ValueError("Cc export address precedes its image base")

    declarations = parse_secondary_declarations(secondary_lines)
    rows = []
    status_counts: Counter[str] = Counter()
    used_api_ids: set[str] = set()
    for symbol, address in sorted(exports.items()):
        api_id = msvc_api_id(symbol)
        candidate_count = declarations.get(api_id, 0)
        if candidate_count == 0:
            status = "NO_SECONDARY_NAME_MATCH"
        elif candidate_count == 1:
            status = "SECONDARY_NAME_MATCH"
        else:
            status = "SECONDARY_OVERLOAD_GROUP"
        status_counts[status] += 1
        if candidate_count:
            used_api_ids.add(api_id)
        rows.append({
            "decorated_symbol": symbol,
            "api_id": api_id,
            "rva": f"0x{address - image_base:08x}",
            "subsystem": classify_import(f"Cc.dll!{symbol}"),
            "secondary_candidate_count": candidate_count,
            "secondary_status": status,
        })

    unmatched_secondary = sorted(set(declarations) - used_api_ids)
    subsystem_counts = Counter(row["subsystem"] for row in rows)
    return {
        "schema": 1,
        "source": {
            "module": "Cc.dll",
            "sha256": cc_sha256,
            "image_base": f"0x{image_base:08x}",
            "authority": "PINNED_DUTCH_PE_EXPORT_TABLE",
        },
        "secondary_observation": {
            "repository": "Yepoleb/willywerkel",
            "commit": WILLYWERKEL_COMMIT,
            "path": "Cc_symbols.txt",
            "url": WILLYWERKEL_URL,
            "sha256": secondary_sha256,
            "line_count": len(secondary_lines),
            "license": "NO_LICENSE_DECLARED",
            "evidence_role": "DISCOVERY_ONLY",
            "unmatched_api_ids": unmatched_secondary,
        },
        "policy": {
            "identity": "The decorated PE export and RVA are authoritative.",
            "secondary_limit": (
                "Owner/member matches are overload-neutral discovery evidence; "
                "they never establish ABI or behavioral parity."
            ),
            "promotion": (
                "Runtime equivalence still requires an ABI contract and native "
                "differential observation against the pinned module."
            ),
        },
        "summary": {
            "exports": len(rows),
            "subsystems": dict(sorted(subsystem_counts.items())),
            "secondary_status": dict(sorted(status_counts.items())),
            "secondary_unmatched_api_ids": len(unmatched_secondary),
            "semantic_coverage_claimed": False,
        },
        "exports": rows,
    }


def verify_primary_contract(
    contract: dict[str, Any], exports: dict[str, int], *, image_base: int,
    cc_sha256: str,
) -> None:
    """Verify every authoritative field without needing the external notes."""

    source = contract.get("source")
    expected_source = {
        "module": "Cc.dll",
        "sha256": cc_sha256,
        "image_base": f"0x{image_base:08x}",
        "authority": "PINNED_DUTCH_PE_EXPORT_TABLE",
    }
    if source != expected_source:
        raise ValueError("Cc API contract source identity drifted")
    rows = contract.get("exports")
    if not isinstance(rows, list) or len(rows) != len(exports):
        raise ValueError("Cc API contract export inventory drifted")
    expected_primary = [
        {
            "decorated_symbol": symbol,
            "api_id": msvc_api_id(symbol),
            "rva": f"0x{address - image_base:08x}",
            "subsystem": classify_import(f"Cc.dll!{symbol}"),
        }
        for symbol, address in sorted(exports.items())
    ]
    actual_primary = []
    secondary_counts: Counter[str] = Counter()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Cc API contract export row is not an object")
        count = row.get("secondary_candidate_count")
        status = row.get("secondary_status")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("Cc API secondary candidate count is invalid")
        expected_status = (
            "NO_SECONDARY_NAME_MATCH" if count == 0 else
            "SECONDARY_NAME_MATCH" if count == 1 else
            "SECONDARY_OVERLOAD_GROUP"
        )
        if status != expected_status:
            raise ValueError("Cc API secondary status contradicts its candidate count")
        secondary_counts[status] += 1
        actual_primary.append({key: row.get(key) for key in expected_primary[0]})
    if actual_primary != expected_primary:
        raise ValueError("Cc API decorated export binding drifted")

    secondary = contract.get("secondary_observation", {})
    if secondary.get("commit") != WILLYWERKEL_COMMIT \
            or secondary.get("sha256") != WILLYWERKEL_SYMBOL_SHA256 \
            or secondary.get("license") != "NO_LICENSE_DECLARED" \
            or secondary.get("evidence_role") != "DISCOVERY_ONLY":
        raise ValueError("Cc API secondary provenance or evidence role drifted")
    unmatched = secondary.get("unmatched_api_ids")
    if not isinstance(unmatched, list) or unmatched != sorted(set(unmatched)):
        raise ValueError("Cc API unmatched secondary identities are not canonical")

    summary = contract.get("summary", {})
    expected_subsystems = Counter(row["subsystem"] for row in expected_primary)
    if summary.get("exports") != len(exports) \
            or summary.get("subsystems") != dict(sorted(expected_subsystems.items())) \
            or summary.get("secondary_status") != dict(sorted(secondary_counts.items())) \
            or summary.get("secondary_unmatched_api_ids") != len(unmatched) \
            or summary.get("semantic_coverage_claimed") is not False:
        raise ValueError("Cc API summary or semantic-coverage policy drifted")


def read_cc_exports(path: Path) -> tuple[int, dict[str, int]]:
    # Keep the heavy Capstone/Unicorn dependency outside the pure unit-test
    # surface; the production parity environment already pins both packages.
    try:
        from tools.miel_vliegt.analyze_native import PeImage
        from tools.miel_vliegt.pe32_micro_loader import exports
    except ModuleNotFoundError:
        from analyze_native import PeImage
        from pe32_micro_loader import exports

    image = PeImage(path)
    return image.image_base, exports(image, image.image_base)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cc_dll", type=Path)
    parser.add_argument("secondary_symbols", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--source-identity", type=Path,
        default=Path("content/miel_vliegt/source_identity.json"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    identity = json.loads(args.source_identity.read_text(encoding="utf-8"))
    expected_cc = identity.get("cc_dll", {}).get("sha256")
    actual_cc = sha256_file(args.cc_dll)
    if actual_cc != expected_cc:
        raise SystemExit("Cc.dll does not match the pinned Dutch source identity")
    actual_secondary = sha256_file(args.secondary_symbols)
    image_base, export_map = read_cc_exports(args.cc_dll)
    result = build_contract(
        export_map,
        image_base=image_base,
        cc_sha256=actual_cc,
        secondary_lines=args.secondary_symbols.read_text(
            encoding="utf-8", errors="strict"
        ).splitlines(),
        secondary_sha256=actual_secondary,
    )
    verify_primary_contract(
        result, export_map, image_base=image_base, cc_sha256=actual_cc,
    )
    encoded = json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            raise SystemExit("Cc API contract drifted")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
