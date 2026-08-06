#!/usr/bin/env python3
"""Keep every flight-oracle Docker COPY source inside the build context."""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_DOCKERFILE = ROOT / "deployment/docker/Dockerfile.boten"
DOCKERFILES = tuple(
    ROOT / "tools/miel_vliegt" / name / "Dockerfile"
    for name in ("hangover", "x86_wine", "fex_wine")
)
CONTENT_JSON_LITERAL = re.compile(
    r"[\"'`]([^\"'`]*content/miel_vliegt/[^\"'`]+\.json)[\"'`]"
)
LOCAL_C_INCLUDE = re.compile(r'^\s*#include\s+"([^"]+)"', re.MULTILINE)


def copied_repository_paths(dockerfiles: tuple[Path, ...] = DOCKERFILES) -> set[str]:
    paths: set[str] = set()
    for dockerfile in dockerfiles:
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            paths.update(docker_copy_sources(line))
    return paths


def explicit_includes() -> tuple[str, ...]:
    return tuple(
        line[1:]
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.startswith("!")
    )


def explicitly_included(path: str, includes: tuple[str, ...]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern)
        or (pattern.endswith("/") and path.startswith(pattern))
        for pattern in includes
    )


def explicitly_file_included(path: str, includes: tuple[str, ...]) -> bool:
    """Require a file/glob rule instead of accepting its parent directory."""

    return any(
        not pattern.endswith("/") and fnmatch.fnmatchcase(path, pattern)
        for pattern in includes
    )


def production_bundle_content_imports() -> set[str]:
    """Resolve every flight JSON reference in production JavaScript.

    Scanning literals instead of selected import syntax makes side-effect and
    dynamic imports fail closed too. A non-import evidence reference is a safe
    over-approximation: making it available to webpack cannot hide a missing
    bundle dependency.
    """

    imports: set[str] = set()
    for source in (ROOT / "src").rglob("*.js"):
        if "__tests__" in source.parts or source.name.endswith(".test.js"):
            continue
        for value in CONTENT_JSON_LITERAL.findall(source.read_text(encoding="utf-8")):
            resolved = (
                ROOT / value if value.startswith("content/") else source.parent / value
            ).resolve()
            imports.add(resolved.relative_to(ROOT.resolve()).as_posix())
    return imports


def docker_copy_sources(line: str) -> tuple[str, ...]:
    """Parse one Docker COPY without silently ignoring supported syntax."""

    stripped = line.strip()
    match = re.match(r"^COPY\b(.*)$", stripped, re.IGNORECASE)
    if not match:
        return ()
    instruction = match.group(1).strip()
    if not instruction or instruction.endswith("\\"):
        raise ValueError(f"unsupported or incomplete Docker COPY: {line}")
    while instruction.startswith("--"):
        option, separator, remainder = instruction.partition(" ")
        if not separator:
            raise ValueError(f"invalid Docker COPY option: {line}")
        if option.lower().startswith("--from="):
            return ()
        instruction = remainder.lstrip()
    if instruction.startswith("["):
        try:
            values = json.loads(instruction)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON Docker COPY: {line}") from error
        if not isinstance(values, list) or len(values) < 2 \
                or any(not isinstance(value, str) for value in values):
            raise ValueError(f"invalid JSON Docker COPY: {line}")
        return tuple(values[:-1])
    try:
        values = shlex.split(instruction)
    except ValueError as error:
        raise ValueError(f"invalid shell Docker COPY: {line}") from error
    if len(values) < 2:
        raise ValueError(f"invalid shell Docker COPY: {line}")
    return tuple(values[:-1])


def production_builder_copy_sources() -> set[str]:
    """Return repository sources available to the clean webpack build stage."""

    sources: set[str] = set()
    in_builder = False
    for line in PRODUCTION_DOCKERFILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if re.match(r"^FROM\b", stripped, re.IGNORECASE):
            in_builder = bool(re.search(r"\bAS\s+builder_js$", stripped, re.IGNORECASE))
            continue
        if not in_builder:
            continue
        for source in docker_copy_sources(stripped):
            sources.add(source.removeprefix("./"))
    return sources


def win32_builder_src_files(dockerfile: Path) -> dict[str, Path]:
    """Map repository files copied into /src by the first Docker stage."""

    copied: dict[str, Path] = {}
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if re.match(r"^FROM\b", stripped, re.IGNORECASE):
            if copied:
                break
            continue
        match = re.match(r"^COPY\s+(\S+)\s+(/src/\S+)$", stripped)
        if not match:
            continue
        source, destination = match.groups()
        copied[Path(destination).name] = ROOT / source.removeprefix("./")
    return copied


def generated_win32_builder_headers(dockerfile: Path) -> set[str]:
    return set(re.findall(
        r"\bemit-header\s+/src/([A-Za-z0-9_.-]+)",
        dockerfile.read_text(encoding="utf-8"),
    ))


class FlightDockerContextTests(unittest.TestCase):
    def test_every_repository_copy_source_is_explicitly_included(self):
        includes = explicit_includes()
        missing = sorted(
            path for path in copied_repository_paths()
            if not explicitly_included(path, includes)
        )
        self.assertEqual(missing, [])

    def test_observer_sources_are_not_satisfied_by_unrelated_parent_rule(self):
        includes = explicit_includes()
        for path in (
            "tools/miel_vliegt/hangover/native_observer_hook.c",
            "tools/miel_vliegt/hangover/native_observer_launcher.c",
            "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.h",
            "tools/miel_vliegt/hangover/native_dispatch_capture_targets.generated.h",
            "tools/miel_vliegt/x86_wine/native_observer_dinput_proxy.c",
        ):
            self.assertTrue(explicitly_file_included(path, includes), path)

    def test_win32_builder_local_include_closure_is_copied_or_generated(self):
        for dockerfile in DOCKERFILES:
            copied = win32_builder_src_files(dockerfile)
            available = copied.keys() | generated_win32_builder_headers(dockerfile)
            missing: dict[str, list[str]] = {}
            for destination, source in copied.items():
                if source.suffix not in {".c", ".h"}:
                    continue
                local_includes = LOCAL_C_INCLUDE.findall(
                    source.read_text(encoding="utf-8")
                )
                unresolved = sorted(set(local_includes) - available)
                if unresolved:
                    missing[destination] = unresolved
            with self.subTest(dockerfile=dockerfile.relative_to(ROOT)):
                self.assertEqual(missing, {})

    def test_every_observer_dll_links_the_semantic_hook_implementation(self):
        expected = (
            "/src/native_observer_hook.c /src/native_dispatch_semantic_hook.c"
        )
        for dockerfile in DOCKERFILES:
            with self.subTest(dockerfile=dockerfile.relative_to(ROOT)):
                self.assertIn(
                    expected,
                    dockerfile.read_text(encoding="utf-8"),
                )

    def test_clean_production_builder_copies_every_imported_flight_contract(self):
        self.assertEqual(
            sorted(production_bundle_content_imports() - production_builder_copy_sources()),
            [],
        )

    def test_production_copy_parser_does_not_ignore_valid_docker_forms(self):
        self.assertEqual(
            docker_copy_sources('copy --link ["one.json", "two.json", "/build/"]'),
            ("one.json", "two.json"),
        )
        self.assertEqual(
            docker_copy_sources("COPY one.json two.json /build/"),
            ("one.json", "two.json"),
        )
        self.assertEqual(
            docker_copy_sources("COPY --from=builder /build/dist /srv"),
            (),
        )

    def test_repository_copy_inventory_uses_the_same_complete_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            dockerfile = Path(directory) / "Dockerfile"
            dockerfile.write_text(
                "COPY --link ./one.c /src/one.c\n"
                "COPY [\"./two.c\", \"./three.c\", \"/src/\"]\n",
                encoding="utf-8",
            )
            self.assertEqual(
                copied_repository_paths((dockerfile,)),
                {"./one.c", "./two.c", "./three.c"},
            )

    def test_flight_contract_literals_cover_every_javascript_import_form(self):
        source = "\n".join((
            "import '../../../content/miel_vliegt/static.json'",
            "import (`../../../content/miel_vliegt/dynamic.json`)",
            "require ('../../../content/miel_vliegt/required.json')",
        ))
        self.assertEqual(
            set(CONTENT_JSON_LITERAL.findall(source)),
            {
                "../../../content/miel_vliegt/static.json",
                "../../../content/miel_vliegt/dynamic.json",
                "../../../content/miel_vliegt/required.json",
            },
        )


if __name__ == "__main__":
    unittest.main()
