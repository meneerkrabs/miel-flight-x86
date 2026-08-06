#!/usr/bin/env python3
"""Extract placement, animation and timing contracts from UDS DEF scripts."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


SCRIPT_TYPES = {"CHARACTER_SCRIPT", "LOCATION_SCRIPT"}
STRUCTURAL = {"NODE", "LOOP", "{", "}"}


@dataclass(frozen=True)
class Command:
    name: str
    arguments: tuple[str, ...]
    line: int
    node: int | None
    loop: bool


@dataclass(frozen=True)
class CommandRef:
    command: int


@dataclass(frozen=True)
class Composite:
    node: int | None
    repeat: bool
    children: tuple["Composite | CommandRef", ...]


@dataclass(frozen=True)
class UdsScript:
    script_type: str
    name: str | None
    commands: tuple[Command, ...]
    structure: Composite

    @classmethod
    def read(cls, path: Path) -> "UdsScript":
        return cls.parse(path.read_text(encoding="latin-1"), source=str(path))

    @classmethod
    def parse(cls, source_text: str, *, source: str = "<memory>") -> "UdsScript":
        lines = source_text.splitlines()
        significant = [line.strip() for line in lines if _content(line)]
        if not significant or significant[0] not in SCRIPT_TYPES:
            first = significant[0] if significant else "<empty>"
            raise ValueError(f"{source}: unsupported DEF type {first!r}")

        script_name = None
        node_count = 0
        commands: list[Command] = []
        root = {"node": None, "repeat": False, "children": []}
        stack: list[dict[str, object]] = []
        pending: dict[str, object] | None = root
        root_closed = False
        index = 0
        while index < len(lines):
            content = _content(lines[index])
            if not content:
                index += 1
                continue
            if content in SCRIPT_TYPES:
                if index != next(
                    candidate for candidate, line in enumerate(lines) if _content(line)
                ) or content != significant[0]:
                    raise ValueError(f"{source}:{index + 1}: misplaced script header")
                index += 1
                continue
            if content == "{":
                if pending is None:
                    raise ValueError(f"{source}:{index + 1}: unexpected opening brace")
                stack.append(pending)
                pending = None
                index += 1
                continue
            if content == "}":
                if pending is not None:
                    raise ValueError(f"{source}:{index + 1}: NODE must be followed by '{{'")
                if not stack:
                    raise ValueError(f"{source}:{index + 1}: unexpected closing brace")
                closed = stack.pop()
                if closed is root:
                    root_closed = True
                index += 1
                continue
            if root_closed:
                raise ValueError(f"{source}:{index + 1}: trailing script content {content!r}")
            if pending is not None:
                raise ValueError(f"{source}:{index + 1}: NODE must be followed by '{{'")
            if not stack:
                raise ValueError(f"{source}:{index + 1}: script content is outside braces")
            current = stack[-1]
            if content.startswith("NAME"):
                values = content.split(None, 1)
                if current is not root or script_name is not None:
                    raise ValueError(f"{source}:{index + 1}: misplaced or duplicate NAME")
                script_name = values[1].strip() if len(values) == 2 else None
                index += 1
                continue
            if content == "NODE":
                node_count += 1
                child: dict[str, object] = {
                    "node": node_count, "repeat": False, "children": [],
                }
                current["children"].append(child)
                pending = child
                index += 1
                continue
            if content == "LOOP":
                if current["repeat"] is True:
                    raise ValueError(f"{source}:{index + 1}: duplicate LOOP")
                current["repeat"] = True
                index += 1
                continue
            if content.startswith("COMM"):
                start_line = index + 1
                expression = content[4:].strip()
                index += 1
                while index < len(lines):
                    continuation = _content(lines[index])
                    if not continuation:
                        index += 1
                        continue
                    if (
                        continuation in STRUCTURAL
                        or continuation in SCRIPT_TYPES
                        or continuation.startswith(("COMM", "NAME", "NODE"))
                    ):
                        break
                    expression += " " + continuation
                    index += 1
                name, arguments = _command(expression, source, start_line)
                command_index = len(commands)
                commands.append(Command(
                    name, arguments, start_line,
                    current["node"], bool(current["repeat"]),
                ))
                current["children"].append(CommandRef(command_index))
                continue
            raise ValueError(f"{source}:{index + 1}: unsupported script field {content!r}")

        if pending is not None or stack or not root_closed:
            raise ValueError(f"{source}: script has unclosed braces or NODE")

        def freeze(node: dict[str, object]) -> Composite:
            return Composite(
                node=node["node"],
                repeat=bool(node["repeat"]),
                children=tuple(
                    freeze(child) if isinstance(child, dict) else child
                    for child in node["children"]
                ),
            )

        return cls(significant[0], script_name, tuple(commands), freeze(root))

    def manifest(self, source: str | None = None) -> dict[str, object]:
        result: dict[str, object] = asdict(self)
        if source is not None:
            result["source"] = source
        result["placements"] = [
            {
                "character": command.arguments[0],
                "x": _number(command.arguments[1]),
                "y": _number(command.arguments[2]),
                "line": command.line,
                "node": command.node,
            }
            for command in self.commands
            if command.name == "POSITION_CHARACTER" and len(command.arguments) >= 3
        ]
        result["waits"] = [
            {
                "seconds": _number(command.arguments[0]),
                "mode": command.arguments[1] if len(command.arguments) > 1 else None,
                "line": command.line,
                "node": command.node,
                "loop": command.loop,
            }
            for command in self.commands
            if command.name == "WAIT" and command.arguments
        ]
        result["animations"] = [
            {
                "part_id": _number(command.arguments[0]),
                "animation_id": _number(command.arguments[1]),
                "playback_rate_fps": _number(command.arguments[2]),
                "playback": command.arguments[3] if len(command.arguments) > 3 else None,
                "modifier": command.arguments[4] if len(command.arguments) > 4 else None,
                "repeat_count": _number(command.arguments[5]) if len(command.arguments) > 5 else None,
                "line": command.line,
                "node": command.node,
                "loop": command.loop,
            }
            for command in self.commands
            if command.name == "PLAY_CHARACTER_ANIMATION" and len(command.arguments) >= 3
        ]
        return result


def _content(line: str) -> str:
    content = line.strip()
    if not content or content.startswith(("#", "//")):
        return ""
    return content


def _command(expression: str, source: str, line: int) -> tuple[str, tuple[str, ...]]:
    expression = expression.rstrip(", ")
    if not expression:
        raise ValueError(f"{source}:{line}: empty COMM command")
    fields = tuple(field.strip() for field in expression.split(","))
    head = fields[0].split()
    name = head[0]
    if not re.fullmatch(r"[A-Z_]+", name):
        raise ValueError(f"{source}:{line}: malformed command name {name!r}")
    arguments = tuple(head[1:]) + tuple(field for field in fields[1:] if field)
    return name, arguments


def _number(value: str) -> int | float | str:
    try:
        number = float(value)
    except ValueError:
        return value
    return int(number) if number.is_integer() else number


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", type=Path)
    parser.add_argument("--output", type=Path, help="write script contract JSON")
    args = parser.parse_args()

    script = UdsScript.read(args.script)
    encoded = json.dumps(script.manifest(str(args.script)), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
