#!/usr/bin/env python3
"""Harvest exact Miel Vliegt part meshes through the native CCF reference graph.

Part names are presentation data and are not identifiers.  The native path is
Parts.dat -> ATCH node -> object -> mesh; this harvester follows those numeric
references and keeps source hashes beside the resulting browser contract.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import math
import struct
from pathlib import Path

try:
    from tools.miel_vliegt.parse_barn_iff import parse_airplane, parse_part_catalog
    from tools.miel_vliegt.parse_ccf import CcfScene, SceneRecord
except ModuleNotFoundError:  # Direct ``python tools/miel_vliegt/...`` execution.
    from parse_barn_iff import parse_airplane, parse_part_catalog
    from parse_ccf import CcfScene, SceneRecord


DEFAULT_PATH = Path("data/Default")


def _record_uints(record: SceneRecord, count: int) -> tuple[int, ...]:
    return _uints(bytes.fromhex(record.prefix_hex), count)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _uints(data: bytes, count: int) -> tuple[int, ...]:
    if len(data) < count * 4:
        raise ValueError(f"expected {count} uint32 values, got {len(data)} bytes")
    return struct.unpack_from(f"<{count}I", data)


def _single(records: list[SceneRecord], description: str) -> SceneRecord:
    if len(records) != 1:
        raise ValueError(f"expected one {description}, found {len(records)}")
    return records[0]


def _attach_part_id(record: SceneRecord) -> int | None:
    properties = _attach_properties(record)
    return int(properties["part_id"]) if properties else None


def _attach_properties(record: SceneRecord) -> dict[str, object] | None:
    for metadata in record.metadata_chunks:
        if metadata["id"] != "0x4210":
            continue
        payload = bytes.fromhex(str(metadata["payload_hex"]))
        if len(payload) == 44 and payload[4:8] == b"ATCH":
            values = struct.unpack_from("<9I", payload, 8)
            return {
                "component_type": values[0],
                "part_id": values[1],
                "fields": list(values[2:]),
                "payload_hex": payload.hex(),
            }
    return None


def _extension_properties(record: SceneRecord) -> dict[str, object] | None:
    for metadata in record.metadata_chunks:
        if metadata["id"] != "0x4210":
            continue
        payload = bytes.fromhex(str(metadata["payload_hex"]))
        if len(payload) == 12 and payload[4:8] == b"EXT0":
            return {
                "compatibility_mask": struct.unpack_from("<I", payload, 8)[0],
                "payload_hex": payload.hex(),
            }
    return None


def _attachment_targets(scene: CcfScene, model: str) -> dict[int, list[dict[str, object]]]:
    """Rebuild the native Cc blueprint tree and EXT0 wrapper order.

    Cc.dll links source siblings in file order, reverses them while making a
    runtime instance, and Mulle prepends every EXT0 wrapper found by preorder.
    The two runtime reversals make the serialized target list equal to source
    blueprint postorder filtered to EXT0 nodes.
    """
    records_by_reference: dict[int, SceneRecord] = {}
    parent_by_reference: dict[int, int] = {}
    children_by_reference: dict[int, list[int]] = {}
    source_attaches: list[tuple[int, int]] = []
    for record in scene.records:
        prefix = bytes.fromhex(record.prefix_hex)
        if record.kind == "mesh":
            if len(prefix) < 10:
                raise ValueError(f"mesh {record.name!r} has no blueprint references")
            reference = struct.unpack_from("<I", prefix, 0)[0]
            parent_reference = struct.unpack_from("<I", prefix, 6)[0]
        elif record.kind == "node":
            reference, loaded_scene_reference, parent_reference = _record_uints(record, 3)
            if loaded_scene_reference != 0:
                continue
        else:
            continue
        records_by_reference[reference] = record
        parent_by_reference[reference] = parent_reference
        children_by_reference.setdefault(parent_reference, []).append(reference)
        part_id = _attach_part_id(record)
        if part_id is not None:
            source_attaches.append((reference, int(part_id)))

    targets_by_part: dict[int, list[dict[str, object]]] = {}
    for attach_reference, part_id in source_attaches:
        postorder: list[int] = []

        def visit(reference: int) -> None:
            for child_reference in children_by_reference.get(reference, []):
                visit(child_reference)
            postorder.append(reference)

        visit(attach_reference)
        targets = []
        for reference in postorder:
            record = records_by_reference[reference]
            extension = _extension_properties(record)
            if extension is None:
                continue
            targets.append({
                "node_id": f"{model}#part:{part_id}:ext0:{reference:08x}",
                "name": record.name,
                "link_slot": len(targets) + 1,
                "compatibility_mask": extension["compatibility_mask"],
                "transform": {
                    "position": list(record.position or (0.0, 0.0, 0.0)),
                    "scale": record.scale,
                    "orientation": [list(row) for row in (record.orientation or ())],
                },
                "source": {
                    "record_offset": record.offset,
                    "reference": reference,
                    "parent_reference": parent_by_reference[reference],
                    "attach_reference": attach_reference,
                    "payload_hex": extension["payload_hex"],
                    "ordering": "CCF_BLUEPRINT_POSTORDER_STATIC",
                    "native_slot_proven": True,
                },
            })
        if targets:
            targets_by_part[part_id] = targets
    return targets_by_part


def _model_path(source_root: Path, catalog_path: str) -> Path:
    normalized = Path(catalog_path.replace("\\", "/"))
    parts = normalized.parts
    if not parts or parts[0].lower() != "data":
        raise ValueError(f"part model is outside Data/: {catalog_path}")
    return source_root / "data" / Path(*parts[1:])


def _transform_vertex(record: SceneRecord, vertex: tuple[float, float, float]) -> list[float]:
    position = record.position or (0.0, 0.0, 0.0)
    orientation = record.orientation or ((1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (0.0, 0.0, 1.0))
    transformed = [
        position[row]
        + record.scale * sum(orientation[row][column] * vertex[column] for column in range(3))
        for row in range(3)
    ]
    if not all(math.isfinite(value) for value in transformed):
        raise ValueError(f"non-finite transformed vertex in {record.name!r}")
    return transformed


def harvest(source_root: Path) -> dict[str, object]:
    defaults = source_root / DEFAULT_PATH
    catalog_path = defaults / "Parts.dat"
    airplane_path = defaults / "airplane.dat"
    parts = parse_part_catalog(catalog_path)
    airplane = parse_airplane(airplane_path)
    scene_cache: dict[Path, CcfScene] = {}
    output_parts = []
    material_uses = 0
    vertex_count = 0
    triangle_count = 0
    uv_triangle_count = 0
    attachment_target_count = 0
    parts_with_attachment_targets = 0

    for part in parts:
        path = _model_path(source_root, part.model_path)
        if not path.is_file():
            raise ValueError(f"missing CCF model for part {part.part_id}: {path}")
        scene = scene_cache.setdefault(path, CcfScene(path))
        model = str(path.relative_to(source_root)).replace("\\", "/")
        targets_by_part = _attachment_targets(scene, model)
        attach_objects = []
        for candidate in scene.records:
            if candidate.kind != "node" or _attach_part_id(candidate) != part.part_id:
                continue
            attach_reference = _uints(bytes.fromhex(candidate.prefix_hex), 1)[0]
            for object_candidate in scene.records:
                if (
                    object_candidate.kind == "object"
                    and _uints(bytes.fromhex(object_candidate.prefix_hex), 4)[3]
                    == attach_reference
                ):
                    # Mulle and Buffa are preview actors parented to many part
                    # attachment nodes. They are not catalog part geometry.
                    if object_candidate.name not in {"mulle", "buffa"}:
                        attach_objects.append((candidate, object_candidate))
        # Part 45 has two non-actor children. Native child order selects the
        # final object (the first is the static Bleriot preview tail).
        if part.part_id == 45 and len(attach_objects) == 2:
            attach_objects = attach_objects[-1:]
        if len(attach_objects) != 1:
            raise ValueError(
                f"expected one joined ATCH/object pair for part {part.part_id}, "
                f"found {len(attach_objects)}"
            )
        attach, object_record = attach_objects[0]
        native_properties = _attach_properties(attach)
        if native_properties is None or native_properties["part_id"] != part.part_id:
            raise ValueError(f"missing ATCH properties for part {part.part_id}")
        mesh_reference = _uints(bytes.fromhex(object_record.prefix_hex), 2)[1]
        mesh_record = _single(
            [
                record
                for record in scene.records
                if record.kind == "mesh"
                and _uints(bytes.fromhex(record.prefix_hex), 1)[0] == mesh_reference
            ],
            f"mesh for part {part.part_id}",
        )
        geometry = scene.mesh(mesh_record)
        if geometry.reference != mesh_reference:
            raise ValueError(f"mesh reference drift for part {part.part_id}")

        material_references = sorted({triangle.material_reference for triangle in geometry.triangles})
        materials = {}
        for reference in material_references:
            material_record = _single(
                [
                    record
                    for record in scene.records
                    if record.kind == "material"
                    and _uints(bytes.fromhex(record.prefix_hex), 1)[0] == reference
                ],
                f"material {reference:#x} for part {part.part_id}",
            )
            material = scene.material(material_record)
            materials[str(reference)] = {"name": material_record.name, "texture": material.texture}

        vertices = [_transform_vertex(object_record, vertex.position) for vertex in geometry.vertices]
        triangles = [
            {
                "indices": list(triangle.indices),
                "material": triangle.material_reference,
                "uv": [list(point) for point in triangle.uv] if triangle.uv else None,
            }
            for triangle in geometry.triangles
        ]
        xs = [vertex[0] for vertex in vertices]
        ys = [vertex[1] for vertex in vertices]
        zs = [vertex[2] for vertex in vertices]
        output_parts.append(
            {
                "part_id": part.part_id,
                "model": part.model_path,
                "attach": attach.name,
                "object": object_record.name,
                "mesh": mesh_record.name,
                "native_properties": native_properties,
                "transform": {
                    "position": list(object_record.position or (0.0, 0.0, 0.0)),
                    "scale": object_record.scale,
                    "orientation": [list(row) for row in (object_record.orientation or ())],
                },
                "bounds": {"min": [min(xs), min(ys), min(zs)], "max": [max(xs), max(ys), max(zs)]},
                "vertices": vertices,
                "triangles": triangles,
                "materials": materials,
                "attachment_targets": targets_by_part.get(part.part_id, []),
            }
        )
        attachment_target_count += len(targets_by_part.get(part.part_id, []))
        parts_with_attachment_targets += int(bool(targets_by_part.get(part.part_id)))
        vertex_count += len(vertices)
        triangle_count += len(triangles)
        uv_triangle_count += sum(triangle["uv"] is not None for triangle in triangles)
        material_uses += len(materials)

    model_sources = {
        str(path.relative_to(source_root)).replace("\\", "/"): {"sha256": _sha256(path)}
        for path in sorted(scene_cache)
    }
    default_ids = [link.part_id for link in airplane]
    contract = {
        "schema": 2,
        "sources": {
            "Parts.dat": {"sha256": _sha256(catalog_path)},
            "airplane.dat": {"sha256": _sha256(airplane_path)},
            "models": model_sources,
        },
        "counts": {
            "models": len(scene_cache),
            "parts": len(output_parts),
            "vertices": vertex_count,
            "triangles": triangle_count,
            "triangles_with_uv": uv_triangle_count,
            "triangles_without_uv": triangle_count - uv_triangle_count,
            "material_uses": material_uses,
            "attachment_targets": attachment_target_count,
            "parts_with_attachment_targets": parts_with_attachment_targets,
        },
        "default_airplane": default_ids,
        "parts": output_parts,
    }
    expected = {
        "models": 31,
        "parts": 256,
        "vertices": 11882,
        "triangles": 20584,
        "triangles_with_uv": 20552,
        "triangles_without_uv": 32,
        "material_uses": 362,
        "attachment_targets": 537,
        "parts_with_attachment_targets": 148,
    }
    if contract["counts"] != expected:
        raise ValueError(f"CCF corpus invariants drifted: {contract['counts']} != {expected}")
    if default_ids != [6, 47, 209, 31, 80, 55]:
        raise ValueError(f"default airplane graph drifted: {default_ids}")
    return contract


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="root containing extracted data/")
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(harvest(args.source), separators=(",", ":")) + "\n"
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.is_file() else ""
        if current != encoded:
            diff = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    encoded.splitlines(keepends=True),
                    fromfile=str(args.output),
                    tofile="fresh CCF harvest",
                )
            )
            raise SystemExit(f"CCF part parity contract drifted:\n{diff[:12000]}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
