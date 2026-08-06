#!/usr/bin/env python3
"""Validate clean-room engine coverage against the generated subsystem map."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt.behavior_evidence import load_json_strict
    from tools.miel_vliegt.build_mission_action_contracts import build as build_mission_actions
    from tools.miel_vliegt.build_mission_action_contracts import validate as validate_mission_actions
    from tools.miel_vliegt.ccf_pixel_parity import verify as verify_ccf_pixels
    from tools.miel_vliegt.engine_runtime_contract import validate_gameplay_runtime_inventory
    from tools.miel_vliegt.flight_trajectory import verify_contract as verify_trajectories
except ModuleNotFoundError:
    from behavior_evidence import load_json_strict
    from build_mission_action_contracts import build as build_mission_actions
    from build_mission_action_contracts import validate as validate_mission_actions
    from ccf_pixel_parity import verify as verify_ccf_pixels
    from engine_runtime_contract import validate_gameplay_runtime_inventory
    from flight_trajectory import verify_contract as verify_trajectories


DISPOSITIONS = {"PARTIAL", "MISSING", "PLATFORM_SUBSTITUTION", "EQUIVALENT"}
SHA256 = 64
EQUIVALENCE_PROTOCOL = "miel-vliegt-engine-native-differential"
SUBSTITUTION_PROTOCOL = "miel-vliegt-reviewed-platform-substitution"
SUBSTITUTION_REVIEW_AUTHORITIES = {"clean-room-architecture"}
BOUNDARY_OBSERVATION_PROTOCOL = "miel-vliegt-engine-boundary-observation"
BOUNDARY_DIFFERENTIAL_PROTOCOL = "miel-vliegt-engine-boundary-differential"
BOUNDARY_COMPARATOR = "exact-json-v1"
BOUNDARY_COMPARISON_POLICY = {"ordered_observations": "EXACT_CANONICAL_JSON"}
PACKAGE_IO_ARCHIVES = [
    {"filename": "data.up", "sha256": "e5c8c1c7b5f8eb871692ffcf6812050999c9bf2c2fd2799ef6066498c7a9300a"},
    {"filename": "map.up", "sha256": "9f8d52a0df861ff947c2c9bf4f3e738f1c569a8b9c74feda93c24bd96d066c75"},
    {"filename": "sounds.up", "sha256": "7d1fe9a6adcfee26fd91fbf98d78110e5df42f5ddce52568d27548983decf676"},
]
PACKAGE_IO_BUILD_SOURCES = [
    "tools/miel_vliegt/extract_udsp.py",
    "deployment/hydrate-proven-flight-payloads.sh",
]
PACKAGE_IO_RUNTIME_SOURCES = [
    "src/flight/engine/resources/ResourceCatalog.js",
    "src/flight/engine/resources/FlightResourceCatalog.js",
    "src/flight/engine/resources/index.js",
    "src/flight/engine/FlightEngine.js",
]
PACKAGE_IO_TESTS = [
    "tools/miel_vliegt/test_extract_udsp.py",
    "src/flight/engine/resources/__tests__/ResourceCatalog.test.js",
    "tools/miel_vliegt/test_verify_engine_implementation.py",
]
PACKAGE_IO_API = [
    "ResourceDescriptor.constructor({path,kind,source,data,sha256})",
    "ResourceCatalog.constructor(resources,packages)",
    "ResourceCatalog.size",
    "ResourceCatalog.has(path)",
    "ResourceCatalog.get(path)",
    "ResourceCatalog.require(path)",
    "ResourceCatalog.list({kind,prefix})",
    "createFlightResourceCatalog(partsContract,barnContract)",
    "FlightEngine.resources",
]
PACKAGE_IO_IMPORT_MAPPING = {
    "Cc.dll!?CcSetPackageList@@YAXPAVUpPackage@@@Z":
        "FlightEngine.resources=createFlightResourceCatalog(partsContract,barnContract)",
    "UdsPack.dll!??0UpFile@@QAE@PBDPAVUpPackage@@W4__UPFILE_OPENMODE@@@Z":
        "build.extract_udsp:UdspArchive.payload(entry,decode=True)",
    "UdsPack.dll!??0UpFileInfo@@QAE@PAVUpPackage@@@Z":
        "ResourceCatalog.list({kind,prefix})",
    "UdsPack.dll!??0UpPackage@@QAE@PBDPAV0@@Z":
        "build.extract_udsp:UdspArchive(archive)",
    "UdsPack.dll!??1UpFile@@QAE@XZ":
        "build.extract_udsp:ephemeral-file-reader-destroyed-before-runtime",
    "UdsPack.dll!??1UpFileInfo@@QAE@XZ":
        "ResourceCatalog.list-result-is-ephemeral",
    "UdsPack.dll!?Destroy@UpPackage@@QAEPAV1@XZ":
        "build.extract_udsp:archive-reader-destroyed-before-runtime",
    "UdsPack.dll!?FindFirst@UpFileInfo@@QAEXPBD@Z":
        "ResourceCatalog.list({kind,prefix})",
    "UdsPack.dll!?FindNext@UpFileInfo@@QAEXXZ":
        "ResourceCatalog.list({kind,prefix})",
    "UdsPack.dll!?GetSize@UpFile@@QAEIXZ":
        "build.extract_udsp:FileEntry.logical_size",
    "UdsPack.dll!?GetString@UpFile@@QAEPADPADI@Z":
        "build.extract_udsp:UdspArchive.payload(entry,decode=True)",
    "UdsPack.dll!?IsValid@UpFile@@QAE_NXZ":
        "build.extract_udsp:validated-file-entry",
    "UdsPack.dll!?Read@UpFile@@QAEIPAXII@Z":
        "build.extract_udsp:UdspArchive.payload(entry,decode=True)",
    "UdsPack.dll!?ScanString@UpFile@@QAEHPAD0@Z":
        "build.extract_udsp:decoded-contract-parser",
    "UdsPack.dll!?Seek@UpFile@@QAEIHH@Z":
        "build.extract_udsp:no-runtime-streaming-api",
    "UdsPack.dll!?Tell@UpFile@@QAEIXZ":
        "build.extract_udsp:no-runtime-streaming-api",
    "UdsPack.dll!?s_sThreadLock@UpFile@@2U_RTL_CRITICAL_SECTION@@A":
        "NOT_APPLICABLE_IMMUTABLE_RUNTIME_CATALOG",
}
PACKAGE_IO_EXTRACTION_POLICY = {
    "execution_phase": "BUILD_TIME_ONLY",
    "format_validation": "UDSP_HEADER_AND_BOUNDED_TABLES",
    "path_safety": "RELATIVE_NO_DRIVE_ROOT_OR_DOT_DOT_AND_RESOLVED_UNDER_DESTINATION",
    "case_policy": "LOWERCASE_NORMALIZED_PATHS_UNIQUE_BEFORE_WRITE",
    "write_policy": "VALIDATE_COMPLETE_PATH_SET_BEFORE_WRITE",
    "payload_policy": "ENCODING_0_RAW_OR_ENCODING_1_EXACT_LOGICAL_SIZE",
}
PACKAGE_IO_IMMUTABILITY_POLICY = {
    "binary_archive_io": "ABSENT_AT_RUNTIME",
    "catalog_state": "PRIVATE_WEAKMAP",
    "descriptors": "DEEP_FROZEN_CLONES",
    "packages": "DEEP_FROZEN_CLONES",
    "lookups": "CASE_INSENSITIVE_NORMALIZED_RELATIVE_PATHS",
    "mutation": "NO_RUNTIME_REGISTRATION_OR_WRITE_API",
}
PACKAGE_IO_SCOPE = [
    "pinned Dutch data.up, map.up and sounds.up build inputs",
    "validated UDSP extraction into decoded build artifacts",
    "immutable browser ResourceCatalog lookup boundary",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise ValueError("boundary evidence is not canonical JSON") from error


def _repo_file(root: Path, reference: Any, label: str) -> Path:
    if not isinstance(reference, str) or not reference or Path(reference).is_absolute():
        raise ValueError(f"{label} must be a relative repository path")
    path = (root / reference).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the repository") from error
    if not path.is_file():
        raise ValueError(f"{label} is missing: {reference}")
    return path


def _identity(root: Path, value: Any, label: str) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError(f"{label} must be an exact path/sha256 identity")
    path = _repo_file(root, value["path"], f"{label}.path")
    digest = value["sha256"]
    if not isinstance(digest, str) or len(digest) != SHA256 or _sha256(path) != digest:
        raise ValueError(f"{label} drifted from its hash-bound evidence")
    return value["path"], digest


def _json_receipt(root: Path, reference: Any, label: str) -> tuple[Path, dict[str, Any]]:
    path = _repo_file(root, reference, label)
    try:
        value = load_json_strict(path)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"{label} must be a canonical JSON PASS receipt") from error
    return path, value


def _exact_identities(
    root: Path, values: Any, expected_paths: list[str], label: str,
) -> None:
    if not isinstance(values, list) or len(values) != len(expected_paths):
        raise ValueError(f"package_io: {label} identities differ")
    paths = [
        _identity(root, value, f"{label}[{index}]")[0]
        for index, value in enumerate(values)
    ]
    if paths != expected_paths or len(paths) != len(set(paths)):
        raise ValueError(f"package_io: {label} mapping differs")


def _boundary_observation(
    path: Path, *, producer: str, boundary_id: str, source_sha256: str,
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{boundary_id}: {producer.lower()} observation is not JSON") from error
    required = {
        "schema", "protocol", "producer", "boundary_id", "source_sha256",
        "observations",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema") != 1 \
            or value.get("protocol") != BOUNDARY_OBSERVATION_PROTOCOL \
            or value.get("producer") != producer \
            or value.get("boundary_id") != boundary_id \
            or value.get("source_sha256") != source_sha256:
        raise ValueError(f"{boundary_id}: {producer.lower()} observation identity differs")
    observations = value.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError(f"{boundary_id}: {producer.lower()} observations are empty")
    for sequence, observation in enumerate(observations):
        if not isinstance(observation, dict) or set(observation) != {"sequence", "state"} \
                or observation.get("sequence") != sequence \
                or not isinstance(observation.get("state"), dict) \
                or not observation["state"]:
            raise ValueError(f"{boundary_id}: {producer.lower()} observations are invalid")
    return value


def _validate_boundary_differential(
    path: Path, *, boundary_id: str, native_sha256: str, web_sha256: str,
    native: dict[str, Any], web: dict[str, Any],
) -> None:
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{boundary_id}: differential receipt is not JSON") from error
    required = {
        "schema", "protocol", "boundary_id", "result", "comparator",
        "comparison_policy", "comparison_policy_sha256", "native_sha256",
        "web_sha256",
    }
    if not isinstance(receipt, dict) or set(receipt) != required \
            or receipt.get("schema") != 1 \
            or receipt.get("protocol") != BOUNDARY_DIFFERENTIAL_PROTOCOL \
            or receipt.get("boundary_id") != boundary_id \
            or receipt.get("result") != "PASS" \
            or receipt.get("comparator") != BOUNDARY_COMPARATOR \
            or receipt.get("comparison_policy") != BOUNDARY_COMPARISON_POLICY \
            or receipt.get("comparison_policy_sha256") \
            != _canonical_sha256(BOUNDARY_COMPARISON_POLICY) \
            or receipt.get("native_sha256") != native_sha256 \
            or receipt.get("web_sha256") != web_sha256:
        raise ValueError(f"{boundary_id}: invalid boundary differential receipt")
    if _canonical_bytes(native["observations"]) != _canonical_bytes(web["observations"]):
        raise ValueError(f"{boundary_id}: recomputed differential differs")


def validate_equivalence_receipt(
    row: dict[str, Any], root: Path, executable_sha256: str,
) -> dict[str, Any]:
    """Validate one exact native/web differential proof bundle."""

    _path, receipt = _json_receipt(
        root, row.get("native_evidence_receipt"),
        f"{row.get('id')}: native evidence",
    )
    required = {
        "schema", "protocol", "boundary_id", "status", "executable_sha256",
        "runtime", "tests", "evidence",
    }
    if set(receipt) != required or receipt.get("schema") != 1 \
            or receipt.get("protocol") != EQUIVALENCE_PROTOCOL \
            or receipt.get("boundary_id") != row.get("id") \
            or receipt.get("status") != "PASS" \
            or receipt.get("executable_sha256") != executable_sha256:
        raise ValueError(f"{row.get('id')}: native evidence is not a canonical JSON PASS receipt")

    runtime_path, runtime_digest = _identity(root, receipt["runtime"], "runtime")
    if runtime_path != row.get("runtime"):
        raise ValueError(f"{row.get('id')}: runtime identity differs from its receipt")

    tests = receipt.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ValueError(f"{row.get('id')}: receipt needs hash-bound tests")
    test_paths = [_identity(root, item, f"tests[{index}]")[0]
                  for index, item in enumerate(tests)]
    if test_paths != row.get("tests") or len(test_paths) != len(set(test_paths)):
        raise ValueError(f"{row.get('id')}: test identities differ from the receipt")

    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"native", "web", "differential"}:
        raise ValueError(f"{row.get('id')}: receipt needs native, web and differential evidence")
    evidence_identities = {
        kind: _identity(root, evidence[kind], f"evidence.{kind}")
        for kind in ("native", "web", "differential")
    }
    evidence_paths = [identity[0] for identity in evidence_identities.values()]
    if len(set(evidence_paths)) != len(evidence_paths):
        raise ValueError(f"{row.get('id')}: differential evidence artifacts must be independent")
    native = _boundary_observation(
        root / evidence_identities["native"][0], producer="NATIVE",
        boundary_id=row["id"], source_sha256=executable_sha256,
    )
    web = _boundary_observation(
        root / evidence_identities["web"][0], producer="WEB",
        boundary_id=row["id"], source_sha256=runtime_digest,
    )
    _validate_boundary_differential(
        root / evidence_identities["differential"][0], boundary_id=row["id"],
        native_sha256=evidence_identities["native"][1],
        web_sha256=evidence_identities["web"][1], native=native, web=web,
    )
    return receipt


def validate_package_io_substitution(
    row: dict[str, Any], receipt: dict[str, Any], root: Path,
    executable_sha256: str,
) -> dict[str, Any]:
    """Validate the reviewed build-time replacement for native UpPackage I/O."""

    required = {
        "schema", "protocol", "boundary_id", "status", "substitution_kind",
        "runtime", "rationale", "scope", "approved_by",
        "native_streaming_equivalence", "source", "native_boundary",
        "build_pipeline", "runtime_boundary", "tests",
    }
    if set(receipt) != required or receipt.get("schema") != 2 \
            or receipt.get("protocol") != SUBSTITUTION_PROTOCOL \
            or receipt.get("boundary_id") != "package_io" \
            or row.get("id") != "package_io" \
            or receipt.get("status") != "REVIEWED" \
            or receipt.get("substitution_kind") != "BUILD_TIME_PLATFORM_SUBSTITUTION" \
            or receipt.get("runtime") != row.get("runtime") \
            or receipt.get("rationale") != row.get("gap") \
            or receipt.get("scope") != PACKAGE_IO_SCOPE \
            or receipt.get("approved_by") not in SUBSTITUTION_REVIEW_AUTHORITIES \
            or receipt.get("native_streaming_equivalence") != "NOT_CLAIMED":
        raise ValueError("package_io: invalid reviewed build-time substitution receipt")

    source = receipt.get("source")
    if not isinstance(source, dict) or set(source) != {
        "identity_contract", "archive_contract", "iso", "executable",
        "native_libraries", "archives",
    }:
        raise ValueError("package_io: source identities differ")
    identity_path, _digest = _identity(
        root, source["identity_contract"], "package_io.source.identity_contract",
    )
    if identity_path != "content/miel_vliegt/source_identity.json":
        raise ValueError("package_io: source identity contract differs")
    identity = load_json_strict(root / identity_path)
    if source.get("iso") != identity.get("iso") \
            or source.get("executable") != identity.get("executable") \
            or source["executable"].get("sha256") != executable_sha256:
        raise ValueError("package_io: executable or ISO identity differs")
    if source.get("native_libraries") != [
        identity.get("cc_dll"), identity.get("udspack_dll"),
    ]:
        raise ValueError("package_io: native package library identities differ")
    if source.get("archives") != PACKAGE_IO_ARCHIVES:
        raise ValueError("package_io: archive identities differ")

    archive_contract_path, _digest = _identity(
        root, source["archive_contract"], "package_io.source.archive_contract",
    )
    if archive_contract_path != "content/miel_vliegt/flight_scene_asset_contract.json":
        raise ValueError("package_io: archive evidence contract differs")
    archive_contract = load_json_strict(root / archive_contract_path)
    archive_sources = archive_contract.get("sources", {})
    for name in ("data", "sounds"):
        expected = next(
            archive for archive in PACKAGE_IO_ARCHIVES
            if archive["filename"] == f"{name}.up"
        )
        actual = archive_sources.get(name)
        if not isinstance(actual, dict) \
                or actual.get("archive") != expected["filename"] \
                or actual.get("sha256") != expected["sha256"]:
            raise ValueError("package_io: archive evidence differs")

    native = receipt.get("native_boundary")
    if not isinstance(native, dict) or set(native) != {"contract", "import_mapping"}:
        raise ValueError("package_io: native boundary differs")
    native_path, _digest = _identity(
        root, native["contract"], "package_io.native_boundary.contract",
    )
    if native_path != "content/miel_vliegt/native_engine_subsystems.json":
        raise ValueError("package_io: native boundary contract differs")
    native_contract = load_json_strict(root / native_path)
    package_rows = [
        item for item in native_contract.get("subsystems", [])
        if item.get("id") == "package_io"
    ]
    if len(package_rows) != 1 \
            or package_rows[0].get("native_imports") != list(PACKAGE_IO_IMPORT_MAPPING) \
            or native.get("import_mapping") != PACKAGE_IO_IMPORT_MAPPING:
        raise ValueError("package_io: native import mapping differs")

    build = receipt.get("build_pipeline")
    if not isinstance(build, dict) or set(build) != {"sources", "extraction_policy"} \
            or build.get("extraction_policy") != PACKAGE_IO_EXTRACTION_POLICY:
        raise ValueError("package_io: extraction policy differs")
    _exact_identities(root, build["sources"], PACKAGE_IO_BUILD_SOURCES, "build source")

    runtime = receipt.get("runtime_boundary")
    if not isinstance(runtime, dict) or set(runtime) != {
        "sources", "api", "immutability_policy",
    } or runtime.get("api") != PACKAGE_IO_API \
            or runtime.get("immutability_policy") != PACKAGE_IO_IMMUTABILITY_POLICY:
        raise ValueError("package_io: immutable runtime boundary differs")
    _exact_identities(root, runtime["sources"], PACKAGE_IO_RUNTIME_SOURCES, "runtime source")
    _exact_identities(root, receipt.get("tests"), PACKAGE_IO_TESTS, "test")
    return receipt


def validate_substitution_receipt(
    row: dict[str, Any], root: Path, executable_sha256: str,
) -> dict[str, Any]:
    """Require an explicit reviewed boundary decision for platform substitution."""

    _path, receipt = _json_receipt(
        root, row.get("substitution_receipt"),
        f"{row.get('id')}: reviewed substitution receipt",
    )
    if row.get("id") == "package_io":
        return validate_package_io_substitution(
            row, receipt, root, executable_sha256,
        )
    required = {
        "schema", "protocol", "boundary_id", "status", "runtime", "rationale",
        "scope", "approved_by", "executable_sha256",
    }
    if set(receipt) != required or receipt.get("schema") != 1 \
            or receipt.get("protocol") != SUBSTITUTION_PROTOCOL \
            or receipt.get("boundary_id") != row.get("id") \
            or receipt.get("status") != "REVIEWED" \
            or receipt.get("runtime") != row.get("runtime") \
            or receipt.get("rationale") != row.get("gap") \
            or receipt.get("approved_by") not in SUBSTITUTION_REVIEW_AUTHORITIES \
            or receipt.get("executable_sha256") != executable_sha256 \
            or not isinstance(receipt.get("scope"), list) or not receipt["scope"] \
            or any(not isinstance(item, str) or not item for item in receipt["scope"]):
        raise ValueError(f"{row.get('id')}: invalid reviewed substitution receipt")
    return receipt


def validate(root: Path) -> Counter[str]:
    native = load_json_strict(root / "content/miel_vliegt/native_engine_subsystems.json")
    implementation = load_json_strict(root / "content/miel_vliegt/engine_implementation.json")
    source_identity = load_json_strict(root / "content/miel_vliegt/source_identity.json")
    executable_sha256 = source_identity.get("executable", {}).get("sha256")
    if not isinstance(executable_sha256, str) or len(executable_sha256) != SHA256:
        raise ValueError("flight executable identity is unavailable")
    pixel_checkpoints = load_json_strict(root / "content/miel_vliegt/ccf_render_checkpoints.json")
    verify_ccf_pixels(pixel_checkpoints, root, source_identity)
    mission_source = load_json_strict(root / "content/miel_vliegt/uds_flight_contracts.json")
    mission_actions = load_json_strict(root / "content/miel_vliegt/mission_action_contracts.json")
    validate_mission_actions(mission_source, mission_actions)
    if mission_actions != build_mission_actions(mission_source):
        raise ValueError("mission action contract artifact is stale")
    verify_trajectories(root / "content/miel_vliegt/trajectory_contract.json")
    if native.get("schema") != 1 or implementation.get("schema") != 1:
        raise ValueError("unsupported engine subsystem schema")
    native_ids = [item["id"] for item in native["subsystems"]]
    rows = implementation.get("subsystems")
    if not isinstance(rows, list):
        raise ValueError("engine implementation subsystems must be an array")
    ids = [item.get("id") for item in rows]
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise ValueError("engine implementation subsystem ids must be unique and sorted")
    if set(ids) != set(native_ids):
        raise ValueError(
            f"engine subsystem coverage mismatch: missing={sorted(set(native_ids)-set(ids))} "
            f"extra={sorted(set(ids)-set(native_ids))}"
        )
    gameplay_rows = implementation.get("gameplay_runtimes")
    validate_gameplay_runtime_inventory(gameplay_rows)

    counts: Counter[str] = Counter()
    for row in [*rows, *gameplay_rows]:
        disposition = row.get("disposition")
        if disposition not in DISPOSITIONS:
            raise ValueError(f"{row.get('id')}: invalid engine disposition")
        counts[disposition] += 1
        runtime = row.get("runtime")
        if disposition in {"PARTIAL", "EQUIVALENT"}:
            if not isinstance(runtime, str) or not (root / runtime).is_file():
                raise ValueError(f"{row['id']}: runtime implementation path is missing")
            tests = row.get("tests")
            if not tests or any(not (root / path).is_file() for path in tests):
                raise ValueError(f"{row['id']}: executable engine tests are missing")
        if disposition == "MISSING" and (runtime is not None or row.get("tests")):
            raise ValueError(f"{row['id']}: MISSING boundaries cannot point at implementation evidence")
        if disposition == "EQUIVALENT":
            validate_equivalence_receipt(row, root, executable_sha256)
        if disposition == "PLATFORM_SUBSTITUTION":
            validate_substitution_receipt(row, root, executable_sha256)
        if disposition != "EQUIVALENT" and not row.get("gap"):
            raise ValueError(f"{row['id']}: incomplete engine boundary needs an explicit gap")
    release_ready = counts["PARTIAL"] == 0 and counts["MISSING"] == 0
    if implementation["policy"].get("release_ready") is not release_ready:
        raise ValueError("stored engine release readiness does not match implementation evidence")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    counts = validate(args.root.resolve())
    print("flight engine implementation OK: " + ", ".join(
        f"{key}={counts[key]}" for key in sorted(DISPOSITIONS)
    ))


if __name__ == "__main__":
    main()
