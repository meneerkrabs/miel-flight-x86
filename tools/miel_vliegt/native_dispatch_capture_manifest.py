#!/usr/bin/env python3
"""Validate an immutable, explicitly non-promotable native dispatch bundle.

This module proves internal consistency only.  It deliberately has no API that
turns local files into production evidence.  A later boundary must download the
exact archive through GitHub's API and bind it to trusted workflow/job metadata.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

try:
    from tools.miel_vliegt import scene_semantic_evidence_batches as batches
    from tools.miel_vliegt import native_dispatch_semantic_wire as semantic_wire
    from tools.miel_vliegt.native_dispatch_hook_contract import (
        EDITION, EXECUTABLE_SHA256, producer_build_sha256, producer_sources,
    )
except ModuleNotFoundError:  # Direct script execution.
    import scene_semantic_evidence_batches as batches
    import native_dispatch_semantic_wire as semantic_wire
    from native_dispatch_hook_contract import (
        EDITION, EXECUTABLE_SHA256, producer_build_sha256, producer_sources,
    )


BUILD_PROTOCOL = "miel-vliegt-native-dispatch-build"
PROCESS_PROTOCOL = "miel-vliegt-native-dispatch-process-receipt"
RUN_PROTOCOL = "miel-vliegt-native-dispatch-candidate-run"
WIRE_PROTOCOL = "miel-vliegt-native-dispatch-semantic-wire"
CANDIDATE_STATUS = "CANDIDATE_ONLY"
CLAIM_COUNT = 155
MANIFEST_PATH = "native-dispatch-run.json"
MAX_ARCHIVE_SIZE = 64 * 1024 * 1024
MAX_MEMBER_SIZE = 4 * 1024 * 1024
MAX_MEMBER_COUNT = 512

SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$")
SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class NativeDispatchCaptureManifestError(ValueError):
    """A candidate archive or one of its exact bindings is invalid."""


@dataclass(frozen=True)
class ValidatedCandidateBundle:
    """Internally consistent capture bytes; never a production trust token."""

    manifest: dict[str, Any]
    build: dict[str, Any]
    plan: dict[str, Any]
    processes: tuple[dict[str, Any], ...]
    archive_sha256: str
    manifest_sha256: str
    process_receipts_sha256: str
    raw_logs_sha256: str
    production_trusted: bool = False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise NativeDispatchCaptureManifestError(
            "value is not canonical ASCII JSON"
        ) from error


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativeDispatchCaptureManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise NativeDispatchCaptureManifestError(f"forbidden JSON number: {value}")


def load_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDispatchCaptureManifestError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise NativeDispatchCaptureManifestError(f"{label} must be an object")
    return value


def _strict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = set(value) if isinstance(value, dict) else set()
        raise NativeDispatchCaptureManifestError(
            f"{label} fields differ: missing={sorted(fields - actual)}, "
            f"unknown={sorted(actual - fields)}"
        )
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise NativeDispatchCaptureManifestError(
            f"{label} must be an integer >= {minimum}"
        )
    return value


def _text(value: Any, label: str, pattern: re.Pattern[str] = IDENTIFIER) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise NativeDispatchCaptureManifestError(f"{label} is invalid")
    return value


def _hash(value: Any, label: str) -> str:
    return _text(value, label, SHA256)


def _path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise NativeDispatchCaptureManifestError(f"{label} is not a safe archive path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise NativeDispatchCaptureManifestError(f"{label} is not a safe archive path")
    return path.as_posix()


def _reference(value: Any, label: str, *, sized: bool = True) -> dict[str, Any]:
    fields = {"path", "sha256", "size"} if sized else {"path", "sha256"}
    row = _strict(value, fields, label)
    _path(row["path"], f"{label}.path")
    _hash(row["sha256"], f"{label}.sha256")
    if sized:
        _integer(row["size"], f"{label}.size", 1)
    return row


def _self_hash(value: Mapping[str, Any], field: str, label: str) -> None:
    digest = _hash(value.get(field), f"{label}.{field}")
    identity = {key: item for key, item in value.items() if key != field}
    if digest != canonical_sha256(identity):
        raise NativeDispatchCaptureManifestError(f"{label} self-hash differs")


def _validate_pe32(data: bytes, label: str, *, expect_dll: bool) -> None:
    if len(data) < 0x400 or data[:2] != b"MZ":
        raise NativeDispatchCaptureManifestError(f"{label} is not a PE32 binary")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data) \
            or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise NativeDispatchCaptureManifestError(f"{label} has no valid PE header")
    machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size, characteristics = struct.unpack_from("<HH", data, pe_offset + 20)
    optional = pe_offset + 24
    section_table = optional + optional_size
    if machine != 0x014C or not 1 <= section_count <= 96 \
            or optional_size < 0xE0 or section_table + section_count * 40 > len(data) \
            or struct.unpack_from("<H", data, optional)[0] != 0x010B \
            or not characteristics & 0x0002 \
            or bool(characteristics & 0x2000) != expect_dll:
        raise NativeDispatchCaptureManifestError(f"{label} is not an i386 PE32 binary")
    entrypoint = struct.unpack_from("<I", data, optional + 16)[0]
    section_alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
    size_of_image, size_of_headers = struct.unpack_from("<II", data, optional + 56)
    rva_count = struct.unpack_from("<I", data, optional + 92)[0]
    if entrypoint == 0 or section_alignment < 0x1000 \
            or section_alignment & (section_alignment - 1) \
            or file_alignment < 0x200 or file_alignment > section_alignment \
            or file_alignment & (file_alignment - 1) \
            or size_of_image == 0 or size_of_image % section_alignment \
            or size_of_headers == 0 or size_of_headers > len(data) \
            or size_of_headers % file_alignment or rva_count > 16:
        raise NativeDispatchCaptureManifestError(f"{label} optional header is invalid")
    section_table_end = section_table + section_count * 40
    aligned_section_table_end = (
        section_table_end + file_alignment - 1
    ) & ~(file_alignment - 1)
    mapped_header_end = (
        size_of_headers + section_alignment - 1
    ) & ~(section_alignment - 1)
    if size_of_headers < aligned_section_table_end \
            or mapped_header_end > size_of_image:
        raise NativeDispatchCaptureManifestError(f"{label} optional header is invalid")
    raw_ranges: list[tuple[int, int]] = []
    virtual_ranges: list[tuple[int, int]] = []
    first_raw_pointer: int | None = None
    executable_entry_section = False
    for index in range(section_count):
        offset = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, offset + 8,
        )
        section_characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        raw_end = raw_pointer + raw_size
        virtual_end = virtual_address + max(virtual_size, raw_size)
        if virtual_size == 0 or virtual_address < mapped_header_end \
                or virtual_address % section_alignment or raw_size == 0 \
                or raw_size % file_alignment or raw_pointer < size_of_headers \
                or raw_pointer % file_alignment or raw_end > len(data) \
                or virtual_end > size_of_image or section_characteristics == 0:
            raise NativeDispatchCaptureManifestError(f"{label} section table is invalid")
        if any(start < raw_end and raw_pointer < end for start, end in raw_ranges) \
                or any(start < virtual_end and virtual_address < end
                       for start, end in virtual_ranges):
            raise NativeDispatchCaptureManifestError(f"{label} sections overlap")
        raw_ranges.append((raw_pointer, raw_end))
        virtual_ranges.append((virtual_address, virtual_end))
        first_raw_pointer = (
            raw_pointer if first_raw_pointer is None
            else min(first_raw_pointer, raw_pointer)
        )
        executable_code = (
            section_characteristics & 0x00000020 != 0
            and section_characteristics & 0x20000000 != 0
        )
        executable_entry_section |= (
            executable_code
            and virtual_address <= entrypoint < virtual_end
        )
    if first_raw_pointer is None or first_raw_pointer < size_of_headers:
        raise NativeDispatchCaptureManifestError(f"{label} section table is invalid")
    if not executable_entry_section:
        raise NativeDispatchCaptureManifestError(f"{label} has no executable entry section")


def validate_build_manifest(value: Any) -> dict[str, Any]:
    fields = {
        "schema", "protocol", "status", "productionClaim", "commitSha",
        "edition", "executableSha256", "producerBuildSha256",
        "producerSources", "observerBinary", "launcherBinary", "hookContract",
        "compiler", "buildSha256",
    }
    row = _strict(value, fields, "native dispatch build manifest")
    if row["schema"] != 1 or type(row["schema"]) is not int \
            or row["protocol"] != BUILD_PROTOCOL \
            or row["status"] != CANDIDATE_STATUS \
            or row["productionClaim"] is not False:
        raise NativeDispatchCaptureManifestError("build manifest overclaims trust")
    _text(row["commitSha"], "build.commitSha", GIT_SHA)
    _text(row["edition"], "build.edition")
    _hash(row["executableSha256"], "build.executableSha256")
    sources = row["producerSources"]
    if not isinstance(sources, dict) or len(sources) < 2:
        raise NativeDispatchCaptureManifestError("build producer sources are incomplete")
    for source_path, digest in sources.items():
        _path(source_path, "build producer source path")
        _hash(digest, f"build producer source {source_path}")
    if sources != producer_sources() \
            or row["producerBuildSha256"] != producer_build_sha256():
        raise NativeDispatchCaptureManifestError("producer build hash differs")
    if row["edition"] != EDITION or row["executableSha256"] != EXECUTABLE_SHA256:
        raise NativeDispatchCaptureManifestError("build edition/executable differs")
    _reference(row["observerBinary"], "build observer binary")
    _reference(row["launcherBinary"], "build launcher binary")
    _reference(row["hookContract"], "build hook contract")
    compiler = _strict(row["compiler"], {
        "target", "version", "flags", "containerImageDigest",
    }, "build compiler")
    if compiler["target"] != "i686-w64-mingw32" \
            or not isinstance(compiler["version"], str) \
            or not compiler["version"] or not compiler["version"].isascii() \
            or not isinstance(compiler["flags"], list) or not compiler["flags"] \
            or len(set(compiler["flags"])) != len(compiler["flags"]) \
            or any(not isinstance(flag, str) or not flag or not flag.isascii()
                   for flag in compiler["flags"]) \
            or not isinstance(compiler["containerImageDigest"], str) \
            or IMAGE_DIGEST.fullmatch(compiler["containerImageDigest"]) is None:
        raise NativeDispatchCaptureManifestError("build compiler identity is invalid")
    _self_hash(row, "buildSha256", "native dispatch build manifest")
    return row


def validate_process_receipt(value: Any, build: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema", "protocol", "status", "productionClaim", "edition",
        "claimId", "evidenceClass", "planManifestSha256", "jobId",
        "jobSha256", "nativeSliceId", "nativeSliceSha256", "buildSha256",
        "executableSha256", "observerBinarySha256", "launcherBinarySha256",
        "producerBuildSha256", "sessionId", "containerId", "nativeProcessId",
        "engineThreadId", "rawLog", "capabilityCount", "eventCount",
        "eventSha256", "exitCode", "observerBuildReceipt",
    }
    row = _strict(value, fields, "native dispatch process receipt")
    if row["schema"] != 1 or type(row["schema"]) is not int \
            or row["protocol"] != PROCESS_PROTOCOL \
            or row["status"] != CANDIDATE_STATUS \
            or row["productionClaim"] is not False:
        raise NativeDispatchCaptureManifestError("process receipt overclaims trust")
    for field in ("edition", "claimId", "jobId"):
        _text(row[field], f"process.{field}")
    if row["evidenceClass"] not in {"MISSION_DISPATCH", "LOCATION_POLICY"}:
        raise NativeDispatchCaptureManifestError("process evidence class is invalid")
    for field in (
        "planManifestSha256", "jobSha256", "nativeSliceSha256", "buildSha256",
        "executableSha256", "observerBinarySha256", "launcherBinarySha256",
        "producerBuildSha256", "eventSha256",
    ):
        _hash(row[field], f"process.{field}")
    if row["nativeSliceId"] != f"native-slice:{row['nativeSliceSha256']}":
        raise NativeDispatchCaptureManifestError("process native slice identity differs")
    expected = {
        "edition": build["edition"],
        "buildSha256": build["buildSha256"],
        "executableSha256": build["executableSha256"],
        "observerBinarySha256": build["observerBinary"]["sha256"],
        "launcherBinarySha256": build["launcherBinary"]["sha256"],
        "producerBuildSha256": build["producerBuildSha256"],
    }
    if any(row[field] != expected_value for field, expected_value in expected.items()):
        raise NativeDispatchCaptureManifestError("process/build identity differs")
    _text(row["sessionId"], "process.sessionId", SESSION_ID)
    _text(row["containerId"], "process.containerId", CONTAINER_ID)
    _integer(row["nativeProcessId"], "process.nativeProcessId", 1)
    _integer(row["engineThreadId"], "process.engineThreadId", 1)
    _reference(row["rawLog"], "process raw log")
    _reference(row["observerBuildReceipt"], "process observer build receipt")
    if row["capabilityCount"] != 1 or type(row["capabilityCount"]) is not int \
            or row["eventCount"] != 1 or type(row["eventCount"]) is not int \
            or row["exitCode"] != 0 or type(row["exitCode"]) is not int:
        raise NativeDispatchCaptureManifestError(
            "process did not complete with exactly one capability and event"
        )
    return row


class _Archive:
    def __init__(self, data: bytes) -> None:
        if len(data) > MAX_ARCHIVE_SIZE:
            raise NativeDispatchCaptureManifestError("capture archive is too large")
        try:
            self.zip = zipfile.ZipFile(io.BytesIO(data))
            infos = self.zip.infolist()
        except zipfile.BadZipFile as error:
            raise NativeDispatchCaptureManifestError("capture artifact is not ZIP") from error
        names = [info.filename for info in infos]
        if not names or len(names) > MAX_MEMBER_COUNT or len(names) != len(set(names)):
            raise NativeDispatchCaptureManifestError("capture archive paths are empty or reused")
        total_size = 0
        for info in infos:
            if info.is_dir() or _path(info.filename, "capture archive member") != info.filename:
                raise NativeDispatchCaptureManifestError("capture archive member is unsafe")
            if info.flag_bits & 1 or info.file_size <= 0 \
                    or info.file_size > MAX_MEMBER_SIZE:
                raise NativeDispatchCaptureManifestError("capture archive member size is invalid")
            total_size += info.file_size
            mode = info.external_attr >> 16
            if mode and (mode & 0o170000) not in {0, 0o100000}:
                raise NativeDispatchCaptureManifestError("capture archive contains a special file")
        if total_size > MAX_ARCHIVE_SIZE:
            raise NativeDispatchCaptureManifestError("capture archive expands beyond its limit")
        self.names = frozenset(names)

    def read(self, path: str, label: str) -> bytes:
        _path(path, label)
        if path not in self.names:
            raise NativeDispatchCaptureManifestError(f"{label} is absent from archive")
        try:
            return self.zip.read(path)
        except (KeyError, RuntimeError, zipfile.BadZipFile) as error:
            raise NativeDispatchCaptureManifestError(f"cannot read {label}") from error

    def exact(self, reference: Mapping[str, Any], label: str) -> bytes:
        data = self.read(reference["path"], label)
        if len(data) != reference["size"] or sha256_bytes(data) != reference["sha256"]:
            raise NativeDispatchCaptureManifestError(f"{label} bytes differ")
        return data


def _validate_raw_log(
    data: bytes, process: Mapping[str, Any], capture_binding: dict[str, str],
) -> str:
    try:
        lines = data.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise NativeDispatchCaptureManifestError("raw log is not exact ASCII") from error
    records: list[dict[str, Any]] = []
    for line in lines:
        if line.startswith("MVDS "):
            records.append(load_json_bytes(line[5:].encode("ascii"), "MVDS record"))
    capabilities = [row for row in records if row.get("record") == "CAPABILITY"]
    events = [row for row in records if row.get("record") == "EVENT"]
    if len(records) != 2 or len(capabilities) != 1 or len(events) != 1 \
            or records != [capabilities[0], events[0]]:
        raise NativeDispatchCaptureManifestError(
            "raw log must contain exactly one CAPABILITY followed by one EVENT"
        )
    capability, event = capabilities[0], events[0]
    try:
        documents = semantic_wire.parse_lines(lines, capture_binding=capture_binding)
    except semantic_wire.NativeDispatchWireError as error:
        raise NativeDispatchCaptureManifestError(
            "raw log failed native dispatch parser/oracle validation"
        ) from error
    document = documents[0]
    provenance = document.get("captureProvenance", {})
    if capability.get("engineThread") != process["engineThreadId"] \
            or document.get("claimId") != process["claimId"] \
            or document.get("evidenceClass") != process["evidenceClass"] \
            or document.get("supportStatus") != semantic_wire.NATIVE_TRACE_REQUIRED \
            or document.get("parityEligible") is not False \
            or provenance.get("jobId") != process["jobId"] \
            or provenance.get("jobSha256") != process["jobSha256"] \
            or provenance.get("nativeSliceSha256") != process["nativeSliceSha256"] \
            or provenance.get("observerBinarySha256") != process["observerBinarySha256"] \
            or provenance.get("producerBuildSha256") != process["producerBuildSha256"]:
        raise NativeDispatchCaptureManifestError("raw log semantic identity differs")
    event_sha = canonical_sha256(event)
    if event_sha != process["eventSha256"]:
        raise NativeDispatchCaptureManifestError("raw log event hash differs")
    return event_sha


def validate_candidate_archive(data: bytes) -> ValidatedCandidateBundle:
    """Validate all candidate bytes without assigning any production trust."""

    archive = _Archive(data)
    manifest_bytes = archive.read(MANIFEST_PATH, "capture run manifest")
    manifest = load_json_bytes(manifest_bytes, "capture run manifest")
    fields = {
        "schema", "protocol", "status", "productionClaim", "repository",
        "workflowPath", "ref", "headSha", "runId", "runAttempt",
        "captureJobName", "build", "capturePlan", "processReceipts", "claimCount",
        "manifestSha256",
    }
    _strict(manifest, fields, "capture run manifest")
    if manifest["schema"] != 1 or type(manifest["schema"]) is not int \
            or manifest["protocol"] != RUN_PROTOCOL \
            or manifest["status"] != CANDIDATE_STATUS \
            or manifest["productionClaim"] is not False:
        raise NativeDispatchCaptureManifestError("capture run overclaims trust")
    _text(manifest["repository"], "capture repository")
    workflow_path = _path(manifest["workflowPath"], "capture workflow path")
    if not workflow_path.startswith(".github/workflows/") \
            or manifest["ref"] != "refs/heads/master":
        raise NativeDispatchCaptureManifestError("capture workflow/ref is invalid")
    _text(manifest["headSha"], "capture head SHA", GIT_SHA)
    _integer(manifest["runId"], "capture run ID", 1)
    _integer(manifest["runAttempt"], "capture run attempt", 1)
    _text(manifest["captureJobName"], "capture job name")
    if manifest["claimCount"] != CLAIM_COUNT or type(manifest["claimCount"]) is not int:
        raise NativeDispatchCaptureManifestError("capture run must contain 155 claims")
    _self_hash(manifest, "manifestSha256", "capture run manifest")

    build_ref = _reference(manifest["build"], "capture build")
    build_bytes = archive.exact(build_ref, "capture build")
    build = validate_build_manifest(load_json_bytes(build_bytes, "capture build"))
    if build["commitSha"] != manifest["headSha"]:
        raise NativeDispatchCaptureManifestError("capture build commit differs")
    plan_ref = _reference(manifest["capturePlan"], "capture plan")
    plan_bytes = archive.exact(plan_ref, "capture plan")
    plan = load_json_bytes(plan_bytes, "capture plan")
    try:
        batches.validate_plan(plan)
    except batches.SemanticEvidenceBatchError as error:
        raise NativeDispatchCaptureManifestError("capture plan is invalid") from error
    dispatch_jobs = {
        job["id"]: job
        for batch in plan["batches"]
        for job in batch["jobs"]
        if job["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}
    }
    if len(dispatch_jobs) != CLAIM_COUNT:
        raise NativeDispatchCaptureManifestError("capture plan dispatch inventory differs")
    observer = archive.exact(build["observerBinary"], "observer binary")
    launcher = archive.exact(build["launcherBinary"], "launcher binary")
    archive.exact(build["hookContract"], "hook contract")
    _validate_pe32(observer, "observer binary", expect_dll=True)
    _validate_pe32(launcher, "launcher binary", expect_dll=False)
    if build["observerBinary"]["sha256"] == build["launcherBinary"]["sha256"]:
        raise NativeDispatchCaptureManifestError("observer and launcher are not independent")

    receipt_refs = manifest["processReceipts"]
    if not isinstance(receipt_refs, list) or len(receipt_refs) != CLAIM_COUNT:
        raise NativeDispatchCaptureManifestError("capture process receipt inventory differs")
    processes: list[dict[str, Any]] = []
    receipt_hashes: list[str] = []
    raw_hashes: list[str] = []
    semantic_inputs: list[tuple[bytes, bytes]] = []
    for index, reference in enumerate(receipt_refs):
        ref = _reference(reference, f"process receipt reference {index}")
        receipt_bytes = archive.exact(ref, f"process receipt {index}")
        process = validate_process_receipt(
            load_json_bytes(receipt_bytes, f"process receipt {index}"), build,
        )
        job = dispatch_jobs.get(process["jobId"])
        native_slices = [
            item for item in job.get("captureSlices", [])
            if item.get("producer") == "NATIVE"
        ] if isinstance(job, dict) else []
        if len(native_slices) != 1 or any((
            process["claimId"] != job["claimId"],
            process["evidenceClass"] != job["evidenceClass"],
            process["jobSha256"] != job["jobSha256"],
            process["nativeSliceId"] != native_slices[0]["sliceId"],
            process["planManifestSha256"] != plan["manifestSha256"],
        )):
            raise NativeDispatchCaptureManifestError("capture process/plan job differs")
        raw = archive.exact(process["rawLog"], f"process raw log {index}")
        build_receipt = archive.exact(
            process["observerBuildReceipt"],
            f"process observer build receipt {index}",
        )
        processes.append(process)
        receipt_hashes.append(ref["sha256"])
        raw_hashes.append(process["rawLog"]["sha256"])
        semantic_inputs.append((raw, build_receipt))

    unique_fields = {
        "claimId", "jobId", "jobSha256", "nativeSliceSha256", "sessionId",
        "containerId",
    }
    for field in unique_fields:
        values = [row[field] for row in processes]
        if len(set(values)) != CLAIM_COUNT:
            raise NativeDispatchCaptureManifestError(
                f"capture process {field} is reused"
            )
    if len(set(receipt_hashes)) != CLAIM_COUNT or len(set(raw_hashes)) != CLAIM_COUNT:
        raise NativeDispatchCaptureManifestError("capture receipt/raw hash is reused")
    if {row["jobId"] for row in processes} != set(dispatch_jobs):
        raise NativeDispatchCaptureManifestError("capture plan job inventory differs")

    temp_parent = Path(__file__).resolve().parents[2] / "tmp"
    temp_parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="native-dispatch-candidate-", dir=temp_parent,
    ) as directory:
        materialized = Path(directory)
        plan_path = materialized / "capture-plan.json"
        observer_path = materialized / "observer.dll"
        plan_path.write_bytes(plan_bytes)
        observer_path.write_bytes(observer)
        for index, (process, inputs) in enumerate(zip(processes, semantic_inputs)):
            raw, build_receipt = inputs
            build_receipt_path = materialized / f"build-receipt-{index:03d}.json"
            build_receipt_path.write_bytes(build_receipt)
            binding = {
                "capturePlanJobId": process["jobId"],
                "nativeSliceSha256": process["nativeSliceSha256"],
                "observerBinarySha256": process["observerBinarySha256"],
                "observerBuildReceiptSha256": process["observerBuildReceipt"]["sha256"],
                "capturePlanPath": plan_path.relative_to(temp_parent.parent).as_posix(),
                "capturePlanSha256": plan_ref["sha256"],
                "observerBinaryPath": observer_path.relative_to(temp_parent.parent).as_posix(),
                "observerBuildReceiptPath": build_receipt_path.relative_to(
                    temp_parent.parent
                ).as_posix(),
            }
            _validate_raw_log(raw, process, binding)
    expected_paths = {
        MANIFEST_PATH,
        build_ref["path"],
        plan_ref["path"],
        build["observerBinary"]["path"],
        build["launcherBinary"]["path"],
        build["hookContract"]["path"],
        *(reference["path"] for reference in receipt_refs),
        *(process["rawLog"]["path"] for process in processes),
        *(process["observerBuildReceipt"]["path"] for process in processes),
    }
    if archive.names != expected_paths:
        raise NativeDispatchCaptureManifestError("capture archive has unreferenced members")
    plan_hashes = {row["planManifestSha256"] for row in processes}
    if len(plan_hashes) != 1:
        raise NativeDispatchCaptureManifestError("capture plan manifest is not unique")

    return ValidatedCandidateBundle(
        manifest=manifest,
        build=build,
        plan=plan,
        processes=tuple(processes),
        archive_sha256=sha256_bytes(data),
        manifest_sha256=sha256_bytes(manifest_bytes),
        process_receipts_sha256=canonical_sha256(sorted(receipt_hashes)),
        raw_logs_sha256=canonical_sha256(sorted(raw_hashes)),
    )
