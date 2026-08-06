#!/usr/bin/env python3
import copy
import io
import json
import struct
import unittest
import zipfile
from pathlib import Path

from tools.miel_vliegt import native_dispatch_capture_manifest as manifests
from tools.miel_vliegt import scene_semantic_coverage as coverage
from tools.miel_vliegt import native_dispatch_semantic_wire as wire
from tools.miel_vliegt import test_native_dispatch_semantic_wire as wire_fixtures
from tools.miel_vliegt.native_dispatch_hook_contract import (
    EXECUTABLE_SHA256, producer_build_sha256, producer_sources,
)
from tools.miel_vliegt.test_native_dispatch_semantic_wire import (
    capability, event_for,
)


HEAD_SHA = "1" * 40
EXECUTABLE_SHA = EXECUTABLE_SHA256
WORKFLOW = ".github/workflows/capture-native-dispatch.yml"
REPOSITORY = "cgnl/miel.js"
ROOT = Path(__file__).resolve().parents[2]
PLAN_BYTES = (ROOT / "content/miel_vliegt/scene_semantic_evidence_batches.json").read_bytes()
PLAN = json.loads(PLAN_BYTES)
PLAN_SHA = PLAN["manifestSha256"]
DISPATCH_JOBS = [
    job for batch in PLAN["batches"] for job in batch["jobs"]
    if job["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}
]
LEDGER = json.loads(coverage.DEFAULT_LEDGER.read_bytes())
RECORDS = {
    row["id"]: row for row in LEDGER["records"]
    if row["evidenceClass"] in {"MISSION_DISPATCH", "LOCATION_POLICY"}
}


def json_bytes(value):
    return manifests.canonical_bytes(value) + b"\n"


def valid_pe(marker, *, dll):
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x014C, 1)
    struct.pack_into("<H", data, 0x94, 0xE0)
    struct.pack_into("<H", data, 0x96, 0x2102 if dll else 0x0102)
    struct.pack_into("<H", data, 0x98, 0x010B)
    struct.pack_into("<I", data, 0x98 + 16, 0x1000)
    struct.pack_into("<II", data, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, 0x98 + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, 0x98 + 92, 16)
    section = 0x98 + 0xE0
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[-1] = marker
    return bytes(data)


def pe_with_sections(
    sections, *, entrypoint, size_of_headers=0x200, size_of_image=None,
):
    raw_end = max(raw_pointer + raw_size for (
        _name, _virtual_size, _virtual_address, raw_size, raw_pointer,
        _characteristics,
    ) in sections)
    data = bytearray(max(0x400, raw_end))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x014C, len(sections))
    struct.pack_into("<H", data, 0x94, 0xE0)
    struct.pack_into("<H", data, 0x96, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x010B)
    struct.pack_into("<I", data, optional + 16, entrypoint)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    highest_virtual_end = max(
        virtual_address + max(virtual_size, raw_size) for (
            _name, virtual_size, virtual_address, raw_size, _raw_pointer,
            _characteristics,
        ) in sections
    )
    if size_of_image is None:
        size_of_image = (highest_virtual_end + 0xFFF) & ~0xFFF
    struct.pack_into(
        "<II", data, optional + 56, size_of_image, size_of_headers,
    )
    struct.pack_into("<I", data, optional + 92, 16)
    section_table = optional + 0xE0
    for index, (
        name, virtual_size, virtual_address, raw_size, raw_pointer,
        characteristics,
    ) in enumerate(sections):
        offset = section_table + index * 40
        data[offset:offset + 8] = name.ljust(8, b"\0")
        struct.pack_into(
            "<IIII", data, offset + 8,
            virtual_size, virtual_address, raw_size, raw_pointer,
        )
        struct.pack_into("<I", data, offset + 36, characteristics)
    return bytes(data)


def reference(path, data):
    return {"path": path, "sha256": manifests.sha256_bytes(data), "size": len(data)}


def build_bundle(
    *, duplicate_session=False, tamper_raw=False, fake_pe=False,
    wrong_job_binding=False, invented_wire=False, wrong_pe_type=False,
):
    files = {}
    observer = b"MZ fake" if fake_pe else valid_pe(1, dll=not wrong_pe_type)
    launcher = valid_pe(2, dll=False)
    hook = (ROOT / "content/miel_vliegt/native_dispatch_hook_contract.json").read_bytes()
    files["build/observer.dll"] = observer
    files["build/launcher.exe"] = launcher
    files["build/hook-contract.json"] = hook
    sources = producer_sources()
    build = {
        "schema": 1,
        "protocol": manifests.BUILD_PROTOCOL,
        "status": manifests.CANDIDATE_STATUS,
        "productionClaim": False,
        "commitSha": HEAD_SHA,
        "edition": "miel-vliegt-de-wereld-rond-nl",
        "executableSha256": EXECUTABLE_SHA,
        "producerBuildSha256": producer_build_sha256(),
        "producerSources": sources,
        "observerBinary": reference("build/observer.dll", observer),
        "launcherBinary": reference("build/launcher.exe", launcher),
        "hookContract": reference("build/hook-contract.json", hook),
        "compiler": {
            "target": "i686-w64-mingw32",
            "version": "13.2.0",
            "flags": ["-std=c11", "-Os", "-shared"],
            "containerImageDigest": "sha256:" + "6" * 64,
        },
    }
    build["buildSha256"] = manifests.canonical_sha256(build)
    build_data = json_bytes(build)
    files["build/build.json"] = build_data
    files["plan/scene-semantic-evidence-batches.json"] = PLAN_BYTES

    receipt_refs = []
    raw_paths = []
    for index, job in enumerate(DISPATCH_JOBS):
        session_index = 0 if duplicate_session and index == 1 else index
        session = f"session-{session_index:09d}"
        process_id = 1000 + index
        thread_id = 2000 + index
        native_slice = next(
            row for row in job["captureSlices"] if row["producer"] == "NATIVE"
        )
        native_slice_sha = native_slice["sliceId"].removeprefix("native-slice:")
        build_receipt = {
            "schema": 1,
            "protocol": wire.BUILD_RECEIPT_PROTOCOL,
            "capturePlanJobId": job["id"],
            "nativeSliceSha256": native_slice_sha,
            "observerBinarySha256": build["observerBinary"]["sha256"],
            "producerBuildSha256": build["producerBuildSha256"],
        }
        build_receipt_data = json_bytes(build_receipt)
        build_receipt_path = f"build-receipts/{index:03d}.json"
        files[build_receipt_path] = build_receipt_data
        binding = {
            "capturePlanJobId": job["id"],
            "nativeSliceSha256": native_slice_sha,
            "observerBinarySha256": build["observerBinary"]["sha256"],
            "observerBuildReceiptSha256": manifests.sha256_bytes(build_receipt_data),
        }
        record = RECORDS[job["claimId"]]
        if invented_wire:
            capability_record = {
                "schema": 1, "protocol": manifests.WIRE_PROTOCOL,
                "record": "CAPABILITY", "engineThread": thread_id,
            }
            event = {
                "schema": 1, "protocol": manifests.WIRE_PROTOCOL,
                "record": "EVENT", "thread": thread_id,
            }
        else:
            capability_record = capability(binding=binding, engineThread=thread_id)
            event = event_for(record, 1)
            event["thread"] = thread_id
        raw = b"MVDS " + manifests.canonical_bytes(capability_record) + b"\n" \
            + b"MVDS " + manifests.canonical_bytes(event) + b"\n"
        raw_path = f"raw/{index:03d}.log"
        raw_paths.append(raw_path)
        files[raw_path] = raw
        receipt = {
            "schema": 1,
            "protocol": manifests.PROCESS_PROTOCOL,
            "status": manifests.CANDIDATE_STATUS,
            "productionClaim": False,
            "edition": build["edition"],
            "claimId": job["claimId"],
            "evidenceClass": job["evidenceClass"],
            "planManifestSha256": PLAN_SHA,
            "jobId": job["id"],
            "jobSha256": (
                "f" * 64 if wrong_job_binding and index == 0 else job["jobSha256"]
            ),
            "nativeSliceId": native_slice["sliceId"],
            "nativeSliceSha256": native_slice_sha,
            "buildSha256": build["buildSha256"],
            "executableSha256": build["executableSha256"],
            "observerBinarySha256": build["observerBinary"]["sha256"],
            "launcherBinarySha256": build["launcherBinary"]["sha256"],
            "producerBuildSha256": build["producerBuildSha256"],
            "sessionId": session,
            "containerId": f"{index + 1:064x}",
            "nativeProcessId": process_id,
            "engineThreadId": thread_id,
            "rawLog": reference(raw_path, raw),
            "capabilityCount": 1,
            "eventCount": 1,
            "eventSha256": manifests.canonical_sha256(event),
            "exitCode": 0,
            "observerBuildReceipt": reference(
                build_receipt_path, build_receipt_data
            ),
        }
        receipt_data = json_bytes(receipt)
        receipt_path = f"receipts/{index:03d}.json"
        files[receipt_path] = receipt_data
        receipt_refs.append(reference(receipt_path, receipt_data))
    if tamper_raw:
        files[raw_paths[-1]] += b"tampered\n"

    run = {
        "schema": 1,
        "protocol": manifests.RUN_PROTOCOL,
        "status": manifests.CANDIDATE_STATUS,
        "productionClaim": False,
        "repository": REPOSITORY,
        "workflowPath": WORKFLOW,
        "ref": "refs/heads/master",
        "headSha": HEAD_SHA,
        "runId": 1234,
        "runAttempt": 2,
        "captureJobName": "capture-native-dispatch",
        "build": reference("build/build.json", build_data),
        "capturePlan": reference(
            "plan/scene-semantic-evidence-batches.json", PLAN_BYTES
        ),
        "processReceipts": receipt_refs,
        "claimCount": manifests.CLAIM_COUNT,
    }
    run["manifestSha256"] = manifests.canonical_sha256(run)
    files[manifests.MANIFEST_PATH] = json_bytes(run)

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    return stream.getvalue(), build


class NativeDispatchCaptureManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wire_fixtures.CAPABILITY_TARGETS = {}
        cls.archive, cls.build = build_bundle()

    def test_valid_bundle_remains_explicitly_non_promotable(self):
        result = manifests.validate_candidate_archive(self.archive)
        self.assertFalse(result.production_trusted)
        self.assertFalse(result.manifest["productionClaim"])
        self.assertEqual(result.manifest["status"], "CANDIDATE_ONLY")
        self.assertEqual(len(result.processes), 155)
        self.assertEqual(
            {row["evidenceClass"] for row in result.processes},
            {"MISSION_DISPATCH", "LOCATION_POLICY"},
        )

    def test_reused_process_session_is_rejected(self):
        archive, _ = build_bundle(duplicate_session=True)
        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError, "sessionId is reused"
        ):
            manifests.validate_candidate_archive(archive)

    def test_raw_log_hash_is_recomputed_from_archive_bytes(self):
        archive, _ = build_bundle(tamper_raw=True)
        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError, "raw log 154 bytes differ"
        ):
            manifests.validate_candidate_archive(archive)

    def test_job_and_native_slice_are_recomputed_from_exact_plan(self):
        archive, _ = build_bundle(wrong_job_binding=True)
        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError,
            "capture process/plan job differs",
        ):
            manifests.validate_candidate_archive(archive)

    def test_fake_mz_marker_is_not_a_binary_identity(self):
        archive, _ = build_bundle(fake_pe=True)
        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError, "not a PE32 binary"
        ):
            manifests.validate_candidate_archive(archive)

    def test_observer_must_be_dll_and_launcher_must_be_exe(self):
        archive, _ = build_bundle(wrong_pe_type=True)
        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError,
            "not an i386 PE32 binary",
        ):
            manifests.validate_candidate_archive(archive)

    def test_size_of_headers_must_cover_file_aligned_section_table(self):
        image = pe_with_sections([
            (b".text", 0x100, 0x1000, 0x200, 0x200, 0x60000020),
            (b".rdata", 0x100, 0x2000, 0x200, 0x400, 0x40000040),
            (b".data", 0x100, 0x3000, 0x200, 0x600, 0xC0000040),
            (b".rsrc", 0x100, 0x4000, 0x200, 0x800, 0x40000040),
        ], entrypoint=0x1000, size_of_headers=0x200)

        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError,
            "optional header is invalid",
        ):
            manifests._validate_pe32(image, "launcher", expect_dll=False)

    def test_entrypoint_must_belong_to_executable_code_section(self):
        image = pe_with_sections([
            (b".text", 0x100, 0x1000, 0x200, 0x200, 0x60000020),
            (b".data", 0x100, 0x2000, 0x200, 0x400, 0xC0000040),
        ], entrypoint=0x2000)

        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError,
            "no executable entry section",
        ):
            manifests._validate_pe32(image, "launcher", expect_dll=False)

    def test_section_virtual_address_must_follow_mapped_headers(self):
        image = pe_with_sections([
            (b".text", 0x100, 0x1000, 0x200, 0x2000, 0x60000020),
        ], entrypoint=0x1000, size_of_headers=0x2000)

        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError,
            "section table is invalid",
        ):
            manifests._validate_pe32(image, "launcher", expect_dll=False)

    def test_mapped_headers_must_fit_inside_size_of_image(self):
        image = pe_with_sections([
            (b".text", 0x100, 0x1000, 0x200, 0x4000, 0x60000020),
        ], entrypoint=0x1000, size_of_headers=0x4000, size_of_image=0x3000)

        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError,
            "optional header is invalid",
        ):
            manifests._validate_pe32(image, "launcher", expect_dll=False)

    def test_invented_minimal_wire_receipt_fails_real_parser(self):
        archive, _ = build_bundle(invented_wire=True)
        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError,
            "failed native dispatch parser/oracle validation",
        ):
            manifests.validate_candidate_archive(archive)

    def test_local_status_cannot_overclaim_production(self):
        build = copy.deepcopy(self.build)
        build["status"] = "PRODUCTION_COMPLETE"
        build["buildSha256"] = manifests.canonical_sha256({
            key: value for key, value in build.items() if key != "buildSha256"
        })
        with self.assertRaisesRegex(
            manifests.NativeDispatchCaptureManifestError, "overclaims trust"
        ):
            manifests.validate_build_manifest(build)


if __name__ == "__main__":
    unittest.main()
