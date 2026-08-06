#!/usr/bin/env python3
"""Generate deterministic contract-model traces for all natural transitions.

The JavaScript side executes a typed scenario model and the canonical
``WebSceneTransitionRecorder``.  It does not drive the release game, a browser,
or user input.  The resulting traces are therefore classified as synthetic
contract-model evidence and are deliberately incompatible with the
``web-gameplay`` differential input accepted by ``natural_transition_trace``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

try:
    from tools.miel_vliegt import natural_transition_trace, web_transition_build
except ModuleNotFoundError:
    import natural_transition_trace
    import web_transition_build


ROOT = Path(__file__).resolve().parents[2]
NODE_RUNNER = ROOT / "tools/miel_vliegt/run_web_natural_transition_capture.cjs"
OUTPUT_DIRECTORY = ROOT / "content/miel_vliegt/web_natural_transition_captures"
MANIFEST_PATH = ROOT / "content/miel_vliegt/web_natural_transition_capture_manifest.json"
PROTOCOL = "miel-web-natural-transition-capture-manifest"
BUNDLE_PROTOCOL = "miel-web-natural-transition-capture-bundle"
STATUS = "SYNTHETIC_CONTRACT_MODEL_COMPLETE_REAL_GAMEPLAY_REQUIRED"
EVIDENCE_CLASS = "SYNTHETIC_CONTRACT_MODEL"
ENTRY_DRIVER = "web-contract-model"
PRODUCER = "synthetic-contract-model"
COMPLETE_RESULT = "TEST_ONLY"
SOURCE_PATHS = (
    "src/flight/runtime/WebNaturalTransitionCaptureRunner.js",
    "src/flight/runtime/WebSceneTransitionRecorder.js",
    "src/flight/runtime/SceneTransitionContract.js",
    "src/flight/engine/scene/SceneDispatchRuntime.js",
    "tools/miel_vliegt/run_web_natural_transition_capture.cjs",
    "tools/miel_vliegt/web_natural_transition_capture.py",
)


class WebNaturalTransitionCaptureError(ValueError):
    """Raised when the headless web capture is incomplete or drifted."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _json_line(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def _run_javascript_capture() -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["node", str(NODE_RUNNER)],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        detail = getattr(error, "stderr", b"").decode("utf-8", "replace").strip()
        raise WebNaturalTransitionCaptureError(
            f"headless web transition capture failed: {detail or error}"
        ) from error
    try:
        return json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WebNaturalTransitionCaptureError(
            "headless web transition capture returned invalid JSON"
        ) from error


def _validate_bundle(bundle: Any) -> list[dict[str, Any]]:
    if not isinstance(bundle, dict) or set(bundle) != {
        "schema", "protocol", "evidenceClass", "buildSha256", "captures",
    } or bundle.get("schema") != 1 or bundle.get("protocol") != BUNDLE_PROTOCOL \
            or bundle.get("evidenceClass") != EVIDENCE_CLASS \
            or bundle.get("buildSha256") != natural_transition_trace.WEB_BUILD_SHA256 \
            or not isinstance(bundle.get("captures"), list):
        raise WebNaturalTransitionCaptureError("web transition capture bundle differs")
    expected_edges = list(natural_transition_trace.EDGES)
    captures = bundle["captures"]
    if len(captures) != 48 or [row.get("edge") for row in captures] != expected_edges:
        raise WebNaturalTransitionCaptureError(
            "web transition capture inventory differs from the 48-edge contract"
        )
    capture_ids: set[str] = set()
    for index, capture in enumerate(captures):
        if not isinstance(capture, dict) or set(capture) != {
            "edge", "captureId", "scenario", "records",
        } or not natural_transition_trace.CAPTURE_ID.fullmatch(
            capture.get("captureId", "")
        ) or not isinstance(capture.get("scenario"), str) \
                or capture["scenario"] != f"natural-transition:{capture['edge']}" \
                or not isinstance(capture.get("records"), list) \
                or len(capture["records"]) != 3:
            raise WebNaturalTransitionCaptureError(
                f"web transition capture is invalid at index {index}"
            )
        if capture["captureId"] in capture_ids:
            raise WebNaturalTransitionCaptureError("web capture IDs are not unique")
        capture_ids.add(capture["captureId"])
    return captures


def _normalized_records(
    capture: dict[str, Any], raw_name: str, raw_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    edge = capture["edge"]
    raw_event = capture["records"][1]
    identity = natural_transition_trace.canonical_identity(
        edge, raw_event.get("transition_site"),
    )
    common = {
        "schema": natural_transition_trace.VERSION,
        "protocol": natural_transition_trace.PROTOCOL,
        "edition": natural_transition_trace.EDITION,
        "entry_driver": ENTRY_DRIVER,
        "capture_id": capture["captureId"],
        "debug_entry": False,
        "evidence_scope": natural_transition_trace.SCOPE,
    }
    start = {
        **common,
        "record": "capture_start",
        "scenario": capture["scenario"],
        "producer": PRODUCER,
        "subject_sha256": natural_transition_trace.WEB_BUILD_SHA256,
        "raw_trace": {"path": raw_name, "sha256": raw_sha256},
    }
    transition = {
        "schema": natural_transition_trace.VERSION,
        "protocol": natural_transition_trace.PROTOCOL,
        "record": "scene_transition",
        **identity,
        "entry_driver": ENTRY_DRIVER,
        "capture_id": capture["captureId"],
        "sequence": raw_event.get("sequence"),
        "tick": raw_event.get("tick"),
        "debug_entry": False,
        "evidence_scope": natural_transition_trace.SCOPE,
    }
    complete = {
        **common,
        "record": "capture_complete",
        "final_sequence": capture["records"][2].get("sequence"),
        "result": COMPLETE_RESULT,
    }
    return start, transition, complete


def _validate_synthetic_pair(
    raw_path: Path,
    normalized_path: Path,
    expected_edge: str,
    expected_capture_id: str,
) -> dict[str, Any]:
    """Validate contract-model evidence without admitting it as gameplay."""
    try:
        raw = [
            json.loads(line)
            for line in raw_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        normalized = [
            json.loads(line)
            for line in normalized_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as error:
        raise WebNaturalTransitionCaptureError(
            "synthetic web transition artifact is invalid"
        ) from error
    if len(raw) != 3 or len(normalized) != 3:
        raise WebNaturalTransitionCaptureError(
            "synthetic web transition requires one complete model session"
        )
    start, transition, complete = normalized
    raw_start, raw_transition, raw_complete = raw
    identity = natural_transition_trace.canonical_identity(
        expected_edge, raw_transition.get("transition_site"),
    )
    if raw_start.get("record") != "session.start" \
            or raw_transition.get("record") != "scene_transition" \
            or raw_complete.get("record") != "session.complete" \
            or raw_transition.get("edge") != expected_edge \
            or raw_transition.get("capture_id") != expected_capture_id \
            or raw_transition.get("classification") != \
                "SYNTHETIC_CONTRACT_MODEL_EDGE" \
            or raw_transition.get("parity_eligible") is not False \
            or any(row.get("build_sha256") != natural_transition_trace.WEB_BUILD_SHA256
                   for row in raw):
        raise WebNaturalTransitionCaptureError(
            "synthetic web transition classification differs"
        )
    if start.get("entry_driver") != ENTRY_DRIVER \
            or start.get("producer") != PRODUCER \
            or start.get("raw_trace") != {
                "path": raw_path.name,
                "sha256": sha256_file(raw_path),
            } \
            or transition.get("entry_driver") != ENTRY_DRIVER \
            or complete.get("entry_driver") != ENTRY_DRIVER \
            or complete.get("result") != COMPLETE_RESULT \
            or transition.get("capture_id") != expected_capture_id \
            or complete.get("capture_id") != expected_capture_id \
            or {key: transition.get(key) for key in identity} != identity:
        raise WebNaturalTransitionCaptureError(
            "synthetic normalized transition classification differs"
        )
    try:
        natural_transition_trace.load_capture(
            normalized_path, "web-gameplay",
        )
    except ValueError:
        pass
    else:
        raise WebNaturalTransitionCaptureError(
            "synthetic transition was admitted as web gameplay evidence"
        )
    return {
        "edge": transition["edge"],
        "capture_id": transition["capture_id"],
        "transition_site": transition["transition_site"],
    }


def _source_receipts() -> list[dict[str, str]]:
    return [
        {"path": relative, "sha256": sha256_file(ROOT / relative)}
        for relative in SOURCE_PATHS
    ]


def _build_manifest(
    captures: list[dict[str, Any]], output_directory: Path,
    manifest_path: Path, published_directory: Path | None = None,
) -> dict[str, Any]:
    published_directory = published_directory or output_directory
    rows = []
    for index, capture in enumerate(captures):
        stem = f"{index:02d}-{capture['edge']}"
        raw_path = output_directory / f"{stem}.raw.ndjson"
        normalized_path = output_directory / f"{stem}.ndjson"
        raw_path.write_bytes(b"".join(_json_line(row) for row in capture["records"]))
        normalized = _normalized_records(
            capture, raw_path.name, sha256_file(raw_path),
        )
        normalized_path.write_bytes(b"".join(_json_line(row) for row in normalized))
        loaded = _validate_synthetic_pair(
            raw_path, normalized_path, capture["edge"], capture["captureId"],
        )
        rows.append({
            "index": index,
            "edge": capture["edge"],
            "scenario": capture["scenario"],
            "captureId": capture["captureId"],
            "transitionSite": loaded["transition_site"],
            "raw": {
                "path": raw_path.name,
                "sha256": sha256_file(raw_path),
                "size": raw_path.stat().st_size,
            },
            "normalized": {
                "path": normalized_path.name,
                "sha256": sha256_file(normalized_path),
                "size": normalized_path.stat().st_size,
            },
            "validated": True,
        })
    web_manifest = web_transition_build.validate_manifest()
    manifest = {
        "schema": 1,
        "protocol": PROTOCOL,
        "edition": natural_transition_trace.EDITION,
        "status": STATUS,
        "parityEligible": False,
        "captureDirectory": published_directory.relative_to(
            manifest_path.parent
        ).as_posix(),
        "webBuild": {
            "path": web_transition_build.MANIFEST_PATH.relative_to(ROOT).as_posix(),
            "fileSha256": sha256_file(web_transition_build.MANIFEST_PATH),
            "buildSha256": web_manifest["build_sha256"],
        },
        "producerSources": _source_receipts(),
        "policy": {
            "browserE2ERequired": False,
            "contractModelOnly": True,
            "debugEntryAllowed": False,
            "evidenceScope": natural_transition_trace.SCOPE,
            "edgeCount": 48,
            "promotionAllowed": False,
            "realGameplayCaptureRequiredForPromotion": True,
        },
        "captures": rows,
        "inventorySha256": sha256_bytes(canonical_bytes([
            {
                "index": row["index"],
                "edge": row["edge"],
                "rawSha256": row["raw"]["sha256"],
                "normalizedSha256": row["normalized"]["sha256"],
            }
            for row in rows
        ])),
    }
    manifest["manifestSha256"] = sha256_bytes(canonical_bytes(manifest))
    return manifest


def generate(
    output_directory: Path = OUTPUT_DIRECTORY,
    manifest_path: Path = MANIFEST_PATH,
) -> dict[str, Any]:
    web_transition_build.validate_manifest()
    captures = _validate_bundle(_run_javascript_capture())
    output_directory = output_directory.resolve()
    manifest_path = manifest_path.resolve()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="web-natural-transitions-", dir=output_directory.parent,
    ) as temporary:
        staging = Path(temporary) / output_directory.name
        staging.mkdir()
        manifest = _build_manifest(
            captures, staging, manifest_path,
            published_directory=output_directory,
        )
        if output_directory.exists():
            shutil.rmtree(output_directory)
        staging.replace(output_directory)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    validate_manifest(manifest_path)
    return manifest


def validate_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WebNaturalTransitionCaptureError(
            "web natural-transition capture manifest is unavailable"
        ) from error
    required = {
        "schema", "protocol", "edition", "status", "parityEligible",
        "captureDirectory", "webBuild", "producerSources", "policy",
        "captures", "inventorySha256", "manifestSha256",
    }
    if not isinstance(value, dict) or set(value) != required \
            or value.get("schema") != 1 or value.get("protocol") != PROTOCOL \
            or value.get("edition") != natural_transition_trace.EDITION \
            or value.get("status") != STATUS \
            or value.get("parityEligible") is not False:
        raise WebNaturalTransitionCaptureError(
            "web natural-transition capture manifest fields differ"
        )
    unhashed = {key: item for key, item in value.items() if key != "manifestSha256"}
    if value.get("manifestSha256") != sha256_bytes(canonical_bytes(unhashed)):
        raise WebNaturalTransitionCaptureError(
            "web natural-transition capture manifest hash differs"
        )
    expected_build = web_transition_build.validate_manifest()
    expected_web_build = {
        "path": web_transition_build.MANIFEST_PATH.relative_to(ROOT).as_posix(),
        "fileSha256": sha256_file(web_transition_build.MANIFEST_PATH),
        "buildSha256": expected_build["build_sha256"],
    }
    if value.get("webBuild") != expected_web_build \
            or value.get("producerSources") != _source_receipts() \
            or value.get("policy") != {
                "browserE2ERequired": False,
                "contractModelOnly": True,
                "debugEntryAllowed": False,
                "evidenceScope": natural_transition_trace.SCOPE,
                "edgeCount": 48,
                "promotionAllowed": False,
                "realGameplayCaptureRequiredForPromotion": True,
            }:
        raise WebNaturalTransitionCaptureError(
            "web natural-transition capture provenance differs"
        )
    capture_directory = (path.parent / value.get("captureDirectory", "")).resolve()
    try:
        capture_directory.relative_to(path.parent.resolve())
    except ValueError as error:
        raise WebNaturalTransitionCaptureError(
            "web transition capture directory escapes manifest root"
        ) from error
    expected_edges = list(natural_transition_trace.EDGES)
    rows = value.get("captures")
    if not isinstance(rows, list) or len(rows) != 48 \
            or [row.get("edge") for row in rows if isinstance(row, dict)] != expected_edges:
        raise WebNaturalTransitionCaptureError(
            "web natural-transition capture inventory differs"
        )
    inventory = []
    declared_files = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "index", "edge", "scenario", "captureId", "transitionSite",
            "raw", "normalized", "validated",
        } or row.get("index") != index or row.get("validated") is not True:
            raise WebNaturalTransitionCaptureError(
                f"web natural-transition row differs at index {index}"
            )
        for kind in ("raw", "normalized"):
            receipt = row.get(kind)
            if not isinstance(receipt, dict) or set(receipt) != {
                "path", "sha256", "size",
            } or Path(receipt.get("path", "")).name != receipt.get("path"):
                raise WebNaturalTransitionCaptureError(
                    f"web natural-transition {kind} receipt differs"
                )
            artifact = capture_directory / receipt["path"]
            if artifact.name in declared_files or not artifact.is_file() \
                    or artifact.stat().st_size != receipt["size"] \
                    or sha256_file(artifact) != receipt["sha256"]:
                raise WebNaturalTransitionCaptureError(
                    f"web natural-transition {kind} artifact drifted"
                )
            declared_files.add(artifact.name)
        loaded = _validate_synthetic_pair(
            capture_directory / row["raw"]["path"],
            capture_directory / row["normalized"]["path"],
            row["edge"],
            row["captureId"],
        )
        if loaded["edge"] != row["edge"] \
                or loaded["capture_id"] != row["captureId"] \
                or loaded["transition_site"] != row["transitionSite"]:
            raise WebNaturalTransitionCaptureError(
                "web normalized transition identity differs"
            )
        inventory.append({
            "index": index,
            "edge": row["edge"],
            "rawSha256": row["raw"]["sha256"],
            "normalizedSha256": row["normalized"]["sha256"],
        })
    if set(path.name for path in capture_directory.iterdir() if path.is_file()) \
            != declared_files:
        raise WebNaturalTransitionCaptureError(
            "web transition capture directory contains undeclared files"
        )
    if value.get("inventorySha256") != sha256_bytes(canonical_bytes(inventory)):
        raise WebNaturalTransitionCaptureError(
            "web natural-transition inventory hash differs"
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output-directory", type=Path, default=OUTPUT_DIRECTORY)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args()
    if args.check:
        value = validate_manifest(args.manifest)
    else:
        value = generate(args.output_directory, args.manifest)
    print(
        f"{value['status']} edges={len(value['captures'])} "
        f"build={value['webBuild']['buildSha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
