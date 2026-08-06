#!/usr/bin/env python3
"""Compare deterministic browser CCF renders with native reference captures.

This gate deliberately distinguishes source-asset parity from rendered-pixel
parity.  A checkpoint cannot become ``EQUIVALENT`` until two distinct images,
native capture provenance, hashes and measured deltas are all present.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image


ALLOWED_STATUSES = {"BLOCKED_NATIVE_REFERENCE", "PARTIAL", "EQUIVALENT"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_runtime_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    render_root = root / "src/flight/engine/render"
    for path in sorted(item for item in render_root.glob("*.js")):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _verify_native_receipt(
    receipt_path: Path, checkpoint: dict[str, object], native_path: Path,
    root: Path, executable_sha256: str
) -> None:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    required = {
        "schema", "protocol", "review_status", "checkpoint_id", "executable_sha256",
        "target_module", "image_sha256", "camera_contract_sha256", "capture_tool",
        "capture_command", "capture_host", "raw_capture_log", "raw_capture_log_sha256",
    }
    if set(receipt) != required or receipt.get("schema") != 1 \
            or receipt.get("protocol") != "miel-vliegt-native-render-capture" \
            or receipt.get("review_status") != "REVIEWED":
        raise ValueError(f"{checkpoint['id']}: native capture receipt must be complete and REVIEWED")
    if receipt["checkpoint_id"] != checkpoint["id"] \
            or receipt["executable_sha256"] != executable_sha256:
        raise ValueError(f"{checkpoint['id']}: native receipt targets another checkpoint or executable")
    if receipt["target_module"] != {"filename": "MulleMeck.exe", "image_base": "0x00400000"}:
        raise ValueError(f"{checkpoint['id']}: native receipt does not bind the target module")
    if receipt["image_sha256"] != _sha256(native_path):
        raise ValueError(f"{checkpoint['id']}: native receipt image hash drifted")
    camera_path = root / checkpoint.get("camera_contract", "")
    if not camera_path.is_file() or json.loads(camera_path.read_text()).get("schema") != 1 \
            or receipt["camera_contract_sha256"] != _sha256(camera_path):
        raise ValueError(f"{checkpoint['id']}: native receipt camera contract is absent or stale")
    log_path = root / receipt["raw_capture_log"]
    if not log_path.is_file() or receipt["raw_capture_log_sha256"] != _sha256(log_path):
        raise ValueError(f"{checkpoint['id']}: native raw capture log is absent or stale")
    if not isinstance(receipt["capture_command"], list) or not receipt["capture_command"] \
            or not isinstance(receipt["capture_tool"], str) or not receipt["capture_tool"].strip():
        raise ValueError(f"{checkpoint['id']}: native capture command/tool is missing")
    host = receipt["capture_host"]
    if not isinstance(host, dict) or host.get("kind") not in {"windows-i386", "hangover-arm64"}:
        raise ValueError(f"{checkpoint['id']}: native capture host is invalid")
    if host["kind"] == "windows-i386" and host.get("review_status") != "REVIEWED":
        raise ValueError(f"{checkpoint['id']}: native Windows capture host is unreviewed")
    if host["kind"] == "hangover-arm64":
        host_receipt = json.loads((root / host.get("receipt", "")).read_text())
        if host_receipt.get("capture_host_usable") is not True \
                or host_receipt.get("native_parity_evidence") is not False \
                or host_receipt.get("executable_sha256") != executable_sha256:
            raise ValueError(f"{checkpoint['id']}: Hangover capture host receipt is invalid")


def compare_images(native_path: Path, web_path: Path) -> dict[str, object]:
    with Image.open(native_path) as native_image, Image.open(web_path) as web_image:
        native = native_image.convert("RGBA")
        web = web_image.convert("RGBA")
        if native.size != web.size:
            raise ValueError(f"pixel checkpoint dimensions differ: native={native.size}, web={web.size}")
        native_bytes = native.tobytes()
        web_bytes = web.tobytes()
    deltas = [abs(left - right) for left, right in zip(native_bytes, web_bytes)]
    pixel_deltas = [max(deltas[offset : offset + 4]) for offset in range(0, len(deltas), 4)]
    return {
        "width": native.width,
        "height": native.height,
        "different_pixels": sum(delta != 0 for delta in pixel_deltas),
        "maximum_channel_delta": max(deltas, default=0),
        "mean_absolute_channel_delta": sum(deltas) / len(deltas) if deltas else 0.0,
        "native_sha256": _sha256(native_path),
        "web_sha256": _sha256(web_path),
    }


def verify(manifest: dict[str, object], root: Path, source_identity: dict[str, object]) -> dict[str, int]:
    if manifest.get("schema") != 1:
        raise ValueError("unsupported CCF pixel parity schema")
    policy = manifest.get("policy")
    if not isinstance(policy, dict) or set(policy) != {
        "maximum_channel_delta", "maximum_different_pixels", "maximum_mean_absolute_channel_delta"
    }:
        raise ValueError("CCF pixel parity policy is incomplete")
    checkpoints = manifest.get("checkpoints")
    if not isinstance(checkpoints, list) or not checkpoints:
        raise ValueError("CCF pixel parity requires at least one checkpoint")
    totals = {status: 0 for status in sorted(ALLOWED_STATUSES)}
    seen = set()
    for checkpoint in checkpoints:
        identifier = checkpoint.get("id")
        status = checkpoint.get("status")
        if not isinstance(identifier, str) or not identifier or identifier in seen:
            raise ValueError(f"invalid or duplicate CCF pixel checkpoint id: {identifier!r}")
        seen.add(identifier)
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"{identifier}: invalid pixel parity status {status!r}")
        totals[status] += 1
        native = checkpoint.get("native_reference")
        web = checkpoint.get("web_capture")
        metrics = checkpoint.get("metrics")
        if status == "BLOCKED_NATIVE_REFERENCE":
            if native is not None or metrics is not None:
                raise ValueError(f"{identifier}: blocked checkpoint must not invent native evidence")
            continue
        if not isinstance(native, dict) or not isinstance(web, dict) or not isinstance(metrics, dict):
            raise ValueError(f"{identifier}: compared checkpoint is missing images or metrics")
        native_path = root / native["path"]
        web_path = root / web["path"]
        if native_path.resolve() == web_path.resolve():
            raise ValueError(f"{identifier}: native and web captures must be distinct files")
        receipt_path = root / native.get("capture_receipt", "")
        if not receipt_path.is_file():
            raise ValueError(f"{identifier}: native capture receipt is missing")
        _verify_native_receipt(
            receipt_path, checkpoint, native_path, root,
            source_identity["executable"]["sha256"]
        )
        if web.get("image_sha256") != _sha256(web_path) \
                or web.get("runtime_sha256") != render_runtime_sha256(root):
            raise ValueError(f"{identifier}: web capture image/runtime receipt drifted")
        fresh = compare_images(native_path, web_path)
        if metrics != fresh:
            raise ValueError(f"{identifier}: stored pixel metrics drifted")
        within = (
            fresh["maximum_channel_delta"] <= policy["maximum_channel_delta"]
            and fresh["different_pixels"] <= policy["maximum_different_pixels"]
            and fresh["mean_absolute_channel_delta"] <= policy["maximum_mean_absolute_channel_delta"]
        )
        if status == "EQUIVALENT" and not within:
            raise ValueError(f"{identifier}: EQUIVALENT exceeds pixel tolerances")
        if status == "PARTIAL" and within:
            raise ValueError(f"{identifier}: PARTIAL is stale; measured evidence meets EQUIVALENT policy")
    return totals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    compare = subparsers.add_parser("compare")
    compare.add_argument("native", type=Path)
    compare.add_argument("web", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("manifest", type=Path)
    verify_parser.add_argument("--root", type=Path, default=Path("."))
    verify_parser.add_argument(
        "--source-identity", type=Path, default=Path("content/miel_vliegt/source_identity.json")
    )
    args = parser.parse_args()
    if args.command == "compare":
        print(json.dumps(compare_images(args.native, args.web), indent=2, sort_keys=True))
        return 0
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    identity = json.loads(args.source_identity.read_text(encoding="utf-8"))
    print(json.dumps(verify(manifest, args.root, identity), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
