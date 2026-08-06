import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_framebuffer_origin_contract as origin


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "content/miel_vliegt/native_framebuffer_origin_contract.json"
SCHEMA = ROOT / "tools/miel_vliegt/schemas/native-framebuffer-origin-contract.schema.json"
LOCAL_NATIVE = ROOT / "tmp/miel-vliegt-native-local"


def rehash(value):
    value["receiptSha256"] = origin.sha256_json({
        key: item for key, item in value.items() if key != "receiptSha256"
    })
    return value


class NativeFramebufferOriginContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    def test_checked_contract_and_schema_are_strict(self):
        origin.validate_contract(self.contract, self.schema)
        self.assertEqual(self.contract["derivation"]["resultOrigin"], "TOP_LEFT")
        self.assertEqual(self.contract["derivation"]["kind"], "CONDITIONAL")
        self.assertFalse(
            self.contract["reviewedApiAuthority"]["networkRequiredInCi"]
        )
        self.assertFalse(
            self.contract["nativeProof"]["readScreen"]
            ["excludedAlternativeLock"]["originEligible"]
        )

    def test_top_left_requires_full_surface_site_and_measured_positive_pitch(self):
        self.assertEqual(
            origin.resolve_origin(self.contract, measured_pitch=1280),
            "TOP_LEFT",
        )
        for pitch in (0, -1, True, None):
            with self.subTest(pitch=pitch), self.assertRaisesRegex(
                origin.FramebufferOriginContractError, "measured positive"
            ):
                origin.resolve_origin(self.contract, measured_pitch=pitch)
        with self.assertRaisesRegex(
            origin.FramebufferOriginContractError, "NULL/full-surface"
        ):
            origin.resolve_origin(
                self.contract, measured_pitch=1280, lock_call_address=0x10008380
            )

    def test_hash_repair_cannot_hide_reviewed_or_native_metadata_forgery(self):
        mutations = (
            lambda value: value["sources"]["Cc.dll"].update({"sha256": "0" * 64}),
            lambda value: value["nativeProof"]["vtableBinding"].update(
                {"slotIndex": 46}
            ),
            lambda value: value["nativeProof"]["readScreen"]["fullSurfaceLock"][
                "arguments"
            ].update({"lpDestRect": "NON_NULL"}),
            lambda value: value["nativeProof"]["readScreen"]["forwardLoops"][0].update(
                {"rowTransform": "REVERSE"}
            ),
            lambda value: value["nativeProof"]["tgaOrigin"].update(
                {"saveDescriptorValue": "0x00"}
            ),
            lambda value: value["nativeProof"]["slices"][0].update(
                {"sha256": "f" * 64}
            ),
            lambda value: value["reviewedApiAuthority"]["claims"][0].update(
                {"normalizedClaim": "Forged external premise."}
            ),
            lambda value: value["runtimeRequirement"]["measuredPitch"].update(
                {"operator": ">="}
            ),
            lambda value: value["derivation"].update({"kind": "UNCONDITIONAL"}),
        )
        for mutate in mutations:
            forged = copy.deepcopy(self.contract)
            mutate(forged)
            rehash(forged)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(
                origin.FramebufferOriginContractError,
                "reviewed/native metadata differs",
            ):
                origin.validate_contract(forged, self.schema)

    def test_receipt_forgery_fails_before_semantic_acceptance(self):
        forged = copy.deepcopy(self.contract)
        forged["receiptSha256"] = "0" * 64
        with self.assertRaisesRegex(
            origin.FramebufferOriginContractError, "receipt hash differs"
        ):
            origin.validate_contract(forged, self.schema)

    def test_schema_cannot_make_top_left_unconditional(self):
        forged = copy.deepcopy(self.schema)
        forged["properties"]["derivation"]["properties"]["kind"]["const"] = (
            "UNCONDITIONAL"
        )
        with self.assertRaisesRegex(
            origin.FramebufferOriginContractError, "schema policy drifted"
        ):
            origin.validate_schema_guard(forged)

    def test_wrong_binary_identity_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            bad_cc = Path(directory) / "Cc.dll"
            bad_gt = Path(directory) / "gtSoftware.dll"
            bad_cc.write_bytes(b"MZ" + b"\0" * 128)
            bad_gt.write_bytes(b"MZ" + b"\0" * 128)
            with self.assertRaisesRegex(
                origin.FramebufferOriginContractError, "Cc.dll identity drifted"
            ):
                origin.verify_binaries(bad_cc, bad_gt)

    @unittest.skipUnless(
        (LOCAL_NATIVE / "Cc.dll").is_file()
        and (LOCAL_NATIVE / "gtSoftware.dll").is_file(),
        "pinned local native binaries are not present",
    )
    def test_generator_reproduces_contract_from_pinned_native_binaries(self):
        generated = origin.build_contract(
            LOCAL_NATIVE / "Cc.dll", LOCAL_NATIVE / "gtSoftware.dll"
        )
        self.assertEqual(generated, self.contract)


if __name__ == "__main__":
    unittest.main()
