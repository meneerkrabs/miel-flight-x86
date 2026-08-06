#!/usr/bin/env python3
import unittest

from tools.miel_vliegt.harvest_cc_api_contract import (
    WILLYWERKEL_SYMBOL_SHA256,
    build_contract,
    declaration_api_id,
    msvc_api_id,
    verify_primary_contract,
)


class CcApiContractTests(unittest.TestCase):
    def test_normalizes_vc6_members_without_claiming_overload_signatures(self):
        self.assertEqual(
            msvc_api_id("?ResetMembers@CcRigidBody@@QAEXXZ"),
            "CcRigidBody::ResetMembers",
        )
        self.assertEqual(msvc_api_id("??0CcCamera@@QAE@XZ"), "CcCamera::CcCamera")
        self.assertEqual(msvc_api_id("??BCcString@@QAEHXZ"), "CcString::operator conversion")
        self.assertEqual(msvc_api_id("??_7CcCamera@@6B@"), "CcCamera::`vftable'")

    def test_normalizes_secondary_declarations_without_retaining_their_text(self):
        self.assertEqual(
            declaration_api_id(
                "public: void __thiscall CcRigidBody::ResetMembers(void)"
            ),
            "CcRigidBody::ResetMembers",
        )
        self.assertEqual(
            declaration_api_id("public: __thiscall CcCamera::CcCamera(void)"),
            "CcCamera::CcCamera",
        )
        self.assertEqual(
            declaration_api_id("public: __thiscall CcString::operator int(void)"),
            "CcString::operator conversion",
        )
        self.assertEqual(
            declaration_api_id("const CcCustomObject::`vftable'{for `CcSrtNode'}"),
            "CcCustomObject::`vftable'",
        )

    def test_contract_keeps_secondary_observations_discovery_only(self):
        contract = build_contract(
            {
                "?ResetMembers@CcRigidBody@@QAEXXZ": 0x10001000,
                "??0CcCamera@@QAE@XZ": 0x10002000,
                "??BCcString@@QAEHXZ": 0x10003000,
            },
            image_base=0x10000000,
            cc_sha256="a" * 64,
            secondary_lines=[
                "public: void __thiscall CcRigidBody::ResetMembers(void)",
                "public: __thiscall CcCamera::CcCamera(void)",
                "public: __thiscall CcString::operator int(void)",
                "public: __thiscall CcString::operator char const *(void)const ",
            ],
            secondary_sha256=WILLYWERKEL_SYMBOL_SHA256,
        )
        self.assertEqual(contract["summary"]["exports"], 3)
        self.assertEqual(
            contract["summary"]["secondary_status"],
            {"SECONDARY_NAME_MATCH": 2, "SECONDARY_OVERLOAD_GROUP": 1},
        )
        self.assertFalse(contract["summary"]["semantic_coverage_claimed"])
        self.assertEqual(
            contract["exports"][2]["subsystem"], "physics_collision"
        )

    def test_rejects_secondary_or_binary_identity_drift(self):
        with self.assertRaisesRegex(ValueError, "secondary.*identity drifted"):
            build_contract(
                {}, image_base=0x10000000, cc_sha256="a" * 64,
                secondary_lines=[], secondary_sha256="b" * 64,
            )
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            build_contract(
                {}, image_base=0x10000000, cc_sha256="bad",
                secondary_lines=[], secondary_sha256=WILLYWERKEL_SYMBOL_SHA256,
            )

    def test_primary_verifier_rejects_export_and_promotion_drift(self):
        export_map = {"?ResetMembers@CcRigidBody@@QAEXXZ": 0x10001000}
        contract = build_contract(
            export_map,
            image_base=0x10000000,
            cc_sha256="a" * 64,
            secondary_lines=[
                "public: void __thiscall CcRigidBody::ResetMembers(void)"
            ],
            secondary_sha256=WILLYWERKEL_SYMBOL_SHA256,
        )
        verify_primary_contract(
            contract, export_map, image_base=0x10000000, cc_sha256="a" * 64,
        )
        contract["summary"]["semantic_coverage_claimed"] = True
        with self.assertRaisesRegex(ValueError, "semantic-coverage"):
            verify_primary_contract(
                contract, export_map, image_base=0x10000000,
                cc_sha256="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()
