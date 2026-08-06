import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt.harvest_cca_contract import harvest_directory
from tools.miel_vliegt.parse_cca import FRAME, HEADER, NAME_SIZE


def cca_fixture(*, animations=("body", "wing"), frame_count=2, frame_rate=25.0):
    payload = bytearray(HEADER.pack(b"CCA\0", 1, len(animations), frame_count, frame_rate))
    for animation_index, name in enumerate(animations):
        payload.extend((name.encode("ascii") + b"\0").ljust(NAME_SIZE, b"\0"))
        for frame_index in range(frame_count):
            base = float(animation_index * 10 + frame_index)
            payload.extend(FRAME.pack(base, base + 1, base + 2, 1.0, 0.0, 0.0, 0.0))
    return bytes(payload)


class CcaContractHarvestTest(unittest.TestCase):
    def test_harvests_case_insensitive_extensions_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "data/Graphics/a.CCA"
            second = root / "data/Graphics/Z.cca"
            first.parent.mkdir(parents=True)
            first.write_bytes(cca_fixture(animations=("a",), frame_count=1))
            second.write_bytes(cca_fixture(animations=("z1", "z2"), frame_count=3))
            contract = harvest_directory(root)
            self.assertEqual(contract["claim"], "SOURCE_STRUCTURE_EXACT")
            self.assertEqual(
                contract["counts"],
                {"files": 2, "blueprint_animations": 3, "transform_records": 7},
            )
            self.assertEqual(
                [record["path"] for record in contract["files"]],
                ["data/Graphics/a.CCA", "data/Graphics/Z.cca"],
            )
            self.assertEqual(contract, harvest_directory(root))

    def test_quaternion_norm_uses_a_stable_fsum_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "stable.cca"
            payload = bytearray(cca_fixture(animations=("stable",), frame_count=1))
            # A non-trivial f32 quaternion exposes host/Python accumulation
            # drift more readily than the identity fixture.
            from tools.miel_vliegt.parse_cca import FRAME, HEADER, NAME_SIZE
            FRAME.pack_into(payload, HEADER.size + NAME_SIZE, 0, 0, 0, 0.5, 0.5, 0.5, 0.5)
            path.write_bytes(payload)
            norm = harvest_directory(root)["files"][0]["animations"][0]["orientation_norm_squared"]
            self.assertEqual(norm, {"minimum": 1.0, "maximum": 1.0})

    def test_contract_keeps_runtime_claims_explicitly_out_of_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "one.cca"
            path.write_bytes(cca_fixture(animations=("one",), frame_count=1))
            contract = harvest_directory(root)
            self.assertEqual(
                contract["structural_oracle"]["role"], "SECONDARY_STRUCTURAL_ORACLE"
            )
            limit = contract["claim_limit"]
            self.assertIn("interpolation", limit)
            self.assertIn("runtime rendering", limit)


if __name__ == "__main__":
    unittest.main()
