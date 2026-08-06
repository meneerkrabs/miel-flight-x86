import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.miel_vliegt.decode_gti import GtiImage
from tools.miel_vliegt.harvest_ccf_materials import _texture_index, check_assets, write_assets


class CcfMaterialHarvestTest(unittest.TestCase):
    def test_indexes_only_the_proven_part_texture_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            texture = root / "data/Graphics/Parts/Textures/Wing.gti"
            texture.parent.mkdir(parents=True)
            texture.write_bytes(b"source")
            duplicate = root / "data/Graphics/Misc/Wing.gti"
            duplicate.parent.mkdir(parents=True)
            duplicate.write_bytes(b"wrong")
            self.assertEqual(_texture_index(root), {"wing": texture})

    def test_exported_assets_are_hash_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "texture.gti"
            source.write_bytes(b"raw")
            image = GtiImage(1, 1, 5, 1, bytes([10, 20, 30, 255]))
            from tools.miel_vliegt.export_web_assets import encode_png
            import hashlib
            png = encode_png(image)
            contract = {
                "textures": [{
                    "id": "texture", "source": "texture.gti", "asset_name": "texture.png",
                    "png_sha256": hashlib.sha256(png).hexdigest(),
                }]
            }
            assets = root / "assets"
            with mock.patch("tools.miel_vliegt.harvest_ccf_materials.decode_gti", return_value=image):
                write_assets(contract, root, assets)
            check_assets(contract, assets)
            (assets / "texture.png").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, r"changed=\['texture.png'\]"):
                check_assets(contract, assets)


if __name__ == "__main__":
    unittest.main()
