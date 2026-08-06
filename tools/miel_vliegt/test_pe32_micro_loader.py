#!/usr/bin/env python3
import hashlib
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

from unicorn import UC_ARCH_X86, UC_MODE_32, Uc

from tools.miel_vliegt.pe32_micro_loader import (
    exports as read_exports, highlow_relocation_count, link_imports, map_pe32,
)


SYSTEM = Path("/private/tmp/miel-vliegt-installed/System_Files")


class FakeRelocationImage:
    image_base = 0x10000000

    def __init__(self, payload: bytes):
        self._directories = [(0, 0)] * 5 + [(0x1000, len(payload))]
        self.payload = payload

    def bytes_at(self, address: int, size: int) -> bytes:
        offset = address - self.image_base - 0x1000
        return self.payload[offset:offset + size]


class FakeExportImage:
    image_base = 0x10000000

    def __init__(self, function_rva: int, ordinal: int = 0):
        self._directories = [(0x1000, 0x100)]
        self.payload = bytearray(0x200)
        struct.pack_into(
            "<IIHHIIIIIII", self.payload, 0,
            0, 0, 0, 0, 0, 1, 1, 1, 0x1100, 0x1110, 0x1120,
        )
        struct.pack_into("<I", self.payload, 0x100, function_rva)
        struct.pack_into("<I", self.payload, 0x110, 0x1130)
        struct.pack_into("<H", self.payload, 0x120, ordinal)
        self.payload[0x130:0x135] = b"Test\0"

    def bytes_at(self, address: int, size: int) -> bytes:
        offset = address - self.image_base - 0x1000
        return bytes(self.payload[offset:offset + size])

    def cstring(self, address: int) -> str:
        offset = address - self.image_base - 0x1000
        end = self.payload.index(0, offset)
        return bytes(self.payload[offset:end]).decode("ascii")


class Pe32MicroLoaderPolicyTests(unittest.TestCase):
    def test_rejects_malformed_relocation_block(self):
        image = FakeRelocationImage(struct.pack("<II", 0x2000, 7))
        with self.assertRaisesRegex(ValueError, "invalid PE relocation block"):
            highlow_relocation_count(image)

    def test_rejects_unsupported_relocation_type(self):
        image = FakeRelocationImage(struct.pack("<IIH", 0x2000, 10, 0x5004))
        with self.assertRaisesRegex(ValueError, "unsupported PE relocation type 5"):
            highlow_relocation_count(image)

    def test_imports_are_fail_closed_and_provider_bound(self):
        machine = Uc(UC_ARCH_X86, UC_MODE_32)
        machine.mem_map(0x20000000, 0x1000)
        module = SimpleNamespace(imports={0x20000000: "Pinned.dll!Reset"})
        with self.assertRaisesRegex(ValueError, "unique trap"):
            link_imports(machine, module, {}, {})
        provider = SimpleNamespace(exports={"Reset": 0x12345678})
        link_imports(machine, module, {"pinned.dll": provider}, {})
        self.assertEqual(bytes(machine.mem_read(0x20000000, 4)), struct.pack("<I", 0x12345678))

    def test_rejects_forwarded_exports(self):
        with self.assertRaisesRegex(ValueError, "forwarded PE exports"):
            read_exports(FakeExportImage(0x1050), 0x10000000)

    def test_rejects_export_ordinal_outside_function_table(self):
        with self.assertRaisesRegex(ValueError, "ordinal is outside"):
            read_exports(FakeExportImage(0x2000, ordinal=1), 0x10000000)


@unittest.skipUnless((SYSTEM / "Cc.dll").is_file(), "private installed DLLs are unavailable")
class Pe32MicroLoaderTests(unittest.TestCase):
    def test_maps_cc_and_rebases_udspack_with_exact_exports(self):
        machine = Uc(UC_ARCH_X86, UC_MODE_32)
        cc_path = SYSTEM / "Cc.dll"
        uds_path = SYSTEM / "UdsPack.dll"
        cc = map_pe32(machine, cc_path, 0x10000000, hashlib.sha256(cc_path.read_bytes()).hexdigest())
        uds = map_pe32(machine, uds_path, 0x10200000, hashlib.sha256(uds_path.read_bytes()).hexdigest())
        self.assertEqual(len(cc.exports), 1230)
        self.assertEqual(len(cc.imports), 46)
        self.assertEqual(cc.image.image_base, 0x10000000)
        self.assertEqual(cc.size, 1634304)
        self.assertEqual(uds.image.image_base, 0x10000000)
        self.assertEqual(uds.base, 0x10200000)
        self.assertEqual(uds.size, 24576)
        self.assertEqual(highlow_relocation_count(cc.image), 4328)
        self.assertEqual(highlow_relocation_count(uds.image), 83)
        self.assertEqual(uds.relocation_count, 83)
        self.assertEqual(len(uds.exports), 47)
        self.assertEqual(
            cc.exports["?ResetMembers@CcRigidBody@@QAEXXZ"],
            0x1002B220,
        )
        self.assertEqual(
            uds.exports["?Read@UpFile@@QAEIPAXII@Z"],
            0x10202560,
        )


if __name__ == "__main__":
    unittest.main()
