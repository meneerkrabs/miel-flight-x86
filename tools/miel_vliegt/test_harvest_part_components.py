#!/usr/bin/env python3
import unittest

from tools.miel_vliegt.harvest_part_components import classify_part


class PartComponentClassifierTests(unittest.TestCase):
    @staticmethod
    def part(part_id, component_type):
        return {
            "part_id": part_id,
            "native_properties": {"component_type": component_type},
        }

    def test_special_fuselage_also_supplies_the_native_nose_bit(self):
        self.assertEqual(classify_part(self.part(96, 3)), ("fuselage", "nose"))
        self.assertEqual(classify_part(self.part(95, 3)), ("fuselage",))

    def test_type_thirteen_uses_the_native_propeller_path(self):
        self.assertEqual(classify_part(self.part(281, 13)), ("propeller",))


if __name__ == "__main__":
    unittest.main()
