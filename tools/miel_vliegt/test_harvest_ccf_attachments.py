import unittest

from tools.miel_vliegt.harvest_ccf_attachments import project_attachments


class HarvestCcfAttachmentsTests(unittest.TestCase):
    def test_projects_only_runtime_attachment_fields_without_reordering(self):
        first = {"node_id": "root:1", "link_slot": 1}
        second = {"node_id": "root:2", "link_slot": 2}
        full = {
            "sources": {"models": {"part.ccf": {"sha256": "a" * 64}}},
            "counts": {
                "parts": 2,
                "attachment_targets": 2,
                "parts_with_attachment_targets": 1,
            },
            "parts": [
                {"part_id": 6, "vertices": [1, 2, 3], "attachment_targets": [first, second]},
                {"part_id": 7, "vertices": [4, 5, 6], "attachment_targets": []},
            ],
        }

        compact = project_attachments(full)

        self.assertEqual(compact["schema"], 1)
        self.assertEqual(compact["counts"], full["counts"])
        self.assertEqual(compact["parts"], [
            {"part_id": 6, "attachment_targets": [first, second]},
            {"part_id": 7, "attachment_targets": []},
        ])
        self.assertNotIn("vertices", compact["parts"][0])


if __name__ == "__main__":
    unittest.main()
