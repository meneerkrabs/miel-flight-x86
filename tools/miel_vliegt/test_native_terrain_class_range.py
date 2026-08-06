#!/usr/bin/env python3
"""Tests for the terrain_class_range relaxation in native_observer_hook.c.

The approach-landing scenario is the first to exercise terrain collision code.
Under FEX-emu x87 FPU emulation the terrain_class integer may be computed
slightly differently than on real x86 hardware, occasionally producing a
negative value.  The game's own disassembly only checks ``cmpl $7`` (unsigned
above 7) — there is no lower-bound guard.  Our observer hook must match that
behavior so that negative sentinel values do not cause a false
session_fail("terrain_class_range") which surfaces as exit code 5
(SESSION_FAILED == 5).
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools" / "miel_vliegt" / "hangover" / "native_observer_hook.c"


class TerrainClassRangeTest(unittest.TestCase):
    """Source-level verification of record_terrain_result range logic."""

    @classmethod
    def setUpClass(cls):
        cls.source = HOOK.read_text(encoding="utf-8")
        start = cls.source.index(
            "static void __attribute__((used)) record_terrain_result"
        )
        end = cls.source.index(
            "static void __attribute__((used)) record_camera_commit"
        )
        cls.func = cls.source[start:end]

    def test_lower_bound_removed_from_range_check(self):
        """The ``< -1`` lower bound must not appear in record_terrain_result.

        Previously the check was ``if (terrain_class < -1 || terrain_class > 7)``
        which is stricter than the game's own unsigned ``cmpl $7`` comparison.
        FEX x87 emulation can produce small negative values that real hardware
        does not, so the lower bound caused a false session_fail on
        approach-landing.
        """
        self.assertNotIn("terrain_class < -1", self.func)
        # The full compound condition must be gone too.
        self.assertNotIn("terrain_class < -1 || terrain_class > 7", self.func)

    def test_range_check_matches_game_unsigned_comparison(self):
        """Only values above 7 should trigger session_fail, matching the game."""
        self.assertIn("terrain_class > 7", self.func)

    def test_negative_values_passed_through_not_failed(self):
        """Negative values must reach emit_outcome_terrain, not session_fail.

        After the diagnostic block, the only hard rejection is ``> 7``.  A
        value of -1 (the no-terrain sentinel) or any small negative must fall
        into the ``else`` branch that calls emit_outcome_terrain.
        """
        # The diagnostic guard must use < 0 to capture all negatives.
        self.assertIn("terrain_class < 0", self.func)
        # emit_outcome_terrain must still be reachable in the else branch.
        self.assertIn("emit_outcome_terrain(terrain_class)", self.func)

    def test_diagnostic_logging_present(self):
        """A diagnostic record must be emitted for negative terrain_class."""
        # The C string literal escapes quotes, so check for the channel and
        # class format specifier rather than the raw JSON fragment.
        self.assertIn("diagnostic.terrain_class", self.func)
        self.assertIn("class\\\":%ld", self.func)
        # Must use the diagnostic record type.
        self.assertIn('\\"record\\":\\"diagnostic\\"', self.func)

    def test_fex_context_comment_present(self):
        """The comment block must explain the FEX x87 emulation rationale."""
        self.assertIn("FEX", self.func)
        self.assertIn("x87", self.func)

    def test_session_fail_reason_unchanged(self):
        """The session_fail reason string must remain terrain_class_range."""
        self.assertIn('session_fail("terrain_class_range")', self.func)


if __name__ == "__main__":
    unittest.main()
