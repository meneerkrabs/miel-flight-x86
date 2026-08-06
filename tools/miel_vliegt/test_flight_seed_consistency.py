#!/usr/bin/env python3
"""Flight seed consistency gate.

Pins the canonical ``LOCATION_PHASE_RNG`` seed contract -- the seed VALUE
``1592639710`` emitted by the observer hook at ``phase=seed`` together with its
companion caller RVA ``0x00030a8a`` -- across every place the contract is
referenced:

* the production library ``native_scenario_artifacts`` (which anchors the seed
  VALUE via ``LOCATION_PHASE_RNG_SEED_VALUE`` and enforces it post-capture
  through ``validate_location_phase_rng_seed``);
* the observer-log test module ``test_native_scenario_artifacts`` (whose
  module-level constant is the original programmatic anchor and remains the
  independent test-owned pin);
* the authoritative flight docs that restate the line-4 seed contract;
* the C observer hook source that pins the caller RVA half
  (``#define LOCATION_PHASE_RAND_CALLER_RVA 0x00030a8au``).

The native observer hook itself only guards ``caller_rva ==
LOCATION_PHASE_RAND_CALLER_RVA``; the seed VALUE half of the contract is
enforced on the host side -- in the production library and these test gates --
so a capture that passes ``caller_rva`` while emitting the wrong seed, or a doc
that drifts away from the canonical value, can no longer go unnoticed.

This test creates no artifacts and runs no parity commands; it only reads
existing files and asserts they agree.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

# Import the existing observer-log test module: it owns the only programmatic
# anchor for the seed VALUE today (its module-level constant). Pinning that
# constant from a second module is what makes VALUE drift between test modules
# impossible to land silently.
from tools.miel_vliegt import test_native_scenario_artifacts as observer_test


# --------------------------------------------------------------------------- #
# Canonical contract -- single source of truth for THIS gate. Every other      #
# reference (test module constant, docs, hook source) is asserted to agree.    #
# --------------------------------------------------------------------------- #
LOCATION_PHASE_RNG_SEED_VALUE = 1592639710
LOCATION_PHASE_RAND_CALLER_RVA = "0x00030a8a"

# The C observer hook writes the caller RVA as the unsigned literal
# ``0x00030a8au``; the observer log and docs render the bare hex ``0x00030a8a``.
# Both halves are pinned so a change to either representation is caught.
LOCATION_PHASE_RAND_CALLER_RVA_C_LITERAL = "0x00030a8au"

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
_DOC_DIR = _REPO_ROOT / "docs"

# Docs that restate the authoritative line-4 seed contract. The list is kept
# explicit on purpose; a companion test enforces that it stays in sync with
# whichever flight docs actually quote the contract.
SEED_CONTRACT_DOCS = (
    "flight-takeoff-climb-diagnosis.md",
    "flight-parity-capture-plan.md",
    "flight-capture-fix-bundle.md",
    "flight-dispatch-readiness.md",
)

# Matches the doc contract line, e.g.
#   `native-location-phase-rng phase=seed value=1592639710 caller_rva=0x00030a8a`
# Note the docs use the short protocol name (``native-location-phase-rng``);
# the observer log uses the prefixed ``miel-vliegt-native-location-phase-rng``.
SEED_CONTRACT_RE = re.compile(
    r"native-location-phase-rng\s+phase=seed\s+value=(?P<value>\d+)\s+"
    r"caller_rva=(?P<caller>0x[0-9a-fA-F]{8})"
)

# A named UPPER_SNAKE source constant that looks like a seed anchor, e.g.
# ``LOCATION_PHASE_RNG_SEED_VALUE = 1592639710``. The production library now
# anchors the value; this regex still guards that every such anchor agrees.
_SOURCE_SEED_ANCHOR_RE = re.compile(
    r"(?m)^[ \t]*(?P<name>[A-Z0-9_]*SEED[A-Z0-9_]*)\s*=\s*(?P<value>\d+)"
)


class FlightSeedConsistencyTests(unittest.TestCase):
    """Assert the flight location-phase RNG seed contract does not drift.

    The seed VALUE ``1592639710`` and caller RVA ``0x00030a8a`` must be identical
    in: this gate, the observer-log test module, every flight doc that quotes the
    contract, and the C observer hook (caller RVA half). Drift in any one place
    fails this gate before an owner-gated capture can go green on a wrong seed.
    """

    # ----- canonical value pin ---------------------------------------------- #

    def test_canonical_seed_value_is_pinned(self):
        """The canonical seed VALUE must stay pinned at 1592639710."""
        self.assertEqual(
            LOCATION_PHASE_RNG_SEED_VALUE,
            1592639710,
            "LOCATION_PHASE_RNG_SEED_VALUE must stay pinned at 1592639710",
        )
        # Sanity: the value is a valid u32 (the hook emits it as a u32).
        self.assertLess(
            LOCATION_PHASE_RNG_SEED_VALUE, 1 << 32,
            "seed VALUE must fit in an unsigned 32-bit integer",
        )

    def test_canonical_caller_rva_is_pinned(self):
        """The canonical caller RVA must stay pinned at 0x00030a8a in both forms."""
        self.assertEqual(LOCATION_PHASE_RAND_CALLER_RVA, "0x00030a8a")
        self.assertEqual(LOCATION_PHASE_RAND_CALLER_RVA_C_LITERAL, "0x00030a8au")
        # The log/doc form must be the hex stem of the C literal.
        self.assertTrue(
            LOCATION_PHASE_RAND_CALLER_RVA_C_LITERAL.startswith(
                LOCATION_PHASE_RAND_CALLER_RVA
            ),
            "C literal must render the same hex as the log/doc form",
        )

    # ----- cross-test pin (original programmatic anchor) -------------------- #

    def test_observer_log_test_module_constant_matches_seed(self):
        """The seed VALUE in test_native_scenario_artifacts must equal canonical."""
        existing = getattr(observer_test, "LOCATION_PHASE_RNG_SEED_VALUE", None)
        self.assertIsNotNone(
            existing,
            "test_native_scenario_artifacts.LOCATION_PHASE_RNG_SEED_VALUE is "
            "missing -- it is the original programmatic anchor for the seed "
            "VALUE",
        )
        self.assertEqual(
            existing,
            LOCATION_PHASE_RNG_SEED_VALUE,
            "seed VALUE drifted between test modules: "
            f"{existing!r} != {LOCATION_PHASE_RNG_SEED_VALUE!r}",
        )

    def test_observer_log_test_module_constant_matches_caller_rva(self):
        """The caller RVA in test_native_scenario_artifacts must equal canonical."""
        existing = getattr(observer_test, "LOCATION_PHASE_RAND_CALLER_RVA", None)
        self.assertIsNotNone(
            existing,
            "test_native_scenario_artifacts.LOCATION_PHASE_RAND_CALLER_RVA is "
            "missing -- it is the programmatic anchor for the caller RVA",
        )
        self.assertEqual(
            existing,
            LOCATION_PHASE_RAND_CALLER_RVA,
            f"caller RVA drifted: {existing!r} != "
            f"{LOCATION_PHASE_RAND_CALLER_RVA!r}",
        )

    # ----- doc contract pin ------------------------------------------------- #

    def test_all_seed_contract_docs_quote_canonical_pair(self):
        """Every seed contract line in the listed docs matches the canonical pair."""
        failures = []
        matched_any = False
        for relative in SEED_CONTRACT_DOCS:
            doc = _DOC_DIR / relative
            self.assertTrue(doc.exists(), f"seed-contract doc missing: {doc}")
            for match in SEED_CONTRACT_RE.finditer(doc.read_text(encoding="utf-8")):
                matched_any = True
                value = int(match.group("value"))
                caller = match.group("caller").lower()
                location = f"{relative}:value={value}:caller_rva={caller}"
                if value != LOCATION_PHASE_RNG_SEED_VALUE:
                    failures.append(
                        f"{location} (value != "
                        f"{LOCATION_PHASE_RNG_SEED_VALUE})"
                    )
                if caller != LOCATION_PHASE_RAND_CALLER_RVA:
                    failures.append(
                        f"{location} (caller_rva != "
                        f"{LOCATION_PHASE_RAND_CALLER_RVA})"
                    )
        self.assertTrue(
            matched_any,
            "no seed contract lines matched across the listed docs -- the "
            "regex is stale or every doc lost the line-4 contract",
        )
        self.assertEqual(
            failures,
            [],
            "seed contract drift detected across docs: " + "; ".join(failures),
        )

    def test_seed_contract_doc_list_is_exhaustive(self):
        """Every flight doc quoting the contract must be in SEED_CONTRACT_DOCS."""
        listed = set(SEED_CONTRACT_DOCS)
        quoting = set()
        for doc in _DOC_DIR.glob("flight-*.md"):
            if SEED_CONTRACT_RE.search(doc.read_text(encoding="utf-8")):
                quoting.add(doc.name)
        self.assertEqual(
            sorted(quoting),
            sorted(listed),
            "SEED_CONTRACT_DOCS is out of sync with the flight docs that quote "
            f"the contract -- quoting={sorted(quoting)} "
            f"listed={sorted(listed)}",
        )

    def test_flight_docs_each_quote_contract_at_least_once(self):
        """No listed doc may have silently dropped the contract line."""
        for relative in SEED_CONTRACT_DOCS:
            doc = _DOC_DIR / relative
            self.assertTrue(doc.exists(), f"seed-contract doc missing: {doc}")
            text = doc.read_text(encoding="utf-8")
            self.assertTrue(
                SEED_CONTRACT_RE.search(text),
                f"{relative} no longer quotes the seed contract line",
            )

    # ----- source / hook pin ------------------------------------------------ #

    def test_observer_hook_source_pins_caller_rva(self):
        """native_observer_hook.c must define the caller RVA half of the contract."""
        hook = _HERE / "hangover" / "native_observer_hook.c"
        self.assertTrue(hook.exists(), f"observer hook source missing: {hook}")
        source = hook.read_text(encoding="utf-8")
        define = (
            "#define LOCATION_PHASE_RAND_CALLER_RVA "
            f"{LOCATION_PHASE_RAND_CALLER_RVA_C_LITERAL}"
        )
        self.assertIn(
            define,
            source,
            f"native_observer_hook.c must define {define!r}",
        )

    def test_seed_value_remains_consistent_if_anchored_in_source(self):
        """Any ``*_SEED*`` integer constant in the production source must agree.

        ``native_scenario_artifacts.py`` anchors the seed VALUE through
        ``LOCATION_PHASE_RNG_SEED_VALUE``; this test guards that every
        ``*_SEED*`` integer constant in that module equals the canonical value,
        so a disagreeing literal (or a second anchor that drifts) can no longer
        land silently.
        """
        artifacts = _HERE / "native_scenario_artifacts.py"
        self.assertTrue(artifacts.exists(), f"artifacts module missing: {artifacts}")
        source = artifacts.read_text(encoding="utf-8")
        mismatches = []
        for match in _SOURCE_SEED_ANCHOR_RE.finditer(source):
            name = match.group("name")
            value = int(match.group("value"))
            if value != LOCATION_PHASE_RNG_SEED_VALUE:
                mismatches.append(f"{name}={value}")
        self.assertEqual(
            mismatches,
            [],
            "native_scenario_artifacts.py defines a seed constant that "
            "disagrees with the canonical value: " + ", ".join(mismatches),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
