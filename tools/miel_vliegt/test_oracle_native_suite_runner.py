#!/usr/bin/env python3
"""Contracts for the unattended oracle-miel seven-scenario suite runner."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

from tools.miel_vliegt import native_semantic_suite


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "deployment/run-oracle-flight-native-suite.sh"
WORKFLOW = ROOT / ".github/workflows/native-flight-semantic-suite.yml"
DEPLOY_WORKFLOW = ROOT / ".github/workflows/deploy-oracle.yml"


class OracleNativeSuiteRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.deploy_workflow = DEPLOY_WORKFLOW.read_text(encoding="utf-8")

    def test_runner_is_valid_bash_and_documents_its_only_selectors(self):
        subprocess.run(["bash", "-n", str(RUNNER)], check=True)
        help_result = subprocess.run(
            ["bash", str(RUNNER), "--help"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--run-root", help_result.stdout)
        self.assertNotIn("--private-game-root", help_result.stdout)
        self.assertIn("--private-iso", help_result.stdout)
        self.assertIn("--image-reference", help_result.stdout)

    def test_runner_does_not_accept_caller_declared_hashes_or_container_ids(self):
        for forbidden in (
            "--container-id",
            "--container-image-sha256",
            "--source-executable-sha256",
            "--observer-dll-sha256",
            "--private-game-root",
        ):
            result = subprocess.run(
                ["bash", str(RUNNER), forbidden, "untrusted"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 64, forbidden)
            self.assertIn("unknown argument", result.stderr)

        parse_surface = self.runner[
            self.runner.index("while (($#));"):
            self.runner.index("[[ -n \"${RUN_ROOT}\" ]]")
        ]
        self.assertNotIn("--container-id", parse_surface)
        self.assertNotIn("-sha256", parse_surface)

    def test_image_selection_resolves_and_validates_immutable_content(self):
        self.assertIn(
            "--filter 'reference=miel-flight-fex-wine:*'",
            self.runner,
        )
        self.assertIn(
            "candidate_id=\"$(docker image inspect --format '{{.Id}}'",
            self.runner,
        )
        self.assertIn(
            r"^sha256:[0-9a-f]{64}$",
            self.runner,
        )
        self.assertIn(
            'cmp -s "${IMAGE_CONTRACT}"',
            self.runner,
        )
        self.assertRegex(
            self.runner,
            re.compile(
                r'python3 "\$\{OBSERVER_BUILD\}".*?--check.*?'
                r'--output "\$\{candidate_root\}/native-observer-build\.json".*?'
                r'--artifact "\$\{candidate_root\}/native-observer-hook\.dll"',
                re.DOTALL,
            ),
        )
        self.assertIn(
            '[[ "${#validated_images[@]}" -ne 1 ]]',
            self.runner,
        )
        self.assertIn('if validate_image "${candidate}"; then', self.runner)
        self.assertNotIn('validation="$(validate_image', self.runner)
        self.assertIn(
            'VALIDATION_RESULT="${candidate_id}"$\'\\t\'"${candidate_root}"',
            self.runner,
        )

    def test_runner_owns_fresh_roots_container_and_exact_fex_budget(self):
        self.assertIn(
            '[[ ! -e "${RUN_ROOT}" && ! -L "${RUN_ROOT}" ]]',
            self.runner,
        )
        self.assertIn('mkdir -m 0700 "${RUN_ROOT}"', self.runner)
        self.assertIn("readonly OBSERVE_MS=3600000", self.runner)
        self.assertIn("readonly MAX_RECORDS=1000000", self.runner)
        self.assertIn('--observe-ms "${OBSERVE_MS}"', self.runner)
        self.assertIn('--max-records "${MAX_RECORDS}"', self.runner)
        self.assertIn(
            '--mount "type=bind,source=${RUN_ROOT},target=${RUN_ROOT}"',
            self.runner,
        )
        self.assertIn(
            "CONTAINER_ID=\"$(docker inspect --format '{{.Id}}'",
            self.runner,
        )
        self.assertIn(
            '--container-image-sha256 "${IMAGE_SHA256}"',
            self.runner,
        )
        self.assertIn(
            '--container-id "${CONTAINER_ID}"',
            self.runner,
        )
        self.assertEqual(
            self.runner.count(
                'nl.mielmonteur.native-suite.run-id=${GITHUB_RUN_ID:-manual}'
            ),
            2,
        )
        self.assertIn("trap cleanup EXIT", self.runner)
        cleanup = self.runner[
            self.runner.index("cleanup() {"):
            self.runner.index("trap cleanup EXIT")
        ]
        self.assertIn('docker rm --force "${PROBE_CONTAINER}"', cleanup)
        self.assertIn('docker rm --force "${CONTAINER_ID}"', cleanup)

    def test_runner_derives_every_suite_hash_from_staged_bytes(self):
        expected_labels = set(native_semantic_suite.INPUT_LABELS)
        labels = set(re.findall(r"^  \[([a-z_]+)\]=", self.runner, re.MULTILINE))
        self.assertEqual(labels, expected_labels)
        self.assertEqual(
            native_semantic_suite.FEX_CALIBRATED_SUITE_OBSERVE_MS,
            3_600_000,
        )
        self.assertIn(
            'input_sha256["${label}"]="$(sha256sum "${input_paths[${label}]}"',
            self.runner,
        )
        self.assertIn(
            '"--${label//_/-}-sha256" "${input_sha256[${label}]}"',
            self.runner,
        )
        self.assertIn(
            'actual_iso_sha256="$(sha256sum "${PRIVATE_ISO}"',
            self.runner,
        )
        self.assertIn(
            '[[ "${actual_iso_sha256}" == "${expected_iso_sha256}" ]]',
            self.runner,
        )
        self.assertIn(
            '("executable", "launcher", "cc_dll", "udspack_dll", "help_file")',
            self.runner,
        )
        self.assertIn(
            'CAPTURE_DRIVER_FOUNDATION["initial_user_sha256"]',
            self.runner,
        )
        self.assertIn(
            '[[ "${actual_user_sha256}" == "${expected_user_sha256}" ]]',
            self.runner,
        )

    def test_runner_hydrates_and_verifies_private_game_from_pinned_iso(self):
        self.assertNotIn("--private-game-root", self.runner)
        self.assertIn("unshield", self.runner)
        self.assertIn(
            '7z x -y "-o${INSTALLER_ROOT}" "${PRIVATE_ISO}"',
            self.runner,
        )
        self.assertIn(
            'unshield -g "System Files" x "${INSTALLER_ROOT}/data1.cab"',
            self.runner,
        )
        self.assertIn(
            'readonly PRIVATE_GAME_ROOT="${EXTRACTED_SYSTEM_ROOT}/System_Files"',
            self.runner,
        )
        iso_verification = self.runner.index(
            '[[ "${actual_iso_sha256}" == "${expected_iso_sha256}" ]]'
        )
        iso_extraction = self.runner.index(
            '7z x -y "-o${INSTALLER_ROOT}" "${PRIVATE_ISO}"'
        )
        source_verification = self.runner.index(
            'for row in "${private_identity_rows[@]:1}"'
        )
        game_staging = self.runner.index(
            'cp -a "${PRIVATE_GAME_ROOT}/." "${GAME_ROOT}/"'
        )
        self.assertLess(iso_verification, iso_extraction)
        self.assertLess(iso_extraction, source_verification)
        self.assertLess(source_verification, game_staging)
        for source_key in (
            "executable",
            "launcher",
            "cc_dll",
            "udspack_dll",
            "help_file",
        ):
            self.assertIn(f'"{source_key}"', self.runner)

    def test_workflow_never_depends_on_mutable_preinstalled_game_root(self):
        self.assertNotIn(
            "/home/ubuntu/miel-isos/mielvliegt-system",
            self.workflow,
        )
        self.assertNotIn("--private-game-root", self.workflow)
        self.assertIn("command -v 7z", self.workflow)
        self.assertIn("command -v unshield", self.workflow)
        self.assertIn("packages+=(p7zip-full)", self.workflow)
        self.assertIn("packages+=(unshield)", self.workflow)
        self.assertIn('--private-iso "$PRIVATE_ISO"', self.workflow)

    def test_workflow_is_manual_private_and_evidence_preserving(self):
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotRegex(self.workflow, re.compile(r"^\s+pull_request:", re.MULTILINE))
        self.assertNotRegex(self.workflow, re.compile(r"^\s+push:", re.MULTILINE))
        self.assertIn("group: mielmonteur-oracle-native-flight", self.workflow)
        self.assertIn("group: mielmonteur-oracle-production", self.deploy_workflow)
        self.assertNotIn(
            "group: mielmonteur-oracle-production",
            self.workflow,
        )
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertIn(
            "runs-on: [self-hosted, linux, ARM64, oracle-miel]",
            self.workflow,
        )
        self.assertIn('test "$GITHUB_REF" = "refs/heads/master"', self.workflow)
        self.assertIn(
            'test "$REQUEST_ACTOR" = "$REPOSITORY_OWNER"',
            self.workflow,
        )
        private_access = self.workflow.index(
            "Authorize private native evidence access"
        )
        native_run = self.workflow.index(
            "Run calibrated seven-scenario native suite"
        )
        self.assertLess(private_access, native_run)
        self.assertIn("timeout-minutes: 480", self.workflow)
        for evidence in (
            "runner-receipt.json",
            "input-identities.tsv",
            "orchestration.log",
            "native-suite.log",
            "calibrated-suite/**",
            "output/**",
        ):
            self.assertIn(evidence, self.workflow)
        projection = self.workflow.index(
            "Project native evidence onto canonical completion gates"
        )
        upload = self.workflow.index(
            "Upload complete calibrated and exact replay evidence"
        )
        self.assertLess(native_run, projection)
        self.assertLess(projection, upload)
        self.assertIn(
            "flight_scenario_completion_adapter.py",
            self.workflow[projection:upload],
        )
        self.assertNotIn(
            "--require-all",
            self.workflow[projection:upload],
        )
        self.assertIn("if: always()", self.workflow)
        self.assertIn("retention-days: 30", self.workflow)
        self.assertIn("compression-level: 1", self.workflow)
        cleanup = self.workflow.index("Remove run-scoped native resources")
        self.assertLess(upload, cleanup)
        cleanup_block = self.workflow[cleanup:]
        self.assertIn(
            '"$RUNNER_TEMP"/miel-native-'
            '"$GITHUB_RUN_ID"-"$GITHUB_RUN_ATTEMPT")',
            cleanup_block,
        )
        self.assertIn('rm -rf "$NATIVE_RUN_ROOT"', cleanup_block)
        run_root = (
            "NATIVE_RUN_ROOT: ${{ runner.temp }}/miel-native-"
            "${{ github.run_id }}-${{ github.run_attempt }}"
        )
        self.assertNotIn(run_root, self.workflow[:self.workflow.index("    steps:")])
        self.assertEqual(self.workflow.count(run_root), 5)
        for step_name in (
            "Run calibrated seven-scenario native suite",
            "Project native evidence onto canonical completion gates",
            "Summarize native suite receipt",
            "Upload complete calibrated and exact replay evidence",
            "Remove run-scoped native resources",
        ):
            step = self.workflow.split(f"- name: {step_name}", 1)[1]
            step = step.split("- name:", 1)[0]
            self.assertIn(run_root, step, step_name)

    def test_workflow_builds_source_faithful_image_when_no_reference_given(self):
        # The oracle runner only VALIDATES cached miel-flight-fex-wine images
        # against the checked-out sources; it never builds one. When observer
        # sources evolve between dispatches every cached image legitimately
        # drifts and the dispatch spends ~50 min rebuilding before failing.
        # The workflow must therefore build a content-addressed image from the
        # exact checkout when no caller-supplied reference is given, and must
        # always hand the runner an --image-reference so the drift check is
        # satisfied by construction (the runner still re-validates the built
        # image against the same sources) rather than bypassed.
        build_step = self.workflow.index(
            "Ensure a source-faithful FEX capture image"
        )
        native_run = self.workflow.index(
            "Run calibrated seven-scenario native suite"
        )
        self.assertLess(build_step, native_run)
        build_block = self.workflow[build_step:native_run]
        self.assertIn(
            "docker build -f tools/miel_vliegt/fex_wine/Dockerfile",
            build_block,
        )
        self.assertIn("miel-flight-fex-wine:src-${GITHUB_SHA}", build_block)
        self.assertIn(
            'echo "IMAGE_REFERENCE=$reference" >> "$GITHUB_ENV"', build_block
        )
        # The run step must always pass the resolved reference, never omit it
        # (a missing reference falls back to scanning every cached image and
        # rebuilds for ~50 min when all are stale).
        run_block = self.workflow[native_run:]
        self.assertIn('--image-reference "$IMAGE_REFERENCE"', run_block)


if __name__ == "__main__":
    unittest.main()
