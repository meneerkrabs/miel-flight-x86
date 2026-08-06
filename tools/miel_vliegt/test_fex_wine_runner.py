#!/usr/bin/env python3
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools/miel_vliegt/fex_wine"


class FexWineRunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads((RUNNER / "contract.json").read_text())
        cls.dockerfile = (RUNNER / "Dockerfile").read_text()
        cls.canary = (RUNNER / "canary.sh").read_text()
        cls.installer = (RUNNER / "install_guest_wine.sh").read_text()
        cls.wine_launcher = (RUNNER / "wine.sh").read_text()
        cls.suite_launcher = (RUNNER / "run_native_suite.sh").read_text()
        cls.deployment_launcher = (
            ROOT / "deployment/run-flight-native-suite.sh"
        ).read_text()

    def test_contract_pins_fex_rootfs_and_wine(self):
        self.assertEqual(self.contract["protocol"], "miel-vliegt-fex-wine-runner")
        self.assertEqual(self.contract["target"]["host_arch"], "arm64")
        self.assertFalse(self.contract["target"]["host_binfmt_registration"])
        self.assertEqual(self.contract["fex"]["release"], "FEX-2607")
        self.assertEqual(self.contract["fex"]["package_version"], "2607-1~n")
        self.assertRegex(self.contract["fex"]["package_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.contract["rootfs"]["snapshot"], "2025-12-27")
        self.assertEqual(self.contract["rootfs"]["size_bytes"], 520323072)
        self.assertRegex(self.contract["rootfs"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(
            self.contract["rootfs"]["upstream_xxh3_64"], r"^[0-9a-f]{16}$"
        )
        self.assertEqual(self.contract["wine"]["version"], "9.0~repack-4build3")
        self.assertEqual(self.contract["wine"]["snapshot"], "20251227T000000Z")
        self.assertEqual(
            self.contract["wine"]["mingw_runtime"]["version"],
            "13.2.0-6ubuntu1+26.1",
        )
        self.assertEqual(
            self.contract["wine"]["mingw_runtime"]["prefix_bootstrap_dlls"],
            ["zlib1.dll", "libgcc_s_dw2-1.dll"],
        )
        self.assertEqual(
            self.contract["wine"]["installation"],
            "host-verified-snapshot-extract",
        )
        self.assertFalse(
            self.contract["evidence_policy"]["canary_is_native_parity_evidence"]
        )
        self.assertEqual(
            self.contract["runtime_compatibility"],
            {
                "fex_smc_checks": "full",
                "full_smc_processes": [
                    "MulleMeck*.exe",
                    "native-observer-launcher.exe",
                    "native-scene-debugger.exe",
                ],
                "auxiliary_smc_checks": "mtrack",
                "wine_renderer": "gdi",
                "renderer_configuration_owner":
                    "single-process-readiness-canary",
                "wine_session_boundary":
                    "readiness-and-game-share-live-wineserver",
                "wine_session_start_proof":
                    "spawn-plus-smoke-plus-runtime-readiness",
                "wine_session_shutdown":
                    "kill-then-wait-before-state-removal",
                "readiness_budget": {
                    "guest_process_timeout_seconds": 90,
                    "rpcss_poll_timeout_milliseconds": 30000,
                    "sleep_based_readiness": False,
                },
                "gtsoftware_sha256":
                    "c3cebce34373255993b23ca54e3f678487f44a5fb7c1b9f4a63aa3b5d82a9ee8",
                "native_client": "640x480x16",
                "xvfb_screen": "646x512x16",
                "wine_client_offset": [3, 29],
                "disabled_optional_installers": ["mscoree", "mshtml"],
                "required_service": "RpcSs",
                "required_com_classes": [
                    "{47D4D946-62E8-11CF-93BC-444553540000}",
                    "{BCDE0395-E52F-467C-8E3D-C4579291692E}",
                ],
                "baseline_observation_seconds": 25,
                "baseline_outcome": "STAYED_RUNNING_NO_EXCEPTION",
                "baseline_is_native_parity_evidence": False,
            },
        )
        performance = self.contract["performance_lane"]
        self.assertEqual(performance["default_mode"], "cold-audit")
        self.assertEqual(performance["sealed_slots"], ["A", "B"])
        self.assertTrue(performance["independent_bootstrap_per_slot"])
        self.assertEqual(
            performance["wine_z_symlink_policy"],
            "preserve-link-never-follow",
        )
        self.assertEqual(performance["tmpfs"], {
            "bytes_per_job": 2147483648,
            "max_jobs": 2,
            "aggregate_bytes": 4294967296,
            "no_swap": True,
            "minimum_headroom_bytes": 8589934592,
        })
        self.assertEqual(performance["retry"]["maximum"], 1)
        self.assertFalse(
            performance["retry"]["semantic_or_focus_failure_retry"]
        )
        self.assertEqual(
            performance["path_visibility"],
            "sealed-store-and-tmpfs-below-exact-container-bind-root",
        )
        self.assertEqual(performance["store_retention"], {
            "managed_root_mode": "0700",
            "suite_lock": "shared-for-complete-suite-lifetime",
            "prune_lock": "exclusive",
            "inactive_ttl_seconds": 2592000,
            "unmarked_or_active_identity_pruning": False,
        })

    def test_dockerfile_uses_contract_pins_and_explicit_fex_only(self):
        for value in (
            self.contract["fex"]["package_url"],
            self.contract["fex"]["package_sha256"],
            self.contract["fex"]["package_version"],
            self.contract["rootfs"]["url"],
            self.contract["rootfs"]["sha256"],
            self.contract["rootfs"]["upstream_xxh3_64"],
            self.contract["wine"]["snapshot"],
            self.contract["wine"]["version"],
            self.contract["wine"]["mingw_runtime"]["version"],
        ):
            self.assertIn(str(value), self.dockerfile)
        self.assertIn('test "${TARGETARCH}" = arm64', self.dockerfile)
        self.assertIn("FEX /usr/bin/uname -m", self.dockerfile)
        self.assertIn("FEXBash -c", self.installer)
        self.assertIn(
            "ln -s /opt/fex/rootfs/usr/share/wine /usr/share/wine",
            self.dockerfile,
        )
        self.assertIn("xxhsum -H3", self.dockerfile)
        self.assertNotIn("add-apt-repository", self.dockerfile)
        self.assertNotIn("update-binfmts", self.dockerfile)
        self.assertNotIn("fex-emu-binfmt32_", self.dockerfile)
        self.assertNotIn("fex-emu-binfmt64_", self.dockerfile)
        self.assertIn(
            'ENTRYPOINT ["/opt/miel/fex-wine-canary"]', self.dockerfile
        )

    def test_suite_launcher_keeps_sealed_and_cold_audit_explicit(self):
        self.assertIn("--prefix-mode cold-audit", self.suite_launcher)
        self.assertIn("--prefix-mode sealed", self.suite_launcher)
        self.assertIn("--backend-hodll-sha256", self.suite_launcher)
        self.assertIn("--expected-gid", self.suite_launcher)
        self.assertIn("findmnt -n -o FSTYPE", self.suite_launcher)
        self.assertIn(
            '${MIEL_NATIVE_TMPFS_ROOT}/wine-prefix-$$', self.suite_launcher
        )
        self.assertIn(
            'MIEL_NATIVE_PREFIX_MODE:-cold-audit', self.deployment_launcher
        )
        self.assertIn(
            "must be mounted before the Docker container starts",
            self.deployment_launcher,
        )
        self.assertNotIn("sudo mount", self.deployment_launcher)
        self.assertIn('exec "${launcher}" "${mode}"', self.deployment_launcher)

    def test_guest_wine_installer_uses_signed_snapshot_without_guest_apt(self):
        self.assertIn("set -euo pipefail", self.installer)
        self.assertIn(
            "snapshot.ubuntu.com/ubuntu/${ubuntu_snapshot}", self.installer
        )
        self.assertIn(
            "signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg",
            self.installer,
        )
        self.assertIn("--download-only", self.installer)
        self.assertIn("dpkg-deb --extract", self.installer)
        self.assertIn("guest-wine-packages.sha256", self.installer)
        self.assertIn("require_package wine32 i386", self.installer)
        self.assertIn("require_package libwine amd64", self.installer)
        self.assertIn(
            "require_package gcc-mingw-w64-i686-win32-runtime amd64",
            self.installer,
        )
        self.assertIn("MINGW_RUNTIME_VERSION is required", self.installer)
        self.assertNotIn("trusted=yes", self.installer)
        self.assertNotIn("AllowUnauthenticated", self.installer)

    def test_image_contains_the_observer_binaries(self):
        self.assertEqual(self.dockerfile.count("ubuntu:24.04@sha256:"), 2)
        self.assertIn("ca-certificates curl python3", self.dockerfile)
        self.assertIn("/opt/miel/native-observer-launcher.exe", self.dockerfile)
        self.assertIn("/opt/miel/native-observer-hook.dll", self.dockerfile)
        self.assertIn("/opt/miel/native-observer-build.json", self.dockerfile)
        self.assertIn("/opt/miel/native-scene-debugger.exe", self.dockerfile)
        self.assertIn("/opt/miel/DINPUT.dll", self.dockerfile)
        self.assertIn("win32_readiness_canary.c", self.dockerfile)
        self.assertIn("/opt/miel/wine-readiness-canary.exe", self.dockerfile)
        self.assertIn(
            "/opt/fex/rootfs/usr/lib/i386-linux-gnu/wine/i386-windows/dinput.dll",
            self.dockerfile,
        )
        self.assertIn("/opt/miel/dinput-real.dll", self.dockerfile)
        self.assertIn("-Wall -Wextra -Werror", self.dockerfile)
        self.assertIn("native_observer_build.py", self.dockerfile)

    def test_image_allows_isolated_runner_uid_to_reach_exact_bind_mount(self):
        self.assertIn("chmod 0711 /home/ubuntu", self.dockerfile)
        self.assertNotIn("chmod 0755 /home/ubuntu", self.dockerfile)

    def test_canary_is_disposable_bounded_and_arm64_only(self):
        self.assertIn("aarch64|arm64", self.canary)
        self.assertIn("mktemp -d", self.canary)
        self.assertIn("WINEARCH=win32", self.canary)
        self.assertIn("Xvfb", self.canary)
        self.assertIn("646x512x16", self.canary)
        self.assertIn("xdpyinfo", self.canary)
        self.assertIn("FEX_SMCCHECKS=full", self.canary)
        self.assertIn("FEX_DUMPIR=stderr", self.canary)
        self.assertIn("ValidateCode", self.canary)
        self.assertNotIn("FEX_SMCChecks", self.canary)
        self.assertIn("timeout --signal=TERM --kill-after=5s", self.canary)
        self.assertIn("/opt/miel/fex-wine wineboot --init", self.canary)
        self.assertNotIn("/opt/miel/fex-wine cmd", self.canary)
        self.assertIn('wineserver64" -p0', self.canary)
        self.assertIn('kill -0 "${wineserver_pid}"', self.canary)
        self.assertIn("WINEDLLOVERRIDES='mscoree,mshtml='", self.canary)
        self.assertIn("wine-readiness-canary.exe", self.canary)
        self.assertIn("MIEL_RPCSS_STATE=RUNNING", self.canary)
        self.assertIn("MIEL_WINE_RENDERER=GDI", self.canary)
        self.assertIn("MIEL_WINE_DECORATED=N", self.canary)
        self.assertIn("MIEL_FEX_WINE_READINESS_OK", self.canary)
        self.assertIn("--rpcss-timeout-ms", self.canary)
        readiness_source = (
            RUNNER / "win32_readiness_canary.c"
        ).read_text()
        self.assertIn("MIEL_FEX_WINE_CANARY_OK", readiness_source)
        self.assertIn(r"Software\\Wine\\Direct3D", readiness_source)
        self.assertIn('"renderer", "gdi"', readiness_source)
        self.assertIn(r"Software\\Wine\\X11 Driver", readiness_source)
        self.assertIn('"Decorated", "N"', readiness_source)
        self.assertIn("parse_timeout_ms", readiness_source)
        self.assertIn("wait_for_rpcss(rpcss_timeout_ms)", readiness_source)
        for clsid in self.contract["runtime_compatibility"]["required_com_classes"]:
            self.assertIn(clsid.lower(), readiness_source.lower())
        self.assertIn('wineserver64" -k', self.canary)
        self.assertIn('wineserver64" -w', self.canary)
        for hive in ("system.reg", "user.reg", "userdef.reg"):
            self.assertIn(f'${{WINEPREFIX}}/{hive}', self.canary)
        self.assertIn('dosdevices/c:', self.canary)
        self.assertIn('dosdevices/z:', self.canary)
        self.assertIn(
            self.contract["entrypoint"]["success_sentinel"], self.canary
        )
        self.assertIn('rm -rf "${canary_root}"', self.canary)
        self.assertNotIn("sudo ", self.canary)
        self.assertNotIn("update-binfmts", self.canary)

    def test_wine_launcher_is_explicit_and_bootstraps_guest_dependencies(self):
        self.assertIn(
            'exec FEX "${rootfs}/usr/lib/wine/wine"', self.wine_launcher
        )
        self.assertIn("WINELOADER", self.wine_launcher)
        self.assertIn("WINESERVER", self.wine_launcher)
        self.assertIn("WINEDLLPATH", self.wine_launcher)
        self.assertIn("zlib1.dll", self.wine_launcher)
        self.assertIn("libgcc_s_dw2-1.dll", self.wine_launcher)
        self.assertIn("mullemeck*.exe|native-observer-launcher.exe", self.wine_launcher)
        self.assertIn("native-scene-debugger.exe", self.wine_launcher)
        self.assertIn("export FEX_SMCCHECKS=full", self.wine_launcher)
        self.assertIn("export FEX_SMCCHECKS=mtrack", self.wine_launcher)
        self.assertNotIn("FEX_SMCChecks", self.wine_launcher)
        self.assertIn(
            '${WINEPREFIX:?WINEPREFIX is required}', self.wine_launcher
        )
        self.assertNotIn("FEXBash", self.wine_launcher)


if __name__ == "__main__":
    unittest.main()
