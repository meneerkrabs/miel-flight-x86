import os
import fcntl
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.miel_vliegt.fex_wine import native_runner


class FexNativeRunnerTests(unittest.TestCase):
    LAUNCHER_IDENTITY = {
        "original_executable_sha256": "1" * 64,
        "patched_executable_sha256": "1" * 64,
        "observer_dll_sha256": "2" * 64,
        "real_dinput_sha256": "3" * 64,
    }

    def identity(self, **overrides):
        values = {
            "backend": {"id": "fex", "hodll": "libwow64fex.dll"},
            "container_image": "miel-flight-fex-wine:test",
            "container_image_sha256": "1" * 64,
            "smoke_sha256": "2" * 64,
            "hodll_sha256": "3" * 64,
            "bootstrap_contract_sha256": "4" * 64,
            "startup_contract_sha256": "5" * 64,
            "expected_uid": 1000,
            "expected_gid": 1000,
            "fex_contract": {
                "wine": {"version": "9", "snapshot": "snapshot"},
                "fex": {
                    "release": "release",
                    "package_version": "version",
                    "package_sha256": "6" * 64,
                },
                "rootfs": {"sha256": "7" * 64},
            },
        }
        values.update(overrides)
        return native_runner.contract_identity(**values)

    @staticmethod
    def write_proxy_timeout_receipt(root: Path, **overrides):
        start_receipt = root / "native-unmodified-start-fex.json"
        start_receipt.write_text("{}", encoding="ascii")
        checks = {
            "created_suspended": True,
            "loader_initialization_completed": True,
            "proxy_observer_ready": True,
            "observer_loaded": True,
            "observer_initialized": True,
            "login_pending_observed": False,
            "ready_before_login_pending": False,
            "login_activation_observed": False,
            "ready_before_login_activation": False,
            "main_thread_resumed": True,
            "main_thread_resume_count": 1,
            "message_loop_wake_posted": False,
            "projector_input_idle": False,
            "scenario_completion_event": False,
            "observer_failure_event_clear": False,
            "native_dispatch_requested": False,
            "native_dispatch_completion_event": False,
            "observation_window_completed": False,
            "target_terminated": True,
        }
        receipt = {
            "schema": 1,
            "protocol": "miel-vliegt-native-observer-launch",
            "status": "FAIL",
            "phase": "proxy",
            "detail": "proxy-bootstrap-timeout",
            "bootstrap_strategy":
                "dinput-post-loader-worker-or-call-bootstrap",
            "input_idle_probe_timeout_ms": 0,
            "proxy_bootstrap_timeout_ms": 600_000,
            "scene": "flight",
            "original_executable_sha256": "1" * 64,
            "patched_executable_sha256": "1" * 64,
            "observer_dll_sha256": "2" * 64,
            "real_dinput_sha256": "3" * 64,
            "patch_receipt_sha256": native_runner.sha256_file(start_receipt),
            "capture_process": None,
            "checks": checks,
        }
        receipt.update(overrides)
        (root / "native-observer-launch-fex.json").write_text(
            json.dumps(receipt), encoding="utf-8",
        )

    @classmethod
    def write_scenario_timeout_receipt(cls, root: Path, **overrides):
        cls.write_proxy_timeout_receipt(root)
        path = root / "native-observer-launch-fex.json"
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt.update({
            "phase": "scenario",
            "detail": "scenario-completion-timeout",
        })
        receipt["checks"].update({
            "login_pending_observed": True,
            "ready_before_login_pending": True,
            "login_activation_observed": True,
            "ready_before_login_activation": True,
            "message_loop_wake_posted": True,
            "projector_input_idle": True,
        })
        receipt.update(overrides)
        path.write_text(json.dumps(receipt), encoding="utf-8")

    @staticmethod
    def inactive_observer_records():
        loaded = {
            "schema": 1,
            "protocol": "miel-vliegt-native-observer-hook",
            "status": "LOADED",
            "thread_id": 300,
        }
        profile = {
            "schema": 1,
            "protocol": "miel-vliegt-native-observation-profile",
            "sequence": 0,
            "profile": "scenario-bounded",
            "profile_id": "production-semantic-v1",
            "profile_sha256": "1" * 64,
            "contract_sha256": "2" * 64,
            "omit_mask": "0x1fff",
            "target_hook_mask": "0x00000000",
            "omitted_channels": [],
            "retained_channels": [],
            "applicable_receipt_channels": [],
            "omitted_receipt_channels": [],
            "framebuffer_required": False,
            "evidence_eligible": True,
            "evidence_blocker": None,
            "signature_preflight_complete": True,
            "profile_state_writes": False,
            "thread_id": 300,
        }
        bootstrap = {
            "schema": 1,
            "protocol": "miel-vliegt-native-bootstrap",
            "application": False,
            "controls": False,
            "dispatcher": False,
            "audio": False,
            "archive": False,
            "video": False,
            "presentation": False,
            "manager": False,
            "manager_alias": False,
            "current_mode": False,
            "current_is_login": False,
            "current_is_flight": False,
            "current_name": "unresolved",
            "current_is_mygghanget": False,
            "mygghanget_flight_start": 0,
            "location_state": 0xFFFFFFFF,
            "location_manager_alias": False,
            "start_engine_faster_sample": 255,
            "start_engine_throttle_f32_bits": "0xffffffff",
            "start_engine_timer_f32_bits": "0xffffffff",
            "start_engine_latched": 255,
            "start_engine_audio_owner": 0xFFFFFFFF,
            "start_engine_audio_take": 0xFFFFFFFF,
            "start_engine_global_phase": 0xFFFFFFFF,
            "location_camera": False,
            "location_physics_alias": False,
            "location_shared_flight_alias": False,
            "flight_loaded": 0,
            "flight_opened": 0,
            "login_aliases": False,
            "user_id": -999,
            "pending_mode": False,
            "native_preroll_state": 255,
            "native_preroll_pending": False,
            "barn_view": 0xFFFFFFFF,
            "airplane_complete": -1,
            "mode_count": 0,
            "current_loaded": 0,
            "current_opened": 0,
            "manager_ticks": 0,
        }
        return loaded, profile, bootstrap

    @staticmethod
    def write_observer_records(root: Path, *records):
        (root / "native-observer-fex.log").write_text(
            "\n".join(
                f"{prefix} {json.dumps(record, separators=(',', ':'))}"
                for prefix, record in records
            ) + "\n",
            encoding="utf-8",
        )

    def classify_startup(self, error, root):
        return native_runner.classify_pre_scenario_startup_hang(
            error, root, self.LAUNCHER_IDENTITY,
        )

    def test_identity_binds_hodll_startup_and_unix_identity(self):
        baseline = self.identity()
        self.assertNotEqual(
            baseline["sha256"], self.identity(hodll_sha256="8" * 64)["sha256"]
        )
        self.assertNotEqual(
            baseline["sha256"],
            self.identity(startup_contract_sha256="9" * 64)["sha256"],
        )
        self.assertNotEqual(
            baseline["sha256"], self.identity(expected_gid=1001)["sha256"]
        )

    def test_pair_bootstraps_independent_slots_and_preserves_wine_z_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = []

            def bootstrap(prefix):
                calls.append(prefix)
                (prefix / "dosdevices").mkdir(parents=True)
                (prefix / "system.reg").write_text(
                    f"slot={len(calls)}", encoding="ascii"
                )
                (prefix / "dosdevices/z:").symlink_to("/")
                return {"usable": True}

            identity = self.identity()
            pair = native_runner.ensure_sealed_pair(root / "store", identity, bootstrap)
            self.assertEqual(len(calls), 2)
            self.assertNotEqual(calls[0], calls[1])
            for slot in native_runner.SLOTS:
                template = Path(pair["root"]) / slot / "template"
                receipt = native_runner.verify_seal(
                    template, identity["sha256"], slot
                )
                self.assertEqual(
                    native_runner.seal_receipt_path(template),
                    Path(pair["root"]) / slot / "seal.json",
                )
                self.assertEqual(
                    receipt["symlink_policy"], "preserve-link-never-follow"
                )
                self.assertTrue((template / "dosdevices/z:").is_symlink())
                self.assertEqual(os.readlink(template / "dosdevices/z:"), "/")

            clone = root / "clone"
            native_runner.clone_sealed_prefix(pair, "A", clone)
            self.assertTrue((clone / "dosdevices/z:").is_symlink())
            self.assertEqual(os.readlink(clone / "dosdevices/z:"), "/")

    def test_seal_verification_fails_after_template_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def bootstrap(prefix):
                prefix.mkdir()
                (prefix / "system.reg").write_text("sealed", encoding="ascii")
                return {"usable": True}

            identity = self.identity()
            pair = native_runner.ensure_sealed_pair(root / "store", identity, bootstrap)
            template = Path(pair["root"]) / "A" / "template"
            system_reg = template / "system.reg"
            system_reg.chmod(0o600)
            system_reg.write_text("tampered", encoding="ascii")
            with self.assertRaisesRegex(native_runner.NativeRunnerError, "content drifted"):
                native_runner.verify_seal(template, identity["sha256"], "A")

    def test_failed_clone_never_exposes_a_partial_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def bootstrap(prefix):
                prefix.mkdir()
                (prefix / "system.reg").write_text("sealed", encoding="ascii")
                return {"usable": True}

            identity = self.identity()
            pair = native_runner.ensure_sealed_pair(root / "store", identity, bootstrap)
            destination = root / "tmpfs" / "prefix"
            with patch.object(
                native_runner, "_make_writable",
                side_effect=RuntimeError("permission transition failed"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "permission transition failed"
                ):
                    native_runner.clone_sealed_prefix(pair, "A", destination)
            self.assertFalse(destination.exists())
            self.assertFalse(any(destination.parent.glob(".prefix.clone-*")))

    def test_atomic_copyout_fsyncs_and_leaves_no_partial_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "receipt.json").write_text("{}", encoding="ascii")
            destination = root / "published" / "evidence"
            with patch.object(
                native_runner.os, "fsync", wraps=os.fsync,
            ) as fsync:
                receipt = native_runner.atomic_copyout_tree(source, destination)
            self.assertGreaterEqual(fsync.call_count, 3)
            self.assertEqual(
                receipt["destination_sha256"],
                native_runner.tree_sha256(destination),
            )
            self.assertFalse(any(destination.parent.glob(".evidence.copyout-*")))

    def test_tmpfs_guard_rejects_swap_and_accepts_exact_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            aggregate = 2 * 1024**3
            statvfs = SimpleNamespace(
                f_bavail=aggregate // 4096,
                f_blocks=aggregate // 4096,
                f_frsize=4096,
            )
            with patch.object(native_runner, "filesystem_type", return_value="tmpfs"), \
                 patch.object(
                     native_runner, "memory_status",
                     return_value={
                         "MemAvailable": aggregate + 8 * 1024**3,
                         "SwapTotal": 0,
                     },
                 ), patch.object(native_runner.os, "statvfs", return_value=statvfs):
                receipt = native_runner.validate_tmpfs_staging(
                    root, bytes_per_job=1024**3, max_jobs=2
                )
            self.assertEqual(receipt["aggregate_bytes"], aggregate)
            with patch.object(native_runner, "filesystem_type", return_value="tmpfs"), \
                 patch.object(
                     native_runner, "memory_status",
                     return_value={
                         "MemAvailable": aggregate + 8 * 1024**3,
                         "SwapTotal": 4096,
                     },
                 ):
                with self.assertRaisesRegex(
                    native_runner.NativeRunnerError, "no-swap"
                ):
                    native_runner.validate_tmpfs_staging(
                        root, bytes_per_job=1024**3, max_jobs=2
                    )

    def test_retry_classifier_excludes_semantic_and_focus_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            indeterminate = self.classify_startup(
                TimeoutError("observer timed out"), root,
            )
            self.assertFalse(indeterminate["retryable"])
            self.assertEqual(
                indeterminate["classification"],
                "host-deadline-before-launcher-receipt",
            )
            self.write_proxy_timeout_receipt(root)
            retryable = self.classify_startup(
                TimeoutError("observer timed out"), root,
            )
            self.assertTrue(retryable["retryable"])
            receipt_path = root / "native-observer-launch-fex.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["checks"]["main_thread_resume_count"] = True
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            tampered = self.classify_startup(
                TimeoutError("observer timed out"), root,
            )
            self.assertFalse(tampered["retryable"])
            self.assertEqual(
                tampered["launcher"]["blocking_reason"],
                "unproven-launcher-terminal-phase",
            )
            self.write_proxy_timeout_receipt(root)
            (root / "native-observer-fex.log").write_text(
                "new-protocol-evidence-with-no-known-marker\n", encoding="utf-8"
            )
            semantic = self.classify_startup(
                TimeoutError("observer timed out"), root,
            )
            self.assertFalse(semantic["retryable"])
            self.assertEqual(semantic["classification"], "non-retryable")

    def test_retry_classifier_binds_launcher_and_start_receipt_identity(self):
        mutations = {
            "original_executable_sha256": "f" * 64,
            "patched_executable_sha256": "f" * 64,
            "observer_dll_sha256": "f" * 64,
            "real_dinput_sha256": "f" * 64,
            "patch_receipt_sha256": "f" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_proxy_timeout_receipt(root, **{field: value})
                classified = self.classify_startup(
                    TimeoutError("observer timed out"), root,
                )
                self.assertFalse(classified["retryable"])
                self.assertEqual(
                    classified["launcher"]["blocking_reason"],
                    "unproven-launcher-terminal-phase",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_proxy_timeout_receipt(root)
            (root / "native-unmodified-start-fex.json").unlink()
            classified = self.classify_startup(
                TimeoutError("observer timed out"), root,
            )
            self.assertFalse(classified["retryable"])
            self.assertEqual(
                classified["launcher"]["blocking_reason"],
                "missing-start-receipt",
            )

    def test_retry_classifier_accepts_only_proven_inactive_bootstrap_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observer = root / "native-observer-fex.log"
            loaded, profile, bootstrap = self.inactive_observer_records()

            def write_records(*records):
                self.write_observer_records(root, *records)

            write_records(
                ("MVO", loaded), ("MVD", profile), ("MVD", bootstrap),
            )
            without_receipt = (
                self.classify_startup(
                    TimeoutError("did not bootstrap cleanly"), root,
                )
            )
            self.assertFalse(without_receipt["retryable"])
            self.assertEqual(
                without_receipt["classification"],
                "host-deadline-before-launcher-receipt",
            )
            self.write_proxy_timeout_receipt(root)
            classified = self.classify_startup(
                TimeoutError("did not bootstrap cleanly"), root,
            )
            self.assertTrue(classified["retryable"])
            self.assertFalse(classified["semantic_or_focus_started"])
            self.assertEqual(classified["observer_record_count"], 3)
            self.assertEqual(classified["pre_scenario_record_count"], 3)
            self.assertEqual(classified["blocking_records"], [])

            dispatched_bootstrap = {**bootstrap, "current_mode": True}
            write_records(
                ("MVO", loaded), ("MVD", profile),
                ("MVD", dispatched_bootstrap),
            )
            dispatched = self.classify_startup(
                TimeoutError("did not bootstrap cleanly"), root,
            )
            self.assertFalse(dispatched["retryable"])
            self.assertTrue(dispatched["semantic_or_focus_started"])
            self.assertEqual(len(dispatched["blocking_records"]), 1)

            state_writing_profile = {**profile, "profile_state_writes": True}
            write_records(
                ("MVO", loaded), ("MVD", state_writing_profile),
                ("MVD", bootstrap),
            )
            state_writing = self.classify_startup(
                TimeoutError("did not bootstrap cleanly"), root,
            )
            self.assertFalse(state_writing["retryable"])

            write_records(
                ("MVD", profile), ("MVO", loaded), ("MVD", bootstrap),
            )
            out_of_order = self.classify_startup(
                TimeoutError("did not bootstrap cleanly"), root,
            )
            self.assertFalse(out_of_order["retryable"])

            observer.write_bytes(b"MVO \xff\n")
            invalid_utf8 = self.classify_startup(
                TimeoutError("did not bootstrap cleanly"), root,
            )
            self.assertFalse(invalid_utf8["retryable"])

    def test_retry_classifier_accepts_only_exact_inactive_scenario_timeout(self):
        def classify(root: Path):
            return self.classify_startup(
                TimeoutError("did not bootstrap cleanly"), root,
            )

        def prepare(root: Path):
            loaded, profile, bootstrap = self.inactive_observer_records()
            self.write_observer_records(
                root, ("MVO", loaded), ("MVD", profile), ("MVD", bootstrap),
            )
            self.write_scenario_timeout_receipt(root)
            return loaded, profile, bootstrap

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepare(root)
            classified = classify(root)
            self.assertTrue(classified["retryable"])
            self.assertEqual(
                classified["launcher"]["terminal_timeout_kind"],
                "scenario-completion-timeout",
            )

        launcher_mutations = {
            "status": ("status", "PASS"),
            "phase": ("phase", "cleanup"),
            "detail": ("detail", "observer-bootstrap-complete"),
            "identity": ("observer_dll_sha256", "f" * 64),
        }
        for name, (field, value) in launcher_mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                prepare(root)
                receipt_path = root / "native-observer-launch-fex.json"
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                receipt[field] = value
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                self.assertFalse(classify(root)["retryable"])

        check_mutations = {
            "scenario": ("scenario_completion_event", True),
            "native_dispatch_requested": ("native_dispatch_requested", True),
            "native_dispatch_completed":
                ("native_dispatch_completion_event", True),
            "observation": ("observation_window_completed", True),
            "target": ("target_terminated", False),
        }
        for name, (field, value) in check_mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                prepare(root)
                receipt_path = root / "native-observer-launch-fex.json"
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                receipt["checks"][field] = value
                receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                self.assertFalse(classify(root)["retryable"])

        observer_mutations = {
            "current_mode": lambda loaded, profile, bootstrap: (
                ("MVO", loaded), ("MVD", profile),
                ("MVD", {**bootstrap, "current_mode": True}),
            ),
            "semantic": lambda loaded, profile, bootstrap: (
                ("MVO", loaded), ("MVD", profile), ("MVD", bootstrap),
                ("MVT", {"schema": 1, "event": "semantic-dispatch"}),
            ),
            "focus": lambda loaded, profile, bootstrap: (
                ("MVO", loaded), ("MVD", profile), ("MVD", bootstrap),
                ("MVD", {"schema": 1, "protocol": "focus"}),
            ),
            "out_of_order": lambda loaded, profile, bootstrap: (
                ("MVD", profile), ("MVO", loaded), ("MVD", bootstrap),
            ),
            "missing_bootstrap": lambda loaded, profile, _bootstrap: (
                ("MVO", loaded), ("MVD", profile),
            ),
        }
        for name, mutation in observer_mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                loaded, profile, bootstrap = prepare(root)
                self.write_observer_records(
                    root, *mutation(loaded, profile, bootstrap),
                )
                self.assertFalse(classify(root)["retryable"])

    def test_managed_store_holds_shared_retention_lock_and_marks_inactive(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Path(temporary) / "sealed"
            identity = "a" * 64
            lease = native_runner.acquire_managed_store(
                store, identity,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            marker = store / native_runner.STORE_MARKER
            self.assertTrue(marker.is_file())
            activity = (
                store / identity / native_runner.IDENTITY_ACTIVITY
            ).read_text(encoding="ascii")
            self.assertIn('"state":"active"', activity)
            contender = (
                store / native_runner.STORE_RETENTION_LOCK
            ).open("r+b", buffering=0)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(
                        contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
            finally:
                contender.close()
            lease.close()
            activity = (
                store / identity / native_runner.IDENTITY_ACTIVITY
            ).read_text(encoding="ascii")
            self.assertIn('"state":"inactive"', activity)

    def test_managed_store_prunes_only_marked_expired_inactive_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = Path(temporary) / "sealed"
            old_identity = "b" * 64
            old = native_runner.acquire_managed_store(
                store, old_identity,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            old.close()
            native_runner._write_identity_activity(
                store, old_identity, "inactive", inactive_since_unix_ns=0,
            )
            unmarked = store / ("c" * 64)
            unmarked.mkdir()
            current = native_runner.acquire_managed_store(
                store, "d" * 64,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            try:
                self.assertFalse((store / old_identity).exists())
                self.assertTrue(unmarked.is_dir())
                self.assertEqual(
                    current.prune_receipt["removed_identities"], [old_identity]
                )
            finally:
                current.close()


if __name__ == "__main__":
    unittest.main()
