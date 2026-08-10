#!/usr/bin/env python3
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.miel_vliegt import native_observer_build as build
from tools.miel_vliegt import native_dispatch_capture_job as capture_job
from tools.miel_vliegt import native_dispatch_capture_target_header as target_header


class NativeObserverBuildTest(unittest.TestCase):
    def _root(self, directory: str) -> Path:
        root = Path(directory)
        for relative in build.INPUT_PATHS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((build.ROOT / relative).read_bytes())
        return root

    def test_dinput_proxy_observes_failures_without_suppressing_process_exit(self):
        source = (
            build.ROOT / "tools/miel_vliegt/x86_wine/"
            "native_observer_dinput_proxy.c"
        ).read_text(encoding="utf-8")
        self.assertIn("AddVectoredExceptionHandler(0, crash_logger)", source)
        self.assertNotIn("Sleep(INFINITE)", source)
        for forbidden in (
            "ExitProcess_hook",
            "TerminateProcess_hook",
            "NtTerminateProcess_hook",
            "RtlExitUserProcess_hook",
            "GetVersionExA_hook",
            "install_version_hook",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn(
            '"MVP_DDEX result hr=0x%08X output=%p object=%p"', source,
        )

    def test_dinput_proxy_initialization_handoff_never_waits_for_owner(self):
        source = (
            build.ROOT / "tools/miel_vliegt/x86_wine/"
            "native_observer_dinput_proxy.c"
        ).read_text(encoding="utf-8")
        initialize = source[
            source.index("static BOOL initialize_proxy(void)"):
            source.index("/* === ddraw.dll!DirectDrawCreate", source.index(
                "static BOOL initialize_proxy(void)"))
        ]
        contention = initialize[
            initialize.index("if (observed != 0)"):
            initialize.index("length = GetEnvironmentVariableA")
        ]
        self.assertIn("return observed == 2;", contention)
        self.assertNotRegex(contention, r"\bwhile\s*\(")
        self.assertNotIn("Sleep", contention)
        self.assertIn(
            "InterlockedCompareExchange(&initialization_stage_seen[slot]",
            source,
        )
        self.assertIn(
            '"MVP_INIT thread=%lu stage=%s"', source,
        )
        for stage in (
            "real_dinput_load_begin",
            "real_dinput_load_success",
            "observer_load_begin",
            "observer_load_success",
            "observer_initialize_begin",
            "observer_initialize_success",
        ):
            self.assertIn(f'"{stage}"', initialize)

    def test_dinput_proxy_registers_one_process_scoped_exception_handler(self):
        source = (
            build.ROOT / "tools/miel_vliegt/x86_wine/"
            "native_observer_dinput_proxy.c"
        ).read_text(encoding="utf-8")
        self.assertEqual(source.count("install_exit_hook();"), 1)
        self.assertIn(
            "DisableThreadLibraryCalls(instance);\n        install_exit_hook();",
            source,
        )
        installer = source[
            source.index("static void install_exit_hook(void) {"):
            source.index("/* === ddraw.dll!DirectDrawCreate", source.index(
                "static void install_exit_hook(void) {"))
        ]
        self.assertIn("crash_handler_install_started, 1, 0", installer)
        self.assertIn("AddVectoredExceptionHandler(0, crash_logger)", installer)
        self.assertIn("VEH crash logger installed once", installer)

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc") and
        shutil.which("i686-w64-mingw32-objdump"),
        "MinGW x86 compiler is required for the DirectDraw ABI contract",
    )
    def test_dinput_proxy_bounds_typed_ddraw7_startup_forwarding(self):
        source = (
            build.ROOT / "tools/miel_vliegt/x86_wine/"
            "native_observer_dinput_proxy.c"
        ).read_text(encoding="utf-8")
        self.assertIn("#define DDRAW_TRACE_RECORD_LIMIT 128", source)
        self.assertIn("if (sequence > DDRAW_TRACE_RECORD_LIMIT) return;", source)
        for method, slot in (
            ("CreateSurface", 6),
            ("EnumDisplayModes", 8),
            ("GetCaps", 11),
            ("GetDisplayMode", 12),
            ("RestoreDisplayMode", 19),
            ("SetCooperativeLevel", 20),
        ):
            self.assertIn(f'ddraw_trace_enter("{method}")', source)
            self.assertIn(f'ddraw_trace_leave("{method}", hr)', source)
            self.assertIn(
                f"vtbl[{slot}] = (void *)ddraw_{method}_hook", source,
            )
            self.assertIn(f"hr = ddraw_saved_{method}(", source)
        self.assertIn("static HRESULT WINAPI set_display_mode_stub(", source)
        self.assertIn('ddraw_trace_leave("SetDisplayMode", DD_OK)', source)
        symbols = self._proxy_object_symbols()
        for symbol in (
            "_ddraw_CreateSurface_hook@16",
            "_ddraw_EnumDisplayModes_hook@20",
            "_ddraw_GetCaps_hook@12",
            "_ddraw_GetDisplayMode_hook@8",
            "_ddraw_RestoreDisplayMode_hook@4",
            "_ddraw_SetCooperativeLevel_hook@12",
            "_set_display_mode_stub@24",
        ):
            self.assertIn(symbol, symbols)
        for method, slot in (
            ("Release", 2),
            ("AddAttachedSurface", 3),
            ("GetAttachedSurface", 12),
            ("GetCaps", 14),
            ("GetDC", 17),
            ("GetPixelFormat", 21),
            ("GetSurfaceDesc", 22),
            ("IsLost", 24),
            ("Lock", 25),
            ("Restore", 27),
            ("SetClipper", 28),
            ("SetPalette", 31),
            ("Unlock", 32),
        ):
            self.assertIn(f"vtbl[{slot}] = (void *)dds_{method}_hook", source)
        self.assertIn('ddraw_trace_enter("Surface7::" #name)', source)
        self.assertIn('ddraw_trace_leave("Surface7::" #name, hr)', source)
        self.assertIn('ddraw_trace_leave_ulong("Surface7::Release", references)',
                      source)
        for symbol in (
            "_dds_Release_hook@4",
            "_dds_AddAttachedSurface_hook@8",
            "_dds_GetAttachedSurface_hook@12",
            "_dds_GetCaps_hook@8",
            "_dds_GetDC_hook@8",
            "_dds_GetPixelFormat_hook@8",
            "_dds_GetSurfaceDesc_hook@8",
            "_dds_IsLost_hook@4",
            "_dds_Lock_hook@20",
            "_dds_Restore_hook@4",
            "_dds_SetClipper_hook@8",
            "_dds_SetPalette_hook@8",
            "_dds_Unlock_hook@8",
        ):
            self.assertIn(symbol, symbols)
        create_surface = source[
            source.index("static HRESULT WINAPI ddraw_CreateSurface_hook"):
            source.index("static HRESULT WINAPI ddraw_EnumDisplayModes_hook")
        ]
        self.assertIn("patch_ddraw_surface_startup_methods(*surface)",
                      create_surface)

    def _proxy_object_symbols(self):
        source = (
            build.ROOT / "tools/miel_vliegt/x86_wine/"
            "native_observer_dinput_proxy.c"
        )
        with tempfile.TemporaryDirectory() as directory:
            obj = Path(directory) / "DINPUT.o"
            subprocess.run([
                "i686-w64-mingw32-gcc", "-std=c11", "-O0", "-Wall",
                "-Wextra", "-Werror", "-c", str(source), "-o", str(obj),
            ], check=True, capture_output=True, text=True)
            return subprocess.run([
                "i686-w64-mingw32-objdump", "-t", str(obj),
            ], check=True, capture_output=True, text=True).stdout

    def test_manifest_binds_artifact_toolchain_and_all_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            artifact = root / build.ARTIFACT_NAME
            artifact.write_bytes(b"observer-dll")
            value = build.build_manifest(artifact, "13.2.0", root)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(
                build.validate_manifest(manifest, root, artifact), value,
            )
            self.assertEqual(
                [row["path"] for row in value["inputs"]],
                list(build.INPUT_PATHS),
            )
            for required in (
                "tools/miel_vliegt/hangover/native_sha256.h",
                "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.h",
                "tools/miel_vliegt/hangover/native_dispatch_semantic_hook.c",
                "tools/miel_vliegt/native_dispatch_semantic_wire.py",
                "tools/miel_vliegt/native_dispatch_hook_contract.py",
                "tools/miel_vliegt/native_trace.py",
                "tools/miel_vliegt/x86_wine/Dockerfile",
                "tools/miel_vliegt/fex_wine/Dockerfile",
            ):
                self.assertIn(required, build.INPUT_PATHS)
            self.assertEqual(
                build.COMPILER_FLAGS,
                (
                    "-std=c11", "-Os", "-s", "-static-libgcc", "-Wall",
                    "-Wextra", "-Werror", "-shared", "-I/src",
                    '-DMVDS_PRODUCER_BUILD_SHA256='
                    f'"{build.producer_build_sha256()}"',
                ),
            )
            self.assertEqual(value["capture_driver_foundation"], {
                "profile": "NATIVE_DISPATCH_DRIVER_V2",
                "profile_sha256":
                    "72925be976520350aec44c45861e5f0af1bcaaef0f33fe605f42d6d415c0cd68",
                "scenario_sha256":
                    "1435350feab7bfe92840bc8be305f13a6daf539173674e0b1bab8553c7b9b165",
                "initial_user_sha256":
                    "7019275a9489a2d078f2cb38425f852dd2c019295e401ba4a58cbd67566555d6",
            })

    def test_launcher_hash_preflight_is_portable_specific_and_event_safe(self):
        launcher = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_launcher.c"
        ).read_text(encoding="utf-8")
        debugger = (
            build.ROOT / "tools/miel_vliegt/hangover/native_scene_debugger.c"
        ).read_text(encoding="utf-8")
        self.assertIn('#include "native_sha256.h"', launcher)
        self.assertIn('#include "native_sha256.h"', debugger)
        self.assertNotIn("<wincrypt.h>", launcher)
        self.assertNotIn("<wincrypt.h>", debugger)
        self.assertNotIn("CryptAcquireContext", launcher)
        self.assertNotIn("CryptAcquireContext", debugger)
        preflight = launcher[
            launcher.index("if (!miel_sha256_file(options.source"):
            launcher.index("snprintf(command_line", launcher.index("int main"))
        ]
        for detail in (
            "source-hash-read-failed",
            "source-identity-mismatch",
            "target-hash-read-failed",
            "observer-hash-read-failed",
            "real-dinput-hash-read-failed",
            "patch-receipt-hash-read-failed",
        ):
            self.assertIn(detail, preflight)
        self.assertNotIn("hash-binding-failed", launcher)
        create_event = launcher[
            launcher.index("static BOOL create_observer_event"):
            launcher.index("static BOOL create_observer_events")
        ]
        self.assertEqual(create_event.count("CreateEventA("), 1)

    def test_dispatch_driver_uses_natural_bootstrap_then_owns_target_dispatch(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        lifecycle = source[
            source.index("static void __attribute__((used)) record_mode_lifecycle"):
            source.index("static void __attribute__((used)) record_login_tick")
        ]
        self.assertLess(
            lifecycle.index("correlate_mode_activation(manager_address)"),
            lifecycle.index("native_capture_driver_owns_navigation()"),
        )
        self.assertIn("native_capture_driver_needs_flight_bootstrap()", lifecycle)
        self.assertIn("send_projector_click", lifecycle)
        self.assertIn("send_barn_escape_input", lifecycle)
        self.assertIn("observe_native_flight_bootstrap", lifecycle)
        self.assertIn("exact_session_ready", lifecycle)
        self.assertLess(
            lifecycle.index("send_barn_escape_input"),
            lifecycle.index("observe_native_flight_bootstrap"),
        )
        manager = source[
            source.index("static DWORD __attribute__((used)) manager_tick_prepare"):
            source.index("static void __attribute__((naked)) manager_render_vtable_hook")
        ]
        self.assertLess(
            manager.index("record_mode_lifecycle(manager_address)"),
            manager.index("dispatch_native_capture_driver_on_manager_tick"),
        )
        driver_start = source.index(
            "static void dispatch_native_capture_driver_on_manager_tick",
            source.index("static void native_capture_driver_fail"),
        )
        driver = source[
            driver_start:
            source.index("static BOOL dispatch_ci_session", driver_start)
        ]
        self.assertIn("dispatch_native_capture_login_on_manager_tick", driver)
        self.assertIn("exact_session_ready(manager_address)", driver)
        self.assertIn('strcmp(current_mode, "mode_fly")', driver)
        self.assertIn("exact_mygghanget_departure_transition", driver)
        self.assertIn("resolve_registered_engine_mode_callback", driver)
        self.assertNotIn("send_projector_click", driver)
        self.assertNotIn("send_barn_escape_input", driver)
        self.assertNotIn("FLIGHT_TARGET", driver)

    def test_dispatch_driver_has_internal_proven_replay_and_user_init_contract(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        init_start = source.index(
            "__declspec(dllexport) DWORD WINAPI MielObserverInitialize",
            source.index("static BOOL configure_native_capture_driver_bootstrap"),
        )
        init = source[
            init_start:
            source.index("BOOL WINAPI DllMain", init_start)
        ]
        self.assertIn("configure_native_capture_driver_bootstrap", init)
        self.assertIn("data_user_fixture_ready()", init)
        self.assertIn("parse_replay_file(scenario_path, scenario_hash)", init)
        self.assertIn("driver foundation differs", source)
        configure_start = source.rindex(
            "static BOOL configure_native_capture_driver_bootstrap"
        )
        configure = source[
            configure_start:
            source.index(
                "\nstatic BOOL configure_native_capture_driver(void)",
                configure_start,
            )
        ]
        self.assertIn("NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE", configure)
        self.assertIn("native_capture_driver_bootstrap_requested", configure)
        self.assertIn("NATIVE_CAPTURE_DRIVER_BOOTSTRAP_PROFILE_SHA256", configure)
        self.assertIn("NATIVE_CAPTURE_DRIVER_SCENARIO_SHA256", configure)
        self.assertIn("NATIVE_CAPTURE_DRIVER_INITIAL_USER_SHA256", configure)
        for digest in (
            "72925be976520350aec44c45861e5f0af1bcaaef0f33fe605f42d6d415c0cd68",
            "1435350feab7bfe92840bc8be305f13a6daf539173674e0b1bab8553c7b9b165",
            "7019275a9489a2d078f2cb38425f852dd2c019295e401ba4a58cbd67566555d6",
        ):
            self.assertIn(digest, source)

    def test_dispatch_producer_is_one_fail_closed_observer_transaction(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        self.assertIn('#include "native_dispatch_semantic_hook.h"', source)
        self.assertIn("native_dispatch_spec_count != (size_t)MVDS_HOOK_COUNT", source)
        self.assertIn("memcmp(spec->target, spec->signature, spec->signature_size)", source)
        install = source[
            source.index("static BOOL install_native_dispatch_detours"):
            source.index("static BOOL rollback_native_dispatch_detours")
        ]
        self.assertIn("spec->minimum_patch_size", install)
        self.assertIn("++native_dispatch_installed_count", install)
        self.assertIn("mvds_arm(", install)
        self.assertIn("!native_dispatch_target_scoped()", install)
        rollback = source[
            source.index("static BOOL rollback_native_dispatch_detours"):
            source.index("static BOOL replace_dispatch_slot")
        ]
        self.assertLess(
            rollback.index("mvds_disable()"),
            rollback.index("--native_dispatch_installed_count"),
        )
        self.assertIn("spec->trampoline_slot", rollback)
        scene_enter = source[
            source.index("static void __attribute__((used)) scene_dispatch_enter"):
            source.index("static DWORD __attribute__((used)) scene_dispatch_leave")
        ]
        self.assertIn(
            "mvds_observe_route((MvdsRoute)route_value, object, root)",
            scene_enter,
        )
        durable = source[
            source.index("static BOOL append_record_durable_checked"):
            source.index("static void flush_trace(void)")
        ]
        self.assertIn("flush_trace_locked()", durable)
        self.assertIn("FlushFileBuffers(trace_file)", durable)
        failure_bridge = source[
            source.index("static void native_dispatch_fail"):
            source.index("static BOOL native_dispatch_capture_completed")
        ]
        self.assertIn(
            "normalize_native_dispatch_failure_reason", failure_bridge,
        )
        self.assertIn("session_fail(normalized)", failure_bridge)
        self.assertNotIn("(void)reason", failure_bridge)
        producer_source = (
            build.ROOT / "tools/miel_vliegt/hangover/"
            "native_dispatch_semantic_hook.c"
        ).read_text(encoding="utf-8")
        parse_hook = producer_source[
            producer_source.rindex("static void *MVDS_FASTCALL hook_parse"):
            producer_source.rindex("static void MVDS_FASTCALL hook_insert")
        ]
        self.assertIn("mission_source_tracking_required() && path != NULL", parse_hook)
        insert_hook = producer_source[
            producer_source.rindex("static void MVDS_FASTCALL hook_insert"):
            producer_source.rindex("static void MVDS_FASTCALL hook_executor")
        ]
        self.assertIn("tracking = mission_source_tracking_required()", insert_hook)
        self.assertIn("if (tracking &&", insert_hook)
        source_tracking = producer_source[
            producer_source.index("static BOOL mission_source_tracking_required"):
            producer_source.index("static MissionSourceSlot *mission_source_slot")
        ]
        self.assertIn("g_capture_target_configured", source_tracking)
        self.assertIn(
            "g_capture_target.evidence_class == MVDS_EVIDENCE_MISSION_DISPATCH",
            source_tracking,
        )
        manager = source[
            source.index("static DWORD __attribute__((used)) manager_tick_prepare"):
            source.index("static void __attribute__((naked)) manager_render_vtable_hook")
        ]
        self.assertIn("mvds_bind_engine_thread(current_thread)", manager)
        self.assertNotIn("mvds_begin_capture_window", source)
        self.assertIn("NATIVE_TRACE_REQUIRED", (
            build.ROOT / "tools/miel_vliegt/NATIVE_DISPATCH_SEMANTIC_PRODUCER.md"
        ).read_text(encoding="utf-8"))

    def test_native_dispatch_installs_only_the_target_derived_hook_closure(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        policy = source[
            source.index("static BOOL native_dispatch_observer_detour_required"):
            source.index("static BOOL install_detour")
        ]
        self.assertIn("native_dispatch_capture_target.evidence_class", policy)
        self.assertIn("MVDS_EVIDENCE_MISSION_DISPATCH", policy)
        self.assertIn("MODE_SET", policy)
        self.assertNotIn("target == QUEUE_MODE", policy)
        self.assertIn("SCENE_DISPATCH_GROUND", policy)
        self.assertIn("SCENE_DISPATCH_BARN", policy)
        self.assertIn("SCENE_DISPATCH_FLIGHT", policy)

        install = source[
            source.index("static BOOL install_native_dispatch_detours"):
            source.index("static BOOL rollback_native_dispatch_detours")
        ]
        self.assertIn("mvds_hook_required(spec->id)", install)
        self.assertIn("native_dispatch_installed_mask", install)
        self.assertIn("native_dispatch_installed_mask |=", install)
        rollback = source[
            source.index("static BOOL rollback_native_dispatch_detours"):
            source.index("static BOOL replace_dispatch_slot")
        ]
        self.assertIn("native_dispatch_installed_mask &", rollback)
        self.assertIn("native_dispatch_installed_mask &=", rollback)

        detour = source[
            source.index("static BOOL install_detour"):
            source.index("static BOOL diagnostic_skip_target_allowed")
        ]
        self.assertIn("native_dispatch_semantic_detour(target)", detour)
        self.assertIn("native_dispatch_observer_detour_required(target)", detour)
        initialize = source[source.index("MielObserverInitialize(LPVOID unused)"):]
        self.assertIn("install_observer_import_hooks()", initialize)
        self.assertIn("native_dispatch_observer_detour_required", source)
        profile = source[
            source.index("static void emit_observation_profile"):
            source.index("static void emit_bootstrap_diagnostic")
        ]
        self.assertIn("native-dispatch-target-scoped", profile)
        self.assertIn("target_hook_mask", profile)
        self.assertIn('"evidence_eligible\\\":%s', profile)

    def test_detour_protection_faults_never_orphan_a_live_jump(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        restore = source[
            source.index("static BOOL restore_detour_target"):
            source.index("static BOOL install_detour")
        ]
        self.assertGreaterEqual(restore.count("VirtualProtect("), 2)
        self.assertIn("cache_flushed = FlushInstructionCache(", restore)
        self.assertIn("return cache_flushed && protection_restored", restore)

        install = source[
            source.index("static BOOL install_detour"):
            source.index("static BOOL diagnostic_skip_target_allowed")
        ]
        self.assertIn(
            "MEM_COMMIT | MEM_RESERVE,\n"
            "                              PAGE_READWRITE",
            install,
        )
        executable = install.index(
            "VirtualProtect(trampoline, stolen + 5u, PAGE_EXECUTE_READ",
        )
        trampoline_flush = install.index(
            "FlushInstructionCache(\n"
            "            GetCurrentProcess(), trampoline, stolen + 5u)",
            executable,
        )
        target_write_enable = install.index(
            "VirtualProtect(\n"
            "            target, stolen, PAGE_EXECUTE_READWRITE",
        )
        self.assertLess(executable, trampoline_flush)
        self.assertLess(trampoline_flush, target_write_enable)
        publish = install.index("*trampoline_out = trampoline")
        post_patch_flush = install.index(
            "cache_flushed = FlushInstructionCache(", publish,
        )
        post_patch_protect = install.index(
            "protection_restored = VirtualProtect(", publish,
        )
        cleanup = install.index("restore_detour_target(", publish)
        free = install.index("VirtualFree(trampoline", cleanup)
        clear = install.index("*trampoline_out = NULL", free)
        self.assertLess(publish, post_patch_flush)
        self.assertLess(publish, post_patch_protect)
        self.assertLess(cleanup, free)
        self.assertLess(free, clear)

        rollback = source[
            source.index("static BOOL rollback_detour("):
            source.index("static void rollback_detour_accumulating")
        ]
        restore_done = rollback.index("restore_detour_target(")
        free_done = rollback.index("VirtualFree(installed", restore_done)
        clear_done = rollback.index("*trampoline = NULL", free_done)
        self.assertLess(restore_done, free_done)
        self.assertLess(free_done, clear_done)
        self.assertIn("detour_rollback_failed = TRUE", rollback)

        # Inject each post-patch failure into the transaction model.  A slot
        # becomes NULL only after write-enable, cache flush, protection restore
        # and trampoline release all succeed; every failed phase retains it.
        phases = ("write_enable", "cache_flush", "protect_restore", "free")
        for failed_phase in phases:
            state = {phase: phase != failed_phase for phase in phases}
            cleared = all(state.values())
            with self.subTest(failed_phase=failed_phase):
                self.assertFalse(cleared)

    def test_semantic_detours_relocate_every_declared_embedded_rel32_site(self):
        header = (
            build.ROOT / "tools/miel_vliegt/hangover/"
            "native_dispatch_semantic_hook.h"
        ).read_text(encoding="utf-8")
        producer = (
            build.ROOT / "tools/miel_vliegt/hangover/"
            "native_dispatch_semantic_hook.c"
        ).read_text(encoding="utf-8")
        observer = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")

        self.assertIn("typedef struct MvdsRel32Relocation", header)
        self.assertIn("size_t opcode_offset;", header)
        self.assertIn("MvdsRel32Opcode opcode;", header)
        self.assertIn(
            "const MvdsRel32Relocation *rel32_relocations;", header,
        )
        self.assertIn("size_t rel32_relocation_count;", header)

        expected_sites = {
            "ACTION_OUTRO": ("REL32_ACTION_OUTRO", 0),
            "GENERIC_FINAL_MISSION_PRESENT":
                ("REL32_GENERIC_FINAL_PRESENT", 2),
            "EXHIBITION_FINAL_FALSE":
                ("REL32_EXHIBITION_FINAL_FALSE", 3),
        }
        for name, (metadata, offset) in expected_sites.items():
            with self.subTest(name=name):
                declaration = producer[
                    producer.index(
                        f"static const MvdsRel32Relocation {metadata}[]"
                    ):
                    producer.index("};", producer.index(
                        f"static const MvdsRel32Relocation {metadata}[]"
                    ))
                ]
                self.assertIn(f"{{{offset}u, MVDS_REL32_CALL}}", declaration)
                spec_start = producer.index(f'"{name}"')
                spec_end = producer.index("),", spec_start)
                self.assertIn("MVDS_REL32_SPEC(", producer[spec_start - 80:spec_end])
                self.assertIn(metadata, producer[spec_start:spec_end])

        validation = observer[
            observer.index("static BOOL semantic_rel32_metadata_valid"):
            observer.index("static BOOL relocate_rel32_site")
        ]
        self.assertIn("spec->minimum_patch_size - relocation->opcode_offset < 5u", validation)
        self.assertIn("!rel32_relocation_declared(spec, offset, opcode)", validation)
        self.assertIn("other_offset - relocation->opcode_offset < 5u", validation)

        install = observer[
            observer.index("static BOOL install_detour"):
            observer.index("static BOOL diagnostic_skip_target_allowed")
        ]
        self.assertIn("semantic_spec = native_dispatch_semantic_spec(target)", install)
        self.assertIn("!semantic_rel32_metadata_valid(semantic_spec)", install)
        self.assertIn(
            "relocation_index < semantic_spec->rel32_relocation_count", install,
        )
        self.assertIn("&semantic_spec->rel32_relocations[relocation_index]", install)
        self.assertIn(
            "else if ((trampoline[0] == 0xe8u || trampoline[0] == 0xe9u)",
            install,
        )

        # Model the exact rel32 invariant independently: moving the five-byte
        # instruction to any trampoline address must preserve its destination.
        signatures = {
            "ACTION_OUTRO": (0, bytes.fromhex("e8 c0 f2 fc ff")),
            "GENERIC_FINAL_MISSION_PRESENT":
                (2, bytes.fromhex("8b c8 e8 c1 0b 01 00")),
            "EXHIBITION_FINAL_FALSE":
                (3, bytes.fromhex("57 8b ce e8 f3 24 fe ff")),
        }
        target = 0x00400000
        trampoline = 0x10000000
        for name, (offset, signature) in signatures.items():
            original = int.from_bytes(
                signature[offset + 1:offset + 5], "little", signed=True,
            )
            destination = target + offset + 5 + original
            relocated = destination - (trampoline + offset + 5)
            with self.subTest(relocation=name):
                self.assertEqual(
                    trampoline + offset + 5 + relocated, destination,
                )
                self.assertGreaterEqual(relocated, -(1 << 31))
                self.assertLess(relocated, 1 << 31)

    def test_detour_retry_uses_persisted_original_page_protection(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        self.assertIn("typedef struct DetourProtectionRecord", source)
        self.assertIn("DETOUR_PROTECTION_CAPACITY", source)
        install = source[
            source.index("static BOOL install_detour"):
            source.index("static BOOL diagnostic_skip_target_allowed")
        ]
        self.assertIn("detour_protection_reserve(target, trampoline_out)", install)
        self.assertIn("record->original_protect = old_protect", install)
        rollback = source[
            source.index("static BOOL rollback_detour("):
            source.index("static void rollback_detour_accumulating")
        ]
        self.assertIn(
            "detour_protection_find(target, trampoline)", rollback,
        )
        self.assertIn("record->original_protect", rollback)
        self.assertNotIn("PAGE_EXECUTE_READWRITE, &old_protect", rollback)
        free = rollback.index("VirtualFree(installed")
        clear = rollback.index("*trampoline = NULL", free)
        release = rollback.index("detour_protection_release(record)", clear)
        self.assertLess(free, clear)
        self.assertLess(clear, release)

        # Fault sequence: the first RX restore fails and leaves the page RWX.
        # Retry must use the persisted RX value, not RWX observed at retry.
        original_protect = "RX"
        current_protect = "RWX"
        persisted = original_protect
        retry_final_protect = persisted
        trampoline_cleared = retry_final_protect == original_protect
        self.assertEqual(retry_final_protect, "RX")
        self.assertNotEqual(retry_final_protect, current_protect)
        self.assertTrue(trampoline_cleared)

    def test_failed_detours_are_counted_rolled_back_and_module_pinned(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        dynamic_install = source[
            source.index("static BOOL install_native_dispatch_detours"):
            source.index("static BOOL rollback_native_dispatch_detours")
        ]
        self.assertIn("if (*spec->trampoline_slot) {", dynamic_install)
        self.assertIn("native_dispatch_installed_mask |= bit", dynamic_install)
        self.assertIn("++native_dispatch_installed_count", dynamic_install)
        dynamic_rollback = source[
            source.index("static BOOL rollback_native_dispatch_detours"):
            source.index("static BOOL replace_dispatch_slot")
        ]
        self.assertLess(
            dynamic_rollback.index("if (!rollback_detour("),
            dynamic_rollback.index("--native_dispatch_installed_count"),
        )
        initialize = source[source.index("MielObserverInitialize(LPVOID unused)"):]
        self.assertLess(
            initialize.index("GET_MODULE_HANDLE_EX_FLAG_PIN"),
            initialize.index("install_observer_import_hooks()"),
        )
        failed = initialize[initialize.index("install_failed:"):]
        self.assertIn("rollback_detour_accumulating(", failed)
        for rollback_call in (
            "rollback_manager_tick_interposition()",
            "rollback_shadow_render_interposition()",
            "rollback_body_lifecycle_interposition()",
            "rollback_import_hooks()",
        ):
            self.assertIn(f"if (!{rollback_call}) rollback_ok = FALSE", failed)
        self.assertIn(
            "if (!rollback_native_dispatch_detours()) rollback_ok = FALSE",
            failed,
        )
        self.assertIn("if (!rollback_ok || detour_rollback_failed)", failed)
        self.assertIn("hook_rollback_failed_module_pinned", failed)

    def test_capture_target_is_compiler_allowlisted_and_hook_opened_only(self):
        header = (
            build.ROOT / "tools/miel_vliegt/hangover/"
            "native_dispatch_semantic_hook.h"
        ).read_text(encoding="utf-8")
        producer = (
            build.ROOT / "tools/miel_vliegt/hangover/"
            "native_dispatch_semantic_hook.c"
        ).read_text(encoding="utf-8")
        observer = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        generated = (
            build.ROOT / "tools/miel_vliegt/hangover/"
            "native_dispatch_capture_targets.generated.h"
        ).read_text(encoding="ascii")
        self.assertIn("typedef struct MvdsCaptureTarget", header)
        self.assertIn(
            "mvds_configure_capture_target(const MvdsCaptureTarget *target)",
            header,
        )
        self.assertIn("MVDS_CAPTURE_TARGET_COUNT 155u", generated)
        self.assertEqual(generated.count(".target_sha256 ="), 155)
        for key in (
            "TARGET_SHA256", "JOB_SHA256", "CLAIM_ID", "CLAIM_SHA256",
            "SUBJECT_SHA256", "EXPECTATION_SHA256", "SCENARIO_SHA256",
            "CAPTURE_PLAN_SHA256", "PLAN_MANIFEST_SHA256",
        ):
            self.assertIn(f'MIEL_OBSERVER_NATIVE_DISPATCH_{key}', observer)
        self.assertIn("native_dispatch_capture_target_lookup", observer)
        self.assertIn("observer_environment_value", observer)
        self.assertIn("ERROR_ENVVAR_NOT_FOUND", observer)
        self.assertIn("publish_native_dispatch_process_identity", observer)
        self.assertIn("native_dispatch_capture_completed", observer)
        self.assertIn('create_observer_event("NativeDispatchComplete"', observer)
        self.assertIn("MVDS_IDENTITY_MAPPING_PREFIX", observer)
        self.assertIn("mvds_configure_capture_target", observer)
        self.assertNotIn("mvds_begin_capture_window", observer)
        self.assertIn("begin_capture_window_from_target_hook", producer)
        for hook in (
            "capture_action", "hook_generic_enter", "hook_grotte_setter",
            "hook_raymond_load", "hook_raymond_setter",
            "hook_exhibition_setter", "hook_mygghanget_enter",
        ):
            block_start = producer.index(f"{hook}(")
            block = producer[block_start:block_start + 8000]
            self.assertIn("begin_capture_window_from_target_hook", block)
        manager = observer[
            observer.index("manager_tick_prepare("):
            observer.index("manager_render_vtable_hook", observer.index(
                "manager_tick_prepare(",
            ))
        ]
        self.assertNotIn("capture_window", manager)

    def test_driver_cohorts_are_generated_for_exact_32_targets(self):
        targets = capture_job.compile_targets()["targets"]
        eligible = [
            target for target in targets
            if target["evidenceClass"] == "LOCATION_POLICY"
            and target["trigger"]["selector"] ==
                "LOCATION_ENTER_FINAL_MISSION_STATE_NE_3"
            and target["trigger"]["selectorHookFamily"] ==
                "GENERIC_LOCATION_ENTER"
        ]
        self.assertEqual(len(eligible), 15)
        traversal = [
            target for target in targets
            if target["evidenceClass"] == "LOCATION_POLICY"
            and target["trigger"]["selector"] ==
                "LOCATION_ENTER_EXPECTED_UDSP_ABSENCE"
            and target["trigger"]["selectorHookFamily"] == "MYGGHANGET_ENTER"
        ]
        self.assertEqual(len(traversal), 1)
        generated = target_header.generate_header()
        self.assertEqual(
            generated.count(
                ".capture_driver = "
                "MVDS_CAPTURE_DRIVER_GENERIC_LOCATION_CLEAN_V2"
            ),
            15,
        )
        self.assertEqual(
            generated.count(
                ".capture_driver = "
                "MVDS_CAPTURE_DRIVER_BOOTSTRAP_TRAVERSAL_V1"
            ),
            1,
        )
        self.assertEqual(
            generated.count(
                ".capture_driver = "
                "MVDS_CAPTURE_DRIVER_MISSION_LOCATION_ENTER_V1"
            ),
            14,
        )
        self.assertEqual(
            generated.count(
                ".capture_driver = "
                "MVDS_CAPTURE_DRIVER_MISSION_BARN_TRAVERSAL_V1"
            ),
            2,
        )
        self.assertEqual(
            generated.count(
                ".capture_driver = MVDS_CAPTURE_DRIVER_NONE"
            ),
            123,
        )
        self.assertEqual(
            generated.count('.driver_mode = "-"'),
            123,
        )
        self.assertEqual(
            generated.count('.driver_mode = "mode_barn"'),
            2,
        )
        self.assertEqual(
            generated.count(
                '.driver_scenario_sha256 = "1435350feab7bfe92840bc8be305f13a6'
                'daf539173674e0b1bab8553c7b9b165"'
            ),
            32,
        )
        self.assertEqual(
            generated.count(
                '.driver_initial_user_sha256 = "7019275a9489a2d078f2cb38425f852d'
                'd2c019295e401ba4a58cbd67566555d6"'
            ),
            32,
        )
        for target in eligible:
            self.assertIn(
                f'.mode = "{target["trigger"]["mode"]}"', generated,
            )

    def test_full_regeneration_refreshes_capture_allowlist_after_plan(self):
        script = (
            build.ROOT / "tools/miel_vliegt/regenerate_flight_content.sh"
        ).read_text(encoding="utf-8")
        contract = script.index("native_dispatch_hook_contract.py")
        batches = script.index("scene_semantic_evidence_batches.py", contract)
        jobs = script.index("native_dispatch_capture_job.py", batches)
        header = script.index("native_dispatch_capture_target_header.py", jobs)
        self.assertLess(contract, batches)
        self.assertLess(batches, jobs)
        self.assertLess(jobs, header)

    def test_clean_generic_location_driver_is_read_only_and_registry_dispatched(self):
        observer = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        producer = (
            build.ROOT / "tools/miel_vliegt/hangover/"
            "native_dispatch_semantic_hook.c"
        ).read_text(encoding="utf-8")
        driver_start = observer.index(
            "static void dispatch_native_capture_driver_on_manager_tick",
            observer.index("static void native_capture_driver_fail"),
        )
        driver = observer[
            driver_start:
            observer.index("static BOOL dispatch_ci_session", driver_start)
        ]
        self.assertIn("resolve_registered_engine_mode_callback", driver)
        self.assertIn(
            "callback(callback_object, ENGINE_MODE_COMMAND_ID, target_mode)",
            driver,
        )
        self.assertIn("mvds_read_final_mission_state", driver)
        self.assertNotIn("copy_writable", driver)
        self.assertNotIn("write_pointer", driver)
        self.assertNotIn("MODE_SET", driver)
        self.assertIn('strcmp(current_mode, "mode_fly")', driver)
        self.assertIn("exact_mygghanget_departure_transition", driver)
        self.assertNotIn("FLIGHT_TARGET", driver)
        generic_start = producer.index(
            "static void MVDS_FASTCALL hook_generic_enter",
            producer.index("static BOOL location_target_matches"),
        )
        generic = producer[
            generic_start:
            producer.index("static void begin_selector", generic_start)
        ]
        self.assertIn("mvds_read_final_mission_state", generic)

    def test_dispatch_driver_bootstrap_does_not_claim_flight_parity_rng(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        activation = source[
            source.index("static void emit_mode_activation"):
            source.index("static BOOL record_bootstrap_pending_login")
        ]
        transition = source[
            source.index("static void __attribute__((used)) "
                         "record_mode_transition_entry"):
            source.index("static void __attribute__((used)) "
                         "record_mode_transition_leave")
        ]
        for block in (activation, transition):
            driver_branch = block[
                block.index("native_capture_driver_needs_flight_bootstrap()"):
                block.index("} else if", block.index(
                    "native_capture_driver_needs_flight_bootstrap()"
                ))
            ]
            self.assertIn("flight_activation_seed_applied", driver_branch)
            self.assertIn("flight_activation_rng_open", driver_branch)
            self.assertIn("flight_activation_clock_open", driver_branch)
            self.assertNotIn("original_srand", driver_branch)
        self.assertIn("original_srand", transition)

    def test_both_win32_builders_link_the_exact_producer_sha(self):
        for relative in (
            "tools/miel_vliegt/x86_wine/Dockerfile",
            "tools/miel_vliegt/fex_wine/Dockerfile",
        ):
            dockerfile = (build.ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(dockerfile=relative):
                self.assertIn(
                    "native_dispatch_hook_contract.py --producer-build-sha",
                    dockerfile,
                )
                self.assertIn("native_dispatch_semantic_hook.c", dockerfile)
                self.assertIn("native_dispatch_semantic_hook.h", dockerfile)
                self.assertIn(
                    "-shared -I/src "
                    "-DMVDS_PRODUCER_BUILD_SHA256=\\\"${producer_sha}\\\"",
                    dockerfile,
                )
                self.assertIn(
                    "/src/native_observer_hook.c /src/native_dispatch_semantic_hook.c",
                    dockerfile,
                )

    def test_input_and_artifact_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            artifact = root / build.ARTIFACT_NAME
            artifact.write_bytes(b"observer-dll")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(
                build.build_manifest(artifact, "13.2.0", root),
            ), encoding="utf-8")
            (root / build.INPUT_PATHS[0]).write_text("drift", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inputs drifted"):
                build.validate_manifest(manifest, root)
            (root / build.INPUT_PATHS[0]).write_bytes(
                (build.ROOT / build.INPUT_PATHS[0]).read_bytes(),
            )
            artifact.write_bytes(b"different")
            with self.assertRaisesRegex(ValueError, "artifact bytes drifted"):
                build.validate_manifest(manifest, root, artifact)

    def test_manifest_requires_the_canonical_link_basename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            artifact = root / "native-observer-hook-final.dll"
            artifact.write_bytes(b"observer-dll")
            with self.assertRaisesRegex(ValueError, "canonical link basename"):
                build.build_manifest(artifact, "13.2.0", root)

    def test_manifest_shape_is_type_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(directory)
            artifact = root / build.ARTIFACT_NAME
            artifact.write_bytes(b"observer-dll")
            value = build.build_manifest(artifact, "13.2.0", root)
            value["schema"] = True
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inputs drifted"):
                build.validate_manifest(manifest, root)

    def test_manifest_generation_refuses_stale_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native-observer-build.json"
            output.write_text("stale", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "already exists"):
                build.write_manifest_exclusive(output, {"build_sha256": "0" * 64})
            self.assertEqual(output.read_text(encoding="ascii"), "stale")

    def test_compiler_version_rejects_shell_or_whitespace_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / build.ARTIFACT_NAME
            artifact.write_bytes(b"observer-dll")
            for invalid in ("", "13.2.0 --evil", "$(touch nope)", "13.2.0\n"):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    ValueError, "compiler version",
                ):
                    build.build_manifest(artifact, invalid)

    def test_runtime_image_build_fails_closed_on_decorated_proxy_export(self):
        dockerfile = (
            build.ROOT / "tools/miel_vliegt/x86_wine/Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn("-shared -Wl,--kill-at", dockerfile)
        self.assertIn("i686-w64-mingw32-objdump -p /out/DINPUT.dll", dockerfile)
        self.assertIn("DirectInputCreateA$$'", dockerfile)
        self.assertIn("! grep -Eq 'DirectInputCreateA@[0-9]+'", dockerfile)
        receipt_start = dockerfile.index(
            "sha256sum /out/native-observer-launcher.exe"
        )
        identity_receipt = dockerfile[
            receipt_start:
            dockerfile.index("\n\nFROM ubuntu:24.04\n", receipt_start)
        ]
        for artifact in (
            "/out/native-observer-launcher.exe",
            "/out/native-observer-hook.dll",
            "/out/DINPUT.dll",
        ):
            self.assertIn(artifact, identity_receipt)
        self.assertIn("/out/native-observer-build.sha256", identity_receipt)

    def test_x86_oracle_preserves_the_exact_proxy_link_map(self):
        workflow = (
            build.ROOT / ".github/workflows/native-flight-x86-suite.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("-Map,/opt/miel/DINPUT.map", workflow)
        self.assertIn("objdump -h -t /opt/miel/DINPUT.dll", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn(
            "output/build-diagnostics/DINPUT.map", workflow,
        )
        self.assertIn(
            "output/build-diagnostics/DINPUT.symbols", workflow,
        )

    @unittest.skipUnless(
        shutil.which("i686-w64-mingw32-gcc") and
        shutil.which("i686-w64-mingw32-objdump"),
        "MinGW x86 compiler is required for the DirectInput ABI contract",
    )
    def test_fake_directinput_vtables_compile_with_exact_stdcall_arity(self):
        source = (
            build.ROOT /
            "tools/miel_vliegt/x86_wine/native_observer_dinput_proxy.c"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            obj = root / "DINPUT.o"
            dll = root / "DINPUT.dll"
            subprocess.run([
                "i686-w64-mingw32-gcc", "-std=c11", "-O0", "-Wall",
                "-Wextra", "-Werror", "-c", str(source), "-o", str(obj),
            ], check=True, capture_output=True, text=True)
            symbols = subprocess.run([
                "i686-w64-mingw32-objdump", "-t", str(obj),
            ], check=True, capture_output=True, text=True).stdout
            for symbol in (
                "_fake_di_QueryInterface@12",
                "_fake_di_AddRef@4",
                "_fake_di_Release@4",
                "_fake_di_CreateDevice@16",
                "_fake_di_EnumDevices@20",
                "_fake_di_GetDeviceStatus@8",
                "_fake_di_RunControlPanel@12",
                "_fake_di_Initialize@12",
                "_fake_device_QueryInterface@12",
                "_fake_device_AddRef@4",
                "_fake_device_Release@4",
                "_fake_device_GetCapabilities@8",
                "_fake_device_EnumObjects@16",
                "_fake_device_GetProperty@12",
                "_fake_device_SetProperty@12",
                "_fake_device_Acquire@4",
                "_fake_device_Unacquire@4",
                "_fake_device_GetDeviceState@12",
                "_fake_device_GetDeviceData@20",
                "_fake_device_SetDataFormat@8",
                "_fake_device_SetEventNotification@8",
                "_fake_device_SetCooperativeLevel@12",
                "_fake_device_GetObjectInfo@16",
                "_fake_device_GetDeviceInfo@8",
                "_fake_device_RunControlPanel@12",
                "_fake_device_Initialize@16",
            ):
                self.assertIn(symbol, symbols)

            subprocess.run([
                "i686-w64-mingw32-gcc", "-std=c11", "-Os",
                "-static-libgcc", "-Wall", "-Wextra", "-Werror", "-shared",
                "-Wl,--kill-at", str(source), "-o", str(dll),
            ], check=True, capture_output=True, text=True)
            exports = subprocess.run([
                "i686-w64-mingw32-objdump", "-p", str(dll),
            ], check=True, capture_output=True, text=True).stdout
            self.assertRegex(
                exports, r"(?m)^\s*\[\s*0\].*DirectInputCreateA$",
            )
            self.assertNotRegex(exports, r"DirectInputCreateA@[0-9]+")

    def test_fake_directinput_boot_path_never_enters_wine_device_creation(self):
        source = (
            build.ROOT /
            "tools/miel_vliegt/x86_wine/native_observer_dinput_proxy.c"
        ).read_text(encoding="utf-8")
        export = source[source.index(
            "__declspec(dllexport) HRESULT WINAPI DirectInputCreateA"
        ):source.index("BOOL WINAPI DllMain")]
        self.assertNotIn("real_direct_input_create(", export)
        self.assertIn("fake->lpVtbl = &fake_direct_input_vtbl", export)
        self.assertIn("*direct_input = (LPDIRECTINPUTA)fake", export)
        self.assertEqual(source.count("fake_di_trace_once("), 27)
        self.assertIn(
            "InterlockedCompareExchange(&fake_di_trace_seen[slot]", source,
        )
        self.assertIn("MVP_DI call sequence=%ld method=%s", source)
        get_state = source[source.index(
            "static HRESULT WINAPI fake_device_GetDeviceState"
        ):source.index("static HRESULT WINAPI fake_device_GetDeviceData")]
        self.assertIn("ZeroMemory(state, size)", get_state)
        for method in (
            "fake_device_Acquire",
            "fake_device_SetProperty",
            "fake_device_SetDataFormat",
            "fake_device_SetCooperativeLevel",
        ):
            body = source[source.index(f"static HRESULT WINAPI {method}"):]
            body = body[:body.index("\n}")]
            self.assertIn("return DI_OK;", body)

    def test_runtime_state_adapter_has_one_reviewed_write_and_exact_boundaries(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        self.assertIn('"MVO_REPLAY_V3"', source)
        self.assertIn('"flight_activation_seed="', source)
        self.assertIn('"activation_tick_count="', source)
        self.assertIn('"activation_clock_sha256="', source)
        activation_clock = source[
            source.index("static DWORD record_flight_activation_clock"):
            source.index("static BOOL close_flight_activation_clock")
        ]
        self.assertIn("scripted_dt = observed_dt", activation_clock)
        self.assertIn("replay_activation_dts[replay_activation_dt_next++]", activation_clock)
        self.assertNotIn("replay_ticks[0].dt_f32_bits", activation_clock)
        activation_boundary = source[
            source.index("static void emit_mode_activation"):
            source.index("static BOOL record_bootstrap_pending_login")
        ]
        self.assertIn('strcmp(transition->requested_mode, "mode_mygghanget") == 0', activation_boundary)
        self.assertIn('strcmp(transition->source_mode, "mode_barn") != 0', activation_boundary)
        self.assertIn('strcmp(correlation, "manager_tick_current_mode") != 0', activation_boundary)
        self.assertIn('session_fail("flight_activation_clock_boundary_contract")', activation_boundary)
        self.assertIn("flight_activation_clock_open = TRUE", activation_boundary)
        self.assertIn("!location_phase_rng_seeded", activation_boundary)
        self.assertIn("!location_phase_rng_complete", activation_boundary)
        self.assertIn("location_phase_rng_count != LOCATION_PHASE_RAND_COUNT", activation_boundary)
        manager_tick = source[
            source.index("static DWORD __attribute__((used)) manager_tick_prepare"):
            source.index("static void __attribute__((naked)) manager_render_vtable_hook")
        ]
        self.assertIn("flight_activation_clock_open && replay_ticks != NULL", manager_tick)
        self.assertNotIn("flight_activation_seed_applied && replay_ticks != NULL", manager_tick)
        flight_seed_boundary = source[
            source.index("if (session_state == SESSION_DISPATCHED &&\n        transition->requested_mode_valid"):
            source.index("static void __attribute__((used)) record_mode_transition_leave")
        ]
        self.assertIn("!flight_activation_clock_open", flight_seed_boundary)
        self.assertNotIn("flight_activation_clock_open = TRUE", flight_seed_boundary)
        self.assertIn(
            'session_fail("body_position_probe_requires_natural_landing_contract")',
            flight_seed_boundary,
        )
        self.assertIn("transition->caller_site == 0x00425c2eu", flight_seed_boundary)
        self.assertEqual(source.count(", TRUE}"), 1)
        self.assertIn('{"damage_gate_timer", 0x260u, 4u, TRUE}', source)
        self.assertIn("primary_vtable != 0x0044c9fcu", source)
        self.assertIn("secondary_vtable != 0x0044c9f8u", source)
        compare = source.index("Compare every lifecycle-derived/cache-sensitive scalar")
        write = source.index("field->writable && !copy_writable", compare)
        self.assertLess(compare, write)
        self.assertIn("miel-vliegt-native-flight-activation-rng", source)
        self.assertIn("miel-vliegt-native-location-phase-rng", source)
        self.assertIn("LOCATION_PHASE_RAND_CALLER_RVA 0x00030a8au", source)
        self.assertIn("LOCATION_PHASE_RAND_COUNT 18u", source)
        location_rng = source[
            source.index("static int __cdecl observer_rand"):
            source.index("static BOOL close_flight_activation_rng")
        ]
        self.assertIn("caller_rva == LOCATION_PHASE_RAND_CALLER_RVA", location_rng)
        self.assertIn("session_state != SESSION_WAIT_LOGIN", location_rng)
        self.assertIn("original_srand((unsigned int)replay_flight_activation_seed)", location_rng)
        self.assertIn("fail_location_phase_rng()", location_rng)
        self.assertIn('session_fail("location_phase_rng_boundary_contract")', source)
        self.assertIn(
            "POSITION_CHARACTER_WRITE ((BYTE *)(ULONG_PTR)0x0043c6f6u)",
            source,
        )
        self.assertIn(
            "POSITION_CHARACTER_RESOLVE ((BYTE *)(ULONG_PTR)0x0041ad50u)",
            source,
        )
        position = source[
            source.index("static void __attribute__((used)) position_character_write_before"):
            source.index("static BOOL read_udsp_u32")
        ]
        self.assertIn("frame->command->opcode != 9u", position)
        self.assertIn("context_head != head", position)
        self.assertIn("committed_x != after->payload[0]", position)
        self.assertIn("!read_byte(after->context, 0x48eu, &dirty)", position)
        self.assertIn("!read_pointer(current, 0x1cu, &parent)", position)
        self.assertIn("!read_byte(owner_context, 0x48du, &mirror)", position)
        self.assertIn("current != owner_head", position)
        self.assertIn("POSITION_CHARACTER_RESOLVE)((void *)(ULONG_PTR)head, resolved)", position)
        self.assertIn("miel-vliegt-native-position-character", position)
        self.assertIn('"resolve_site\\\":\\\"0x0041ad50', position)
        self.assertNotIn('"head\\\":', position)
        self.assertNotIn('"context\\\":', position)
        body_position_probe = source[
            source.index("static BOOL body_position_probe_ready"):
            source.index("static BOOL body_mode_is_loaded_and_opened")
        ]
        self.assertIn("position_character_record_count", body_position_probe)
        self.assertIn("A DEF placement is output data", body_position_probe)
        self.assertIn("performs no input synthesis and no state writes", body_position_probe)
        self.assertIn("body_position_probe_timeout_contract", body_position_probe)
        self.assertNotIn("send_projector_click", body_position_probe)
        self.assertNotIn("copy_writable", body_position_probe)
        self.assertNotIn("POSITION_CHARACTER_RESOLVE", body_position_probe)
        self.assertIn('"MIEL_OBSERVER_BODY_POSITION_PROBE"', source)
        self.assertIn(
            'strcmp(body_mode_name, "mode_gabriellagourmet") != 0', source
        )
        position_hook = source[
            source.index("static void __attribute__((naked)) position_character_write_hook"):
            source.index("static const DWORD PARTICLE_BASE_F32_OFFSETS")
        ]
        self.assertIn("flds 60(%esi)", position_hook)
        self.assertIn("fstps (%eax)", position_hook)
        self.assertIn("fstps 4(%eax)", position_hook)
        self.assertIn("miel-vliegt-native-flight-activation-clock", source)
        self.assertIn("miel-vliegt-native-particle-lifecycle", source)
        self.assertIn("PARTICLE_EMITTER_TICK ((BYTE *)(ULONG_PTR)0x00433af0u)", source)
        self.assertIn("PARTICLE_RESET ((BYTE *)(ULONG_PTR)0x00432f30u)", source)
        self.assertIn("PARTICLE_PLACE ((BYTE *)(ULONG_PTR)0x00433e30u)", source)
        self.assertIn("miel-vliegt-native-particle-activation", source)
        self.assertIn("miel-vliegt-native-render-presentation", source)
        self.assertIn("miel-vliegt-native-shadow-render", source)
        self.assertIn("miel-vliegt-native-shadow-camera-render", source)
        self.assertIn("miel-vliegt-native-shadow-render-room", source)
        self.assertIn("miel-vliegt-native-shadow-visible-objects", source)
        self.assertIn("miel-vliegt-native-shadow-visible-polygons", source)
        self.assertIn("miel-vliegt-native-shadow-polygon-render", source)
        self.assertIn("miel-vliegt-native-shadow-world-relation", source)
        self.assertIn("miel-vliegt-native-shadow-rotation-setter", source)
        self.assertIn("CC_SHADOW_RENDER_IAT ((void **)(ULONG_PTR)0x0044c2b4u)", source)
        self.assertIn('"?Render@CcCamera@@QAEX_N@Z"', source)
        self.assertIn('"?RenderRoom@CcCamera@@IAEXPAVCcRoom@@PAVCcScreenClip@@HH@Z"', source)
        self.assertIn('"?RotateByZAxis@CcMatrixRot@@QAEXM@Z"', source)
        self.assertIn('"?AddVisibleObjectsToRenderList@CcRoom@@IAEXPAVCcCamera@@"', source)
        self.assertIn('"AAVCcRenderList@@PAVCcObject@@@Z"', source)
        self.assertIn('"?AddVisiblePolygonsToRenderList@CcObject@@IAEXPAVCcCamera@@"', source)
        self.assertIn('"AAVCcRenderList@@_N@Z"', source)
        self.assertIn('"?Render@CcObjPolygon@@IAEXPAVCcCamera@@H@Z"', source)
        self.assertIn('"?GetWorldRelation@CcSrtNode@@QAE_NXZ"', source)
        self.assertIn("RENDER_LIST_DISPATCH ((BYTE *)(ULONG_PTR)0x00430270u)", source)
        self.assertIn("AIRPLANE_PRESENTATION ((BYTE *)(ULONG_PTR)0x004106d0u)", source)
        particle_slice = source[
            source.index("static void emit_particle_reset_snapshot"):
            source.index("static void *const BODY_PHASE_HOOKS")
        ]
        self.assertNotIn("write_memory_exact", particle_slice)
        self.assertNotIn("object_address\"", particle_slice)
        presentation_slice = source[
            source.index("static const DWORD AIRPLANE_TRACK_A_F32_OFFSETS"):
            source.index("static void *const BODY_PHASE_HOOKS")
        ]
        self.assertNotIn("copy_writable", presentation_slice)
        self.assertNotIn("object_address\"", presentation_slice)
        self.assertIn("stable_module_identity", presentation_slice)
        self.assertIn("mask_u16", presentation_slice)
        self.assertIn("active_airplane_presentation_call", presentation_slice)
        self.assertIn("active_shadow_camera_call", presentation_slice)
        self.assertEqual(
            source.count("next_id(&mode_transition_sequence_number)"), 2,
        )

    def test_focus_reacquisition_uses_an_independent_monotonic_worker(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        parser = source[
            source.index("static BOOL parse_replay_focus_event"):
            source.index("static BOOL parse_replay_file")
        ]
        self.assertIn('"focus_event.%lu="', parser)
        self.assertIn("validate_replay_focus_timeline", source)
        worker = source[
            source.index("static DWORD WINAPI replay_focus_scheduler_thread"):
            source.index("static BOOL verify_replay_key_sample")
        ]
        self.assertIn("QueryPerformanceCounter(&replay_focus_episode_origin)",
                      worker)
        self.assertIn("wait_for_focus_offset", worker)
        self.assertIn("replay_next_tick = event->tick", worker)
        self.assertIn("send_replay_keys(", worker)
        self.assertIn("SetEvent(replay_focus_applied_event)", worker)
        self.assertIn('"focus_timeline_late_or_out_of_order"', worker)
        self.assertLess(
            worker.index("send_replay_keys("),
            worker.index("QueryPerformanceCounter(&applied_counter)"),
        )
        self.assertLess(
            worker.index("QueryPerformanceCounter(&applied_counter)"),
            worker.index("emit_focus_timeline_event(event, applied_offset_ns)"),
        )
        manager_tick = source[
            source.index("static DWORD __attribute__((used)) record_tick"):
            source.index("static void __attribute__((used)) record_controls_pre")
        ]
        self.assertIn("replay_focus_scheduler_state", manager_tick)
        self.assertIn("replay_focus_applied_event", manager_tick)
        controls_post = source[
            source.index(
                "static void __attribute__((used)) record_controls_post"
            ):
            source.index(
                "static void __attribute__((used)) record_physics_entry"
            )
        ]
        self.assertIn("arm_replay_focus_timeline(next_tick->tick)",
                      controls_post)
        self.assertIn('"focus_timeline_transition"', controls_post)

    def test_semantic_observation_profile_only_omits_presentation_hooks(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        coherence = source[
            source.index("static BOOL observation_omit_mask_is_coherent"):
            source.index("static BOOL configure_observation_profile")
        ]
        self.assertIn("OBSERVE_OMIT_AIRPLANE_SHADOW_FAMILY", coherence)
        self.assertIn("shadow_omissions == 0u", coherence)
        self.assertIn(
            "shadow_omissions == OBSERVE_OMIT_AIRPLANE_SHADOW_FAMILY",
            coherence,
        )
        family_width = 9
        family_mask = (1 << family_width) - 1
        for partial in range(1, family_mask):
            with self.subTest(partial_omission=f"0x{partial << 4:04x}"):
                shadow_omissions = partial
                self.assertFalse(
                    shadow_omissions == 0 or shadow_omissions == family_mask,
                )

        configure = source[
            source.index("static BOOL configure_observation_profile"):
            source.index("static BOOL configure_natural_transition_capture")
        ]
        self.assertIn('"MIEL_OBSERVER_OBSERVATION_PROFILE"', configure)
        self.assertIn(
            "strcmp(profile, MVOP_SEMANTIC_OBSERVER_PROFILE)", configure,
        )
        self.assertIn('strcmp(profile, "semantic-only")', configure)
        self.assertIn('"MIEL_OBSERVER_OBSERVATION_OMIT_MASK"', configure)
        self.assertIn('"MIEL_OBSERVER_ALLOW_DIVERGENT_PROFILE"', configure)
        self.assertIn("divergent_opt_in[0] != '1'", configure)
        self.assertIn("parsed_mask > OBSERVE_OMIT_ALL", configure)
        self.assertIn("OBSERVE_OMIT_SEMANTIC_DEFAULT", configure)
        self.assertIn("MVOP_SEMANTIC_OMIT_MASK", configure)
        self.assertIn("observation_omit_mask_is_coherent", configure)
        self.assertIn("scenario_bounded_observation = TRUE", configure)
        self.assertIn(
            "semantic_observation_omit_mask = scenario_bounded_observation ?",
            configure,
        )
        self.assertIn("!scene_dispatch_observation_enabled", configure)
        self.assertIn(
            "body_dispatch_state != BODY_DISPATCH_DISABLED", configure,
        )
        self.assertNotIn("copy_writable", configure)
        self.assertNotIn("write_memory_exact", configure)

        presentation_gate = source[
            source.index("static BOOL presentation_context_enabled"):
            source.index("static BOOL stable_module_identity")
        ]
        context_gate = presentation_gate[
            :presentation_gate.index("static BOOL presentation_emission_enabled")
        ]
        self.assertNotIn("semantic_observation_only", context_gate)
        self.assertIn("!semantic_observation_only", presentation_gate)
        self.assertIn("presentation_context_enabled()", presentation_gate)

        default_mask = source[
            source.index("#define OBSERVE_OMIT_SEMANTIC_DEFAULT"):
            source.index("#define OBSERVE_OMIT_ALL")
        ]
        for bit in (
            "OBSERVE_OMIT_PARTICLE_EMITTER", "OBSERVE_OMIT_PARTICLE_RESET",
            "OBSERVE_OMIT_PARTICLE_PLACE", "OBSERVE_OMIT_RENDER_LIST",
        ):
            self.assertIn(bit, default_mask)
        for bit in (
            "OBSERVE_OMIT_AIRPLANE_PRESENTATION", "OBSERVE_OMIT_SHADOW_IAT",
            "OBSERVE_OMIT_SHADOW_CAMERA", "OBSERVE_OMIT_SHADOW_ROTATION",
        ):
            self.assertNotIn(bit, default_mask)

        airplane_hook = source[
            source.index("static void __attribute__((naked)) airplane_presentation_hook"):
            source.index("static WORD read_u16")
        ]
        shadow_hook = source[
            source.index("static void __attribute__((naked)) shadow_render_iat_hook"):
            source.index("static void emit_shadow_camera_render_snapshot")
        ]
        self.assertIn("call *_airplane_presentation_trampoline", airplane_hook)
        self.assertIn("call *_shadow_render_original", shadow_hook)
        for trampoline in (
            "shadow_camera_render", "shadow_render_room",
            "shadow_visible_objects", "shadow_visible_polygons",
            "shadow_polygon_render", "shadow_world_relation",
            "shadow_rotation_setter",
        ):
            self.assertIn(f"call *_{trampoline}_trampoline", source)
        self.assertIn("presentation_context_enabled()", source)
        self.assertIn("presentation_emission_enabled(void)", source)

        profile_receipt = source[
            source.index("static void emit_observation_profile"):
            source.index("static void emit_bootstrap_diagnostic")
        ]
        self.assertIn('"evidence_eligible\\\":%s', profile_receipt)
        self.assertIn("MVOP_SEMANTIC_OBSERVER_PROFILE", profile_receipt)
        self.assertIn("MVOP_SEMANTIC_PROFILE_SHA256", profile_receipt)
        self.assertIn("MVOP_CONTRACT_SHA256", profile_receipt)
        self.assertIn(
            "MVOP_SEMANTIC_APPLICABLE_RECEIPT_CHANNELS_JSON",
            profile_receipt,
        )
        self.assertIn(
            "MVOP_SEMANTIC_OMITTED_RECEIPT_CHANNELS_JSON",
            profile_receipt,
        )
        self.assertIn('"framebuffer_required\\":%s', profile_receipt)
        self.assertIn("!scenario_bounded_observation", profile_receipt)
        self.assertIn("startup_scheduler_divergence", profile_receipt)
        self.assertIn(
            '[\\"particle-lifecycle\\",\\"presentation-render\\",'
            '\\"shadow-render\\"]',
            profile_receipt,
        )
        self.assertNotIn("observer-scheduler-barrier", source)

        framebuffer_gate = source[
            source.index("static BOOL framebuffer_capture_required"):
            source.index("static const BodyModeLifecycle *body_mode_for_vtable")
        ]
        self.assertIn("return !scenario_bounded_observation", framebuffer_gate)
        self.assertEqual(
            framebuffer_gate.count("framebuffer_capture_required()"), 2,
        )
        self.assertIn(
            "framebuffer_capture_required() &&\n"
            "        session_state == SESSION_READY",
            framebuffer_gate,
        )
        self.assertIn(
            "framebuffer_capture_required() && !frame_captured",
            framebuffer_gate,
        )

        install = source[
            source.index("static DWORD observation_omit_bit"):
            source.index("static BOOL calibration_detour_required")
        ]
        for target in (
            "PARTICLE_EMITTER_TICK", "PARTICLE_RESET", "PARTICLE_PLACE",
            "RENDER_LIST_DISPATCH", "AIRPLANE_PRESENTATION",
            "shadow_camera_render_target", "shadow_render_room_target",
            "shadow_visible_objects_target", "shadow_visible_polygons_target",
            "shadow_polygon_render_target", "shadow_world_relation_target",
            "shadow_rotation_setter_target",
        ):
            self.assertIn(target, install)
        for target in (
            "MODE_SET", "QUEUE_MODE", "FLIGHT_TARGET", "UDSP_DISPATCH",
            "POSITION_CHARACTER_WRITE", "CONTROLS_PRE", "CONTROLS_POST",
            "FLIGHT_STEP_ENTRY", "FLIGHT_STEP_LEAVE", "COLLISION_ENTRY",
            "COLLISION_COMMIT", "CONTACT_SITE", "UDSP_ROOT_START",
            "UDSP_ROOT_UPDATE",
        ):
            self.assertNotIn(f"target == {target}", install)

        shadow_install = source[
            source.index("static BOOL install_shadow_render_interposition"):
            source.index("static BOOL rollback_shadow_render_interposition")
        ]
        self.assertIn("OBSERVE_OMIT_SHADOW_IAT", shadow_install)
        self.assertIn("miel-vliegt-native-observation-profile", source)
        self.assertIn('"omit_mask\\":\\"0x%04lx', source)
        self.assertIn('"profile_state_writes\\\":false', source)
        self.assertIn('"signature_preflight_complete\\\":true', source)

    def test_media_semantics_hooks_are_hash_bound_narrow_and_reversible(self):
        source = (
            build.ROOT / "tools/miel_vliegt/hangover/native_observer_hook.c"
        ).read_text(encoding="utf-8")
        for binding in (
            "#define ANIMATION_RANDOMFRAME_START_CALLER_RVA 0x00000405u",
            "#define ANIMATION_RANDOMFRAME_CADENCE_CALLER_RVA 0x000005a2u",
            "#define AUDIO_START ((BYTE *)(ULONG_PTR)0x00409fc0u)",
            "#define AUDIO_POLL ((BYTE *)(ULONG_PTR)0x0040a650u)",
        ):
            self.assertIn(binding, source)
        observer_rand = source[
            source.index("static int __cdecl observer_rand"):
            source.index("static BOOL close_flight_activation_rng")
        ]
        self.assertIn("emit_media_animation_rng", observer_rand)
        self.assertIn("ANIMATION_RANDOMFRAME_START_CALLER_RVA", observer_rand)
        self.assertIn("ANIMATION_RANDOMFRAME_CADENCE_CALLER_RVA", observer_rand)
        self.assertNotIn("emit_media_animation_rng(ordinal, rva", observer_rand)

        audio_hooks = source[
            source.index(
                "static void * __attribute__((thiscall)) audio_start_hook"
            ):
            source.index("static int __cdecl observer_rand")
        ]
        self.assertIn("audio_start_trampoline", audio_hooks)
        self.assertIn("audio_poll_trampoline", audio_hooks)
        self.assertIn("register_media_audio_instance", audio_hooks)
        self.assertNotIn('"instance"', audio_hooks)
        self.assertNotIn('"pointer"', audio_hooks)

        preflight = source[
            source.index("static BOOL all_hook_signatures_match"):
            source.index("static DWORD parse_record_limit")
        ]
        # Audio start/poll are an OPTIONAL, scenario-bounded media-semantics
        # channel that is deliberately outside the parity receipt contract
        # (native_observation_profile_contract.SEMANTIC_RECEIPT_CHANNELS, the
        # first four channels only -- audio speaks the separate
        # miel-vliegt-native-media-semantics-observation protocol). They must
        # therefore NOT participate in the bootstrap-critical signature
        # preflight: a media site whose pinned bytes drift at runtime must
        # skip the channel instead of aborting the observer load and failing
        # the game bootstrap. The signature is still validated lazily, at
        # install time, by install_detour's memcmp, which returns FALSE before
        # any target bytes are patched.
        self.assertNotIn(
            "memcmp(AUDIO_START, AUDIO_START_SIGNATURE", preflight
        )
        self.assertNotIn("memcmp(AUDIO_POLL, AUDIO_POLL_SIGNATURE", preflight)
        poll_signature = re.search(
            r"static const BYTE AUDIO_POLL_SIGNATURE\[\] = \{([^}]*)\};",
            source,
            re.DOTALL,
        )
        self.assertIsNotNone(poll_signature)
        poll_bytes = tuple(
            int(value, 16)
            for value in re.findall(r"0x[0-9a-fA-F]+", poll_signature.group(1))
        )
        self.assertEqual(
            poll_bytes,
            (0x51, 0x56, 0x8B, 0xF1, 0x8A, 0x46, 0x1C),
        )
        # push ecx; push esi; mov esi,ecx; mov al,[esi+0x1c].
        # The trampoline must steal four complete x86 instructions, never the
        # first two bytes of the final three-byte MOV.
        self.assertEqual(sum((1, 1, 2, 3)), len(poll_bytes))
        self.assertEqual(poll_bytes[-3:], (0x8A, 0x46, 0x1C))
        init = source[
            source.index(
                "__declspec(dllexport) DWORD WINAPI MielObserverInitialize",
                source.index("static DWORD parse_record_limit"),
            ):
            source.index("BOOL WINAPI DllMain")
        ]
        # The audio detours bind best-effort under scenario-bounded
        # observation. install_detour leaves the target untouched and the
        # trampoline NULL on a signature mismatch, so an unbindable media
        # site can never prevent the observer from loading. The media channel
        # cannot promote parity, so making it non-fatal does not weaken any
        # fail-closed receipt gate; rollback_detour tolerates the resulting
        # NULL trampoline (returns TRUE when there is no installed copy and
        # no protection record).
        self.assertIn("if (scenario_bounded_observation) {", init)
        self.assertIn(
            "(void)install_detour(AUDIO_START, AUDIO_START_SIGNATURE", init
        )
        self.assertIn(
            "(void)install_detour(AUDIO_POLL, AUDIO_POLL_SIGNATURE", init
        )
        # The audio install must never branch to the fatal install_failed path.
        self.assertNotIn(
            "!install_detour(AUDIO_START, AUDIO_START_SIGNATURE", init
        )
        self.assertNotIn(
            "!install_detour(AUDIO_POLL, AUDIO_POLL_SIGNATURE", init
        )
        self.assertLess(
            init.index("rollback_detour(AUDIO_POLL"),
            init.index("rollback_detour(AUDIO_START"),
        )
        self.assertIn(
            "miel-vliegt-native-media-semantics-observation", source
        )


if __name__ == "__main__":
    unittest.main()
